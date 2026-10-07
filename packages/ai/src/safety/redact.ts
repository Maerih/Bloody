import { createHmac, randomBytes } from "node:crypto";
import { isRecord } from "../util/json.js";

/**
 * Secret / PII redaction applied to everything Bloody sends to a model (prompts, grounding,
 * tool results, tool-call arguments) and to everything it writes to AI audit logs.
 *
 * Redacted values are replaced by stable placeholders `[REDACTED:<kind>:<tag>]`. The tag is an
 * HMAC of the value under a per-run random salt, so the same value maps to the same placeholder
 * within one AI run (the model can still correlate "the same password appears on 3 hosts") but
 * placeholders are not linkable across runs or tenants. The {@link RedactionVault} keeps the
 * mapping in memory only, so tool-call arguments that echo a placeholder can be re-hydrated
 * before Bloody executes the tool — the model never sees the secret, investigations still work.
 */

export type SecretKind =
  | "private_key"
  | "url_credentials"
  | "slack_webhook"
  | "anthropic_key"
  | "openai_key"
  | "github_token"
  | "gitlab_token"
  | "slack_token"
  | "stripe_key"
  | "google_api_key"
  | "aws_access_key"
  | "aws_secret_key"
  | "bloody_api_key"
  | "jwt"
  | "bearer_token"
  | "connection_secret"
  | "password"
  | "secret_value";

export type PiiKind = "email" | "credit_card" | "us_ssn" | "iban";
export type RedactionKind = SecretKind | PiiKind;

export interface RedactionOptions {
  /** Redact credentials, keys, tokens, passwords. Default true. */
  secrets?: boolean;
  /** Redact personal data (cards, SSNs, IBANs). Default false. */
  pii?: boolean;
  /** Redact e-mail addresses. Defaults to the `pii` setting. */
  emails?: boolean;
}

export interface RedactionStats {
  total: number;
  byKind: Partial<Record<RedactionKind, number>>;
}

export function emptyRedactionStats(): RedactionStats {
  return { total: 0, byKind: {} };
}

export function mergeRedactionStats(a: RedactionStats, b: RedactionStats): RedactionStats {
  const byKind: Partial<Record<RedactionKind, number>> = { ...a.byKind };
  for (const [k, v] of Object.entries(b.byKind) as [RedactionKind, number][]) byKind[k] = (byKind[k] ?? 0) + v;
  return { total: a.total + b.total, byKind };
}

const PLACEHOLDER_RE = /\[REDACTED:([a-z0-9_]+):([0-9a-f]{8})\]/g;
const PLACEHOLDER_PREFIX = "[REDACTED:";

export class RedactionVault {
  private readonly salt: Buffer;
  private readonly originals = new Map<string, string>();

  constructor(salt?: Buffer) {
    this.salt = salt ?? randomBytes(32);
  }

  placeholder(kind: RedactionKind, value: string): string {
    const tag = createHmac("sha256", this.salt).update(kind).update("\u0000").update(value).digest("hex").slice(0, 8);
    const ph = `[REDACTED:${kind}:${tag}]`;
    if (!this.originals.has(ph)) this.originals.set(ph, value);
    return ph;
  }

  get size(): number {
    return this.originals.size;
  }

  /** Replace known placeholders with their original values (unknown placeholders are kept). */
  rehydrate(text: string): string {
    if (!text.includes(PLACEHOLDER_PREFIX)) return text;
    return text.replace(PLACEHOLDER_RE, (ph) => this.originals.get(ph) ?? ph);
  }

  rehydrateValue<T>(value: T): T {
    return mapStrings(value, (s) => this.rehydrate(s)) as T;
  }
}

function mapStrings(value: unknown, fn: (s: string) => string, depth = 0): unknown {
  if (depth > 64) return value;
  if (typeof value === "string") return fn(value);
  if (Array.isArray(value)) return value.map((v) => mapStrings(v, fn, depth + 1));
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = mapStrings(v, fn, depth + 1);
    return out;
  }
  return value;
}

interface Rule {
  kind: RedactionKind;
  pattern: RegExp;
  /** Index of the capture group holding the secret; 0 = whole match. Other groups are kept verbatim. */
  secretGroup: number;
  pii?: "email" | "pii";
  validate?: (value: string) => boolean;
}

function luhnValid(digits: string): boolean {
  const d = digits.replace(/[ -]/g, "");
  if (d.length < 13 || d.length > 19 || /^(\d)\1+$/.test(d)) return false;
  let sum = 0;
  let double = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

function ibanValid(iban: string): boolean {
  const s = iban.replace(/ /g, "").toUpperCase();
  if (s.length < 15 || s.length > 34) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const chunk = code >= 65 && code <= 90 ? String(code - 55) : ch;
    for (const digit of chunk) remainder = (remainder * 10 + (digit.charCodeAt(0) - 48)) % 97;
  }
  return remainder === 1;
}

const KV_SECRET_NAMES =
  "password|passwd|passphrase|secret|client_secret|secret_key|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|session[_-]?token|private[_-]?key|aws_secret_access_key|aws_secret";

/** Ordered: specific token formats first, generic key/value heuristics last. */
const RULES: Rule[] = [
  { kind: "private_key", pattern: /-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END \1PRIVATE KEY(?: BLOCK)?-----/g, secretGroup: 0 },
  { kind: "url_credentials", pattern: /(\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@'"]{1,256}:)([^\s@/'"]{1,256})(@)/gi, secretGroup: 2 },
  { kind: "slack_webhook", pattern: /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9/_-]{10,}/g, secretGroup: 0 },
  { kind: "anthropic_key", pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/g, secretGroup: 0 },
  { kind: "openai_key", pattern: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g, secretGroup: 0 },
  { kind: "github_token", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g, secretGroup: 0 },
  { kind: "gitlab_token", pattern: /\bglpat-[A-Za-z0-9_-]{20,}/g, secretGroup: 0 },
  { kind: "slack_token", pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, secretGroup: 0 },
  { kind: "stripe_key", pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/g, secretGroup: 0 },
  { kind: "google_api_key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, secretGroup: 0 },
  { kind: "aws_access_key", pattern: /\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b/g, secretGroup: 0 },
  { kind: "bloody_api_key", pattern: /\bbk_[A-Za-z0-9_-]{16,}/g, secretGroup: 0 },
  { kind: "jwt", pattern: /\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/g, secretGroup: 0 },
  { kind: "bearer_token", pattern: /(\b(?:Bearer|Basic|Token)\s+)([A-Za-z0-9._~+/=-]{16,})/g, secretGroup: 2 },
  {
    kind: "connection_secret",
    // Case-sensitive on purpose: matches connection strings, not e.g. the PWD= environment variable.
    pattern: /(\b(?:AccountKey|SharedAccessKey|SharedAccessSignature|Pwd)\s*=\s*)([^;&\s"']{6,})/g,
    secretGroup: 2,
  },
  { kind: "aws_secret_key", pattern: /(\baws_?secret_?access_?key["']?\s*[:=]\s*["']?)([A-Za-z0-9/+=]{40})/gi, secretGroup: 2 },
  {
    kind: "password",
    pattern: new RegExp(`((?:^|\\s)--?(?:${KV_SECRET_NAMES})(?:\\s+|=))([^\\s"']{3,})`, "gi"),
    secretGroup: 2,
  },
  {
    kind: "password",
    pattern: new RegExp(`(\\b(?:${KV_SECRET_NAMES})\\b["']?\\s*[:=]\\s*["']?)([^\\s"',;}{&<>]{4,})`, "gi"),
    secretGroup: 2,
  },
  // ── personal data ──
  { kind: "email", pattern: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g, secretGroup: 0, pii: "email" },
  { kind: "credit_card", pattern: /\b\d(?:[ -]?\d){12,18}\b/g, secretGroup: 0, pii: "pii", validate: luhnValid },
  { kind: "us_ssn", pattern: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g, secretGroup: 0, pii: "pii" },
  { kind: "iban", pattern: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g, secretGroup: 0, pii: "pii", validate: ibanValid },
];

const SENSITIVE_KEY_RE =
  /^(?:password|passwd|pwd|passphrase|secret|client_?secret|secret_?key|secret_?access_?key|api_?key|apikey|x-api-key|access_?token|refresh_?token|id_?token|auth_?token|session_?token|token|authorization|proxy-authorization|cookie|set-cookie|private_?key|credential|credentials)$/i;

export class Redactor {
  readonly options: Required<RedactionOptions>;
  private readonly rules: Rule[];

  constructor(options: RedactionOptions = {}) {
    const pii = options.pii ?? false;
    this.options = { secrets: options.secrets ?? true, pii, emails: options.emails ?? pii };
    this.rules = RULES.filter((r) => {
      if (r.pii === "email") return this.options.emails;
      if (r.pii === "pii") return this.options.pii;
      return this.options.secrets;
    });
  }

  get active(): boolean {
    return this.rules.length > 0;
  }

  redactText(text: string, vault: RedactionVault, stats?: RedactionStats): string {
    if (!text || this.rules.length === 0) return text;
    let out = text;
    for (const rule of this.rules) out = this.applyOutsidePlaceholders(out, rule, vault, stats);
    return out;
  }

  /** Apply one rule to the text between existing placeholders (placeholders are never rewritten). */
  private applyOutsidePlaceholders(text: string, rule: Rule, vault: RedactionVault, stats?: RedactionStats): string {
    if (!text.includes(PLACEHOLDER_PREFIX)) return this.applyRule(text, rule, vault, stats);
    let out = "";
    let last = 0;
    const re = new RegExp(PLACEHOLDER_RE.source, "g");
    for (let m = re.exec(text); m !== null; m = re.exec(text)) {
      out += this.applyRule(text.slice(last, m.index), rule, vault, stats) + m[0];
      last = m.index + m[0].length;
    }
    return out + this.applyRule(text.slice(last), rule, vault, stats);
  }

  private applyRule(text: string, rule: Rule, vault: RedactionVault, stats?: RedactionStats): string {
    if (!text) return text;
    rule.pattern.lastIndex = 0;
    return text.replace(rule.pattern, (...args: unknown[]) => {
      const match = args[0] as string;
      // replace() callback args: match, ...captureGroups, offset, input (no named groups used).
      const groups = args.slice(1, args.length - 2) as (string | undefined)[];
      const secret = rule.secretGroup === 0 ? match : groups[rule.secretGroup - 1];
      if (!secret || secret.startsWith(PLACEHOLDER_PREFIX)) return match;
      if (rule.validate && !rule.validate(secret)) return match;
      if (stats) {
        stats.total += 1;
        stats.byKind[rule.kind] = (stats.byKind[rule.kind] ?? 0) + 1;
      }
      const ph = vault.placeholder(rule.kind, secret);
      if (rule.secretGroup === 0) return ph;
      // Groups partition the match; replace only the secret group.
      let rebuilt = "";
      for (let i = 0; i < groups.length; i++) {
        const g = groups[i];
        if (g === undefined) continue;
        rebuilt += i === rule.secretGroup - 1 ? ph : g;
      }
      return rebuilt;
    });
  }

  /** Deep-redact a JSON-like value. Values under sensitive keys are always replaced. */
  redactValue<T>(value: T, vault: RedactionVault, stats?: RedactionStats): T {
    return this.walk(value, vault, stats, false, 0, new WeakSet()) as T;
  }

  private walk(value: unknown, vault: RedactionVault, stats: RedactionStats | undefined, sensitive: boolean, depth: number, seen: WeakSet<object>): unknown {
    if (depth > 64) return "[depth-limit]";
    if (typeof value === "string") {
      if (sensitive && this.options.secrets && value.length > 0 && !value.startsWith(PLACEHOLDER_PREFIX)) {
        if (stats) {
          stats.total += 1;
          stats.byKind.secret_value = (stats.byKind.secret_value ?? 0) + 1;
        }
        return vault.placeholder("secret_value", value);
      }
      return this.redactText(value, vault, stats);
    }
    if (typeof value === "number" && sensitive && this.options.secrets) {
      if (stats) {
        stats.total += 1;
        stats.byKind.secret_value = (stats.byKind.secret_value ?? 0) + 1;
      }
      return vault.placeholder("secret_value", String(value));
    }
    if (Array.isArray(value)) {
      if (seen.has(value)) return "[circular]";
      seen.add(value);
      return value.map((v) => this.walk(v, vault, stats, sensitive, depth + 1, seen));
    }
    if (isRecord(value)) {
      if (seen.has(value)) return "[circular]";
      seen.add(value);
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) {
        out[k] = this.walk(v, vault, stats, sensitive || SENSITIVE_KEY_RE.test(k), depth + 1, seen);
      }
      return out;
    }
    return value;
  }
}

const secretsOnly = new Redactor({ secrets: true, pii: false });

/** One-shot secret scrub for log lines / error messages (placeholders are not reversible). */
export function scrubSecrets(text: string): string {
  return secretsOnly.redactText(text, new RedactionVault());
}

export function scrubSecretsDeep<T>(value: T): T {
  return secretsOnly.redactValue(value, new RedactionVault());
}

/** Buffers streamed deltas so placeholders split across chunks are re-hydrated correctly. */
export class StreamingRehydrator {
  private buffer = "";
  constructor(
    private readonly vault: RedactionVault,
    private readonly emit: (text: string) => void,
  ) {}

  push(text: string): void {
    this.buffer += text;
    const open = this.buffer.lastIndexOf("[");
    if (open >= 0) {
      const tail = this.buffer.slice(open);
      const couldBePlaceholder = !tail.includes("]") && tail.length < 48 && (PLACEHOLDER_PREFIX.startsWith(tail) || tail.startsWith(PLACEHOLDER_PREFIX));
      if (couldBePlaceholder) {
        const head = this.buffer.slice(0, open);
        this.buffer = tail;
        if (head) this.emit(this.vault.rehydrate(head));
        return;
      }
    }
    const out = this.buffer;
    this.buffer = "";
    if (out) this.emit(this.vault.rehydrate(out));
  }

  flush(): void {
    const out = this.buffer;
    this.buffer = "";
    if (out) this.emit(this.vault.rehydrate(out));
  }
}
