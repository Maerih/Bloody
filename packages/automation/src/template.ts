import { getPath, isValidPath } from "./util/path.js";

/**
 * Bloody's notification template language — a deliberately tiny, logic-less, mustache-like
 * syntax. There are no sections, loops, partials, helpers with side effects, raw/unescaped
 * output or expression evaluation: a template can only *read* variables from the context it
 * is given and pass them through a fixed set of pure formatting filters.
 *
 *   {{ incident.title }}
 *   {{ severity | upper }}
 *   {{ incident.assignee.name | default:"unassigned" }}
 *   {{ indicator.value | defang }}
 *   {{ incident.detectedAt | date }}
 *
 * In `html` mode every interpolated value is HTML-escaped (& < > " ' ` =), so data coming from
 * events (hostnames, process command lines, attacker-controlled strings) can never inject
 * markup or script into an e-mail.
 */
export type EscapeMode = "html" | "none";

export interface RenderOptions {
  escape?: EscapeMode;
  /** Upper bound on the rendered output length (default 100 000 chars). */
  maxLength?: number;
  /** Time zone for the date filters (IANA; default UTC). */
  timeZone?: string;
}

export interface RenderResult {
  output: string;
  /** Variables referenced but absent from the context (rendered as empty / default). */
  missing: string[];
  warnings: string[];
}

export class TemplateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TemplateError";
  }
}

const TAG_RE = /\{\{\s*([^{}]*?)\s*\}\}/g;
const HTML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "`": "&#96;",
  "=": "&#61;",
};

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"'`=]/g, (ch) => HTML_ESCAPES[ch] ?? ch);
}

/** Remove C0/C1 control characters except tab and newline. */
export function stripControlChars(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, "");
}

/** Single-line header value (e-mail subject etc.): no CR/LF (header injection), trimmed, bounded. */
export function sanitizeHeaderValue(value: string, max = 250): string {
  const single = stripControlChars(value).replace(/[\r\n\t\u2028\u2029]+/g, " ").replace(/\s{2,}/g, " ").trim();
  return single.length > max ? `${single.slice(0, max - 1)}…` : single;
}

/** Make an indicator non-clickable for safe sharing ("hxxps://evil[.]com", "10.0.0[.]1"). */
export function defang(value: string): string {
  return value
    .replace(/^http(s?):\/\//i, (_m, s: string) => `hxxp${s}://`)
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");
}

interface ParsedFilter {
  name: string;
  arg: string | number | undefined;
}

interface ParsedTag {
  path: string;
  filters: ParsedFilter[];
}

const KNOWN_FILTERS = new Set(["default", "upper", "lower", "title", "truncate", "date", "datetime", "number", "percent", "join", "json", "defang", "severity"]);

function parseArg(raw: string | undefined): string | number | undefined {
  if (raw === undefined) return undefined;
  const t = raw.trim();
  if (t === "") return undefined;
  const quoted = /^"((?:[^"\\]|\\.)*)"$/.exec(t) ?? /^'((?:[^'\\]|\\.)*)'$/.exec(t);
  if (quoted) return (quoted[1] ?? "").replace(/\\(.)/g, "$1");
  if (/^-?\d+(\.\d+)?$/.test(t)) return Number(t);
  return t;
}

/** Split on `|` that are not inside quotes. */
function splitPipes(expr: string): string[] {
  const parts: string[] = [];
  let cur = "";
  let quote: string | null = null;
  for (let i = 0; i < expr.length; i++) {
    const ch = expr[i]!;
    if (quote) {
      cur += ch;
      if (ch === "\\" && i + 1 < expr.length) {
        cur += expr[++i];
      } else if (ch === quote) {
        quote = null;
      }
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      cur += ch;
    } else if (ch === "|") {
      parts.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  parts.push(cur);
  return parts.map((p) => p.trim());
}

function parseTag(expr: string): ParsedTag | { error: string } {
  const [pathPart, ...filterParts] = splitPipes(expr);
  const path = (pathPart ?? "").trim();
  if (!isValidPath(path)) return { error: `invalid variable "${path}"` };
  const filters: ParsedFilter[] = [];
  for (const fp of filterParts) {
    const idx = fp.indexOf(":");
    const name = (idx === -1 ? fp : fp.slice(0, idx)).trim();
    const arg = idx === -1 ? undefined : parseArg(fp.slice(idx + 1));
    filters.push({ name, arg });
  }
  return { path, filters };
}

function formatDate(value: unknown, withTime: boolean, timeZone: string): string | undefined {
  const d = value instanceof Date ? value : typeof value === "string" || typeof value === "number" ? new Date(value) : null;
  if (!d || Number.isNaN(d.getTime())) return undefined;
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone,
    year: "numeric",
    month: "short",
    day: "2-digit",
    ...(withTime ? { hour: "2-digit", minute: "2-digit", hourCycle: "h23" as const } : {}),
  }).formatToParts(d);
  const get = (t: string): string => parts.find((p) => p.type === t)?.value ?? "";
  const date = `${get("day")} ${get("month")} ${get("year")}`;
  if (!withTime) return date;
  const tzLabel = timeZone === "UTC" ? "UTC" : timeZone;
  return `${date} ${get("hour")}:${get("minute")} ${tzLabel}`;
}

/** Turn any context value into display text. */
export function stringifyValue(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "";
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? "" : value.toISOString();
  if (Array.isArray(value)) return value.map((v) => stringifyValue(v)).filter((s) => s !== "").join(", ");
  try {
    return JSON.stringify(value);
  } catch {
    return "";
  }
}

function applyFilter(value: unknown, filter: ParsedFilter, timeZone: string, warnings: string[]): unknown {
  switch (filter.name) {
    case "default":
      return value === undefined || value === null || value === "" || (Array.isArray(value) && value.length === 0) ? (filter.arg ?? "") : value;
    case "upper":
      return stringifyValue(value).toUpperCase();
    case "lower":
      return stringifyValue(value).toLowerCase();
    case "title":
      return stringifyValue(value)
        .replace(/[_-]+/g, " ")
        .replace(/\b\w/g, (c) => c.toUpperCase());
    case "severity": {
      const s = stringifyValue(value);
      return s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : s;
    }
    case "truncate": {
      const n = typeof filter.arg === "number" ? Math.max(1, Math.floor(filter.arg)) : 80;
      const s = stringifyValue(value);
      return s.length > n ? `${s.slice(0, Math.max(0, n - 1))}…` : s;
    }
    case "date":
    case "datetime":
      return value === undefined || value === null || value === "" ? value : (formatDate(value, filter.name === "datetime", timeZone) ?? stringifyValue(value));
    case "number": {
      const n = typeof value === "number" ? value : Number(stringifyValue(value));
      if (!Number.isFinite(n) || stringifyValue(value) === "") return value;
      const digits = typeof filter.arg === "number" ? Math.min(6, Math.max(0, Math.floor(filter.arg))) : undefined;
      return new Intl.NumberFormat("en-US", digits === undefined ? {} : { minimumFractionDigits: digits, maximumFractionDigits: digits }).format(n);
    }
    case "percent": {
      const n = typeof value === "number" ? value : Number(stringifyValue(value));
      if (!Number.isFinite(n) || stringifyValue(value) === "") return value;
      // Values in [0,1] are treated as ratios; larger values as already-percent.
      const pct = Math.abs(n) <= 1 ? n * 100 : n;
      return `${pct.toFixed(typeof filter.arg === "number" ? Math.min(4, Math.max(0, filter.arg)) : 1)}%`;
    }
    case "join":
      return Array.isArray(value) ? value.map((v) => stringifyValue(v)).join(typeof filter.arg === "string" ? filter.arg : ", ") : value;
    case "json":
      try {
        return JSON.stringify(value ?? null);
      } catch {
        return "";
      }
    case "defang":
      return defang(stringifyValue(value));
    default:
      warnings.push(`unknown filter "${filter.name}" ignored`);
      return value;
  }
}

/** Render a template against a context. Never throws for missing data; see {@link validateTemplate}. */
export function renderTemplateDetailed(template: string, context: unknown, opts: RenderOptions = {}): RenderResult {
  const escape = opts.escape ?? "none";
  const maxLength = opts.maxLength ?? 100_000;
  const timeZone = opts.timeZone ?? "UTC";
  const missing: string[] = [];
  const warnings: string[] = [];
  const output = template.replace(TAG_RE, (_m, expr: string) => {
    const tag = parseTag(expr);
    if ("error" in tag) {
      warnings.push(tag.error);
      return "";
    }
    let value = getPath(context, tag.path);
    if (value === undefined && !missing.includes(tag.path)) missing.push(tag.path);
    for (const f of tag.filters) value = applyFilter(value, f, timeZone, warnings);
    const text = stripControlChars(stringifyValue(value));
    return escape === "html" ? escapeHtml(text) : text;
  });
  const bounded = output.length > maxLength ? `${output.slice(0, maxLength - 1)}…` : output;
  return { output: bounded, missing, warnings };
}

export function renderTemplate(template: string, context: unknown, opts: RenderOptions = {}): string {
  return renderTemplateDetailed(template, context, opts).output;
}

/** Variables referenced by a template (for editor autocomplete / "unknown variable" hints). */
export function templateVariables(template: string): string[] {
  const vars = new Set<string>();
  for (const m of template.matchAll(TAG_RE)) {
    const tag = parseTag(m[1] ?? "");
    if (!("error" in tag)) vars.add(tag.path);
  }
  return [...vars];
}

/** Editor-time validation: syntax, unknown filters, unbalanced braces, size. */
export function validateTemplate(template: string, opts: { maxLength?: number; knownRoots?: readonly string[] } = {}): { path: string; message: string }[] {
  const issues: { path: string; message: string }[] = [];
  const max = opts.maxLength ?? 20_000;
  if (template.length > max) issues.push({ path: "template", message: `template exceeds ${max} characters` });
  const stripped = template.replace(TAG_RE, "");
  if (stripped.includes("{{") || stripped.includes("}}")) issues.push({ path: "template", message: "unbalanced '{{' / '}}'" });
  for (const m of template.matchAll(TAG_RE)) {
    const tag = parseTag(m[1] ?? "");
    if ("error" in tag) {
      issues.push({ path: "template", message: tag.error });
      continue;
    }
    for (const f of tag.filters) {
      if (!KNOWN_FILTERS.has(f.name)) issues.push({ path: "template", message: `unknown filter "${f.name}" in {{${m[1]}}}` });
    }
    if (opts.knownRoots && !opts.knownRoots.includes(tag.path.split(".")[0] ?? "")) {
      issues.push({ path: "template", message: `unknown variable "${tag.path}"` });
    }
  }
  return issues;
}

/** Render step parameters: strings are templated; a string that is exactly one tag keeps the raw value type. */
export function renderParameters(params: Record<string, unknown>, context: unknown, depth = 0): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) out[k] = renderParamValue(v, context, depth);
  return out;
}

function renderParamValue(v: unknown, context: unknown, depth: number): unknown {
  if (depth > 8) return v;
  if (typeof v === "string") {
    const single = /^\{\{\s*([^{}|]+?)\s*\}\}$/.exec(v);
    if (single && isValidPath(single[1]!.trim())) {
      const raw = getPath(context, single[1]!.trim());
      return raw === undefined ? null : raw;
    }
    return v.includes("{{") ? renderTemplate(v, context) : v;
  }
  if (Array.isArray(v)) return v.map((x) => renderParamValue(x, context, depth + 1));
  if (v !== null && typeof v === "object") return renderParameters(v as Record<string, unknown>, context, depth + 1);
  return v;
}

const URL_RE = /\bhttps?:\/\/[^\s<>"'`]+[^\s<>"'`.,;:!?)\]]/gi;

/**
 * Convert plain notification text into safe HTML: everything is escaped first, then a tiny
 * formatting vocabulary is applied — blank-line paragraphs, "- " bullet lists, **bold** and
 * auto-linked http(s) URLs. No author- or data-supplied markup ever survives.
 */
export function textToHtml(text: string, opts: { linkColor?: string } = {}): string {
  const linkStyle = `color:${opts.linkColor ?? "#2a78d6"};text-decoration:underline;`;
  const inline = (line: string): string => {
    let out = "";
    let last = 0;
    for (const m of line.matchAll(URL_RE)) {
      const idx = m.index ?? 0;
      out += formatBold(escapeHtml(line.slice(last, idx)));
      const url = m[0];
      out += `<a href="${escapeHtml(url)}" style="${linkStyle}" target="_blank" rel="noopener noreferrer">${escapeHtml(url)}</a>`;
      last = idx + url.length;
    }
    out += formatBold(escapeHtml(line.slice(last)));
    return out;
  };
  const blocks = stripControlChars(text).replace(/\r\n?/g, "\n").split(/\n{2,}/);
  return blocks
    .map((block) => block.trim())
    .filter((block) => block.length > 0)
    .map((block) => {
      const lines = block.split("\n");
      if (lines.every((l) => /^\s*[-*•]\s+/.test(l))) {
        const items = lines.map((l) => `<li style="margin:0 0 6px 0;">${inline(l.replace(/^\s*[-*•]\s+/, ""))}</li>`).join("");
        return `<ul style="margin:0 0 16px 0;padding:0 0 0 20px;">${items}</ul>`;
      }
      return `<p style="margin:0 0 16px 0;">${lines.map(inline).join("<br>")}</p>`;
    })
    .join("\n");
}

function formatBold(escaped: string): string {
  return escaped.replace(/\*\*([^*]+?)\*\*/g, "<strong>$1</strong>");
}
