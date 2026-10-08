import { EventCategory, IndicatorType, Severity, SourceKind } from "@bloody/contracts";

/**
 * Bloody event query syntax (shared by SIEM search, module lenses, hunting and the AI SOC's
 * `search_events` tool): Lucene-style `field:value` terms combined with AND / OR / NOT.
 *
 *   eq        field:value            field:"quoted value"
 *   neq       NOT field:value
 *   contains  field:*value*          (spaces escaped with "\ ")
 *   gt/gte    field:>10  field:>=10
 *   lt/lte    field:<10  field:<=10
 *   exists    field:*
 *   in        field:(a OR b OR c)
 *
 * The query builder represents a query as AND-ed clauses (chips) plus optional free text.
 * `serializeQuery` and `parseQuery` round-trip that representation; queries using top-level
 * OR, grouping or other constructs are kept as raw text (parseQuery returns null).
 */

export const QUERY_OPS = ["eq", "neq", "contains", "gt", "gte", "lt", "lte", "in", "exists"] as const;
export type QueryOp = (typeof QUERY_OPS)[number];

export const QUERY_OP_LABELS: Record<QueryOp, string> = {
  eq: "is",
  neq: "is not",
  contains: "contains",
  gt: ">",
  gte: "≥",
  lt: "<",
  lte: "≤",
  in: "is one of",
  exists: "exists",
};

export interface QueryClause {
  field: string;
  op: QueryOp;
  /** For `in`, a comma-separated list. Ignored for `exists`. */
  value: string;
}

export interface ParsedQuery {
  clauses: QueryClause[];
  freeText: string;
}

export type FieldType = "string" | "number" | "enum" | "ip" | "boolean";

export interface EventFieldDef {
  field: string;
  label: string;
  type: FieldType;
  options?: readonly string[];
}

/** Canonical event (BCE) fields offered by the builder. Any dotted path is still accepted. */
export const EVENT_FIELDS: EventFieldDef[] = [
  { field: "category", label: "Category", type: "enum", options: EventCategory.options },
  { field: "eventType", label: "Event type", type: "string" },
  { field: "action", label: "Action", type: "string" },
  { field: "outcome", label: "Outcome", type: "enum", options: ["success", "failure", "unknown"] },
  { field: "severity", label: "Severity", type: "enum", options: Severity.options },
  { field: "risk", label: "Risk", type: "number" },
  { field: "message", label: "Message", type: "string" },
  { field: "source.kind", label: "Source kind", type: "enum", options: SourceKind.options },
  { field: "source.product", label: "Source product", type: "string" },
  { field: "asset.id", label: "Asset id", type: "string" },
  { field: "asset.hostname", label: "Hostname", type: "string" },
  { field: "asset.ip", label: "Asset IP", type: "ip" },
  { field: "asset.os", label: "Asset OS", type: "string" },
  { field: "user.name", label: "User name", type: "string" },
  { field: "user.email", label: "User email", type: "string" },
  { field: "identity.id", label: "Identity id", type: "string" },
  { field: "identity.principal", label: "Identity principal", type: "string" },
  { field: "identity.provider", label: "Identity provider", type: "string" },
  { field: "identity.sourceIp", label: "Sign-in source IP", type: "ip" },
  { field: "identity.geo.country", label: "Sign-in country", type: "string" },
  { field: "identity.mfa", label: "MFA used", type: "boolean" },
  { field: "identity.privileged", label: "Privileged identity", type: "boolean" },
  { field: "process.name", label: "Process name", type: "string" },
  { field: "process.commandLine", label: "Command line", type: "string" },
  { field: "process.path", label: "Process path", type: "string" },
  { field: "process.user", label: "Process user", type: "string" },
  { field: "process.hashSha256", label: "Process SHA-256", type: "string" },
  { field: "process.pid", label: "PID", type: "number" },
  { field: "process.parent.name", label: "Parent process", type: "string" },
  { field: "file.path", label: "File path", type: "string" },
  { field: "file.name", label: "File name", type: "string" },
  { field: "file.sha256", label: "File SHA-256", type: "string" },
  { field: "file.action", label: "File action", type: "enum", options: ["create", "modify", "delete", "rename", "read", "execute"] },
  { field: "network.direction", label: "Direction", type: "enum", options: ["inbound", "outbound", "lateral", "unknown"] },
  { field: "network.protocol", label: "Protocol", type: "string" },
  { field: "network.srcIp", label: "Source IP", type: "ip" },
  { field: "network.srcPort", label: "Source port", type: "number" },
  { field: "network.dstIp", label: "Destination IP", type: "ip" },
  { field: "network.dstPort", label: "Destination port", type: "number" },
  { field: "network.bytesOut", label: "Bytes out", type: "number" },
  { field: "network.bytesIn", label: "Bytes in", type: "number" },
  { field: "network.dnsQuery", label: "DNS query", type: "string" },
  { field: "network.httpHost", label: "HTTP host", type: "string" },
  { field: "network.httpUrl", label: "HTTP URL", type: "string" },
  { field: "network.tlsSni", label: "TLS SNI", type: "string" },
  { field: "network.ja3", label: "JA3", type: "string" },
  { field: "cloudResource.provider", label: "Cloud provider", type: "enum", options: ["aws", "azure", "gcp", "kubernetes", "other"] },
  { field: "cloudResource.accountId", label: "Cloud account", type: "string" },
  { field: "cloudResource.region", label: "Cloud region", type: "string" },
  { field: "cloudResource.resourceType", label: "Resource type", type: "string" },
  { field: "cloudResource.action", label: "Cloud API action", type: "string" },
  { field: "indicators.type", label: "Indicator type", type: "enum", options: IndicatorType.options },
  { field: "indicators.value", label: "Indicator value", type: "string" },
  { field: "detection.ruleName", label: "Detection rule", type: "string" },
  { field: "attack.id", label: "ATT&CK technique", type: "string" },
  { field: "attack.tactic", label: "ATT&CK tactic", type: "string" },
];

export function fieldDef(field: string): EventFieldDef | undefined {
  return EVENT_FIELDS.find((f) => f.field === field);
}

const FIELD_RE = /^[A-Za-z_][A-Za-z0-9_.]*$/;
const RESERVED = new Set(["AND", "OR", "NOT"]);
/** Characters allowed in an unquoted value. */
const BARE_RE = /^[A-Za-z0-9_.\-/@$#%+=,~^?]+$/;

export function isValidField(field: string): boolean {
  return FIELD_RE.test(field) && field.length <= 100;
}

function quote(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** A value as a term: bare when safe, otherwise quoted. */
export function formatValue(value: string): string {
  const v = value.trim();
  if (v !== "" && BARE_RE.test(v) && !RESERVED.has(v.toUpperCase())) return v;
  return quote(v);
}

/** Escape a value for use inside a wildcard term (`*value*`), where quoting is not available. */
function escapeWildcard(value: string): string {
  return value.trim().replace(/([\\\s:()"*?])/g, "\\$1");
}

export function clauseIsComplete(c: QueryClause): boolean {
  if (!isValidField(c.field)) return false;
  if (c.op === "exists") return true;
  if (c.op === "in") return splitList(c.value).length > 0;
  if (c.op === "gt" || c.op === "gte" || c.op === "lt" || c.op === "lte") return c.value.trim() !== "" && Number.isFinite(Number(c.value.trim()));
  return c.value.trim() !== "";
}

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((v) => v.trim())
    .filter((v) => v !== "");
}

export function serializeClause(c: QueryClause): string {
  const f = c.field.trim();
  const v = c.value.trim();
  switch (c.op) {
    case "eq":
      return `${f}:${formatValue(v)}`;
    case "neq":
      return `NOT ${f}:${formatValue(v)}`;
    case "contains":
      return `${f}:*${escapeWildcard(v)}*`;
    case "gt":
      return `${f}:>${v}`;
    case "gte":
      return `${f}:>=${v}`;
    case "lt":
      return `${f}:<${v}`;
    case "lte":
      return `${f}:<=${v}`;
    case "exists":
      return `${f}:*`;
    case "in":
      return `${f}:(${splitList(v).map(formatValue).join(" OR ")})`;
  }
}

/** Complete clauses AND-ed together, followed by free text (quoted when it contains spaces). */
export function serializeQuery(clauses: QueryClause[], freeText = ""): string {
  const parts = clauses.filter(clauseIsComplete).map(serializeClause);
  const text = freeText.trim();
  if (text) parts.push(/\s/.test(text) || text.includes(":") ? quote(text) : formatValue(text));
  return parts.join(" AND ");
}

// ─── Parsing ────────────────────────────────────────────────────────────────

type Token = { kind: "word"; text: string } | { kind: "quoted"; text: string } | { kind: "group"; text: string };

/** Split on whitespace, keeping quoted strings, escaped characters and parenthesized groups intact. */
function tokenize(input: string): Token[] | null {
  const tokens: Token[] = [];
  let i = 0;
  while (i < input.length) {
    const ch = input[i]!;
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if (ch === '"') {
      let text = "";
      i++;
      let closed = false;
      while (i < input.length) {
        const c = input[i]!;
        if (c === "\\" && i + 1 < input.length) {
          text += input[i + 1];
          i += 2;
          continue;
        }
        if (c === '"') {
          closed = true;
          i++;
          break;
        }
        text += c;
        i++;
      }
      if (!closed) return null;
      tokens.push({ kind: "quoted", text });
      continue;
    }
    // A word may embed a quoted value or a group: field:"a b", field:(a OR b)
    let text = "";
    while (i < input.length && !/\s/.test(input[i]!)) {
      const c = input[i]!;
      if (c === "\\" && i + 1 < input.length) {
        text += c + input[i + 1];
        i += 2;
        continue;
      }
      if (c === '"') {
        const end = findQuoteEnd(input, i);
        if (end < 0) return null;
        text += input.slice(i, end + 1);
        i = end + 1;
        continue;
      }
      if (c === "(") {
        const end = findGroupEnd(input, i);
        if (end < 0) return null;
        text += input.slice(i, end + 1);
        i = end + 1;
        continue;
      }
      text += c;
      i++;
    }
    tokens.push({ kind: text.startsWith("(") ? "group" : "word", text });
  }
  return tokens;
}

function findQuoteEnd(input: string, start: number): number {
  for (let i = start + 1; i < input.length; i++) {
    if (input[i] === "\\") {
      i++;
      continue;
    }
    if (input[i] === '"') return i;
  }
  return -1;
}

function findGroupEnd(input: string, start: number): number {
  let depth = 0;
  for (let i = start; i < input.length; i++) {
    const c = input[i];
    if (c === "\\") {
      i++;
      continue;
    }
    if (c === '"') {
      const end = findQuoteEnd(input, i);
      if (end < 0) return -1;
      i = end;
      continue;
    }
    if (c === "(") depth++;
    if (c === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function unquote(raw: string): string | null {
  if (raw.startsWith('"')) {
    if (!raw.endsWith('"') || raw.length < 2) return null;
    return raw.slice(1, -1).replace(/\\(.)/g, "$1");
  }
  return raw;
}

function unescapeWildcard(raw: string): string {
  return raw.replace(/\\(.)/g, "$1");
}

function parseTerm(text: string, negated: boolean): QueryClause | null {
  const idx = text.indexOf(":");
  if (idx <= 0) return null;
  const field = text.slice(0, idx);
  const rest = text.slice(idx + 1);
  if (!isValidField(field) || rest === "") return null;
  if (negated) {
    const v = unquote(rest);
    if (v === null || rest.startsWith("(") || /^[<>]/.test(rest) || (rest.includes("*") && !rest.startsWith('"'))) return null;
    return { field, op: "neq", value: v };
  }
  if (rest === "*") return { field, op: "exists", value: "" };
  const range = /^(>=|<=|>|<)(-?\d+(?:\.\d+)?)$/.exec(rest);
  if (range) {
    const op = range[1] === ">=" ? "gte" : range[1] === "<=" ? "lte" : range[1] === ">" ? "gt" : "lt";
    return { field, op, value: range[2]! };
  }
  if (rest.startsWith("(") && rest.endsWith(")")) {
    const inner = tokenize(rest.slice(1, -1));
    if (!inner || inner.length === 0) return null;
    const values: string[] = [];
    for (let i = 0; i < inner.length; i++) {
      const t = inner[i]!;
      if (i % 2 === 1) {
        if (t.kind !== "word" || t.text.toUpperCase() !== "OR") return null;
        continue;
      }
      if (t.kind === "group") return null;
      const v = t.kind === "quoted" ? t.text : unquote(t.text);
      if (v === null) return null;
      values.push(v);
    }
    if (inner.length % 2 === 0) return null;
    return { field, op: "in", value: values.join(", ") };
  }
  if (!rest.startsWith('"') && rest.length > 2 && rest.startsWith("*") && rest.endsWith("*") && !rest.endsWith("\\*")) {
    return { field, op: "contains", value: unescapeWildcard(rest.slice(1, -1)) };
  }
  const v = unquote(rest);
  if (v === null) return null;
  return { field, op: "eq", value: v };
}

/**
 * Parse a raw query into builder clauses + free text. Returns null when the query uses
 * constructs the builder cannot represent (top-level OR, nested groups, leading wildcards…).
 */
export function parseQuery(raw: string): ParsedQuery | null {
  const input = raw.trim();
  if (input === "") return { clauses: [], freeText: "" };
  const tokens = tokenize(input);
  if (!tokens) return null;
  const clauses: QueryClause[] = [];
  const free: string[] = [];
  let expectTerm = true;
  let negate = false;
  for (const t of tokens) {
    const upper = t.kind === "word" ? t.text.toUpperCase() : "";
    if (t.kind === "word" && upper === "OR") return null;
    if (t.kind === "word" && upper === "AND") {
      if (expectTerm || negate) return null;
      expectTerm = true;
      continue;
    }
    if (t.kind === "word" && upper === "NOT") {
      if (negate) return null;
      negate = true;
      continue;
    }
    if (t.kind === "group") return null;
    if (t.kind === "quoted") {
      if (negate) return null;
      free.push(t.text);
    } else {
      const clause = t.text.includes(":") ? parseTerm(t.text, negate) : null;
      if (clause) clauses.push(clause);
      else if (!negate && !t.text.includes(":") && !t.text.includes("*")) free.push(unescapeWildcard(t.text));
      else return null;
    }
    negate = false;
    expectTerm = false;
  }
  if (negate || (expectTerm && tokens.length > 0)) return null;
  return { clauses, freeText: free.join(" ") };
}
