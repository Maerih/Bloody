import { isIP } from "node:net";
import type { CanonicalEvent } from "@bloody/contracts";
import { z } from "zod";
import type { Database } from "../db/pool.js";
import { HttpError, badRequest } from "../http/errors.js";
import { decodeCursor, encodeCursor, likePattern } from "../http/params.js";

/**
 * Event search over the tenant's stored canonical events (`events`, partitioned by month).
 *
 * Two inputs compile to the same parameterized SQL (user input is never interpolated):
 *  - a structured filter list `{ field, op, value }[]` (the query builder in the UI), and
 *  - the Bloody query language: `host:kb-ws-fin07 AND (process.name:powershell* OR rule:encoded-*)`,
 *    `network.dstIp:10.0.0.0/8`, `risk:>=70`, `timestamp:[2026-10-01 TO 2026-10-02]`,
 *    `_exists_:file.sha256`, `-outcome:success`, bare words / "quoted phrases" = full text over
 *    the event message.
 * Hot fields map to indexed columns; any other dotted BCE path reads the stored document.
 */

export const FILTER_OPS = ["eq", "neq", "in", "nin", "contains", "prefix", "suffix", "wildcard", "exists", "missing", "gt", "gte", "lt", "lte", "between", "cidr", "regex"] as const;
export type FilterOp = (typeof FILTER_OPS)[number];

export const EventFilter = z.object({
  field: z.string().trim().min(1).max(200),
  op: z.enum(FILTER_OPS).default("eq"),
  value: z.unknown().optional(),
});
export type EventFilter = z.infer<typeof EventFilter>;

type FieldType = "text" | "uuid" | "time" | "number" | "ip" | "severity";
interface FieldDef {
  sql: string;
  type: FieldType;
}

const COLUMN_FIELDS: Record<string, FieldDef> = {
  id: { sql: "e.id", type: "uuid" },
  organizationId: { sql: "e.organization_id", type: "uuid" },
  timestamp: { sql: "e.occurred_at", type: "time" },
  receivedAt: { sql: "e.received_at", type: "time" },
  category: { sql: "e.category", type: "text" },
  eventType: { sql: "e.event_type", type: "text" },
  action: { sql: "e.action", type: "text" },
  outcome: { sql: "e.outcome", type: "text" },
  severity: { sql: "e.severity", type: "severity" },
  risk: { sql: "e.risk", type: "number" },
  "source.kind": { sql: "e.source_kind", type: "text" },
  "source.product": { sql: "e.source_product", type: "text" },
  "source.sensorId": { sql: "e.sensor_id", type: "text" },
  "source.integrationId": { sql: "e.integration_id", type: "uuid" },
  "asset.hostname": { sql: "e.asset_hostname", type: "text" },
  "asset.id": { sql: "e.asset_id", type: "uuid" },
  "user.name": { sql: "e.user_name", type: "text" },
  "identity.principal": { sql: "e.identity_principal", type: "text" },
  "network.srcIp": { sql: "e.src_ip", type: "ip" },
  "network.dstIp": { sql: "e.dst_ip", type: "ip" },
  "network.dnsQuery": { sql: "e.dns_query", type: "text" },
  "process.name": { sql: "e.process_name", type: "text" },
  "file.sha256": { sql: "e.file_sha256", type: "text" },
  "detection.ruleId": { sql: "e.detection_rule", type: "text" },
  message: { sql: "(e.doc->>'message')", type: "text" },
};

/** Short names accepted by the query language. */
const ALIASES: Record<string, string> = {
  host: "asset.hostname",
  hostname: "asset.hostname",
  user: "user.name",
  principal: "identity.principal",
  src: "network.srcIp",
  src_ip: "network.srcIp",
  srcip: "network.srcIp",
  dst: "network.dstIp",
  dst_ip: "network.dstIp",
  dstip: "network.dstIp",
  dns: "network.dnsQuery",
  query: "network.dnsQuery",
  process: "process.name",
  sha256: "file.sha256",
  rule: "detection.ruleId",
  type: "eventType",
  event_type: "eventType",
  product: "source.product",
  sensor: "source.sensorId",
  technique: "attack.id",
  ioc: "indicators.value",
  cmd: "process.commandLine",
  commandline: "process.commandLine",
  time: "timestamp",
  "@timestamp": "timestamp",
};

const SEVERITY_SQL = (expr: string) => `(CASE ${expr} WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)`;
const SEVERITY_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const PATH_SEGMENT = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const LABEL_KEY = /^[A-Za-z0-9_.:-]{1,100}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_IN = 200;

export class QuerySyntaxError extends HttpError {
  constructor(message: string, details?: unknown) {
    super(400, "invalid_query", message, details);
  }
}

class Params {
  readonly values: unknown[] = [];
  add(v: unknown): string {
    this.values.push(v);
    return `$${this.values.length}`;
  }
}

// ─── Query language ─────────────────────────────────────────────────────────

export type QueryNode =
  | { type: "and"; items: QueryNode[] }
  | { type: "or"; items: QueryNode[] }
  | { type: "not"; item: QueryNode }
  | { type: "cond"; filter: EventFilter }
  | { type: "text"; value: string };

type Token = { t: "lp" } | { t: "rp" } | { t: "and" } | { t: "or" } | { t: "not" } | { t: "term"; field: string | null; raw: string; quoted: boolean; list?: string[] };

function tokenize(input: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  const n = input.length;
  const readQuoted = (): string => {
    // input[i] === '"'
    i++;
    let s = "";
    while (i < n && input[i] !== '"') {
      if (input[i] === "\\" && i + 1 < n) {
        s += input[i + 1];
        i += 2;
      } else s += input[i++];
    }
    if (i >= n) throw new QuerySyntaxError("Unterminated quoted string");
    i++;
    return s;
  };
  const readBare = (): string => {
    let s = "";
    while (i < n && !/\s/.test(input[i]!) && input[i] !== "(" && input[i] !== ")") s += input[i++];
    return s;
  };
  while (i < n) {
    const c = input[i]!;
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === "(") {
      out.push({ t: "lp" });
      i++;
      continue;
    }
    if (c === ")") {
      out.push({ t: "rp" });
      i++;
      continue;
    }
    if (c === "-" && i + 1 < n && !/\s/.test(input[i + 1]!)) {
      out.push({ t: "not" });
      i++;
      continue;
    }
    if (c === '"') {
      out.push({ t: "term", field: null, raw: readQuoted(), quoted: true });
      continue;
    }
    // field:value | word
    let word = "";
    while (i < n && !/\s/.test(input[i]!) && input[i] !== "(" && input[i] !== ")" && input[i] !== ":") word += input[i++];
    if (i < n && input[i] === ":" && word.length > 0) {
      i++;
      if (input[i] === '"') {
        out.push({ t: "term", field: word, raw: readQuoted(), quoted: true });
      } else if (input[i] === "(") {
        // field:(a OR b c) → value list
        i++;
        const list: string[] = [];
        while (i < n && input[i] !== ")") {
          if (/\s/.test(input[i]!)) {
            i++;
            continue;
          }
          const v = input[i] === '"' ? readQuoted() : readBare();
          if (v.length === 0) break;
          if (v.toUpperCase() !== "OR") list.push(v);
        }
        if (input[i] !== ")") throw new QuerySyntaxError(`Unterminated value list for ${word}`);
        i++;
        out.push({ t: "term", field: word, raw: list.join(","), quoted: false, list });
      } else if (input[i] === "[") {
        let s = "";
        while (i < n && input[i] !== "]") s += input[i++];
        if (input[i] !== "]") throw new QuerySyntaxError(`Unterminated range for ${word}`);
        i++;
        out.push({ t: "term", field: word, raw: `${s}]`, quoted: false });
      } else {
        out.push({ t: "term", field: word, raw: readBare(), quoted: false });
      }
      continue;
    }
    const upper = word.toUpperCase();
    if (upper === "AND" || upper === "&&") out.push({ t: "and" });
    else if (upper === "OR" || upper === "||") out.push({ t: "or" });
    else if (upper === "NOT") out.push({ t: "not" });
    else if (word.length > 0) out.push({ t: "term", field: null, raw: word, quoted: false });
    else i++;
  }
  return out;
}

function termToNode(tok: Extract<Token, { t: "term" }>): QueryNode {
  if (tok.field === null) {
    if (tok.raw.length === 0) throw new QuerySyntaxError("Empty search term");
    return { type: "text", value: tok.raw };
  }
  const fieldRaw = tok.field;
  if (fieldRaw === "_exists_") return { type: "cond", filter: { field: tok.raw, op: "exists" } };
  if (fieldRaw === "_missing_") return { type: "cond", filter: { field: tok.raw, op: "missing" } };
  if (tok.list) return { type: "cond", filter: { field: fieldRaw, op: "in", value: tok.list } };
  const raw = tok.raw;
  if (raw.length === 0) throw new QuerySyntaxError(`Missing value for ${fieldRaw}`);
  if (!tok.quoted) {
    const range = /^\[(.+?)\s+TO\s+(.+?)\]$/i.exec(raw);
    if (range) return { type: "cond", filter: { field: fieldRaw, op: "between", value: [range[1]!.trim(), range[2]!.trim()] } };
    const cmp = /^(>=|<=|>|<)(.+)$/.exec(raw);
    if (cmp) {
      const op = cmp[1] === ">=" ? "gte" : cmp[1] === "<=" ? "lte" : cmp[1] === ">" ? "gt" : "lt";
      return { type: "cond", filter: { field: fieldRaw, op, value: cmp[2] } };
    }
    if (/\/\d{1,3}$/.test(raw) && isIP(raw.slice(0, raw.lastIndexOf("/"))) !== 0) return { type: "cond", filter: { field: fieldRaw, op: "cidr", value: raw } };
    if (/[*?]/.test(raw)) return { type: "cond", filter: { field: fieldRaw, op: "wildcard", value: raw } };
  }
  return { type: "cond", filter: { field: fieldRaw, op: "eq", value: raw } };
}

/** Parse the Bloody query language into an AST (AND binds tighter than OR; adjacency = AND). */
export function parseQuery(input: string): QueryNode | null {
  if (input.length > 4000) throw new QuerySyntaxError("Query is too long (max 4000 characters)");
  const tokens = tokenize(input);
  if (tokens.length === 0) return null;
  let pos = 0;
  let depth = 0;
  const peek = () => tokens[pos];
  const parseOr = (): QueryNode => {
    const items = [parseAnd()];
    while (peek()?.t === "or") {
      pos++;
      items.push(parseAnd());
    }
    return items.length === 1 ? items[0]! : { type: "or", items };
  };
  const parseAnd = (): QueryNode => {
    const items = [parseNot()];
    for (;;) {
      const t = peek();
      if (!t || t.t === "rp" || t.t === "or") break;
      if (t.t === "and") pos++;
      items.push(parseNot());
    }
    return items.length === 1 ? items[0]! : { type: "and", items };
  };
  const parseNot = (): QueryNode => {
    if (peek()?.t === "not") {
      pos++;
      return { type: "not", item: parseNot() };
    }
    return parsePrimary();
  };
  const parsePrimary = (): QueryNode => {
    const t = peek();
    if (!t) throw new QuerySyntaxError("Unexpected end of query");
    if (t.t === "lp") {
      pos++;
      if (++depth > 20) throw new QuerySyntaxError("Query nesting is too deep");
      const inner = parseOr();
      depth--;
      if (peek()?.t !== "rp") throw new QuerySyntaxError("Missing closing parenthesis");
      pos++;
      return inner;
    }
    if (t.t === "term") {
      pos++;
      return termToNode(t);
    }
    throw new QuerySyntaxError(`Unexpected ${t.t.toUpperCase()} in query`);
  };
  const ast = parseOr();
  if (pos < tokens.length) throw new QuerySyntaxError("Unexpected closing parenthesis");
  return ast;
}

// ─── Compilation ────────────────────────────────────────────────────────────

function resolveField(field: string, p: Params): FieldDef | { sql: string; type: "array_attack" } | { sql: string; type: "array_indicator" } | { sql: string; type: "ip_any" } {
  const name = ALIASES[field.toLowerCase()] ?? field;
  if (name === "ip") return { sql: "", type: "ip_any" };
  const col = COLUMN_FIELDS[name];
  if (col) return col;
  if (name === "attack.id" || name === "attack") return { sql: "e.attack_ids", type: "array_attack" };
  if (name === "indicators.value" || name === "indicators") return { sql: "e.doc->'indicators'", type: "array_indicator" };
  if (name.startsWith("labels.")) {
    const key = name.slice("labels.".length);
    if (!LABEL_KEY.test(key)) throw new QuerySyntaxError(`Invalid label key "${key}"`);
    return { sql: `(e.doc->'labels'->>${p.add(key)})`, type: "text" };
  }
  const segments = name.split(".");
  if (segments.length > 8 || !segments.every((s) => PATH_SEGMENT.test(s))) throw new QuerySyntaxError(`Unknown or invalid field "${field}"`);
  return { sql: `(e.doc #>> ${p.add(segments)}::text[])`, type: "text" };
}

const asString = (v: unknown, field: string): string => {
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  throw new QuerySyntaxError(`A scalar value is required for ${field}`);
};

const asList = (v: unknown, field: string): string[] => {
  const list = Array.isArray(v) ? v : typeof v === "string" ? v.split(",") : [v];
  const out = list.map((x) => asString(x, field).trim()).filter((x) => x.length > 0);
  if (out.length === 0 || out.length > MAX_IN) throw new QuerySyntaxError(`${field}: 1-${MAX_IN} values are required`);
  return out;
};

function wildcardPattern(v: string): string {
  return v.replace(/[\\%_]/g, (c) => `\\${c}`).replace(/\*/g, "%").replace(/\?/g, "_");
}

function parseCidr(v: string, field: string): string {
  const idx = v.lastIndexOf("/");
  const addr = idx > 0 ? v.slice(0, idx) : v;
  const version = isIP(addr);
  const bits = idx > 0 ? Number(v.slice(idx + 1)) : version === 6 ? 128 : 32;
  if (version === 0 || !Number.isInteger(bits) || bits < 0 || bits > (version === 6 ? 128 : 32)) throw new QuerySyntaxError(`${field}: invalid CIDR "${v}"`);
  return `${addr}/${bits}`;
}

function parseTime(v: unknown, field: string): string {
  const s = asString(v, field);
  const ms = Date.parse(/^\d{4}-\d{2}-\d{2}$/.test(s) ? `${s}T00:00:00Z` : s);
  if (Number.isNaN(ms)) throw new QuerySyntaxError(`${field}: invalid timestamp "${s}"`);
  return new Date(ms).toISOString();
}

function parseNumber(v: unknown, field: string): number {
  const n = typeof v === "number" ? v : Number(asString(v, field));
  if (!Number.isFinite(n)) throw new QuerySyntaxError(`${field}: "${String(v)}" is not a number`);
  return n;
}

const NUMERIC_CAST = (expr: string) => `(CASE WHEN ${expr} ~ '^-?[0-9]+(\\.[0-9]+)?$' THEN (${expr})::numeric END)`;

function compileFilter(f: EventFilter, p: Params): string {
  const def = resolveField(f.field, p);
  const field = f.field;
  if (f.op === "exists" || f.op === "missing") {
    const present =
      def.type === "array_attack" ? "cardinality(e.attack_ids) > 0" : def.type === "array_indicator" ? "jsonb_array_length(coalesce(e.doc->'indicators', '[]'::jsonb)) > 0" : def.type === "ip_any" ? "(e.src_ip IS NOT NULL OR e.dst_ip IS NOT NULL)" : `${def.sql} IS NOT NULL`;
    return f.op === "exists" ? present : `NOT (${present})`;
  }
  if (def.type === "ip_any") {
    const a = compileFilter({ ...f, field: "network.srcIp" }, p);
    const b = compileFilter({ ...f, field: "network.dstIp" }, p);
    return f.op === "neq" || f.op === "nin" ? `(${a} AND ${b})` : `(${a} OR ${b})`;
  }
  if (def.type === "array_attack") {
    switch (f.op) {
      case "eq":
        return `${p.add(asString(f.value, field).toUpperCase())} = ANY(e.attack_ids)`;
      case "neq":
        return `NOT (${p.add(asString(f.value, field).toUpperCase())} = ANY(e.attack_ids))`;
      case "in":
        return `e.attack_ids && ${p.add(asList(f.value, field).map((x) => x.toUpperCase()))}::text[]`;
      case "nin":
        return `NOT (e.attack_ids && ${p.add(asList(f.value, field).map((x) => x.toUpperCase()))}::text[])`;
      case "prefix":
      case "wildcard":
      case "contains": {
        const v = asString(f.value, field);
        const pat = f.op === "prefix" ? likePattern(v, "prefix") : f.op === "wildcard" ? wildcardPattern(v) : likePattern(v);
        return `EXISTS (SELECT 1 FROM unnest(e.attack_ids) t(x) WHERE t.x ILIKE ${p.add(pat)})`;
      }
      default:
        throw new QuerySyntaxError(`${f.op} is not supported for ${field}`);
    }
  }
  if (def.type === "array_indicator") {
    switch (f.op) {
      case "eq":
        return `e.doc->'indicators' @> jsonb_build_array(jsonb_build_object('value', ${p.add(asString(f.value, field))}::text))`;
      case "neq":
        return `NOT coalesce(e.doc->'indicators' @> jsonb_build_array(jsonb_build_object('value', ${p.add(asString(f.value, field))}::text)), false)`;
      case "contains":
      case "prefix":
      case "suffix":
      case "wildcard": {
        const v = asString(f.value, field);
        const pat = f.op === "contains" ? likePattern(v) : f.op === "prefix" ? likePattern(v, "prefix") : f.op === "suffix" ? `%${v.replace(/[\\%_]/g, (c) => `\\${c}`)}` : wildcardPattern(v);
        return `EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(e.doc->'indicators', '[]'::jsonb)) x WHERE x->>'value' ILIKE ${p.add(pat)})`;
      }
      case "in":
        return `EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(e.doc->'indicators', '[]'::jsonb)) x WHERE lower(x->>'value') = ANY(${p.add(asList(f.value, field).map((v) => v.toLowerCase()))}::text[]))`;
      default:
        throw new QuerySyntaxError(`${f.op} is not supported for ${field}`);
    }
  }
  const expr = def.sql;
  switch (def.type) {
    case "uuid": {
      const check = (v: string) => {
        if (!UUID_RE.test(v)) throw new QuerySyntaxError(`${field}: "${v}" is not a UUID`);
        return v;
      };
      if (f.op === "eq") return `${expr} = ${p.add(check(asString(f.value, field)))}::uuid`;
      if (f.op === "neq") return `${expr} IS DISTINCT FROM ${p.add(check(asString(f.value, field)))}::uuid`;
      if (f.op === "in") return `${expr} = ANY(${p.add(asList(f.value, field).map(check))}::uuid[])`;
      if (f.op === "nin") return `NOT (${expr} = ANY(${p.add(asList(f.value, field).map(check))}::uuid[]))`;
      throw new QuerySyntaxError(`${f.op} is not supported for ${field}`);
    }
    case "time": {
      if (f.op === "between") {
        const [a, b] = asList(f.value, field);
        if (!a || !b) throw new QuerySyntaxError(`${field}: between needs two timestamps`);
        return `(${expr} >= ${p.add(parseTime(a, field))}::timestamptz AND ${expr} <= ${p.add(parseTime(b, field))}::timestamptz)`;
      }
      const sym = { eq: "=", neq: "<>", gt: ">", gte: ">=", lt: "<", lte: "<=" }[f.op as "eq"];
      if (!sym) throw new QuerySyntaxError(`${f.op} is not supported for ${field}`);
      return `${expr} ${sym} ${p.add(parseTime(f.value, field))}::timestamptz`;
    }
    case "number":
    case "severity": {
      const numExpr = def.type === "severity" ? SEVERITY_SQL(expr) : expr;
      const toNum = (v: unknown) => (def.type === "severity" ? (SEVERITY_RANK[asString(v, field).toLowerCase()] ?? parseNumber(v, field)) : parseNumber(v, field));
      if (def.type === "severity" && (f.op === "eq" || f.op === "neq" || f.op === "in" || f.op === "nin")) {
        const vals = f.op === "in" || f.op === "nin" ? asList(f.value, field).map((v) => v.toLowerCase()) : [asString(f.value, field).toLowerCase()];
        const sql = `${expr} = ANY(${p.add(vals)}::text[])`;
        return f.op === "eq" || f.op === "in" ? sql : `NOT (${sql})`;
      }
      if (f.op === "between") {
        const [a, b] = asList(f.value, field);
        return `(${numExpr} >= ${p.add(toNum(a))} AND ${numExpr} <= ${p.add(toNum(b))})`;
      }
      if (f.op === "in" || f.op === "nin") {
        const sql = `${numExpr} = ANY(${p.add(asList(f.value, field).map(toNum))}::numeric[])`;
        return f.op === "in" ? sql : `NOT (${sql})`;
      }
      const sym = { eq: "=", neq: "<>", gt: ">", gte: ">=", lt: "<", lte: "<=" }[f.op as "eq"];
      if (!sym) throw new QuerySyntaxError(`${f.op} is not supported for ${field}`);
      return `${numExpr} ${sym} ${p.add(toNum(f.value))}`;
    }
    case "ip":
    case "text": {
      switch (f.op) {
        case "eq":
          return `lower(${expr}) = lower(${p.add(asString(f.value, field))})`;
        case "neq":
          return `(${expr} IS NULL OR lower(${expr}) <> lower(${p.add(asString(f.value, field))}))`;
        case "in":
          return `lower(${expr}) = ANY(${p.add(asList(f.value, field).map((v) => v.toLowerCase()))}::text[])`;
        case "nin":
          return `(${expr} IS NULL OR NOT (lower(${expr}) = ANY(${p.add(asList(f.value, field).map((v) => v.toLowerCase()))}::text[])))`;
        case "contains":
          return `${expr} ILIKE ${p.add(likePattern(asString(f.value, field)))}`;
        case "prefix":
          return `${expr} ILIKE ${p.add(likePattern(asString(f.value, field), "prefix"))}`;
        case "suffix":
          return `${expr} ILIKE ${p.add(`%${asString(f.value, field).replace(/[\\%_]/g, (c) => `\\${c}`)}`)}`;
        case "wildcard":
          return `${expr} ILIKE ${p.add(wildcardPattern(asString(f.value, field)))}`;
        case "regex": {
          const re = asString(f.value, field);
          if (re.length > 200) throw new QuerySyntaxError(`${field}: regular expressions are limited to 200 characters`);
          try {
            new RegExp(re);
          } catch {
            throw new QuerySyntaxError(`${field}: invalid regular expression`);
          }
          return `${expr} ~* ${p.add(re)}`;
        }
        case "cidr": {
          const cidr = parseCidr(asString(f.value, field), field);
          return `(CASE WHEN ${expr} ~ '^[0-9a-fA-F:.]+$' AND ${expr} ~ '[.:]' THEN ${expr}::inet <<= ${p.add(cidr)}::cidr ELSE false END)`;
        }
        case "gt":
        case "gte":
        case "lt":
        case "lte":
        case "between": {
          const num = NUMERIC_CAST(expr);
          if (f.op === "between") {
            const [a, b] = asList(f.value, field);
            return `(${num} >= ${p.add(parseNumber(a, field))} AND ${num} <= ${p.add(parseNumber(b, field))})`;
          }
          const sym = { gt: ">", gte: ">=", lt: "<", lte: "<=" }[f.op];
          return `${num} ${sym} ${p.add(parseNumber(f.value, field))}`;
        }
        default:
          throw new QuerySyntaxError(`${f.op} is not supported for ${field}`);
      }
    }
  }
}

function compileNode(node: QueryNode, p: Params): string {
  switch (node.type) {
    case "and":
      return `(${node.items.map((n) => compileNode(n, p)).join(" AND ")})`;
    case "or":
      return `(${node.items.map((n) => compileNode(n, p)).join(" OR ")})`;
    case "not":
      return `NOT coalesce(${compileNode(node.item, p)}, false)`;
    case "cond":
      return `coalesce(${compileFilter(node.filter, p)}, false)`;
    case "text":
      return `(e.doc->>'message') ILIKE ${p.add(likePattern(node.value))}`;
  }
}

// ─── Service ────────────────────────────────────────────────────────────────

export interface EventSearchInput {
  /** Bloody query language. */
  q?: string | undefined;
  /** Structured query-builder filters (AND-ed). */
  filters?: EventFilter[] | undefined;
  /** Full text over the event message. */
  text?: string | undefined;
  from: string;
  to: string;
  limit: number;
  cursor?: string | undefined;
  order?: "desc" | "asc";
}

export interface EventSearchResult {
  items: CanonicalEvent[];
  nextCursor: string | null;
  total: number | null;
  totalCapped: boolean;
  took: number;
  range: { from: string; to: string };
}

export const MAX_SEARCH_SPAN_DAYS = 400;
const COUNT_CAP = 10_000;

export function resolveRange(input: { from?: string | undefined; to?: string | undefined; range?: string | undefined }, now: number): { from: string; to: string } {
  const to = input.to ? Date.parse(input.to) : now;
  let from: number;
  if (input.from) from = Date.parse(input.from);
  else {
    const m = /^(\d{1,4})([mhd])$/.exec(input.range ?? "24h");
    if (!m) throw badRequest(`Invalid range "${input.range}" (use e.g. 15m, 24h, 7d)`);
    const n = Number(m[1]);
    from = to - n * (m[2] === "m" ? 60_000 : m[2] === "h" ? 3_600_000 : 86_400_000);
  }
  if (Number.isNaN(from) || Number.isNaN(to)) throw badRequest("Invalid time range");
  if (from > to) throw badRequest("from must be before to");
  if (to - from > MAX_SEARCH_SPAN_DAYS * 86_400_000) throw badRequest(`The time range may span at most ${MAX_SEARCH_SPAN_DAYS} days`);
  return { from: new Date(from).toISOString(), to: new Date(to).toISOString() };
}

export class EventSearchService {
  constructor(
    private readonly db: Database,
    private readonly now: () => number,
  ) {}

  /** Compile the WHERE clause (tenant via RLS; organization scope + time range + query). */
  compile(orgs: string[] | null, input: Omit<EventSearchInput, "limit" | "cursor">): { where: string[]; params: Params } {
    const p = new Params();
    const where: string[] = [];
    if (orgs) where.push(`e.organization_id = ANY(${p.add(orgs)}::uuid[])`);
    where.push(`e.occurred_at >= ${p.add(input.from)}::timestamptz`, `e.occurred_at <= ${p.add(input.to)}::timestamptz`);
    for (const f of input.filters ?? []) where.push(`coalesce(${compileFilter(EventFilter.parse(f), p)}, false)`);
    if (input.q && input.q.trim().length > 0) {
      const ast = parseQuery(input.q.trim());
      if (ast) where.push(compileNode(ast, p));
    }
    if (input.text && input.text.trim().length > 0) where.push(`(e.doc->>'message') ILIKE ${p.add(likePattern(input.text.trim()))}`);
    return { where, params: p };
  }

  async search(tenantId: string, orgs: string[] | null, input: EventSearchInput, opts: { count?: boolean } = {}): Promise<EventSearchResult> {
    const started = this.now();
    const { where, params } = this.compile(orgs, input);
    const desc = (input.order ?? "desc") === "desc";
    const cursor = decodeCursor(input.cursor);
    const filterWhere = [...where];
    if (cursor) {
      const t = params.add(String(cursor[0]));
      const id = params.add(String(cursor[1]));
      where.push(`(e.occurred_at, e.id) ${desc ? "<" : ">"} (${t}::timestamptz, ${id}::uuid)`);
    }
    const limitParam = params.add(input.limit + 1);
    const dir = desc ? "DESC" : "ASC";
    return this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<{ doc: CanonicalEvent; occurred_at: string; id: string }>(
        `SELECT e.doc, e.occurred_at, e.id FROM events e WHERE ${where.join(" AND ")} ORDER BY e.occurred_at ${dir}, e.id ${dir} LIMIT ${limitParam}`,
        params.values,
      );
      const hasMore = rows.length > input.limit;
      const slice = hasMore ? rows.slice(0, input.limit) : rows;
      const last = slice[slice.length - 1];
      let total: number | null = null;
      let capped = false;
      if (opts.count) {
        const countParams = params.values.slice(0, params.values.length - (cursor ? 3 : 1));
        const c = await tx.query<{ n: number }>(`SELECT count(*)::int AS n FROM (SELECT 1 FROM events e WHERE ${filterWhere.join(" AND ")} LIMIT ${COUNT_CAP + 1}) x`, countParams);
        total = Math.min(c.rows[0]?.n ?? 0, COUNT_CAP);
        capped = (c.rows[0]?.n ?? 0) > COUNT_CAP;
      }
      return {
        items: slice.map((r) => r.doc),
        nextCursor: hasMore && last ? encodeCursor([last.occurred_at, last.id]) : null,
        total,
        totalCapped: capped,
        took: this.now() - started,
        range: { from: input.from, to: input.to },
      };
    });
  }

  /** Top values per field over the matching events (hunting pivots). */
  async aggregate(tenantId: string, orgs: string[] | null, input: Omit<EventSearchInput, "limit" | "cursor">, fields: string[], top = 10): Promise<Record<string, Array<{ key: string; count: number }>>> {
    const out: Record<string, Array<{ key: string; count: number }>> = {};
    if (fields.length > 8) throw badRequest("At most 8 aggregation fields");
    return this.db.withTenant(tenantId, async (tx) => {
      for (const field of fields) {
        const { where, params } = this.compile(orgs, input);
        const def = resolveField(field, params);
        if (def.type === "array_indicator" || def.type === "ip_any") throw new QuerySyntaxError(`Cannot aggregate on ${field}`);
        const keyExpr = def.type === "array_attack" ? "unnest(e.attack_ids)" : def.sql;
        const { rows } = await tx.query<{ key: string | null; n: number }>(
          `SELECT k AS key, count(*)::int AS n FROM (SELECT ${keyExpr}::text AS k FROM events e WHERE ${where.join(" AND ")} LIMIT 200000) x
           WHERE k IS NOT NULL GROUP BY k ORDER BY n DESC, k LIMIT ${Math.min(Math.max(top, 1), 50)}`,
          params.values,
        );
        out[field] = rows.map((r) => ({ key: String(r.key), count: r.n }));
      }
      return out;
    });
  }
}
