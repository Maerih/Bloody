import type { CanonicalEvent } from "@bloody/contracts";
import { decodeCursor, encodeCursor } from "../http/params.js";
import { eventColumns } from "../pipeline/event-columns.js";
import {
  ALIASES,
  COLUMN_FIELDS,
  EventFilter,
  LABEL_KEY,
  PATH_SEGMENT,
  SEVERITY_RANK,
  UUID_RE,
  asList,
  asString,
  parseCidr,
  parseNumber,
  parseQuery,
  parseTime,
  QuerySyntaxError,
  type EventSearchBackend,
  type EventSearchInput,
  type EventSearchResult,
  type QueryNode,
} from "./event-search.js";

/**
 * OpenSearch event index (search at scale). Postgres stays the system of record; every ingested
 * event is mirrored here by the bus consumer and `/events/search` + hunting aggregations run here.
 *
 * - Monthly indices `<prefix>-YYYY.MM` shared by tenants; every document carries tenant_id and
 *   organization_id, documents are routed by tenant, and EVERY query is built by `scoped()` which
 *   always filters on the caller's tenant (and organization scope) — there is no unscoped path.
 * - Hot columns are keyword fields derived exactly like the Postgres columns (eventColumns); the
 *   whole canonical event is a `flat_object` (`ev`) so any dotted BCE path is searchable.
 * - Queries OpenSearch cannot answer with identical semantics (regex, numeric comparison on
 *   arbitrary paths, CIDR on non-IP fields, aggregations on document paths) throw
 *   `UnsupportedSearch` and the EventSearchService answers them from Postgres instead.
 */

/** The query cannot be expressed exactly in OpenSearch; the caller falls back to Postgres. */
export class UnsupportedSearch extends Error {
  readonly unsupported = true;
}

type Dsl = Record<string, unknown>;

export interface OpenSearchOptions {
  url: string;
  username?: string | undefined;
  password?: string | undefined;
  indexPrefix?: string;
  /** Wait for indexed documents to be searchable (tests). */
  refresh?: "false" | "wait_for";
  fetch?: typeof fetch;
  timeoutMs?: number;
}

const COUNT_CAP = 10_000;

/** Canonical column field → OpenSearch field. */
const OS_FIELDS: Record<string, string> = {
  id: "id",
  organizationId: "organization_id",
  timestamp: "timestamp",
  receivedAt: "received_at",
  category: "category",
  eventType: "event_type",
  action: "action",
  outcome: "outcome",
  severity: "severity",
  risk: "risk",
  "source.kind": "source_kind",
  "source.product": "source_product",
  "source.sensorId": "sensor_id",
  "source.integrationId": "integration_id",
  "user.name": "user_name",
  "identity.principal": "identity_principal",
  "network.srcIp": "src_ip",
  "network.dstIp": "dst_ip",
  "network.dnsQuery": "dns_query",
  "process.name": "process_name",
  "file.sha256": "file_sha256",
  "detection.ruleId": "detection_rule",
  "asset.hostname": "asset_hostname",
  message: "message",
};
const IP_ADDR_FIELD: Record<string, string> = { src_ip: "src_ip_addr", dst_ip: "dst_ip_addr" };

const kw = { type: "keyword", ignore_above: 1024 };
export const EVENT_INDEX_MAPPINGS = {
  dynamic: "strict",
  properties: {
    tenant_id: { type: "keyword" },
    organization_id: { type: "keyword" },
    id: { type: "keyword" },
    timestamp: { type: "date" },
    received_at: { type: "date" },
    category: kw,
    event_type: kw,
    action: kw,
    outcome: kw,
    severity: kw,
    severity_rank: { type: "byte" },
    risk: { type: "float" },
    source_kind: kw,
    source_product: kw,
    sensor_id: kw,
    integration_id: kw,
    asset_hostname: kw,
    user_name: kw,
    identity_principal: kw,
    src_ip: kw,
    dst_ip: kw,
    src_ip_addr: { type: "ip", ignore_malformed: true },
    dst_ip_addr: { type: "ip", ignore_malformed: true },
    dns_query: kw,
    process_name: kw,
    file_sha256: kw,
    detection_rule: kw,
    attack_ids: kw,
    indicator_values: kw,
    message: { type: "wildcard" },
    ev: { type: "flat_object" },
  },
} as const;

// ─── Query compilation ──────────────────────────────────────────────────────

const ci = (field: string, value: string): Dsl => ({ term: { [field]: { value, case_insensitive: true } } });
const not = (q: Dsl): Dsl => ({ bool: { must_not: [q] } });
const any = (qs: Dsl[]): Dsl => ({ bool: { should: qs, minimum_should_match: 1 } });
const all = (qs: Dsl[]): Dsl => ({ bool: { filter: qs } });
const exists = (field: string): Dsl => ({ exists: { field } });
/** Escape a literal for a Lucene wildcard pattern. */
const wEsc = (v: string) => v.replace(/[\\*?]/g, (c) => `\\${c}`);
const wildcard = (field: string, value: string): Dsl => ({ wildcard: { [field]: { value, case_insensitive: true } } });
const RANGE_OPS = { gt: "gt", gte: "gte", lt: "lt", lte: "lte" } as const;

type Resolved =
  | { kind: "column"; os: string; type: "text" | "uuid" | "time" | "number" | "ip" | "severity" }
  | { kind: "doc"; os: string }
  | { kind: "attack" }
  | { kind: "indicator" }
  | { kind: "ip_any" };

function resolve(field: string): Resolved {
  const name = ALIASES[field.toLowerCase()] ?? field;
  if (name === "ip") return { kind: "ip_any" };
  const col = COLUMN_FIELDS[name];
  if (col) {
    const os = OS_FIELDS[name];
    if (!os) throw new UnsupportedSearch(`${name} is not indexed in OpenSearch`);
    return { kind: "column", os, type: col.type };
  }
  if (name === "attack.id" || name === "attack") return { kind: "attack" };
  if (name === "indicators.value" || name === "indicators") return { kind: "indicator" };
  if (name.startsWith("labels.")) {
    const key = name.slice("labels.".length);
    if (!LABEL_KEY.test(key)) throw new QuerySyntaxError(`Invalid label key "${key}"`);
    return { kind: "doc", os: `ev.labels.${key}` };
  }
  const segments = name.split(".");
  if (segments.length > 8 || !segments.every((s) => PATH_SEGMENT.test(s))) throw new QuerySyntaxError(`Unknown or invalid field "${field}"`);
  return { kind: "doc", os: `ev.${name}` };
}

/** Case-insensitive string operators shared by keyword columns and document paths. */
function textOp(f: EventFilter, os: string, ipField?: string): Dsl {
  const field = f.field;
  switch (f.op) {
    case "eq":
      return ci(os, asString(f.value, field));
    case "neq":
      return not(ci(os, asString(f.value, field)));
    case "in":
      return any(asList(f.value, field).map((v) => ci(os, v)));
    case "nin":
      return not(any(asList(f.value, field).map((v) => ci(os, v))));
    case "contains":
      return wildcard(os, `*${wEsc(asString(f.value, field))}*`);
    case "prefix":
      return { prefix: { [os]: { value: asString(f.value, field), case_insensitive: true } } };
    case "suffix":
      return wildcard(os, `*${wEsc(asString(f.value, field))}`);
    case "wildcard":
      return wildcard(os, asString(f.value, field).replace(/\\/g, "\\\\"));
    case "cidr":
      if (!ipField) throw new UnsupportedSearch("cidr on a non-IP field");
      return { term: { [ipField]: parseCidr(asString(f.value, field), field) } };
    default:
      // regex (POSIX vs Lucene dialect) and numeric comparison of strings stay on Postgres.
      throw new UnsupportedSearch(`${f.op} on ${field}`);
  }
}

function compileFilter(f: EventFilter): Dsl {
  const def = resolve(f.field);
  const field = f.field;
  if (f.op === "exists" || f.op === "missing") {
    let present: Dsl;
    if (def.kind === "attack") present = exists("attack_ids");
    else if (def.kind === "indicator") present = exists("indicator_values");
    else if (def.kind === "ip_any") present = any([exists("src_ip"), exists("dst_ip")]);
    else if (def.kind === "column") present = exists(def.os);
    else throw new UnsupportedSearch("exists on a document path"); // objects/arrays differ from #>> semantics
    return f.op === "exists" ? present : not(present);
  }
  if (def.kind === "ip_any") {
    const a = compileFilter({ ...f, field: "network.srcIp" });
    const b = compileFilter({ ...f, field: "network.dstIp" });
    return f.op === "neq" || f.op === "nin" ? all([a, b]) : any([a, b]);
  }
  if (def.kind === "attack") {
    switch (f.op) {
      case "eq":
        return { term: { attack_ids: asString(f.value, field).toUpperCase() } };
      case "neq":
        return not({ term: { attack_ids: asString(f.value, field).toUpperCase() } });
      case "in":
        return { terms: { attack_ids: asList(f.value, field).map((x) => x.toUpperCase()) } };
      case "nin":
        return not({ terms: { attack_ids: asList(f.value, field).map((x) => x.toUpperCase()) } });
      case "prefix":
        return { prefix: { attack_ids: { value: asString(f.value, field), case_insensitive: true } } };
      case "wildcard":
        return wildcard("attack_ids", asString(f.value, field).replace(/\\/g, "\\\\"));
      case "contains":
        return wildcard("attack_ids", `*${wEsc(asString(f.value, field))}*`);
      default:
        throw new UnsupportedSearch(`${f.op} on ${field}`);
    }
  }
  if (def.kind === "indicator") {
    switch (f.op) {
      case "eq":
        return { term: { indicator_values: asString(f.value, field) } };
      case "neq":
        return not({ term: { indicator_values: asString(f.value, field) } });
      case "in":
        return any(asList(f.value, field).map((v) => ci("indicator_values", v)));
      case "contains":
      case "prefix":
      case "suffix":
      case "wildcard":
        return textOp(f, "indicator_values");
      default:
        throw new UnsupportedSearch(`${f.op} on ${field}`);
    }
  }
  if (def.kind === "doc") return textOp(f, def.os);

  const os = def.os;
  switch (def.type) {
    case "uuid": {
      const check = (v: string) => {
        if (!UUID_RE.test(v)) throw new QuerySyntaxError(`${field}: "${v}" is not a UUID`);
        return v.toLowerCase();
      };
      if (f.op === "eq") return { term: { [os]: check(asString(f.value, field)) } };
      if (f.op === "neq") return not({ term: { [os]: check(asString(f.value, field)) } });
      if (f.op === "in") return { terms: { [os]: asList(f.value, field).map(check) } };
      if (f.op === "nin") return not({ terms: { [os]: asList(f.value, field).map(check) } });
      throw new UnsupportedSearch(`${f.op} on ${field}`);
    }
    case "time": {
      if (f.op === "between") {
        const [a, b] = asList(f.value, field);
        if (!a || !b) throw new QuerySyntaxError(`${field}: between needs two timestamps`);
        return { range: { [os]: { gte: parseTime(a, field), lte: parseTime(b, field) } } };
      }
      if (f.op === "eq") return { term: { [os]: parseTime(f.value, field) } };
      if (f.op === "neq") return all([exists(os), not({ term: { [os]: parseTime(f.value, field) } })]);
      const op = RANGE_OPS[f.op as keyof typeof RANGE_OPS];
      if (!op) throw new UnsupportedSearch(`${f.op} on ${field}`);
      return { range: { [os]: { [op]: parseTime(f.value, field) } } };
    }
    case "number":
    case "severity": {
      const numField = def.type === "severity" ? "severity_rank" : os;
      const toNum = (v: unknown) => (def.type === "severity" ? (SEVERITY_RANK[asString(v, field).toLowerCase()] ?? parseNumber(v, field)) : parseNumber(v, field));
      if (def.type === "severity" && (f.op === "eq" || f.op === "neq" || f.op === "in" || f.op === "nin")) {
        const vals = f.op === "in" || f.op === "nin" ? asList(f.value, field).map((v) => v.toLowerCase()) : [asString(f.value, field).toLowerCase()];
        const q = { terms: { severity: vals } };
        return f.op === "eq" || f.op === "in" ? q : not(q);
      }
      if (f.op === "between") {
        const [a, b] = asList(f.value, field);
        return { range: { [numField]: { gte: toNum(a), lte: toNum(b) } } };
      }
      if (f.op === "in" || f.op === "nin") {
        const q = { terms: { [numField]: asList(f.value, field).map(toNum) } };
        return f.op === "in" ? q : all([exists(numField), not(q)]);
      }
      if (f.op === "eq") return { term: { [numField]: toNum(f.value) } };
      if (f.op === "neq") return all([exists(numField), not({ term: { [numField]: toNum(f.value) } })]);
      const op = RANGE_OPS[f.op as keyof typeof RANGE_OPS];
      if (!op) throw new UnsupportedSearch(`${f.op} on ${field}`);
      return { range: { [numField]: { [op]: toNum(f.value) } } };
    }
    case "ip":
    case "text":
      return textOp(f, os, def.type === "ip" ? IP_ADDR_FIELD[os] : undefined);
  }
}

function compileNode(node: QueryNode): Dsl {
  switch (node.type) {
    case "and":
      return all(node.items.map(compileNode));
    case "or":
      return any(node.items.map(compileNode));
    case "not":
      return not(compileNode(node.item));
    case "cond":
      return compileFilter(node.filter);
    case "text":
      return wildcard("message", `*${wEsc(node.value)}*`);
  }
}

/**
 * The only way a query is built: tenant (and organization scope) + time range are always present.
 * Exported for tests.
 */
export function scopedQuery(tenantId: string, orgs: string[] | null, input: Omit<EventSearchInput, "limit" | "cursor">): Dsl {
  const filter: Dsl[] = [{ term: { tenant_id: tenantId } }, { range: { timestamp: { gte: input.from, lte: input.to } } }];
  if (orgs) filter.push({ terms: { organization_id: orgs } });
  for (const f of input.filters ?? []) filter.push(compileFilter(EventFilter.parse(f)));
  if (input.q && input.q.trim().length > 0) {
    const ast = parseQuery(input.q.trim());
    if (ast) filter.push(compileNode(ast));
  }
  if (input.text && input.text.trim().length > 0) filter.push(wildcard("message", `*${wEsc(input.text.trim())}*`));
  return { bool: { filter } };
}

// ─── Documents ──────────────────────────────────────────────────────────────

export function toIndexDocument(tenantId: string, organizationId: string, e: CanonicalEvent): Dsl {
  const c = eventColumns(e);
  return {
    tenant_id: tenantId,
    organization_id: organizationId,
    id: e.id.toLowerCase(),
    timestamp: e.timestamp,
    received_at: e.provenance.receivedAt,
    category: e.category,
    event_type: e.eventType,
    action: e.action ?? null,
    outcome: c.outcome,
    severity: e.severity,
    severity_rank: SEVERITY_RANK[e.severity] ?? 0,
    risk: e.risk ?? null,
    source_kind: e.source.kind,
    source_product: e.source.product,
    sensor_id: e.source.sensorId ?? null,
    integration_id: e.source.integrationId ?? null,
    asset_hostname: e.asset?.hostname ?? null,
    user_name: c.userName,
    identity_principal: e.identity?.principal ?? null,
    src_ip: c.srcIp,
    dst_ip: c.dstIp,
    src_ip_addr: c.srcIp,
    dst_ip_addr: c.dstIp,
    dns_query: e.network?.dnsQuery ?? null,
    process_name: c.processName,
    file_sha256: c.fileSha256,
    detection_rule: c.detectionRule,
    attack_ids: c.attackIds,
    indicator_values: (e.indicators ?? []).map((i) => i.value),
    message: e.message ?? null,
    ev: e,
  };
}

// ─── Client / backend ───────────────────────────────────────────────────────

export class OpenSearchError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export class OpenSearchEventIndex implements EventSearchBackend {
  readonly name = "opensearch";
  private readonly base: string;
  private readonly prefix: string;
  private readonly fetchImpl: typeof fetch;
  private templateReady: Promise<void> | null = null;

  constructor(private readonly opts: OpenSearchOptions) {
    this.base = opts.url.replace(/\/+$/, "");
    this.prefix = opts.indexPrefix ?? "bloody-events";
    if (!/^[a-z0-9][a-z0-9_-]{0,60}$/.test(this.prefix)) throw new Error("OPENSEARCH_INDEX_PREFIX must be lowercase letters, digits, - or _");
    this.fetchImpl = opts.fetch ?? fetch;
  }

  private async request<T>(method: string, path: string, body?: unknown, ndjson = false): Promise<T> {
    const headers: Record<string, string> = { "content-type": ndjson ? "application/x-ndjson" : "application/json", accept: "application/json" };
    if (this.opts.username) headers.authorization = `Basic ${Buffer.from(`${this.opts.username}:${this.opts.password ?? ""}`).toString("base64")}`;
    const res = await this.fetchImpl(`${this.base}${path}`, {
      method,
      headers,
      ...(body === undefined ? {} : { body: ndjson ? (body as string) : JSON.stringify(body) }),
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? 10_000),
    });
    const text = await res.text();
    const data = text ? (JSON.parse(text) as T) : ({} as T);
    if (!res.ok) {
      const reason = (data as { error?: { root_cause?: Array<{ reason?: string }>; reason?: string } }).error;
      throw new OpenSearchError(`OpenSearch ${method} ${path.split("?")[0]} → ${res.status}: ${reason?.root_cause?.[0]?.reason ?? reason?.reason ?? "error"}`, res.status);
    }
    return data;
  }

  indexFor(timestamp: string): string {
    return `${this.prefix}-${timestamp.slice(0, 4)}.${timestamp.slice(5, 7)}`;
  }

  /** Install (idempotently) the index template every monthly index is created from. */
  ensureTemplate(): Promise<void> {
    this.templateReady ??= this.request("PUT", `/_index_template/${this.prefix}`, {
      index_patterns: [`${this.prefix}-*`],
      template: { settings: { "index.mapping.total_fields.limit": 2000, "index.refresh_interval": "1s" }, mappings: EVENT_INDEX_MAPPINGS },
      priority: 200,
    }).then(
      () => undefined,
      (err: unknown) => {
        this.templateReady = null;
        throw err;
      },
    );
    return this.templateReady;
  }

  /** Bulk index (idempotent: document id = event id). Throws when any document fails. */
  async index(tenantId: string, organizationId: string, events: readonly CanonicalEvent[]): Promise<number> {
    if (events.length === 0) return 0;
    await this.ensureTemplate();
    const lines: string[] = [];
    for (const e of events) {
      lines.push(JSON.stringify({ index: { _index: this.indexFor(e.timestamp), _id: `${tenantId}:${e.id.toLowerCase()}`, routing: tenantId } }));
      lines.push(JSON.stringify(toIndexDocument(tenantId, organizationId, e)));
    }
    const res = await this.request<{ errors: boolean; items: Array<{ index?: { status: number; error?: { reason?: string } } }> }>(
      "POST",
      `/_bulk?refresh=${this.opts.refresh ?? "false"}`,
      `${lines.join("\n")}\n`,
      true,
    );
    if (res.errors) {
      const failed = res.items.filter((i) => (i.index?.status ?? 500) >= 300);
      throw new OpenSearchError(`OpenSearch rejected ${failed.length}/${events.length} events: ${failed[0]?.index?.error?.reason ?? "unknown"}`, 500);
    }
    return events.length;
  }

  private searchPath(from: string, to: string, tenantId: string): string {
    // Only the monthly indices the range touches (ignore_unavailable: months without data).
    const months: string[] = [];
    const end = new Date(to);
    for (let d = new Date(Date.UTC(new Date(from).getUTCFullYear(), new Date(from).getUTCMonth(), 1)); d <= end && months.length < 40; d.setUTCMonth(d.getUTCMonth() + 1)) {
      months.push(this.indexFor(d.toISOString()));
    }
    return `/${months.join(",")}/_search?ignore_unavailable=true&allow_no_indices=true&routing=${encodeURIComponent(tenantId)}`;
  }

  async search(tenantId: string, orgs: string[] | null, input: EventSearchInput, opts: { count?: boolean } = {}, started = Date.now()): Promise<EventSearchResult> {
    const desc = (input.order ?? "desc") === "desc";
    const query = scopedQuery(tenantId, orgs, input);
    const cursor = decodeCursor(input.cursor);
    const body: Dsl = {
      query,
      size: input.limit + 1,
      sort: [{ timestamp: { order: desc ? "desc" : "asc" } }, { id: { order: desc ? "desc" : "asc" } }],
      track_total_hits: opts.count ? COUNT_CAP + 1 : false,
      _source: ["ev"],
    };
    if (cursor) {
      const t = Date.parse(String(cursor[0]));
      if (Number.isNaN(t)) throw new UnsupportedSearch("cursor");
      body.search_after = [t, String(cursor[1]).toLowerCase()];
    }
    const res = await this.request<{ hits: { total?: { value: number }; hits: Array<{ _source: { ev: CanonicalEvent }; sort: [number, string] }> } }>(
      "POST",
      this.searchPath(input.from, input.to, tenantId),
      body,
    );
    const hits = res.hits.hits;
    const hasMore = hits.length > input.limit;
    const slice = hasMore ? hits.slice(0, input.limit) : hits;
    const last = slice[slice.length - 1];
    const n = res.hits.total?.value ?? 0;
    return {
      items: slice.map((h) => h._source.ev),
      nextCursor: hasMore && last ? encodeCursor([new Date(last.sort[0]).toISOString(), last.sort[1]]) : null,
      total: opts.count ? Math.min(n, COUNT_CAP) : null,
      totalCapped: opts.count ? n > COUNT_CAP : false,
      took: Date.now() - started,
      range: { from: input.from, to: input.to },
    };
  }

  async aggregate(tenantId: string, orgs: string[] | null, input: Omit<EventSearchInput, "limit" | "cursor">, fields: string[], top = 10): Promise<Record<string, Array<{ key: string; count: number }>>> {
    const aggs: Dsl = {};
    fields.forEach((field, i) => {
      const def = resolve(field);
      let os: string;
      if (def.kind === "attack") os = "attack_ids";
      else if (def.kind === "column" && def.type !== "number" && def.type !== "time") os = def.os;
      else throw new UnsupportedSearch(`aggregation on ${field}`);
      if (os === "message") throw new UnsupportedSearch("aggregation on message");
      aggs[`f${i}`] = { terms: { field: os, size: Math.min(Math.max(top, 1), 50), order: [{ _count: "desc" }, { _key: "asc" }] } };
    });
    const res = await this.request<{ aggregations?: Record<string, { buckets: Array<{ key: string | number; doc_count: number }> }> }>(
      "POST",
      this.searchPath(input.from, input.to, tenantId),
      { query: scopedQuery(tenantId, orgs, input), size: 0, aggs },
    );
    const out: Record<string, Array<{ key: string; count: number }>> = {};
    fields.forEach((field, i) => {
      out[field] = (res.aggregations?.[`f${i}`]?.buckets ?? []).map((b) => ({ key: String(b.key), count: b.doc_count }));
    });
    return out;
  }

  /** Cluster reachability for /health. */
  async ping(): Promise<boolean> {
    try {
      await this.request("GET", "/_cluster/health?timeout=2s");
      return true;
    } catch {
      return false;
    }
  }
}
