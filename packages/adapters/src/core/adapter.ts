import {
  IngestEvent,
  IsoDateTime,
  Uuid,
  type AttackTechnique,
  type EventAsset,
  type EventCategory,
  type EventCloudResource,
  type EventDetection,
  type EventFile,
  type EventIdentity,
  type EventNetwork,
  type EventProcess,
  type EventUser,
  type ResponseActionKey,
  type Severity,
  type SourceKind,
} from "@bloody/contracts";
import type { z } from "zod";
import type { EngineClient } from "../http/client.js";
import type { HealthCheckResult } from "../http/health.js";
import type { ResponseActionHandler } from "../response/types.js";
import { mergeTechniques } from "./attack.js";
import { sha256Hex, uuidV5 } from "./hash.js";
import type { Observable } from "./indicators.js";
import { compact, truncate, unique } from "./json.js";
import { jsonRecords, type SplitItem } from "./records.js";

/** A canonical event as produced by an adapter: `IngestEvent` after zod defaults are applied. */
export type NormalizedEvent = z.output<typeof IngestEvent>;

export interface AdapterContext {
  /** When the platform received the payload (ISO-8601). Fallback event time and provenance. */
  receivedAt: string;
  /** Integration instance the payload came from (UUID) — copied into `source.integrationId`. */
  integrationId?: string;
  /** Sensor / collector identifier — copied into `source.sensorId` when the record has none. */
  sensorId?: string;
  /**
   * UUID namespace for deterministic event ids (use the tenant id). When set, each event gets
   * `id = uuidV5(adapter|nativeKey, namespace)` so at-least-once redelivery is idempotent
   * without ids colliding across tenants. When absent the ingest API assigns ids.
   */
  idNamespace?: string;
  /** Embed the (redacted) per-record raw payload under `provenance.raw`. Default true. */
  includeRaw?: boolean;
  /** Raw payloads larger than this (serialized bytes) are not embedded. Default 16 KiB. */
  maxRawBytes?: number;
  /** Hard cap on records processed from one payload. Default 50 000. */
  maxRecords?: number;
  /** Object-storage reference of the original payload (copied to `provenance.rawRef`). */
  rawRef?: string;
  /** Adapter-specific hints (documented per adapter), e.g. `{ logType: "conn" }` for Zeek. */
  options?: Record<string, unknown>;
}

export interface MapContext extends AdapterContext {
  receivedDate: Date;
  /** Position of the record inside the payload. */
  index: number;
  options: Record<string, unknown>;
}

export type LabelValue = string | number | boolean | null | undefined;

/** What a mapper returns for one canonical event, before provenance/validation. */
export interface EventDraft {
  timestamp?: string | undefined;
  category: EventCategory;
  eventType: string;
  action?: string | undefined;
  outcome?: "success" | "failure" | "unknown" | undefined;
  message?: string | undefined;
  asset?: z.input<typeof EventAsset> | undefined;
  user?: z.input<typeof EventUser> | undefined;
  identity?: z.input<typeof EventIdentity> | undefined;
  process?: z.input<typeof EventProcess> | undefined;
  file?: z.input<typeof EventFile> | undefined;
  network?: z.input<typeof EventNetwork> | undefined;
  cloudResource?: z.input<typeof EventCloudResource> | undefined;
  indicators?: Observable[] | undefined;
  severity?: Severity | undefined;
  risk?: number | undefined;
  detection?: z.input<typeof EventDetection> | undefined;
  attack?: AttackTechnique[] | undefined;
  labels?: Record<string, LabelValue> | undefined;
  /** Record-level raw payload (already redacted by the adapter) for provenance. */
  raw?: unknown;
  /** Native identity of the record (e.g. Wazuh alert id, Zeek uid+ts) for idempotent ids. */
  dedupKey?: string | undefined;
  source?: { kind?: SourceKind; product?: string; vendor?: string; sensorId?: string | undefined } | undefined;
}

export interface SkipRecord {
  skip: string;
}

export type MapOutput = EventDraft | EventDraft[] | SkipRecord | undefined;

export function skip(reason: string): SkipRecord {
  return { skip: reason };
}

function isSkip(v: unknown): v is SkipRecord {
  return typeof v === "object" && v !== null && typeof (v as SkipRecord).skip === "string";
}

export interface NormalizationIssue {
  index: number;
  reason: string;
}

export interface NormalizationResult {
  adapter: string;
  adapterVersion: string;
  receivedAt: string;
  /** Records read from the payload (including skipped and rejected ones). */
  records: number;
  events: NormalizedEvent[];
  /** Records that could not be normalized (invalid JSON, schema violation, mapper error). */
  rejected: NormalizationIssue[];
  /** Records deliberately ignored (operational noise, unsupported log types…). */
  skipped: NormalizationIssue[];
  /** True when `maxRecords` stopped processing early. */
  truncated: boolean;
}

export interface Adapter {
  /** Matches an `ENGINES` key (or a generic source key, see `GENERIC_SOURCES`). */
  readonly key: string;
  /** Adapter mapping version (semver) — recorded in every event's provenance. */
  readonly version: string;
  readonly name: string;
  readonly sourceKind: SourceKind;
  /** Human-readable list of the engine outputs this adapter understands. */
  readonly consumes: readonly string[];
  /** Normalize a payload into validated canonical events (invalid records are dropped). */
  normalize(raw: unknown, ctx: AdapterContext): NormalizedEvent[];
  /** Same as `normalize` plus per-record rejections/skips for ingest health reporting. */
  normalizeDetailed(raw: unknown, ctx: AdapterContext): NormalizationResult;
  /** Probe the engine's API (when it has one). */
  healthCheck?(client: EngineClient): Promise<HealthCheckResult>;
  /** Response actions this engine can execute, keyed by contract action key. */
  readonly actions?: Readonly<Partial<Record<ResponseActionKey, ResponseActionHandler>>>;
}

export interface AdapterDefinition {
  key: string;
  version: string;
  name: string;
  sourceKind: SourceKind;
  /** `source.product` (defaults to key). */
  product?: string;
  vendor?: string;
  consumes: readonly string[];
  /** Split a payload into records. Defaults to JSON / JSON-Lines / array splitting. */
  split?: (raw: unknown, ctx: AdapterContext) => Iterable<SplitItem>;
  /** Map one record into zero or more canonical event drafts. May throw (→ rejected). */
  map: (record: unknown, ctx: MapContext) => MapOutput;
  /** Redact a record before it is embedded as provenance (secrets, captured passwords…). */
  redactRaw?: (record: unknown) => unknown;
  healthCheck?: (client: EngineClient) => Promise<HealthCheckResult>;
  actions?: Partial<Record<ResponseActionKey, ResponseActionHandler>>;
}

/** Per-deployment extras wired into an adapter instance (engine API health probe, response handlers). */
export interface AdapterExtras {
  healthCheck?: (client: EngineClient) => Promise<HealthCheckResult>;
  actions?: Partial<Record<ResponseActionKey, ResponseActionHandler>>;
}

const DEFAULT_MAX_RAW_BYTES = 16 * 1024;
const DEFAULT_MAX_RECORDS = 50_000;
const LABEL_KEY_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const MAX_LABELS = 64;
const MAX_LABEL_VALUE = 1024;

export function sanitizeLabels(labels: Record<string, LabelValue> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!labels) return out;
  let n = 0;
  for (const [rawKey, value] of Object.entries(labels)) {
    if (value === undefined || value === null) continue;
    if (n >= MAX_LABELS) break;
    const key = LABEL_KEY_RE.test(rawKey) ? rawKey : rawKey.replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 64);
    if (key === "") continue;
    const v = typeof value === "string" ? value : String(value);
    if (v === "") continue;
    out[key] = truncate(v, MAX_LABEL_VALUE);
    n++;
  }
  return out;
}

function zodIssues(error: z.ZodError): string {
  return error.issues
    .slice(0, 5)
    .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
    .join("; ");
}

function rawForProvenance(raw: unknown, maxBytes: number): { raw?: unknown; omitted?: string } {
  if (raw === undefined) return {};
  let size: number;
  try {
    size = Buffer.byteLength(JSON.stringify(raw) ?? "", "utf8");
  } catch {
    return { omitted: "unserializable" };
  }
  if (size > maxBytes) return { omitted: `size:${size}` };
  return { raw };
}

/** Validate the adapter context once per payload; misconfiguration is a caller bug. */
export function assertContext(ctx: AdapterContext): void {
  if (!IsoDateTime.safeParse(ctx.receivedAt).success) throw new TypeError("AdapterContext.receivedAt must be an ISO-8601 timestamp");
  if (ctx.integrationId !== undefined && !Uuid.safeParse(ctx.integrationId).success) throw new TypeError("AdapterContext.integrationId must be a UUID");
  if (ctx.idNamespace !== undefined && !Uuid.safeParse(ctx.idNamespace).success) throw new TypeError("AdapterContext.idNamespace must be a UUID");
}

/**
 * Turn a mapper's draft into a schema-valid canonical event: provenance, deterministic id,
 * timestamp fallback (with an explicit `timestamp_source` label), label hygiene, size caps.
 */
export function finalizeDraft(
  def: Pick<AdapterDefinition, "key" | "version" | "sourceKind" | "product" | "vendor" | "redactRaw">,
  draft: EventDraft,
  ctx: AdapterContext,
  ordinal: number,
): { ok: true; event: NormalizedEvent } | { ok: false; reason: string } {
  const labels: Record<string, LabelValue> = { ...draft.labels };
  let timestamp = draft.timestamp;
  if (!timestamp || !IsoDateTime.safeParse(timestamp).success) {
    timestamp = ctx.receivedAt;
    labels["timestamp_source"] = "received_at";
  }

  let id: string | undefined;
  if (draft.dedupKey) {
    const native = ordinal > 0 ? `${draft.dedupKey}#${ordinal}` : draft.dedupKey;
    labels["dedup_key"] = sha256Hex(`${def.key}|${native}`).slice(0, 32);
    if (ctx.idNamespace) id = uuidV5(`${def.key}|${native}`, ctx.idNamespace);
  }

  const includeRaw = ctx.includeRaw ?? true;
  const prov = includeRaw ? rawForProvenance(def.redactRaw && draft.raw !== undefined ? def.redactRaw(draft.raw) : draft.raw, ctx.maxRawBytes ?? DEFAULT_MAX_RAW_BYTES) : {};
  if (prov.omitted) labels["raw_omitted"] = prov.omitted;

  const indicators = unique(draft.indicators ?? [], (o) => `${o.type}:${o.value}`);
  const candidate = {
    ...(id ? { id } : {}),
    timestamp,
    source: compact({
      kind: draft.source?.kind ?? def.sourceKind,
      product: draft.source?.product ?? def.product ?? def.key,
      vendor: draft.source?.vendor ?? def.vendor,
      integrationId: ctx.integrationId,
      sensorId: draft.source?.sensorId ?? ctx.sensorId,
    }),
    category: draft.category,
    eventType: truncate(draft.eventType || `${def.key}.event`, 200),
    action: draft.action,
    outcome: draft.outcome,
    message: draft.message !== undefined ? truncate(draft.message, 4000) : undefined,
    asset: draft.asset ? compact(draft.asset) : undefined,
    user: draft.user ? compact(draft.user) : undefined,
    identity: draft.identity ? compact(draft.identity) : undefined,
    process: draft.process ? compact(draft.process) : undefined,
    file: draft.file ? compact(draft.file) : undefined,
    network: draft.network ? compact(draft.network) : undefined,
    cloudResource: draft.cloudResource ? compact(draft.cloudResource) : undefined,
    indicators,
    severity: draft.severity ?? "info",
    risk: draft.risk,
    detection: draft.detection ? compact(draft.detection) : undefined,
    attack: mergeTechniques(draft.attack ?? []),
    labels: sanitizeLabels(labels),
    provenance: compact({
      adapter: def.key,
      adapterVersion: def.version,
      receivedAt: ctx.receivedAt,
      rawRef: ctx.rawRef,
      raw: prov.raw,
    }),
  };
  const parsed = IngestEvent.safeParse(candidate);
  if (!parsed.success) return { ok: false, reason: `schema validation failed: ${zodIssues(parsed.error)}` };
  return { ok: true, event: parsed.data };
}

/** Build an {@link Adapter} from a record mapper. All built-in adapters use this. */
export function defineAdapter(def: AdapterDefinition): Adapter {
  const normalizeDetailed = (raw: unknown, ctx: AdapterContext): NormalizationResult => {
    assertContext(ctx);
    const receivedDate = new Date(ctx.receivedAt);
    const maxRecords = ctx.maxRecords ?? DEFAULT_MAX_RECORDS;
    const result: NormalizationResult = {
      adapter: def.key,
      adapterVersion: def.version,
      receivedAt: ctx.receivedAt,
      records: 0,
      events: [],
      rejected: [],
      skipped: [],
      truncated: false,
    };
    const items = def.split ? def.split(raw, ctx) : jsonRecords(raw);
    for (const item of items) {
      if (result.records >= maxRecords) {
        result.truncated = true;
        break;
      }
      result.records++;
      if (!item.ok) {
        result.rejected.push({ index: item.index, reason: item.error });
        continue;
      }
      let out: MapOutput;
      try {
        out = def.map(item.value, { ...ctx, receivedDate, index: item.index, options: ctx.options ?? {} });
      } catch (err) {
        result.rejected.push({ index: item.index, reason: `mapping failed: ${(err as Error).message}` });
        continue;
      }
      if (out === undefined) {
        result.skipped.push({ index: item.index, reason: "record carries no security-relevant content" });
        continue;
      }
      if (isSkip(out)) {
        result.skipped.push({ index: item.index, reason: out.skip });
        continue;
      }
      const drafts = Array.isArray(out) ? out : [out];
      if (drafts.length === 0) {
        result.skipped.push({ index: item.index, reason: "record produced no events" });
        continue;
      }
      const ordinals = new Map<string, number>();
      for (const draft of drafts) {
        const keyBase = draft.dedupKey ?? "";
        const ordinal = ordinals.get(keyBase) ?? 0;
        ordinals.set(keyBase, ordinal + 1);
        const fin = finalizeDraft(def, draft, ctx, ordinal);
        if (fin.ok) result.events.push(fin.event);
        else result.rejected.push({ index: item.index, reason: fin.reason });
      }
    }
    return result;
  };

  const adapter: Adapter = {
    key: def.key,
    version: def.version,
    name: def.name,
    sourceKind: def.sourceKind,
    consumes: def.consumes,
    normalize: (raw, ctx) => normalizeDetailed(raw, ctx).events,
    normalizeDetailed,
    ...(def.healthCheck ? { healthCheck: def.healthCheck } : {}),
    ...(def.actions ? { actions: Object.freeze({ ...def.actions }) } : {}),
  };
  return Object.freeze(adapter);
}
