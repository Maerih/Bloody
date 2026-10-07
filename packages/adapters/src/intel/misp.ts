import type { AttackTechnique, IndicatorType, Severity } from "@bloody/contracts";
import { techniquesInText } from "../core/attack.js";
import { arr, bool, field, int, isRecord, rec, str, type JsonRecord } from "../core/json.js";
import { toIso } from "../core/time.js";
import { EngineClient, type EngineClientOptions } from "../http/client.js";
import { runHealthCheck, type HealthCheckResult } from "../http/health.js";
import { buildIndicatorRecord, clampConfidence, parseTlp, strictestTlp, type IndicatorRecord, type IntelParseResult, type Tlp } from "./types.js";

/**
 * MISP connector — pulls attributes through the REST API (`POST /attributes/restSearch`,
 * `returnFormat: json`) and maps them to Bloody indicator records. MISP runs as a separate,
 * unmodified service (AGPL); only its documented HTTP API is used.
 *
 * Confidence model (explained per record in `scoring`):
 *   base 75 when `to_ids` (detection-grade) else 40 · event threat level high +15 /
 *   medium +5 / low −5 · an explicit `misp:confidence-level` tag overrides the base.
 */

/** MISP attribute type → Bloody indicator type (+ which half of a composite value to keep). */
export const MISP_TYPE_MAP: Record<string, { type: IndicatorType; part?: 0 | 1 }> = {
  "ip-src": { type: "ip" },
  "ip-dst": { type: "ip" },
  "ip-src|port": { type: "ip", part: 0 },
  "ip-dst|port": { type: "ip", part: 0 },
  domain: { type: "domain" },
  hostname: { type: "domain" },
  "domain|ip": { type: "domain", part: 0 },
  "hostname|port": { type: "domain", part: 0 },
  url: { type: "url" },
  md5: { type: "md5" },
  sha1: { type: "sha1" },
  sha256: { type: "sha256" },
  "filename|md5": { type: "md5", part: 1 },
  "filename|sha1": { type: "sha1", part: 1 },
  "filename|sha256": { type: "sha256", part: 1 },
  "email-src": { type: "email" },
  "email-dst": { type: "email" },
  email: { type: "email" },
  vulnerability: { type: "cve" },
  "ja3-fingerprint-md5": { type: "ja3" },
  "user-agent": { type: "user_agent" },
};

const CONFIDENCE_TAGS: Record<string, number> = {
  confirmed: 95,
  "usually-confident": 75,
  "fairly-confident": 50,
  "rarely-confident": 25,
  unconfident: 10,
  "confidence-cannot-be-evaluated": 40,
};

const THREAT_LEVEL: Record<number, { severity: Severity; delta: number; label: string }> = {
  1: { severity: "high", delta: 15, label: "high" },
  2: { severity: "medium", delta: 5, label: "medium" },
  3: { severity: "low", delta: -5, label: "low" },
  4: { severity: "info", delta: 0, label: "undefined" },
};

const GALAXY_RE = /^misp-galaxy:([a-z0-9-]+)="(.+)"$/i;

interface TagFacts {
  tlp: Tlp | null;
  threatActor: string | null;
  malware: string | null;
  campaign: string | null;
  attack: AttackTechnique[];
  confidenceOverride?: { value: number; tag: string };
  plain: string[];
}

function tagFacts(tags: string[]): TagFacts {
  const facts: TagFacts = { tlp: null, threatActor: null, malware: null, campaign: null, attack: [], plain: [] };
  const tlps: Array<Tlp | null> = [];
  for (const tag of tags) {
    if (/^tlp:/i.test(tag)) {
      tlps.push(parseTlp(tag));
      continue;
    }
    const conf = /^misp:confidence-level="([^"]+)"$/i.exec(tag);
    if (conf) {
      const v = CONFIDENCE_TAGS[(conf[1] ?? "").toLowerCase()];
      if (v !== undefined) facts.confidenceOverride = { value: v, tag };
      continue;
    }
    const g = GALAXY_RE.exec(tag);
    if (g) {
      const galaxy = (g[1] ?? "").toLowerCase();
      const value = g[2] ?? "";
      if (galaxy === "threat-actor" || galaxy === "intrusion-set" || galaxy === "mitre-intrusion-set") facts.threatActor ??= value;
      else if (["malpedia", "ransomware", "tool", "botnet", "rat", "mitre-malware", "mitre-tool", "android", "banker", "stealer"].includes(galaxy)) facts.malware ??= value;
      else if (galaxy === "campaign" || galaxy === "mitre-campaign") facts.campaign ??= value;
      else if (galaxy.includes("attack-pattern")) facts.attack.push(...techniquesInText(value));
      else facts.plain.push(tag);
      continue;
    }
    facts.plain.push(tag);
  }
  facts.tlp = strictestTlp(tlps);
  return facts;
}

function tagNames(v: unknown): string[] {
  return arr(v)
    .map((t) => (isRecord(t) ? str(t["name"]) : str(t)))
    .filter((t): t is string => t !== undefined);
}

export interface MispParseOptions {
  /** Ingest time used when MISP timestamps are missing. */
  now: string;
  ttlDays?: Partial<Record<IndicatorType, number | null>>;
}

/** Map one MISP attribute (restSearch JSON) to an indicator record or a skip reason. */
export function mispAttributeToIndicator(attr: JsonRecord, opts: MispParseOptions): IndicatorRecord | string {
  const mispType = str(attr["type"]) ?? "";
  const mapping = MISP_TYPE_MAP[mispType];
  if (!mapping) return `MISP type "${mispType}" has no Bloody indicator mapping`;
  const rawValue = str(attr["value"]);
  if (!rawValue) return "empty value";
  const value = mapping.part !== undefined ? rawValue.split("|")[mapping.part] ?? "" : rawValue;
  const event = rec(attr["Event"]) ?? {};
  const tags = [...tagNames(attr["Tag"]), ...tagNames(event["Tag"]), ...tagNames(attr["EventTag"])];
  const facts = tagFacts(tags);
  const toIds = bool(attr["to_ids"]) ?? false;
  const threatLevel = int(event["threat_level_id"]);
  const tl = threatLevel !== undefined ? THREAT_LEVEL[threatLevel] : undefined;
  const scoring: string[] = [];
  let confidence: number;
  if (facts.confidenceOverride) {
    confidence = facts.confidenceOverride.value;
    scoring.push(`confidence ${confidence} from tag ${facts.confidenceOverride.tag}`);
  } else {
    confidence = toIds ? 75 : 40;
    scoring.push(toIds ? "base confidence 75: attribute flagged for detection (to_ids)" : "base confidence 40: attribute not flagged for detection (to_ids=false)");
    if (tl && tl.delta !== 0) {
      confidence += tl.delta;
      scoring.push(`${tl.delta > 0 ? "+" : ""}${tl.delta} for MISP event threat level ${tl.label}`);
    }
  }
  confidence = clampConfidence(confidence);
  const severity: Severity | undefined = tl && tl.severity !== "info" ? tl.severity : undefined;
  if (severity) scoring.push(`severity ${severity} from MISP event threat level ${tl?.label}`);
  const ts = toIso(attr["timestamp"]) ?? opts.now;
  const firstSeen = toIso(attr["first_seen"]) ?? ts;
  const lastSeen = toIso(attr["last_seen"]) ?? ts;
  const eventId = str(attr["event_id"]) ?? str(event["id"]);
  const record = buildIndicatorRecord({
    type: mapping.type,
    value,
    externalRef: `misp:attribute:${str(attr["uuid"]) ?? str(attr["id"]) ?? `${mispType}:${value}`}`,
    source: "misp",
    confidence,
    ...(severity ? { severity } : {}),
    firstSeenAt: firstSeen,
    lastSeenAt: lastSeen,
    threatActor: facts.threatActor,
    malware: facts.malware,
    campaign: facts.campaign,
    tags: [...facts.plain, `misp:category:${str(attr["category"]) ?? "unknown"}`, ...(eventId ? [`misp:event:${eventId}`] : [])],
    description: str(attr["comment"]) ?? str(event["info"]) ?? null,
    attack: facts.attack,
    tlp: facts.tlp,
    revoked: bool(attr["deleted"]) ?? false,
    scoring,
    ...(opts.ttlDays ? { ttlDays: opts.ttlDays } : {}),
  });
  return record;
}

/** Parse a restSearch response (`{response:{Attribute:[…]}}` or a bare attribute array). */
export function parseMispAttributes(json: unknown, opts: MispParseOptions): IntelParseResult {
  const list = Array.isArray(json) ? json : arr(field(json, "response.Attribute") ?? field(json, "Attribute") ?? rec(json)?.["response"]);
  const out: IntelParseResult = { records: [], skipped: [] };
  for (const item of list) {
    const attr = isRecord(item) && isRecord(item["Attribute"]) ? (item["Attribute"] as JsonRecord) : item;
    if (!isRecord(attr)) {
      out.skipped.push({ ref: "?", reason: "not an attribute object" });
      continue;
    }
    const r = mispAttributeToIndicator(attr, opts);
    if (typeof r === "string") out.skipped.push({ ref: str(attr["uuid"]) ?? str(attr["id"]) ?? "?", reason: r });
    else out.records.push(r);
  }
  return out;
}

export interface MispSearchParams {
  /** Relative window, e.g. "1d", "7d" (MISP `last`). */
  last?: string;
  /** Only attributes modified after this epoch second (incremental sync cursor). */
  timestamp?: number;
  types?: string[];
  toIds?: boolean;
  published?: boolean;
  tags?: string[];
  limit?: number;
  maxPages?: number;
}

export interface MispConnectorOptions extends Omit<EngineClientOptions, "engine" | "auth"> {
  apiKey: string;
}

/** EngineClient configured for MISP (API key in the `Authorization` header, as MISP expects). */
export function createMispClient(opts: MispConnectorOptions): EngineClient {
  const { apiKey, ...rest } = opts;
  return new EngineClient({ ...rest, engine: "misp", auth: { kind: "api_key", header: "Authorization", value: apiKey } });
}

/** Pull indicators page by page. Pages stop when a page returns fewer than `limit` items. */
export async function pullMispIndicators(client: EngineClient, params: MispSearchParams, opts: MispParseOptions): Promise<IntelParseResult & { pages: number }> {
  const limit = Math.min(Math.max(params.limit ?? 1000, 1), 10_000);
  const maxPages = params.maxPages ?? 50;
  const out: IntelParseResult & { pages: number } = { records: [], skipped: [], pages: 0 };
  for (let page = 1; page <= maxPages; page++) {
    const body: Record<string, unknown> = {
      returnFormat: "json",
      page,
      limit,
      includeEventTags: true,
      deleted: [0, 1],
      to_ids: params.toIds === false ? undefined : 1,
      published: params.published === undefined ? undefined : params.published,
      last: params.last,
      timestamp: params.timestamp,
      type: params.types && params.types.length > 0 ? params.types : Object.keys(MISP_TYPE_MAP),
      tags: params.tags,
    };
    for (const k of Object.keys(body)) if (body[k] === undefined) delete body[k];
    const res = await client.post<unknown>("/attributes/restSearch", { json: body, retry: true, timeoutMs: 60_000 });
    const parsed = parseMispAttributes(res.data, opts);
    out.records.push(...parsed.records);
    out.skipped.push(...parsed.skipped);
    out.pages = page;
    const count = arr(field(res.data, "response.Attribute")).length;
    if (count < limit) break;
  }
  return out;
}

export function mispHealthCheck(client: EngineClient): Promise<HealthCheckResult> {
  return runHealthCheck("misp", async () => {
    const res = await client.get<unknown>("/servers/getVersion");
    const version = str(field(res.data, "version"));
    return { status: version ? "healthy" : "degraded", ...(version ? { version } : {}), details: { permSync: bool(field(res.data, "perm_sync")) ?? false } };
  });
}
