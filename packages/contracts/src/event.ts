import { z } from "zod";
import { IsoDateTime, Severity, Uuid } from "./common.js";

/**
 * Bloody Canonical Event (BCE) — the proprietary, vendor-neutral security event schema.
 * Every adapter (Wazuh, Zeek, Suricata, Velociraptor, osquery, cloud audit logs, IdPs…)
 * normalizes into this shape. Nothing downstream of the data fabric may depend on a
 * vendor's raw format; the raw payload is preserved only under `provenance.raw` / object storage.
 */
export const BCE_SCHEMA_VERSION = "1.0" as const;

export const EventCategory = z.enum([
  "process",
  "file",
  "registry",
  "network",
  "dns",
  "http",
  "tls",
  "authentication",
  "identity",
  "cloud",
  "saas",
  "email",
  "vulnerability",
  "detection",
  "configuration",
  "device",
  "audit",
]);
export type EventCategory = z.infer<typeof EventCategory>;

export const SourceKind = z.enum(["endpoint", "network", "identity", "cloud", "saas", "email", "vuln_scanner", "intel", "custom"]);
export type SourceKind = z.infer<typeof SourceKind>;

export const EventSource = z.object({
  kind: SourceKind,
  /** Product/engine that produced the event, e.g. "wazuh", "zeek", "suricata". Informational only. */
  product: z.string(),
  vendor: z.string().optional(),
  integrationId: Uuid.optional(),
  sensorId: z.string().optional(),
});

export const EventAsset = z.object({
  id: Uuid.optional(),
  hostname: z.string().optional(),
  ip: z.array(z.string()).optional(),
  mac: z.array(z.string()).optional(),
  os: z.string().optional(),
  agentId: z.string().optional(),
  cloudInstanceId: z.string().optional(),
});

export const EventUser = z.object({
  name: z.string().optional(),
  domain: z.string().optional(),
  sid: z.string().optional(),
  email: z.string().optional(),
});

export const EventIdentity = z.object({
  id: Uuid.optional(),
  provider: z.string().optional(),
  principal: z.string().optional(),
  privileged: z.boolean().optional(),
  mfa: z.boolean().optional(),
  sourceIp: z.string().optional(),
  geo: z.object({ country: z.string().optional(), city: z.string().optional(), lat: z.number().optional(), lon: z.number().optional() }).optional(),
  outcome: z.enum(["success", "failure", "unknown"]).optional(),
});

export const EventProcess = z.object({
  pid: z.number().int().optional(),
  name: z.string().optional(),
  path: z.string().optional(),
  commandLine: z.string().optional(),
  user: z.string().optional(),
  hashSha256: z.string().optional(),
  parent: z
    .object({ pid: z.number().int().optional(), name: z.string().optional(), path: z.string().optional(), commandLine: z.string().optional() })
    .optional(),
});

export const EventFile = z.object({
  path: z.string().optional(),
  name: z.string().optional(),
  action: z.enum(["create", "modify", "delete", "rename", "read", "execute"]).optional(),
  sha256: z.string().optional(),
  md5: z.string().optional(),
  size: z.number().int().optional(),
});

export const EventNetwork = z.object({
  direction: z.enum(["inbound", "outbound", "lateral", "unknown"]).optional(),
  protocol: z.string().optional(),
  srcIp: z.string().optional(),
  srcPort: z.number().int().optional(),
  dstIp: z.string().optional(),
  dstPort: z.number().int().optional(),
  bytesIn: z.number().int().optional(),
  bytesOut: z.number().int().optional(),
  dnsQuery: z.string().optional(),
  httpHost: z.string().optional(),
  httpUrl: z.string().optional(),
  tlsSni: z.string().optional(),
  ja3: z.string().optional(),
});

export const EventCloudResource = z.object({
  provider: z.enum(["aws", "azure", "gcp", "kubernetes", "other"]),
  accountId: z.string().optional(),
  region: z.string().optional(),
  resourceType: z.string().optional(),
  resourceId: z.string().optional(),
  action: z.string().optional(),
});

export const IndicatorType = z.enum(["ip", "domain", "url", "sha256", "sha1", "md5", "email", "cve", "ja3", "user_agent"]);
export type IndicatorType = z.infer<typeof IndicatorType>;

export const EventIndicator = z.object({ type: IndicatorType, value: z.string() });

export const EventDetection = z.object({
  ruleId: z.string().optional(),
  ruleName: z.string().optional(),
  engine: z.string().optional(),
  confidence: z.number().min(0).max(1).optional(),
});

export const AttackTechnique = z.object({
  id: z.string().regex(/^T\d{4}(\.\d{3})?$/),
  name: z.string().optional(),
  tactic: z.string().optional(),
});
export type AttackTechnique = z.infer<typeof AttackTechnique>;

export const Provenance = z.object({
  adapter: z.string(),
  adapterVersion: z.string(),
  receivedAt: IsoDateTime,
  rawRef: z.string().optional(),
  raw: z.unknown().optional(),
});

export const CanonicalEvent = z.object({
  schemaVersion: z.literal(BCE_SCHEMA_VERSION).default(BCE_SCHEMA_VERSION),
  id: Uuid,
  tenantId: Uuid,
  organizationId: Uuid,
  timestamp: IsoDateTime,
  source: EventSource,
  category: EventCategory,
  eventType: z.string().min(1).max(200),
  action: z.string().optional(),
  outcome: z.enum(["success", "failure", "unknown"]).optional(),
  message: z.string().max(4000).optional(),
  asset: EventAsset.optional(),
  user: EventUser.optional(),
  identity: EventIdentity.optional(),
  process: EventProcess.optional(),
  file: EventFile.optional(),
  network: EventNetwork.optional(),
  cloudResource: EventCloudResource.optional(),
  indicators: z.array(EventIndicator).default([]),
  severity: Severity.default("info"),
  risk: z.number().min(0).max(100).optional(),
  detection: EventDetection.optional(),
  attack: z.array(AttackTechnique).default([]),
  labels: z.record(z.string()).default({}),
  provenance: Provenance,
});
export type CanonicalEvent = z.infer<typeof CanonicalEvent>;

/** Input accepted by the ingest API; ids/tenancy are assigned server-side. */
export const IngestEvent = CanonicalEvent.omit({ id: true, tenantId: true, organizationId: true, schemaVersion: true }).extend({
  id: Uuid.optional(),
});
export type IngestEvent = z.input<typeof IngestEvent>;

/** Read a dotted field path ("process.parent.name") from an event. Used by detections and search. */
export function getEventField(event: unknown, path: string): unknown {
  let cur: unknown = event;
  for (const part of path.split(".")) {
    if (cur === null || cur === undefined || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}
