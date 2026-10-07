import { z } from "zod";
import { AttackTechnique, IndicatorType } from "./event.js";
import { IsoDateTime, Severity, Uuid } from "./common.js";

/** Columns every tenant-scoped record carries. */
const Scoped = z.object({ id: Uuid, tenantId: Uuid, organizationId: Uuid, createdAt: IsoDateTime, updatedAt: IsoDateTime });

export const AssetKind = z.enum([
  "endpoint",
  "server",
  "domain_controller",
  "database",
  "cloud_instance",
  "cloud_storage",
  "container",
  "kubernetes_cluster",
  "network_device",
  "application",
  "saas_app",
  "external_host",
  "data_store",
]);
export type AssetKind = z.infer<typeof AssetKind>;

export const Criticality = z.enum(["low", "medium", "high", "crown_jewel"]);
export type Criticality = z.infer<typeof Criticality>;

export const Asset = Scoped.extend({
  kind: AssetKind,
  name: z.string(),
  hostname: z.string().nullable(),
  ipAddresses: z.array(z.string()),
  os: z.string().nullable(),
  criticality: Criticality,
  internetFacing: z.boolean(),
  tags: z.array(z.string()),
  owner: z.string().nullable(),
  lastSeenAt: IsoDateTime.nullable(),
  riskScore: z.number().min(0).max(100).nullable(),
});
export type Asset = z.infer<typeof Asset>;

export const UpsertAssetInput = Asset.pick({ kind: true, name: true }).extend({
  hostname: z.string().nullable().optional(),
  ipAddresses: z.array(z.string()).default([]),
  os: z.string().nullable().optional(),
  criticality: Criticality.default("medium"),
  internetFacing: z.boolean().default(false),
  tags: z.array(z.string()).default([]),
  owner: z.string().nullable().optional(),
});
export type UpsertAssetInput = z.input<typeof UpsertAssetInput>;

export const AgentStatus = z.enum(["protected", "unresponsive", "outdated", "isolated", "pending"]);
export type AgentStatus = z.infer<typeof AgentStatus>;

export const Agent = Scoped.extend({
  assetId: Uuid.nullable(),
  hostname: z.string(),
  platform: z.enum(["windows", "macos", "linux"]),
  version: z.string(),
  engine: z.string(),
  status: AgentStatus,
  lastCheckinAt: IsoDateTime.nullable(),
  antivirusStatus: z.enum(["protected", "unhealthy", "unmanaged", "incompatible"]),
  firewallEnabled: z.boolean(),
});
export type Agent = z.infer<typeof Agent>;

export const IdentityKind = z.enum(["user", "service_account", "service_principal", "machine", "api_key", "group"]);
export const Identity = Scoped.extend({
  kind: IdentityKind,
  provider: z.string(),
  principal: z.string(),
  displayName: z.string().nullable(),
  privileged: z.boolean(),
  mfaEnabled: z.boolean(),
  lastActivityAt: IsoDateTime.nullable(),
  riskScore: z.number().min(0).max(100).nullable(),
});
export type Identity = z.infer<typeof Identity>;

export const AlertStatus = z.enum(["new", "triaged", "suppressed", "promoted", "false_positive"]);
export const Alert = Scoped.extend({
  title: z.string(),
  severity: Severity,
  status: AlertStatus,
  ruleId: z.string().nullable(),
  source: z.string(),
  eventIds: z.array(Uuid),
  assetId: Uuid.nullable(),
  identityId: Uuid.nullable(),
  incidentId: Uuid.nullable(),
  attack: z.array(AttackTechnique),
  confidence: z.number().min(0).max(1),
  riskScore: z.number().min(0).max(100),
  firstSeenAt: IsoDateTime,
  lastSeenAt: IsoDateTime,
});
export type Alert = z.infer<typeof Alert>;

export const IncidentStatus = z.enum(["new", "triage", "investigating", "contained", "remediated", "closed", "false_positive"]);
export type IncidentStatus = z.infer<typeof IncidentStatus>;
export const ACTIVE_INCIDENT_STATUSES: IncidentStatus[] = ["new", "triage", "investigating", "contained"];

export const Incident = Scoped.extend({
  number: z.number().int(),
  title: z.string(),
  summary: z.string().nullable(),
  severity: Severity,
  status: IncidentStatus,
  riskScore: z.number().min(0).max(100),
  assigneeId: Uuid.nullable(),
  attack: z.array(AttackTechnique),
  alertCount: z.number().int(),
  assetIds: z.array(Uuid),
  identityIds: z.array(Uuid),
  detectedAt: IsoDateTime,
  acknowledgedAt: IsoDateTime.nullable(),
  containedAt: IsoDateTime.nullable(),
  closedAt: IsoDateTime.nullable(),
});
export type Incident = z.infer<typeof Incident>;

export const CreateIncidentInput = z.object({
  title: z.string().min(3).max(300),
  summary: z.string().max(10000).optional(),
  severity: Severity,
  alertIds: z.array(Uuid).default([]),
  assetIds: z.array(Uuid).default([]),
  identityIds: z.array(Uuid).default([]),
  attack: z.array(AttackTechnique).default([]),
});
export type CreateIncidentInput = z.input<typeof CreateIncidentInput>;

export const UpdateIncidentInput = z.object({
  title: z.string().min(3).max(300).optional(),
  summary: z.string().max(10000).nullable().optional(),
  severity: Severity.optional(),
  status: IncidentStatus.optional(),
  assigneeId: Uuid.nullable().optional(),
});
export type UpdateIncidentInput = z.infer<typeof UpdateIncidentInput>;

export const InvestigationStatus = z.enum(["open", "in_progress", "awaiting_customer", "closed"]);
export const Investigation = Scoped.extend({
  incidentId: Uuid.nullable(),
  title: z.string(),
  status: InvestigationStatus,
  leadId: Uuid.nullable(),
  hypothesis: z.string().nullable(),
  closedAt: IsoDateTime.nullable(),
});
export type Investigation = z.infer<typeof Investigation>;

export const TimelineEntryKind = z.enum(["event", "alert", "note", "action", "evidence", "ai", "status_change"]);
export const TimelineEntry = z.object({
  id: Uuid,
  investigationId: Uuid,
  kind: TimelineEntryKind,
  at: IsoDateTime,
  actorId: z.string().nullable(),
  title: z.string(),
  body: z.string().nullable(),
  refId: z.string().nullable(),
});
export type TimelineEntry = z.infer<typeof TimelineEntry>;

export const Evidence = Scoped.extend({
  investigationId: Uuid,
  name: z.string(),
  kind: z.enum(["file", "memory", "disk_artifact", "log_export", "pcap", "screenshot", "note"]),
  sha256: z.string(),
  sizeBytes: z.number().int(),
  storageRef: z.string(),
  tags: z.array(z.string()),
  collectedBy: z.string(),
  /** Append-only chain-of-custody log; each entry hashes the previous one. */
  custody: z.array(z.object({ at: IsoDateTime, actor: z.string(), action: z.string(), hash: z.string() })),
});
export type Evidence = z.infer<typeof Evidence>;

export const EscalationStatus = z.enum(["open", "acknowledged", "resolved"]);
export const Escalation = Scoped.extend({
  incidentId: Uuid.nullable(),
  title: z.string(),
  severity: Severity,
  status: EscalationStatus,
  dueAt: IsoDateTime,
  resolvedAt: IsoDateTime.nullable(),
});
export type Escalation = z.infer<typeof Escalation>;

export const Indicator = z.object({
  id: Uuid,
  tenantId: Uuid,
  /** null = shared across the whole tenant (e.g. MSSP-wide feed). */
  organizationId: Uuid.nullable(),
  type: IndicatorType,
  value: z.string(),
  confidence: z.number().min(0).max(100),
  severity: Severity,
  source: z.string(),
  threatActor: z.string().nullable(),
  malware: z.string().nullable(),
  campaign: z.string().nullable(),
  tags: z.array(z.string()),
  firstSeenAt: IsoDateTime,
  lastSeenAt: IsoDateTime,
  expiresAt: IsoDateTime.nullable(),
});
export type Indicator = z.infer<typeof Indicator>;

export const Vulnerability = Scoped.extend({
  assetId: Uuid,
  cve: z.string().nullable(),
  title: z.string(),
  cvss: z.number().min(0).max(10).nullable(),
  epss: z.number().min(0).max(1).nullable(),
  knownExploited: z.boolean(),
  severity: Severity,
  status: z.enum(["open", "in_remediation", "accepted", "mitigated", "resolved"]),
  patchAvailable: z.boolean(),
  slaDueAt: IsoDateTime.nullable(),
  riskScore: z.number().min(0).max(100).nullable(),
});
export type Vulnerability = z.infer<typeof Vulnerability>;
