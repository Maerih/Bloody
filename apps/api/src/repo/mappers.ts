import type {
  Account,
  Agent,
  Alert,
  Asset,
  AttackTechnique,
  Escalation,
  Evidence,
  Identity,
  Incident,
  Indicator,
  Investigation,
  Organization,
  TimelineEntry,
  Vulnerability,
} from "@bloody/contracts";

/**
 * Row → contract mappers. SQL lives next to the routes that use it; these functions are the
 * single place where column names become API field names, so the wire format always matches
 * the zod contracts in @bloody/contracts.
 */
export type Row = Record<string, unknown>;

const s = (v: unknown): string => (v === null || v === undefined ? "" : String(v));
const sn = (v: unknown): string | null => (v === null || v === undefined ? null : String(v));
const n = (v: unknown): number => (typeof v === "number" ? v : Number(v ?? 0));
const nn = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));
const arr = <T>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);
const attack = (v: unknown): AttackTechnique[] => arr<AttackTechnique>(v);

export function toAccount(r: Row): Account {
  return { id: s(r.id), name: s(r.name), slug: s(r.slug), kind: s(r.kind) as Account["kind"], dataRegion: s(r.data_region), createdAt: s(r.created_at) };
}

export interface OrganizationView extends Organization {
  plan: string | null;
  mrr: number;
  industry: string | null;
  status: string;
  externalRef: string | null;
  updatedAt: string;
}

export function toOrganization(r: Row): OrganizationView {
  return {
    id: s(r.id),
    tenantId: s(r.tenant_id),
    name: s(r.name),
    slug: s(r.slug),
    parentOrganizationId: sn(r.parent_organization_id),
    retentionDays: n(r.retention_days),
    createdAt: s(r.created_at),
    plan: sn(r.plan),
    mrr: n(r.mrr),
    industry: sn(r.industry),
    status: s(r.status),
    externalRef: sn(r.external_ref),
    updatedAt: s(r.updated_at),
  };
}

const scoped = (r: Row) => ({ id: s(r.id), tenantId: s(r.tenant_id), organizationId: s(r.organization_id), createdAt: s(r.created_at), updatedAt: s(r.updated_at) });

export interface AssetView extends Asset {
  source: string;
  risk: unknown;
}

export function toAsset(r: Row): AssetView {
  return {
    ...scoped(r),
    kind: s(r.kind) as Asset["kind"],
    name: s(r.name),
    hostname: sn(r.hostname),
    ipAddresses: arr<string>(r.ip_addresses),
    os: sn(r.os),
    criticality: s(r.criticality) as Asset["criticality"],
    internetFacing: Boolean(r.internet_facing),
    tags: arr<string>(r.tags),
    owner: sn(r.owner),
    lastSeenAt: sn(r.last_seen_at),
    riskScore: nn(r.risk_score),
    source: s(r.source),
    risk: r.risk ?? null,
  };
}

export function toAgent(r: Row): Agent {
  return {
    ...scoped(r),
    assetId: sn(r.asset_id),
    hostname: s(r.hostname),
    platform: s(r.platform) as Agent["platform"],
    version: s(r.version),
    engine: s(r.engine),
    status: s(r.status) as Agent["status"],
    lastCheckinAt: sn(r.last_checkin_at),
    antivirusStatus: s(r.antivirus_status) as Agent["antivirusStatus"],
    firewallEnabled: Boolean(r.firewall_enabled),
  };
}

export interface IdentityView extends Identity {
  enabled: boolean;
  risk: unknown;
}

export function toIdentity(r: Row): IdentityView {
  return {
    ...scoped(r),
    kind: s(r.kind) as Identity["kind"],
    provider: s(r.provider),
    principal: s(r.principal),
    displayName: sn(r.display_name),
    privileged: Boolean(r.privileged),
    mfaEnabled: Boolean(r.mfa_enabled),
    lastActivityAt: sn(r.last_activity_at),
    riskScore: nn(r.risk_score),
    enabled: r.enabled === undefined ? true : Boolean(r.enabled),
    risk: r.risk ?? null,
  };
}

export interface AlertView extends Alert {
  ruleVersion: number | null;
  explanation: string[];
  entities: unknown[];
  indicators: unknown[];
}

export function toAlert(r: Row): AlertView {
  return {
    ...scoped(r),
    title: s(r.title),
    severity: s(r.severity) as Alert["severity"],
    status: s(r.status) as Alert["status"],
    ruleId: sn(r.rule_id),
    source: s(r.source),
    eventIds: arr<string>(r.event_ids),
    assetId: sn(r.asset_id),
    identityId: sn(r.identity_id),
    incidentId: sn(r.incident_id),
    attack: attack(r.attack),
    confidence: n(r.confidence),
    riskScore: n(r.risk_score),
    firstSeenAt: s(r.first_seen_at),
    lastSeenAt: s(r.last_seen_at),
    ruleVersion: nn(r.rule_version),
    explanation: arr<string>(r.explanation),
    entities: arr<unknown>(r.entities),
    indicators: arr<unknown>(r.indicators),
  };
}

export interface IncidentView extends Incident {
  source: string;
  remediatedAt: string | null;
  escalationReasons: string[];
  correlationKeys: string[];
  mergedInto: string | null;
  firstSeenAt: string | null;
  lastSeenAt: string | null;
}

export function toIncident(r: Row): IncidentView {
  return {
    ...scoped(r),
    number: n(r.number),
    title: s(r.title),
    summary: sn(r.summary),
    severity: s(r.severity) as Incident["severity"],
    status: s(r.status) as Incident["status"],
    riskScore: n(r.risk_score),
    assigneeId: sn(r.assignee_id),
    attack: attack(r.attack),
    alertCount: n(r.alert_count),
    assetIds: arr<string>(r.asset_ids),
    identityIds: arr<string>(r.identity_ids),
    detectedAt: s(r.detected_at),
    acknowledgedAt: sn(r.acknowledged_at),
    containedAt: sn(r.contained_at),
    closedAt: sn(r.closed_at),
    source: s(r.source),
    remediatedAt: sn(r.remediated_at),
    escalationReasons: arr<string>(r.escalation_reasons),
    correlationKeys: arr<string>(r.correlation_keys),
    mergedInto: sn(r.merged_into),
    firstSeenAt: sn(r.first_seen_at),
    lastSeenAt: sn(r.last_seen_at),
  };
}

export function toInvestigation(r: Row): Investigation {
  return {
    ...scoped(r),
    incidentId: sn(r.incident_id),
    title: s(r.title),
    status: s(r.status) as Investigation["status"],
    leadId: sn(r.lead_id),
    hypothesis: sn(r.hypothesis),
    closedAt: sn(r.closed_at),
  };
}

export function toTimelineEntry(r: Row): TimelineEntry {
  return {
    id: s(r.id),
    investigationId: s(r.investigation_id),
    kind: s(r.kind) as TimelineEntry["kind"],
    at: s(r.at),
    actorId: sn(r.actor_id),
    title: s(r.title),
    body: sn(r.body),
    refId: sn(r.ref_id),
  };
}

export function toEvidence(r: Row): Evidence {
  return {
    ...scoped(r),
    investigationId: s(r.investigation_id),
    name: s(r.name),
    kind: s(r.kind) as Evidence["kind"],
    sha256: s(r.sha256),
    sizeBytes: n(r.size_bytes),
    storageRef: s(r.storage_ref),
    tags: arr<string>(r.tags),
    collectedBy: s(r.collected_by),
    custody: arr<Evidence["custody"][number]>(r.custody),
  };
}

export interface EscalationView extends Escalation {
  overdue: boolean;
  reason: string | null;
  acknowledgedAt: string | null;
  acknowledgedBy: string | null;
  resolvedBy: string | null;
  resolutionNote: string | null;
}

export function toEscalation(r: Row, now = Date.now()): EscalationView {
  const status = s(r.status) as Escalation["status"];
  return {
    ...scoped(r),
    incidentId: sn(r.incident_id),
    title: s(r.title),
    severity: s(r.severity) as Escalation["severity"],
    status,
    dueAt: s(r.due_at),
    resolvedAt: sn(r.resolved_at),
    overdue: status !== "resolved" && Date.parse(s(r.due_at)) < now,
    reason: sn(r.reason),
    acknowledgedAt: sn(r.acknowledged_at),
    acknowledgedBy: sn(r.acknowledged_by),
    resolvedBy: sn(r.resolved_by),
    resolutionNote: sn(r.resolution_note),
  };
}

export function toIndicator(r: Row): Indicator {
  return {
    id: s(r.id),
    tenantId: s(r.tenant_id),
    organizationId: sn(r.organization_id),
    type: s(r.type) as Indicator["type"],
    value: s(r.value),
    confidence: n(r.confidence),
    severity: s(r.severity) as Indicator["severity"],
    source: s(r.source),
    threatActor: sn(r.threat_actor),
    malware: sn(r.malware),
    campaign: sn(r.campaign),
    tags: arr<string>(r.tags),
    firstSeenAt: s(r.first_seen_at),
    lastSeenAt: s(r.last_seen_at),
    expiresAt: sn(r.expires_at),
  };
}

export interface VulnerabilityView extends Vulnerability {
  priority: string | null;
  risk: unknown;
}

export function toVulnerability(r: Row): VulnerabilityView {
  return {
    ...scoped(r),
    assetId: s(r.asset_id),
    cve: sn(r.cve),
    title: s(r.title),
    cvss: nn(r.cvss),
    epss: nn(r.epss),
    knownExploited: Boolean(r.known_exploited),
    severity: s(r.severity) as Vulnerability["severity"],
    status: s(r.status) as Vulnerability["status"],
    patchAvailable: Boolean(r.patch_available),
    slaDueAt: sn(r.sla_due_at),
    riskScore: nn(r.risk_score),
    priority: sn(r.priority),
    risk: r.risk ?? null,
  };
}
