import type { AttackTechnique, Criticality, IncidentStatus, PlanKey, RiskFactor, Severity } from "@bloody/contracts";
import type { SlaTargets } from "./sla.js";

/**
 * The data a report needs, as an injected port. The API implements it with SQL (aggregates
 * where volumes are large — events, alerts, vulnerabilities — and bounded fact rows where
 * builders compute derived metrics themselves — incidents, escalations, analysts).
 *
 * Every call carries the tenant and the organization scope the caller is authorised for; the
 * implementation MUST filter by both (and RLS enforces tenant_id as a second line of defence).
 * Rows that carry `organizationId` are additionally verified by the builders.
 *
 * "As of" semantics: state-like metrics (open vulnerabilities, agent status, posture scores)
 * are evaluated at `query.to`; flow metrics (events, alerts, new indicators) count `[from, to)`.
 */
export interface ReportQuery {
  tenantId: string;
  organizationIds: readonly string[] | "all";
  from: Date;
  to: Date;
}

export interface DailyCount {
  /** YYYY-MM-DD (UTC). */
  date: string;
  count: number;
}

export interface NamedCount {
  name: string;
  count: number;
}

export interface OrganizationFact {
  id: string;
  name: string;
  plan: PlanKey | null;
  createdAt: string;
  /** Per-organization SLA targets (null = tenant default). */
  slaTargets: Partial<SlaTargets> | null;
}

export interface IncidentFact {
  id: string;
  organizationId: string;
  number: number;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  riskScore: number;
  detectedAt: string;
  /** Earliest malicious activity linked to the incident (for MTTD). */
  firstActivityAt: string | null;
  acknowledgedAt: string | null;
  containedAt: string | null;
  closedAt: string | null;
  assigneeId: string | null;
  assigneeName: string | null;
  attack: AttackTechnique[];
  alertCount: number;
  assetCount: number;
  identityCount: number;
  riskFactors?: RiskFactor[];
}

export interface AlertStats {
  total: number;
  bySeverity: Record<Severity, number>;
  falsePositives: number;
  promoted: number;
  suppressed: number;
  daily: DailyCount[];
  bySource: NamedCount[];
  topRules: { ruleId: string; name: string; count: number; falsePositives: number }[];
  topTechniques: { id: string; name?: string | null; tactic?: string | null; count: number }[];
}

export interface EventStats {
  total: number;
  daily: DailyCount[];
  bySource: NamedCount[];
}

export interface EscalationFact {
  id: string;
  organizationId: string;
  incidentId: string | null;
  title: string;
  severity: Severity;
  status: "open" | "acknowledged" | "resolved";
  createdAt: string;
  dueAt: string;
  acknowledgedAt: string | null;
  resolvedAt: string | null;
}

export interface VulnerabilityStats {
  /** Open (incl. in_remediation) at `to`. */
  openBySeverity: Record<Severity, number>;
  knownExploitedOpen: number;
  overdueSla: number;
  patchAvailableOpen: number;
  internetFacingCriticalOpen: number;
  openedInPeriod: number;
  resolvedInPeriod: number;
  /** Mean days from first seen to resolved, for vulnerabilities resolved in the period. */
  meanTimeToRemediateDays: number | null;
  ageBuckets: NamedCount[];
  openByAssetCriticality: Partial<Record<Criticality, number>>;
}

export interface VulnerabilityFact {
  id: string;
  organizationId: string;
  cve: string | null;
  title: string;
  severity: Severity;
  cvss: number | null;
  epss: number | null;
  knownExploited: boolean;
  assetName: string;
  assetCriticality: Criticality;
  internetFacing: boolean;
  status: string;
  firstSeenAt: string;
  slaDueAt: string | null;
  riskScore: number | null;
  riskFactors: RiskFactor[];
  patchAvailable: boolean;
}

export interface RiskyAssetFact {
  id: string;
  organizationId: string;
  name: string;
  kind: string;
  criticality: Criticality;
  riskScore: number;
  factors: RiskFactor[];
  openIncidents: number;
  openCriticalVulnerabilities: number;
}

export interface AttackPathStats {
  total: number;
  toCrownJewels: number;
  top: { id: string; organizationId: string; entry: string; target: string; score: number; severity: Severity; hops: number; remediation: string | null; factors: RiskFactor[] }[];
}

export interface PostureStats {
  riskScore: number | null;
  exposureScore: number | null;
  agents: { total: number; protected: number; unresponsive: number; outdated: number; isolated: number };
  identities: { total: number; privileged: number; privilegedWithoutMfa: number; usersWithoutMfa: number; risky: number };
  cloud: { score: number | null; failingControls: number };
  logSources: { total: number; healthy: number; silent: number };
}

export interface PostureTrendPoint {
  date: string;
  riskScore: number | null;
  exposureScore: number | null;
}

export interface IntelStats {
  indicatorsTotal: number;
  indicatorsNew: number;
  byType: NamedCount[];
  bySource: NamedCount[];
  matchesTotal: number;
  matchesDaily: DailyCount[];
  topActors: NamedCount[];
  topMalware: NamedCount[];
  topCampaigns: NamedCount[];
  topMatched: { type: string; value: string; source: string; severity: Severity; confidence: number; matches: number; lastSeenAt: string; threatActor: string | null }[];
}

export interface ComplianceControlFact {
  organizationId: string;
  framework: string;
  controlId: string;
  title: string;
  status: "pass" | "fail" | "partial" | "not_applicable" | "unknown";
  severity: Severity;
  evidence: string | null;
  lastEvaluatedAt: string | null;
  owner: string | null;
}

export interface AnalystActivityFact {
  analystId: string;
  name: string;
  role: string | null;
  incidentsAssigned: number;
  incidentsClosed: number;
  alertsTriaged: number;
  investigationsLed: number;
  notesWritten: number;
  actionsRequested: number;
  actionsApproved: number;
  meanAcknowledgeMinutes: number | null;
  meanResolveMinutes: number | null;
  organizationsServed: number;
  aiAssists: number;
}

export interface ResponseStats {
  actionsTotal: number;
  byAction: NamedCount[];
  byStatus: NamedCount[];
  automated: number;
  manual: number;
  aiInitiated: number;
  pendingApproval: number;
  meanApprovalMinutes: number | null;
  playbookRuns: number;
  playbookSucceeded: number;
  playbookFailed: number;
  notificationsSent: number;
  /** Analyst minutes saved by automation, if the tenant configured per-action estimates. */
  estimatedMinutesSaved: number | null;
}

export interface OrganizationPostureFact {
  organizationId: string;
  riskScore: number | null;
  exposureScore: number | null;
  agentsTotal: number;
  agentsUnhealthy: number;
  criticalVulnerabilities: number;
  knownExploitedOpen: number;
}

export interface UsageFact {
  organizationId: string;
  endpoints: number;
  endpointsLicensed: number | null;
  eventsPerDay: number;
  aiRequests: number;
}

export interface BillingFact {
  organizationId: string;
  plan: PlanKey | null;
  /** Monthly recurring revenue at `to` / at the previous period end. */
  mrr: number;
  previousMrr: number | null;
  currency: string;
}

export interface IncidentDetail {
  incident: IncidentFact & { summary: string | null };
  timeline: { at: string; kind: string; title: string; actor: string | null }[];
  assets: { name: string; kind: string; criticality: Criticality; riskScore: number | null }[];
  identities: { principal: string; provider: string; privileged: boolean; mfaEnabled: boolean }[];
  indicators: { type: string; value: string; source: string | null }[];
  actions: { action: string; status: string; target: string; requestedBy: string; approvedBy: string | null; at: string }[];
  evidence: { name: string; kind: string; sha256: string; collectedBy: string; at: string }[];
  rootCause: string | null;
  lessonsLearned: string[];
}

export interface ReportDataSource {
  organizations(q: ReportQuery): Promise<OrganizationFact[]>;
  /** Incidents detected in [from, to) plus incidents still open at `from` (backlog). */
  incidents(q: ReportQuery): Promise<IncidentFact[]>;
  alertStats(q: ReportQuery): Promise<AlertStats>;
  eventStats(q: ReportQuery): Promise<EventStats>;
  /** Escalations created in [from, to) plus those still open at `from`. */
  escalations(q: ReportQuery): Promise<EscalationFact[]>;
  vulnerabilityStats(q: ReportQuery): Promise<VulnerabilityStats>;
  topVulnerabilities(q: ReportQuery, limit: number): Promise<VulnerabilityFact[]>;
  riskyAssets(q: ReportQuery, limit: number): Promise<RiskyAssetFact[]>;
  attackPaths(q: ReportQuery, limit: number): Promise<AttackPathStats>;
  posture(q: ReportQuery): Promise<PostureStats>;
  postureTrend(q: ReportQuery): Promise<PostureTrendPoint[]>;
  organizationPosture(q: ReportQuery): Promise<OrganizationPostureFact[]>;
  intelStats(q: ReportQuery, limit: number): Promise<IntelStats>;
  complianceControls(q: ReportQuery): Promise<ComplianceControlFact[]>;
  analystActivity(q: ReportQuery): Promise<AnalystActivityFact[]>;
  responseStats(q: ReportQuery): Promise<ResponseStats>;
  usage(q: ReportQuery): Promise<UsageFact[]>;
  billing(q: ReportQuery): Promise<BillingFact[]>;
  /** Full post-incident detail; null when not found in the tenant/scope. */
  incidentDetail(q: ReportQuery, incidentId: string): Promise<IncidentDetail | null>;
}

/** Thrown when a data source returns a row outside the requested tenant/organization scope. */
export class ReportScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReportScopeError";
  }
}

function inScope(scope: readonly string[] | "all", organizationId: string): boolean {
  return scope === "all" || scope.includes(organizationId);
}

function check<T extends { organizationId: string }>(rows: T[], q: ReportQuery, what: string): T[] {
  for (const r of rows) {
    if (!inScope(q.organizationIds, r.organizationId)) {
      throw new ReportScopeError(`${what}: data source returned a row for organization ${r.organizationId} outside the requested scope`);
    }
  }
  return rows;
}

/**
 * Defence in depth: wraps a data source and verifies every organization-scoped row it returns
 * belongs to the requested scope. A leak is a bug in the data source — fail loudly, never render it.
 */
export function scopedDataSource(ds: ReportDataSource): ReportDataSource {
  return {
    organizations: async (q) => {
      const rows = await ds.organizations(q);
      for (const o of rows) if (!inScope(q.organizationIds, o.id)) throw new ReportScopeError(`organizations: ${o.id} outside the requested scope`);
      return rows;
    },
    incidents: async (q) => check(await ds.incidents(q), q, "incidents"),
    alertStats: (q) => ds.alertStats(q),
    eventStats: (q) => ds.eventStats(q),
    escalations: async (q) => check(await ds.escalations(q), q, "escalations"),
    vulnerabilityStats: (q) => ds.vulnerabilityStats(q),
    topVulnerabilities: async (q, limit) => check(await ds.topVulnerabilities(q, limit), q, "topVulnerabilities").slice(0, limit),
    riskyAssets: async (q, limit) => check(await ds.riskyAssets(q, limit), q, "riskyAssets").slice(0, limit),
    attackPaths: async (q, limit) => {
      const s = await ds.attackPaths(q, limit);
      check(s.top, q, "attackPaths");
      return { ...s, top: s.top.slice(0, limit) };
    },
    posture: (q) => ds.posture(q),
    postureTrend: (q) => ds.postureTrend(q),
    organizationPosture: async (q) => check(await ds.organizationPosture(q), q, "organizationPosture"),
    intelStats: (q, limit) => ds.intelStats(q, limit),
    complianceControls: async (q) => check(await ds.complianceControls(q), q, "complianceControls"),
    analystActivity: (q) => ds.analystActivity(q),
    responseStats: (q) => ds.responseStats(q),
    usage: async (q) => check(await ds.usage(q), q, "usage"),
    billing: async (q) => check(await ds.billing(q), q, "billing"),
    incidentDetail: async (q, id) => {
      const d = await ds.incidentDetail(q, id);
      if (d && !inScope(q.organizationIds, d.incident.organizationId)) throw new ReportScopeError("incidentDetail: incident outside the requested scope");
      return d;
    },
  };
}
