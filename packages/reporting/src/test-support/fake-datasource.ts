/**
 * TEST FIXTURES ONLY — an in-memory ReportDataSource with deterministic data for two customer
 * organizations. It honours tenant, organization scope and the [from, to) window exactly like
 * the SQL implementation must, so builders' derived metrics can be asserted precisely.
 */
import type { RiskFactor, Severity } from "@bloody/contracts";
import type {
  AlertStats,
  AnalystActivityFact,
  AttackPathStats,
  BillingFact,
  ComplianceControlFact,
  EscalationFact,
  EventStats,
  IncidentDetail,
  IncidentFact,
  IntelStats,
  OrganizationFact,
  OrganizationPostureFact,
  PostureStats,
  PostureTrendPoint,
  ReportDataSource,
  ReportQuery,
  ResponseStats,
  RiskyAssetFact,
  UsageFact,
  VulnerabilityFact,
  VulnerabilityStats,
} from "../datasource.js";

export const TENANT = "11111111-1111-4111-8111-111111111111";
export const ORG_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const ORG_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
/** Current period: 1 Sep – 1 Oct 2026 (30 days); previous: 2 Aug – 1 Sep. */
export const PERIOD = { from: new Date("2026-09-01T00:00:00Z"), to: new Date("2026-10-01T00:00:00Z") };
export const NOW = new Date("2026-10-01T00:00:00Z");

const iso = (s: string): string => new Date(s).toISOString();
const plus = (s: string, minutes: number): string => new Date(Date.parse(s) + minutes * 60_000).toISOString();

function factor(key: string, label: string, contribution: number, explanation: string): RiskFactor {
  return { key, label, value: Math.min(1, Math.abs(contribution) / 40), weight: 40, contribution, explanation };
}

function incident(p: Partial<IncidentFact> & Pick<IncidentFact, "id" | "organizationId" | "number" | "title" | "severity" | "status" | "detectedAt">): IncidentFact {
  return {
    riskScore: 50,
    firstActivityAt: null,
    acknowledgedAt: null,
    containedAt: null,
    closedAt: null,
    assigneeId: null,
    assigneeName: null,
    attack: [],
    alertCount: 3,
    assetCount: 1,
    identityCount: 0,
    ...p,
  };
}

export const INCIDENTS: IncidentFact[] = [
  // current period — Acme
  incident({ id: "i-101", organizationId: ORG_A, number: 101, title: "Ransomware precursor on FIN-WS-042", severity: "critical", status: "closed", riskScore: 92, detectedAt: iso("2026-09-03T10:00:00Z"), firstActivityAt: iso("2026-09-03T09:00:00Z"), acknowledgedAt: plus("2026-09-03T10:00:00Z", 10), containedAt: plus("2026-09-03T10:00:00Z", 60), closedAt: plus("2026-09-03T10:00:00Z", 180), assigneeName: "Dana Analyst", attack: [{ id: "T1486", name: "Data Encrypted for Impact", tactic: "impact" }, { id: "T1059.001", name: "PowerShell", tactic: "execution" }], assetCount: 2, identityCount: 1, riskFactors: [factor("crit", "Crown-jewel asset", 30, "FIN-WS-042 hosts finance data"), factor("ttp", "Ransomware technique", 25, "T1486 observed")] }),
  incident({ id: "i-102", organizationId: ORG_A, number: 102, title: "Impossible travel for j.doe", severity: "high", status: "closed", riskScore: 74, detectedAt: iso("2026-09-10T08:00:00Z"), acknowledgedAt: plus("2026-09-10T08:00:00Z", 90), closedAt: plus("2026-09-10T08:00:00Z", 1440), assigneeName: "Eli Hunter", attack: [{ id: "T1078", name: "Valid Accounts", tactic: "initial-access" }] }),
  incident({ id: "i-103", organizationId: ORG_A, number: 103, title: "Suspicious scheduled task on SRV-DB-01", severity: "medium", status: "investigating", riskScore: 55, detectedAt: iso("2026-09-28T12:00:00Z"), acknowledgedAt: plus("2026-09-28T12:00:00Z", 60), assigneeName: "Dana Analyst", attack: [{ id: "T1053.005", name: "Scheduled Task", tactic: "persistence" }] }),
  // backlog from previous period — Acme
  incident({ id: "i-099", organizationId: ORG_A, number: 99, title: "Beaconing from LAB-07", severity: "high", status: "contained", riskScore: 68, detectedAt: iso("2026-08-25T00:00:00Z"), acknowledgedAt: plus("2026-08-25T00:00:00Z", 30), containedAt: plus("2026-08-25T00:00:00Z", 1440), assigneeName: "Eli Hunter", attack: [{ id: "T1071", name: "Application Layer Protocol", tactic: "command-and-control" }] }),
  // current period — Globex
  incident({ id: "i-201", organizationId: ORG_B, number: 201, title: "Encryption activity on file server", severity: "critical", status: "remediated", riskScore: 88, detectedAt: iso("2026-09-15T00:00:00Z"), firstActivityAt: iso("2026-09-14T22:00:00Z"), acknowledgedAt: plus("2026-09-15T00:00:00Z", 20), containedAt: plus("2026-09-15T00:00:00Z", 90), closedAt: plus("2026-09-15T00:00:00Z", 360), assigneeName: "Dana Analyst", attack: [{ id: "T1486", name: "Data Encrypted for Impact", tactic: "impact" }] }),
  incident({ id: "i-202", organizationId: ORG_B, number: 202, title: "Admin tool flagged as hack tool", severity: "low", status: "false_positive", riskScore: 10, detectedAt: iso("2026-09-20T09:00:00Z"), acknowledgedAt: plus("2026-09-20T09:00:00Z", 5), closedAt: plus("2026-09-20T09:00:00Z", 30), assigneeName: "Finn Responder" }),
  // previous period
  incident({ id: "i-090", organizationId: ORG_A, number: 90, title: "Phishing payload executed", severity: "high", status: "closed", riskScore: 70, detectedAt: iso("2026-08-05T08:00:00Z"), acknowledgedAt: plus("2026-08-05T08:00:00Z", 30), closedAt: plus("2026-08-05T08:00:00Z", 600) }),
  incident({ id: "i-091", organizationId: ORG_A, number: 91, title: "Brute force against VPN", severity: "medium", status: "closed", riskScore: 45, detectedAt: iso("2026-08-12T08:00:00Z"), acknowledgedAt: plus("2026-08-12T08:00:00Z", 100), closedAt: plus("2026-08-12T08:00:00Z", 1440) }),
  incident({ id: "i-190", organizationId: ORG_B, number: 190, title: "Credential dumping on DC", severity: "critical", status: "closed", riskScore: 90, detectedAt: iso("2026-08-20T08:00:00Z"), acknowledgedAt: plus("2026-08-20T08:00:00Z", 5), closedAt: plus("2026-08-20T08:00:00Z", 200), attack: [{ id: "T1003", name: "OS Credential Dumping", tactic: "credential-access" }] }),
];

export const ESCALATIONS: EscalationFact[] = [
  { id: "e-1", organizationId: ORG_A, incidentId: "i-102", title: "Confirm travel for j.doe", severity: "high", status: "resolved", createdAt: iso("2026-09-10T09:00:00Z"), dueAt: iso("2026-09-11T09:00:00Z"), acknowledgedAt: iso("2026-09-10T10:00:00Z"), resolvedAt: iso("2026-09-11T08:00:00Z") },
  { id: "e-2", organizationId: ORG_A, incidentId: "i-103", title: "Approve isolation of SRV-DB-01", severity: "medium", status: "open", createdAt: iso("2026-09-28T13:00:00Z"), dueAt: iso("2026-09-29T12:00:00Z"), acknowledgedAt: null, resolvedAt: null },
  { id: "e-3", organizationId: ORG_B, incidentId: "i-201", title: "Reset credentials for svc-backup", severity: "critical", status: "resolved", createdAt: iso("2026-09-15T01:00:00Z"), dueAt: iso("2026-09-15T13:00:00Z"), acknowledgedAt: iso("2026-09-15T02:00:00Z"), resolvedAt: iso("2026-09-16T00:00:00Z") },
  { id: "e-0", organizationId: ORG_A, incidentId: "i-090", title: "Confirm phishing scope", severity: "high", status: "resolved", createdAt: iso("2026-08-05T09:00:00Z"), dueAt: iso("2026-08-06T09:00:00Z"), acknowledgedAt: null, resolvedAt: iso("2026-08-05T20:00:00Z") },
];

const DAY = 86_400_000;
const START = Date.parse("2026-08-02T00:00:00Z");
const SOURCES = ["edr", "identity", "network"];
const RULES = [
  { ruleId: "r-ps", name: "Encoded PowerShell" },
  { ruleId: "r-login", name: "Impossible travel" },
  { ruleId: "r-dns", name: "DNS tunnelling" },
];

interface AlertRow {
  at: number;
  organizationId: string;
  severity: Severity;
  source: string;
  ruleId: string;
  falsePositive: boolean;
  promoted: boolean;
}

const SEVS: Severity[] = ["low", "medium", "high", "medium", "critical", "low"];
export const ALERTS: AlertRow[] = [];
for (let d = 0; d < 60; d++) {
  for (const org of [ORG_A, ORG_B]) {
    const n = 2 + ((d + (org === ORG_A ? 0 : 1)) % 3);
    for (let k = 0; k < n; k++) {
      const i = d * 7 + k;
      ALERTS.push({ at: START + d * DAY + k * 3_600_000, organizationId: org, severity: SEVS[i % SEVS.length]!, source: SOURCES[i % 3]!, ruleId: RULES[(i + d) % 3]!.ruleId, falsePositive: i % 4 === 0, promoted: i % 9 === 0 });
    }
  }
}

function inScope(q: ReportQuery, org: string): boolean {
  return q.organizationIds === "all" || q.organizationIds.includes(org);
}

function within(t: number, q: ReportQuery): boolean {
  return t >= q.from.getTime() && t < q.to.getTime();
}

function isCurrent(q: ReportQuery): boolean {
  return q.to.getTime() > Date.parse("2026-09-15T00:00:00Z");
}

function sumRecords<T extends Record<string, number>>(rows: T[]): T {
  const out = {} as Record<string, number>;
  for (const r of rows) for (const [k, v] of Object.entries(r)) out[k] = (out[k] ?? 0) + v;
  return out as T;
}

const VULN_SNAPSHOT: Record<string, { cur: VulnerabilityStats; prev: VulnerabilityStats }> = {
  [ORG_A]: {
    cur: { openBySeverity: { critical: 4, high: 12, medium: 30, low: 18, info: 0 }, knownExploitedOpen: 2, overdueSla: 5, patchAvailableOpen: 40, internetFacingCriticalOpen: 1, openedInPeriod: 20, resolvedInPeriod: 26, meanTimeToRemediateDays: 12.5, ageBuckets: [{ name: "< 30 d", count: 30 }, { name: "30-90 d", count: 24 }, { name: "> 90 d", count: 10 }], openByAssetCriticality: { crown_jewel: 6, high: 20, medium: 28, low: 10 } },
    prev: { openBySeverity: { critical: 6, high: 15, medium: 31, low: 18, info: 0 }, knownExploitedOpen: 3, overdueSla: 8, patchAvailableOpen: 44, internetFacingCriticalOpen: 2, openedInPeriod: 25, resolvedInPeriod: 18, meanTimeToRemediateDays: 16, ageBuckets: [{ name: "< 30 d", count: 35 }, { name: "30-90 d", count: 25 }, { name: "> 90 d", count: 10 }], openByAssetCriticality: { crown_jewel: 8, high: 22, medium: 30, low: 10 } },
  },
  [ORG_B]: {
    cur: { openBySeverity: { critical: 1, high: 5, medium: 10, low: 9, info: 2 }, knownExploitedOpen: 0, overdueSla: 1, patchAvailableOpen: 15, internetFacingCriticalOpen: 0, openedInPeriod: 8, resolvedInPeriod: 9, meanTimeToRemediateDays: 9, ageBuckets: [{ name: "< 30 d", count: 15 }, { name: "30-90 d", count: 9 }, { name: "> 90 d", count: 3 }], openByAssetCriticality: { crown_jewel: 1, high: 6, medium: 12, low: 8 } },
    prev: { openBySeverity: { critical: 1, high: 6, medium: 11, low: 9, info: 2 }, knownExploitedOpen: 1, overdueSla: 2, patchAvailableOpen: 16, internetFacingCriticalOpen: 0, openedInPeriod: 7, resolvedInPeriod: 6, meanTimeToRemediateDays: 11, ageBuckets: [{ name: "< 30 d", count: 16 }, { name: "30-90 d", count: 10 }, { name: "> 90 d", count: 3 }], openByAssetCriticality: { crown_jewel: 1, high: 7, medium: 13, low: 8 } },
  },
};

const POSTURE: Record<string, { cur: PostureStats; prev: PostureStats }> = {
  [ORG_A]: {
    cur: { riskScore: 58, exposureScore: 61, agents: { total: 120, protected: 114, unresponsive: 3, outdated: 2, isolated: 1 }, identities: { total: 300, privileged: 14, privilegedWithoutMfa: 2, usersWithoutMfa: 9, risky: 4 }, cloud: { score: 72, failingControls: 11 }, logSources: { total: 12, healthy: 11, silent: 1 } },
    prev: { riskScore: 64, exposureScore: 66, agents: { total: 118, protected: 110, unresponsive: 5, outdated: 2, isolated: 1 }, identities: { total: 295, privileged: 14, privilegedWithoutMfa: 3, usersWithoutMfa: 12, risky: 6 }, cloud: { score: 70, failingControls: 13 }, logSources: { total: 12, healthy: 12, silent: 0 } },
  },
  [ORG_B]: {
    cur: { riskScore: 41, exposureScore: 38, agents: { total: 60, protected: 59, unresponsive: 1, outdated: 0, isolated: 0 }, identities: { total: 120, privileged: 6, privilegedWithoutMfa: 0, usersWithoutMfa: 2, risky: 1 }, cloud: { score: 81, failingControls: 4 }, logSources: { total: 6, healthy: 6, silent: 0 } },
    prev: { riskScore: 44, exposureScore: 40, agents: { total: 58, protected: 56, unresponsive: 2, outdated: 0, isolated: 0 }, identities: { total: 118, privileged: 6, privilegedWithoutMfa: 1, usersWithoutMfa: 3, risky: 2 }, cloud: { score: 79, failingControls: 5 }, logSources: { total: 6, healthy: 6, silent: 0 } },
  },
};

const VULNS: VulnerabilityFact[] = [
  { id: "v-1", organizationId: ORG_A, cve: "CVE-2026-1001", title: "VPN appliance RCE", severity: "critical", cvss: 9.8, epss: 0.94, knownExploited: true, assetName: "vpn-edge-01", assetCriticality: "high", internetFacing: true, status: "open", firstSeenAt: iso("2026-09-02T00:00:00Z"), slaDueAt: iso("2026-09-09T00:00:00Z"), riskScore: 97, riskFactors: [factor("kev", "Known exploited", 35, "Listed in KEV"), factor("internet", "Internet-facing", 25, "Reachable from the internet"), factor("epss", "EPSS 94%", 20, "High exploit probability")], patchAvailable: true },
  { id: "v-2", organizationId: ORG_A, cve: "CVE-2026-2002", title: "Domain controller privilege escalation", severity: "high", cvss: 8.1, epss: 0.31, knownExploited: true, assetName: "dc-01", assetCriticality: "crown_jewel", internetFacing: false, status: "open", firstSeenAt: iso("2026-08-20T00:00:00Z"), slaDueAt: iso("2026-09-20T00:00:00Z"), riskScore: 89, riskFactors: [factor("kev", "Known exploited", 35, "Listed in KEV"), factor("crown", "Crown jewel", 30, "Domain controller")], patchAvailable: false },
  { id: "v-3", organizationId: ORG_B, cve: "CVE-2026-3003", title: "Web framework deserialisation", severity: "critical", cvss: 9.1, epss: 0.12, knownExploited: false, assetName: "portal-web", assetCriticality: "medium", internetFacing: false, status: "in_remediation", firstSeenAt: iso("2026-09-12T00:00:00Z"), slaDueAt: iso("2026-10-12T00:00:00Z"), riskScore: 66, riskFactors: [factor("cvss", "CVSS 9.1", 30, "Critical severity")], patchAvailable: true },
];

const ASSETS: RiskyAssetFact[] = [
  { id: "a-1", organizationId: ORG_A, name: "dc-01", kind: "domain_controller", criticality: "crown_jewel", riskScore: 86, factors: [factor("vuln", "KEV vulnerability", 32, "CVE-2026-2002 unpatched"), factor("paths", "Attack paths", 22, "2 paths from the internet"), factor("edr", "EDR healthy", -6, "Compensating control")], openIncidents: 0, openCriticalVulnerabilities: 1 },
  { id: "a-2", organizationId: ORG_B, name: "fs-02", kind: "server", criticality: "high", riskScore: 61, factors: [factor("inc", "Recent incident", 25, "Encryption activity in September")], openIncidents: 0, openCriticalVulnerabilities: 0 },
];

const PATHS: AttackPathStats["top"] = [
  { id: "p-1", organizationId: ORG_A, entry: "vpn-edge-01", target: "dc-01", score: 91, severity: "critical", hops: 3, remediation: "Patch CVE-2026-1001 on vpn-edge-01", factors: [factor("entry", "Internet entry", 30, "VPN RCE"), factor("target", "Crown jewel", 35, "Domain controller")] },
];

function controls(org: string, current: boolean): ComplianceControlFact[] {
  const base: [string, string, string, Severity, ComplianceControlFact["status"], ComplianceControlFact["status"]][] = [
    ["CIS v8", "1.1", "Enterprise asset inventory", "medium", "pass", "pass"],
    ["CIS v8", "4.1", "Secure configuration process", "medium", "partial", "fail"],
    ["CIS v8", "6.5", "Require MFA for administrative access", "high", org === ORG_A ? "fail" : "pass", "fail"],
    ["CIS v8", "7.1", "Vulnerability management process", "high", "pass", "partial"],
    ["CIS v8", "8.2", "Collect audit logs", "medium", org === ORG_A ? "partial" : "pass", "pass"],
    ["ISO 27001", "A.8.7", "Protection against malware", "high", "pass", "pass"],
    ["ISO 27001", "A.8.8", "Management of technical vulnerabilities", "high", org === ORG_A ? "fail" : "pass", "fail"],
    ["ISO 27001", "A.8.16", "Monitoring activities", "medium", "pass", "pass"],
    ["ISO 27001", "A.5.30", "ICT readiness for business continuity", "low", "not_applicable", "not_applicable"],
  ];
  return base.map(([framework, controlId, title, severity, cur, prev]) => ({ organizationId: org, framework, controlId, title, severity, status: current ? cur : prev, evidence: `${title}: automated evidence`, lastEvaluatedAt: iso("2026-09-30T00:00:00Z"), owner: framework === "CIS v8" ? "IT operations" : null }));
}

const ANALYSTS_CUR: AnalystActivityFact[] = [
  { analystId: "u-1", name: "Dana Analyst", role: "SOC analyst T2", incidentsAssigned: 3, incidentsClosed: 2, alertsTriaged: 140, investigationsLed: 2, notesWritten: 31, actionsRequested: 4, actionsApproved: 0, meanAcknowledgeMinutes: 15, meanResolveMinutes: 270, organizationsServed: 2, aiAssists: 12 },
  { analystId: "u-2", name: "Eli Hunter", role: "Threat hunter", incidentsAssigned: 2, incidentsClosed: 1, alertsTriaged: 60, investigationsLed: 1, notesWritten: 12, actionsRequested: 1, actionsApproved: 2, meanAcknowledgeMinutes: 60, meanResolveMinutes: 1440, organizationsServed: 1, aiAssists: 4 },
  { analystId: "u-3", name: "Finn Responder", role: "Incident responder", incidentsAssigned: 1, incidentsClosed: 1, alertsTriaged: 35, investigationsLed: 0, notesWritten: 5, actionsRequested: 0, actionsApproved: 3, meanAcknowledgeMinutes: 5, meanResolveMinutes: 30, organizationsServed: 1, aiAssists: 1 },
  { analystId: "u-4", name: "Gale Idle", role: "SOC analyst T1", incidentsAssigned: 0, incidentsClosed: 0, alertsTriaged: 0, investigationsLed: 0, notesWritten: 0, actionsRequested: 0, actionsApproved: 0, meanAcknowledgeMinutes: null, meanResolveMinutes: null, organizationsServed: 0, aiAssists: 0 },
];

export class FakeReportDataSource implements ReportDataSource {
  readonly calls: { method: string; q: ReportQuery }[] = [];
  /** When set, `incidents()` leaks a row from another organization (scope-guard test). */
  leak = false;

  private log(method: string, q: ReportQuery): void {
    if (q.tenantId !== TENANT) throw new Error("unexpected tenant");
    this.calls.push({ method, q });
  }

  private orgs(q: ReportQuery): string[] {
    return [ORG_A, ORG_B].filter((o) => inScope(q, o));
  }

  async organizations(q: ReportQuery): Promise<OrganizationFact[]> {
    this.log("organizations", q);
    const all: OrganizationFact[] = [
      { id: ORG_A, name: "Acme Corp", plan: "professional", createdAt: iso("2025-01-10T00:00:00Z"), slaTargets: null },
      { id: ORG_B, name: "Globex", plan: "enterprise", createdAt: iso("2026-09-05T00:00:00Z"), slaTargets: { acknowledgeMinutes: { critical: 10, high: 30, medium: 240, low: 1440, info: 2880 } } },
    ];
    return all.filter((o) => inScope(q, o.id));
  }

  async incidents(q: ReportQuery): Promise<IncidentFact[]> {
    this.log("incidents", q);
    const rows = INCIDENTS.filter((i) => inScope(q, i.organizationId)).filter((i) => {
      const d = Date.parse(i.detectedAt);
      return within(d, q) || (d < q.from.getTime() && (!i.closedAt || Date.parse(i.closedAt) >= q.from.getTime()));
    });
    return this.leak ? [...rows, { ...INCIDENTS[0]!, id: "leak", organizationId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc" }] : rows.map((r) => structuredClone(r));
  }

  async alertStats(q: ReportQuery): Promise<AlertStats> {
    this.log("alertStats", q);
    const rows = ALERTS.filter((a) => inScope(q, a.organizationId) && within(a.at, q));
    const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const daily = new Map<string, number>();
    const bySource = new Map<string, number>();
    const byRule = new Map<string, { count: number; fp: number }>();
    for (const a of rows) {
      bySeverity[a.severity] += 1;
      const day = new Date(a.at).toISOString().slice(0, 10);
      daily.set(day, (daily.get(day) ?? 0) + 1);
      bySource.set(a.source, (bySource.get(a.source) ?? 0) + 1);
      const r = byRule.get(a.ruleId) ?? { count: 0, fp: 0 };
      r.count += 1;
      if (a.falsePositive) r.fp += 1;
      byRule.set(a.ruleId, r);
    }
    return {
      total: rows.length,
      bySeverity,
      falsePositives: rows.filter((a) => a.falsePositive).length,
      promoted: rows.filter((a) => a.promoted).length,
      suppressed: 0,
      daily: [...daily.entries()].map(([date, count]) => ({ date, count })),
      bySource: [...bySource.entries()].map(([name, count]) => ({ name, count })),
      topRules: [...byRule.entries()].map(([ruleId, v]) => ({ ruleId, name: RULES.find((r) => r.ruleId === ruleId)!.name, count: v.count, falsePositives: v.fp })),
      topTechniques: rows.length > 0 ? [{ id: "T1059.001", name: "PowerShell", tactic: "execution", count: Math.round(rows.length / 3) }] : [],
    };
  }

  async eventStats(q: ReportQuery): Promise<EventStats> {
    this.log("eventStats", q);
    const daily: { date: string; count: number }[] = [];
    let total = 0;
    for (let t = Math.max(START, q.from.getTime()); t < q.to.getTime() && t < START + 60 * DAY; t += DAY) {
      const day = Math.floor((t - START) / DAY);
      const count = this.orgs(q).reduce((s, o) => s + (o === ORG_A ? 2000 : 900) + day * 10, 0);
      daily.push({ date: new Date(t).toISOString().slice(0, 10), count });
      total += count;
    }
    return { total, daily, bySource: [{ name: "edr", count: Math.round(total * 0.6) }, { name: "network", count: Math.round(total * 0.4) }] };
  }

  async escalations(q: ReportQuery): Promise<EscalationFact[]> {
    this.log("escalations", q);
    return ESCALATIONS.filter((e) => inScope(q, e.organizationId)).filter((e) => {
      const c = Date.parse(e.createdAt);
      return within(c, q) || (c < q.from.getTime() && (!e.resolvedAt || Date.parse(e.resolvedAt) >= q.from.getTime()));
    });
  }

  async vulnerabilityStats(q: ReportQuery): Promise<VulnerabilityStats> {
    this.log("vulnerabilityStats", q);
    const snaps = this.orgs(q).map((o) => (isCurrent(q) ? VULN_SNAPSHOT[o]!.cur : VULN_SNAPSHOT[o]!.prev));
    const rem = snaps.filter((s) => s.meanTimeToRemediateDays !== null);
    return {
      openBySeverity: sumRecords(snaps.map((s) => s.openBySeverity)),
      knownExploitedOpen: snaps.reduce((n, s) => n + s.knownExploitedOpen, 0),
      overdueSla: snaps.reduce((n, s) => n + s.overdueSla, 0),
      patchAvailableOpen: snaps.reduce((n, s) => n + s.patchAvailableOpen, 0),
      internetFacingCriticalOpen: snaps.reduce((n, s) => n + s.internetFacingCriticalOpen, 0),
      openedInPeriod: snaps.reduce((n, s) => n + s.openedInPeriod, 0),
      resolvedInPeriod: snaps.reduce((n, s) => n + s.resolvedInPeriod, 0),
      meanTimeToRemediateDays: rem.length ? rem.reduce((n, s) => n + s.meanTimeToRemediateDays!, 0) / rem.length : null,
      ageBuckets: ["< 30 d", "30-90 d", "> 90 d"].map((name) => ({ name, count: snaps.reduce((n, s) => n + (s.ageBuckets.find((b) => b.name === name)?.count ?? 0), 0) })),
      openByAssetCriticality: sumRecords(snaps.map((s) => s.openByAssetCriticality as Record<string, number>)),
    };
  }

  async topVulnerabilities(q: ReportQuery, limit: number): Promise<VulnerabilityFact[]> {
    this.log("topVulnerabilities", q);
    return VULNS.filter((v) => inScope(q, v.organizationId)).sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0)).slice(0, limit);
  }

  async riskyAssets(q: ReportQuery, limit: number): Promise<RiskyAssetFact[]> {
    this.log("riskyAssets", q);
    return ASSETS.filter((a) => inScope(q, a.organizationId)).slice(0, limit);
  }

  async attackPaths(q: ReportQuery, limit: number): Promise<AttackPathStats> {
    this.log("attackPaths", q);
    const top = PATHS.filter((p) => inScope(q, p.organizationId));
    return { total: top.length * 2, toCrownJewels: top.length, top: top.slice(0, limit) };
  }

  async posture(q: ReportQuery): Promise<PostureStats> {
    this.log("posture", q);
    const snaps = this.orgs(q).map((o) => (isCurrent(q) ? POSTURE[o]!.cur : POSTURE[o]!.prev));
    const avg = (f: (p: PostureStats) => number | null): number | null => {
      const v = snaps.map(f).filter((x): x is number => x !== null);
      return v.length ? v.reduce((s, x) => s + x, 0) / v.length : null;
    };
    return {
      riskScore: avg((p) => p.riskScore),
      exposureScore: avg((p) => p.exposureScore),
      agents: sumRecords(snaps.map((p) => p.agents)),
      identities: sumRecords(snaps.map((p) => p.identities)),
      cloud: { score: avg((p) => p.cloud.score), failingControls: snaps.reduce((n, p) => n + p.cloud.failingControls, 0) },
      logSources: sumRecords(snaps.map((p) => p.logSources)),
    };
  }

  async postureTrend(q: ReportQuery): Promise<PostureTrendPoint[]> {
    this.log("postureTrend", q);
    const out: PostureTrendPoint[] = [];
    const n = this.orgs(q).length;
    for (let t = q.from.getTime(); t < q.to.getTime(); t += 3 * DAY) {
      const k = (t - q.from.getTime()) / DAY;
      out.push({ date: new Date(t).toISOString().slice(0, 10), riskScore: n ? Math.round(62 - k * 0.3) : null, exposureScore: n ? Math.round(60 - k * 0.2) : null });
    }
    return out;
  }

  async organizationPosture(q: ReportQuery): Promise<OrganizationPostureFact[]> {
    this.log("organizationPosture", q);
    return this.orgs(q).map((o) => {
      const p = POSTURE[o]!.cur;
      return { organizationId: o, riskScore: p.riskScore, exposureScore: p.exposureScore, agentsTotal: p.agents.total, agentsUnhealthy: p.agents.unresponsive + p.agents.outdated + p.agents.isolated, criticalVulnerabilities: VULN_SNAPSHOT[o]!.cur.openBySeverity.critical, knownExploitedOpen: VULN_SNAPSHOT[o]!.cur.knownExploitedOpen };
    });
  }

  async intelStats(q: ReportQuery, limit: number): Promise<IntelStats> {
    this.log("intelStats", q);
    const cur = isCurrent(q);
    const matchesDaily: { date: string; count: number }[] = [];
    for (let t = q.from.getTime(); t < q.to.getTime(); t += DAY) matchesDaily.push({ date: new Date(t).toISOString().slice(0, 10), count: this.orgs(q).length * (1 + (Math.floor(t / DAY) % 3)) });
    return {
      indicatorsTotal: 12_840,
      indicatorsNew: cur ? 1210 : 980,
      byType: [{ name: "ip", count: 5200 }, { name: "domain", count: 4100 }, { name: "sha256", count: 2900 }, { name: "url", count: 640 }],
      bySource: [{ name: "MISP community", count: 7000 }, { name: "OpenCTI", count: 5000 }, { name: "Internal", count: 840 }],
      matchesTotal: matchesDaily.reduce((s, d) => s + d.count, 0),
      matchesDaily,
      topActors: [{ name: "FIN7", count: 9 }, { name: "Scattered Spider", count: 4 }],
      topMalware: [{ name: "Cobalt Strike", count: 7 }],
      topCampaigns: [],
      topMatched: [
        { type: "domain", value: "update-check.evil-cdn.com", source: "MISP community", severity: "high", confidence: 85, matches: 6, lastSeenAt: iso("2026-09-28T00:00:00Z"), threatActor: "FIN7" },
        { type: "url", value: "https://=cmd|' /C calc'!A0.example/payload", source: "OpenCTI", severity: "critical", confidence: 90, matches: 2, lastSeenAt: iso("2026-09-20T00:00:00Z"), threatActor: null },
      ].slice(0, limit) as IntelStats["topMatched"],
    };
  }

  async complianceControls(q: ReportQuery): Promise<ComplianceControlFact[]> {
    this.log("complianceControls", q);
    return this.orgs(q).flatMap((o) => controls(o, isCurrent(q)));
  }

  async analystActivity(q: ReportQuery): Promise<AnalystActivityFact[]> {
    this.log("analystActivity", q);
    if (isCurrent(q)) return ANALYSTS_CUR.map((a) => ({ ...a }));
    return ANALYSTS_CUR.map((a) => ({ ...a, incidentsClosed: Math.max(0, a.incidentsClosed - 1), alertsTriaged: Math.round(a.alertsTriaged * 0.8) }));
  }

  async responseStats(q: ReportQuery): Promise<ResponseStats> {
    this.log("responseStats", q);
    return { actionsTotal: 14, byAction: [{ name: "isolate_endpoint", count: 3 }, { name: "create_case", count: 6 }, { name: "notify_analyst", count: 5 }], byStatus: [{ name: "succeeded", count: 12 }, { name: "failed", count: 1 }, { name: "pending_approval", count: 1 }], automated: 9, manual: 4, aiInitiated: 1, pendingApproval: 1, meanApprovalMinutes: 7, playbookRuns: 10, playbookSucceeded: 9, playbookFailed: 1, notificationsSent: 42, estimatedMinutesSaved: 360 };
  }

  async usage(q: ReportQuery): Promise<UsageFact[]> {
    this.log("usage", q);
    return this.orgs(q).map((o) => (o === ORG_A ? { organizationId: o, endpoints: 120, endpointsLicensed: 100, eventsPerDay: 2100, aiRequests: 340 } : { organizationId: o, endpoints: 60, endpointsLicensed: 100, eventsPerDay: 950, aiRequests: 80 }));
  }

  async billing(q: ReportQuery): Promise<BillingFact[]> {
    this.log("billing", q);
    return this.orgs(q).map((o) => (o === ORG_A ? { organizationId: o, plan: "professional", mrr: 4800, previousMrr: 4500, currency: "USD" } : { organizationId: o, plan: "enterprise", mrr: 9200, previousMrr: null, currency: "USD" }));
  }

  async incidentDetail(q: ReportQuery, incidentId: string): Promise<IncidentDetail | null> {
    this.log("incidentDetail", q);
    const inc = INCIDENTS.find((i) => i.id === incidentId && inScope(q, i.organizationId));
    if (!inc) return null;
    return {
      incident: { ...inc, summary: "PowerShell launched an encryptor stub on FIN-WS-042; the host was isolated within an hour." },
      timeline: [
        { at: plus(inc.detectedAt, 30), kind: "action", title: "Host isolation approved by Finn Responder", actor: "Finn Responder" },
        { at: inc.detectedAt, kind: "alert", title: "Encoded PowerShell detected", actor: null },
        { at: plus(inc.detectedAt, 120), kind: "note", title: "Encryptor hash submitted to sandbox", actor: "Dana Analyst" },
      ],
      assets: [{ name: "FIN-WS-042", kind: "endpoint", criticality: "high", riskScore: 81 }],
      identities: [{ principal: "ACME\\j.smith", provider: "active_directory", privileged: false, mfaEnabled: true }],
      indicators: [{ type: "domain", value: "update-check.evil-cdn.com", source: "MISP community" }],
      actions: [{ action: "isolate_endpoint", status: "succeeded", target: "FIN-WS-042", requestedBy: "Dana Analyst", approvedBy: "Finn Responder", at: plus(inc.detectedAt, 30) }],
      evidence: [{ name: "memory.dmp", kind: "memory", sha256: "a".repeat(64), collectedBy: "Dana Analyst", at: plus(inc.detectedAt, 45) }],
      rootCause: "Macro-enabled invoice opened by a finance user.",
      lessonsLearned: ["Block Office macros from the internet for finance users"],
    };
  }
}

/** A data source with no data at all (fresh tenant) — every builder must still render real empty states. */
export class EmptyReportDataSource extends FakeReportDataSource {
  override async incidents(): Promise<IncidentFact[]> {
    return [];
  }
  override async escalations(): Promise<EscalationFact[]> {
    return [];
  }
  override async alertStats(): Promise<AlertStats> {
    return { total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, falsePositives: 0, promoted: 0, suppressed: 0, daily: [], bySource: [], topRules: [], topTechniques: [] };
  }
  override async eventStats(): Promise<EventStats> {
    return { total: 0, daily: [], bySource: [] };
  }
  override async topVulnerabilities(): Promise<VulnerabilityFact[]> {
    return [];
  }
  override async riskyAssets(): Promise<RiskyAssetFact[]> {
    return [];
  }
  override async attackPaths(): Promise<AttackPathStats> {
    return { total: 0, toCrownJewels: 0, top: [] };
  }
  override async complianceControls(): Promise<ComplianceControlFact[]> {
    return [];
  }
  override async analystActivity(): Promise<AnalystActivityFact[]> {
    return [];
  }
  override async billing(): Promise<BillingFact[]> {
    return [];
  }
  override async usage(): Promise<UsageFact[]> {
    return [];
  }
  override async postureTrend(): Promise<PostureTrendPoint[]> {
    return [];
  }
}
