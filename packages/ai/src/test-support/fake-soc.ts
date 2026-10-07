import type {
  Agent,
  Alert,
  Asset,
  AttackPath,
  CanonicalEvent,
  Identity,
  Incident,
  Indicator,
  NotificationChannel,
  Playbook,
  ResponseActionRecord,
  RiskAssessment,
  TimelineEntry,
  Vulnerability,
} from "@bloody/contracts";
import type {
  AssetDetail,
  IdentityDetail,
  IncidentDetail,
  InvestigationDetail,
  SendNotificationInput,
  SocDataPort,
  SubmitResponseActionInput,
  InvestigationNoteInput,
} from "../tools/soc-port.js";
import type { SocScope } from "../tools/types.js";
import { ORG_A1, TENANT_A } from "./fixtures.js";

/** Test-only in-memory SocDataPort enforcing tenant/org scoping like the real implementation must. */

const T0 = "2026-10-07T10:00:00.000Z";
const scoped = { tenantId: TENANT_A, organizationId: ORG_A1, createdAt: T0, updatedAt: T0 };

export const IDS = {
  incident: "10000000-0000-4000-8000-000000000001",
  asset: "20000000-0000-4000-8000-000000000001",
  assetDc: "20000000-0000-4000-8000-000000000002",
  identity: "30000000-0000-4000-8000-000000000001",
  alert1: "40000000-0000-4000-8000-000000000001",
  alert2: "40000000-0000-4000-8000-000000000002",
  vulnKev: "50000000-0000-4000-8000-000000000001",
  vulnLow: "50000000-0000-4000-8000-000000000002",
  investigation: "60000000-0000-4000-8000-000000000001",
  channel: "70000000-0000-4000-8000-000000000001",
  channelDisabled: "70000000-0000-4000-8000-000000000002",
  event: "80000000-0000-4000-8000-000000000001",
};

export function sampleIncident(): Incident {
  return {
    ...scoped,
    id: IDS.incident,
    number: 1042,
    title: "Credential theft and lateral movement on FIN-WS-01",
    summary: "Mimikatz-like LSASS access followed by SMB lateral movement.",
    severity: "critical",
    status: "investigating",
    riskScore: 91,
    assigneeId: null,
    attack: [{ id: "T1003.001", name: "LSASS Memory", tactic: "credential-access" }],
    alertCount: 2,
    assetIds: [IDS.asset],
    identityIds: [IDS.identity],
    detectedAt: T0,
    acknowledgedAt: null,
    containedAt: null,
    closedAt: null,
  };
}

export function sampleAlerts(): Alert[] {
  const base = { ...scoped, ruleId: "rule-lsass", source: "edr", eventIds: [], assetId: IDS.asset, identityId: IDS.identity, incidentId: IDS.incident, confidence: 0.9, firstSeenAt: T0, lastSeenAt: T0 };
  return [
    { ...base, id: IDS.alert1, title: "LSASS memory access", severity: "critical", status: "promoted", attack: [{ id: "T1003.001", name: "LSASS Memory", tactic: "credential-access" }], riskScore: 92 },
    { ...base, id: IDS.alert2, title: "SMB lateral movement", severity: "high", status: "new", ruleId: "rule-smb", attack: [{ id: "T1021.002", tactic: "lateral-movement" }], riskScore: 75, lastSeenAt: "2026-10-07T11:00:00.000Z" },
  ];
}

export function sampleAsset(): Asset {
  return { ...scoped, id: IDS.asset, kind: "endpoint", name: "FIN-WS-01", hostname: "fin-ws-01.corp.example", ipAddresses: ["10.1.2.3"], os: "Windows 11", criticality: "high", internetFacing: false, tags: ["finance"], owner: "it-finance", lastSeenAt: T0, riskScore: 88 };
}

export function sampleAgent(): Agent {
  return { ...scoped, id: "90000000-0000-4000-8000-000000000001", assetId: IDS.asset, hostname: "fin-ws-01", platform: "windows", version: "4.7.0", engine: "wazuh", status: "protected", lastCheckinAt: T0, antivirusStatus: "protected", firewallEnabled: false };
}

export function sampleIdentity(): Identity {
  return { ...scoped, id: IDS.identity, kind: "user", provider: "entra", principal: "j.doe@corp.example", displayName: "Jane Doe", privileged: true, mfaEnabled: false, lastActivityAt: T0, riskScore: 81 };
}

export function sampleVulns(): Vulnerability[] {
  const base = { ...scoped, assetId: IDS.asset, status: "open" as const, slaDueAt: null, riskScore: null };
  return [
    { ...base, id: IDS.vulnLow, cve: "CVE-2026-0002", title: "Minor info leak", cvss: 4.3, epss: 0.01, knownExploited: false, severity: "medium", patchAvailable: true },
    { ...base, id: IDS.vulnKev, cve: "CVE-2026-0001", title: "Remote code execution in print spooler", cvss: 9.8, epss: 0.92, knownExploited: true, severity: "critical", patchAvailable: true },
  ];
}

export function sampleRisk(): RiskAssessment {
  return {
    score: 88,
    severity: "high",
    likelihood: 0.8,
    impact: 0.7,
    summary: "High likelihood of compromise",
    modelVersion: "risk-1",
    factors: [
      { key: "kev", label: "Known exploited vulnerability", value: 1, weight: 30, contribution: 30, explanation: "CVE-2026-0001 is in KEV" },
      { key: "edr", label: "EDR coverage", value: 1, weight: -5, contribution: -5, explanation: "Agent healthy" },
      { key: "alerts", label: "Active critical alerts", value: 0.9, weight: 25, contribution: 22.5, explanation: "2 alerts in 24h" },
    ],
  };
}

export function sampleEvent(): CanonicalEvent {
  return {
    schemaVersion: "1.0",
    id: IDS.event,
    tenantId: TENANT_A,
    organizationId: ORG_A1,
    timestamp: T0,
    source: { kind: "endpoint", product: "wazuh" },
    category: "process",
    eventType: "process_start",
    asset: { hostname: "fin-ws-01" },
    process: { name: "rundll32.exe", commandLine: "rundll32.exe comsvcs.dll MiniDump 624 lsass.dmp full password=Winter2026!" },
    indicators: [],
    severity: "high",
    attack: [],
    labels: {},
    provenance: { adapter: "wazuh", adapterVersion: "1", receivedAt: T0, raw: { huge: "raw payload must never reach the model" } },
  };
}

export class FakeSocPort implements SocDataPort {
  incidents: Incident[] = [sampleIncident()];
  alerts: Alert[] = sampleAlerts();
  assets: Asset[] = [sampleAsset()];
  identities: Identity[] = [sampleIdentity()];
  vulns: Vulnerability[] = sampleVulns();
  events: CanonicalEvent[] = [sampleEvent()];
  indicators: Indicator[] = [];
  attackPaths: AttackPath[] = [];
  channels: NotificationChannel[] = [
    { id: IDS.channel, tenantId: TENANT_A, organizationId: ORG_A1, name: "SOC e-mail", kind: "email", config: { to: ["soc@corp.example"] }, enabled: true },
    { id: IDS.channelDisabled, tenantId: TENANT_A, organizationId: ORG_A1, name: "Old webhook", kind: "webhook", config: {}, enabled: false },
  ];
  playbooks: Playbook[] = [];
  notes: Array<{ scope: SocScope; input: InvestigationNoteInput }> = [];
  submitted: Array<{ scope: SocScope; input: SubmitResponseActionInput }> = [];
  sent: Array<{ scope: SocScope; input: SendNotificationInput }> = [];
  scopes: SocScope[] = [];

  private inScope<T extends { tenantId: string; organizationId: string | null }>(scope: SocScope, rows: T[]): T[] {
    this.scopes.push(scope);
    return rows.filter((r) => r.tenantId === scope.tenantId && (r.organizationId === null || r.organizationId === scope.organizationId));
  }

  async getIncident(scope: SocScope, id: string, opts: { includeAlerts: boolean; includeTimeline: boolean }): Promise<IncidentDetail | null> {
    const incident = this.inScope(scope, this.incidents).find((i) => i.id === id);
    if (!incident) return null;
    const timeline: TimelineEntry[] = opts.includeTimeline
      ? [{ id: "t1", investigationId: IDS.investigation, kind: "alert", at: "2026-10-07T10:00:00.000Z", actorId: null, title: "Alert promoted", body: null, refId: IDS.alert1 }]
      : [];
    return { incident, alerts: opts.includeAlerts ? this.inScope(scope, this.alerts).filter((a) => a.incidentId === id) : [], investigations: [], timeline };
  }
  async listIncidents(scope: SocScope): Promise<Incident[]> {
    return this.inScope(scope, this.incidents);
  }
  async getAlert(scope: SocScope, id: string): Promise<Alert | null> {
    return this.inScope(scope, this.alerts).find((a) => a.id === id) ?? null;
  }
  async listAlerts(scope: SocScope, filter: { incidentId?: string }): Promise<Alert[]> {
    return this.inScope(scope, this.alerts).filter((a) => !filter.incidentId || a.incidentId === filter.incidentId);
  }
  async searchEvents(scope: SocScope): Promise<{ events: CanonicalEvent[]; total: number; truncated: boolean }> {
    const events = this.inScope(scope, this.events);
    return { events, total: events.length, truncated: false };
  }
  async graphNeighbors(scope: SocScope): Promise<{ nodes: never[]; edges: never[] }> {
    this.scopes.push(scope);
    return { nodes: [], edges: [] };
  }
  async graphBlastRadius(scope: SocScope): Promise<{ nodes: never[]; edges: never[]; crownJewels: string[] }> {
    this.scopes.push(scope);
    return { nodes: [], edges: [], crownJewels: [] };
  }
  async graphSearch(scope: SocScope): Promise<never[]> {
    this.scopes.push(scope);
    return [];
  }
  async getAsset(scope: SocScope, id: string): Promise<AssetDetail | null> {
    const asset = this.inScope(scope, this.assets).find((a) => a.id === id);
    if (!asset) return null;
    return {
      asset,
      risk: sampleRisk(),
      vulnerabilities: this.inScope(scope, this.vulns).filter((v) => v.assetId === id),
      agent: asset.id === IDS.asset ? sampleAgent() : null,
      identities: [],
      openIncidents: this.inScope(scope, this.incidents).filter((i) => i.assetIds.includes(id)),
    };
  }
  async getIdentity(scope: SocScope, id: string): Promise<IdentityDetail | null> {
    const identity = this.inScope(scope, this.identities).find((i) => i.id === id);
    return identity ? { identity, risk: null, groups: ["Domain Admins"], recentAuthentications: [], openIncidents: [] } : null;
  }
  async getInvestigation(scope: SocScope, id: string): Promise<InvestigationDetail | null> {
    this.scopes.push(scope);
    if (id !== IDS.investigation || scope.tenantId !== TENANT_A) return null;
    return {
      investigation: { ...scoped, id, incidentId: IDS.incident, title: "INV-1", status: "open", leadId: null, hypothesis: "Credential theft", closedAt: null },
      timeline: [],
      evidence: [],
    };
  }
  async searchIntel(scope: SocScope, input: { value?: string }): Promise<{ indicators: Indicator[]; matches: never[] }> {
    return { indicators: this.inScope(scope, this.indicators).filter((i) => !input.value || i.value === input.value), matches: [] };
  }
  async getAttackPaths(scope: SocScope): Promise<AttackPath[]> {
    this.scopes.push(scope);
    return scope.tenantId === TENANT_A ? this.attackPaths : [];
  }
  async getRiskAssessment(scope: SocScope, input: { id: string }): Promise<RiskAssessment | null> {
    this.scopes.push(scope);
    return scope.tenantId === TENANT_A && input.id === IDS.asset ? sampleRisk() : null;
  }
  async runHunt(scope: SocScope, input: { query: string }): Promise<{ queryExecuted: string; hits: CanonicalEvent[]; total: number; truncated: boolean; aggregations: Record<string, Array<{ key: string; count: number }>> }> {
    const hits = this.inScope(scope, this.events);
    return { queryExecuted: input.query, hits, total: hits.length, truncated: false, aggregations: { host: [{ key: "fin-ws-01", count: hits.length }] } };
  }
  async listVulnerabilities(scope: SocScope, input: { assetId?: string }): Promise<Vulnerability[]> {
    return this.inScope(scope, this.vulns).filter((v) => !input.assetId || v.assetId === input.assetId);
  }
  async validateDetectionRule(scope: SocScope, input: { content: string }): Promise<{ valid: boolean; errors: string[]; warnings: string[]; testMatches?: number }> {
    this.scopes.push(scope);
    return input.content.includes("detection:") ? { valid: true, errors: [], warnings: [], testMatches: 3 } : { valid: false, errors: ["missing detection"], warnings: [] };
  }
  async getReportData(scope: SocScope, input: { type: string; periodDays: number }): Promise<{ type: never; organizationName: string; period: { from: string; to: string }; metrics: Record<string, unknown> }> {
    this.scopes.push(scope);
    return { type: input.type as never, organizationName: "Acme Corp", period: { from: "2026-09-07T00:00:00.000Z", to: "2026-10-07T00:00:00.000Z" }, metrics: { incidents: 12, mttrMinutes: 95 } };
  }
  async listPlaybooks(scope: SocScope): Promise<Playbook[]> {
    return this.inScope(scope, this.playbooks);
  }
  async submitResponseAction(scope: SocScope, input: SubmitResponseActionInput): Promise<ResponseActionRecord> {
    this.submitted.push({ scope, input });
    return {
      id: "a0000000-0000-4000-8000-000000000001",
      tenantId: scope.tenantId,
      organizationId: scope.organizationId,
      incidentId: input.incidentId ?? null,
      action: input.action,
      target: input.target,
      parameters: input.parameters,
      reason: input.reason,
      status: "approved",
      requestedBy: scope.principalId,
      requestedVia: "ai",
      approvedBy: scope.approvedBy,
      executor: null,
      result: null,
      createdAt: T0,
      updatedAt: T0,
    };
  }
  async addInvestigationNote(scope: SocScope, input: InvestigationNoteInput): Promise<TimelineEntry> {
    this.notes.push({ scope, input });
    return { id: "b0000000-0000-4000-8000-000000000001", investigationId: input.investigationId, kind: "ai", at: T0, actorId: scope.principalId, title: input.title, body: input.body, refId: null };
  }
  async listNotificationChannels(scope: SocScope): Promise<NotificationChannel[]> {
    return this.inScope(scope, this.channels);
  }
  async sendNotification(scope: SocScope, input: SendNotificationInput): Promise<{ deliveryId: string; channels: number; status: string }> {
    this.sent.push({ scope, input });
    return { deliveryId: "d-1", channels: input.channelIds.length, status: "queued" };
  }
}
