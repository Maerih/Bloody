import { z } from "zod";
import type { Severity } from "./common.js";

/** Role-aware dashboard presets. Each selects and orders Command Center widgets. */
export const DashboardRole = z.enum([
  "soc_analyst",
  "tier1",
  "tier2",
  "tier3_hunter",
  "incident_responder",
  "ciso",
  "security_engineer",
  "mssp_admin",
  "org_admin",
  "executive",
]);
export type DashboardRole = z.infer<typeof DashboardRole>;

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/** Response of GET /api/v1/command-center/summary — one round-trip for the main dashboard. */
export interface CommandCenterSummary {
  generatedAt: string;
  organizationId: string | null;
  windowDays: number;
  activeIncidents: SeverityCounts & { total: number; byAssetType: { endpoint: number; identity: number } };
  socActions: { eventsAnalyzed: number; signalsGenerated: number; investigations: number; incidentsReported: number };
  escalations: { open: number; overdue: number; resolved: number };
  mttdMinutes: number | null;
  mttrMinutes: number | null;
  agents: { total: number; protected: number; unresponsive: number; outdated: number; isolated: number };
  antivirus: { protected: number; unhealthy: number; unmanaged: number; incompatible: number };
  firewall: { enabled: number; disabled: number };
  identityRisk: { score: number; riskyIdentities: number; privilegedWithoutMfa: number };
  exposureScore: number;
  vulnerabilities: { critical: number; high: number; knownExploited: number; overdueSla: number };
  cloudPosture: { score: number; failingControls: number };
  networkHealth: { sensors: number; healthy: number; beaconingHosts: number };
  intelMatches: number;
  attackPaths: { total: number; toCrownJewels: number };
  recommendations: { id: string; title: string; impact: Severity; module: string }[];
  triage: TriageItem[];
  aiActivity: { conversations: number; actionsProposed: number; actionsApproved: number };
  automation: { runs: number; succeeded: number; pendingApproval: number };
}

export interface TriageItem {
  id: string;
  kind: "incident" | "escalation" | "alert";
  title: string;
  severity: Severity;
  organizationId: string;
  organizationName: string;
  at: string;
  status: string;
}

/** MSSP-level command center: aggregate across every customer organization. */
export interface MsspOverview {
  organizations: number;
  assets: number;
  activeIncidents: number;
  critical: number;
  investigations: number;
  analysts: number;
  agents: number;
  eventsPerDay: number;
  customers: {
    organizationId: string;
    name: string;
    plan: string;
    riskScore: number;
    activeIncidents: number;
    critical: number;
    agents: number;
    unhealthyAgents: number;
    slaBreaches: number;
    mrr: number;
  }[];
}
