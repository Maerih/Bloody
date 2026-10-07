/**
 * TEST-ONLY fixtures. Never import from production code — the UI renders API data only.
 */
import type { CommandCenterSummary, MsspOverview, Organization, RoleBinding } from "@bloody/contracts";
import type { MeResponse } from "../api/types";

export const TENANT_ID = "00000000-0000-4000-8000-000000000001";
export const ORG_A = "00000000-0000-4000-8000-0000000000a1";
export const ORG_B = "00000000-0000-4000-8000-0000000000b2";
export const USER_ID = "00000000-0000-4000-8000-0000000000c1";

export function makeOrg(id: string, name: string, slug: string): Organization {
  return { id, tenantId: TENANT_ID, name, slug, parentOrganizationId: null, retentionDays: 90, createdAt: "2026-01-01T00:00:00.000Z" };
}

export function makeMe(overrides: Partial<MeResponse> & { bindings?: RoleBinding[] } = {}): MeResponse {
  const { bindings, ...rest } = overrides;
  return {
    principal: {
      kind: "user",
      id: USER_ID,
      tenantId: TENANT_ID,
      email: "analyst@example.test",
      displayName: "Test Analyst",
      bindings: bindings ?? [{ role: "mssp_admin", organizationId: null }],
    },
    account: { id: TENANT_ID, name: "Fixture Security", slug: "fixture-security", kind: "mssp", dataRegion: "eu-west", createdAt: "2026-01-01T00:00:00.000Z" },
    organizations: [makeOrg(ORG_A, "Acme Corp", "acme"), makeOrg(ORG_B, "Globex", "globex")],
    entitlements: [
      { module: "edr", state: "active", trialEndsAt: null },
      { module: "itdr", state: "trial_ended", trialEndsAt: "2026-09-01T00:00:00.000Z" },
      { module: "ndr", state: "locked", trialEndsAt: null },
    ],
    plan: "mssp",
    ...rest,
  };
}

export function makeSummary(overrides: Partial<CommandCenterSummary> = {}): CommandCenterSummary {
  return {
    generatedAt: new Date().toISOString(),
    organizationId: null,
    windowDays: 90,
    activeIncidents: { critical: 1, high: 2, medium: 1, low: 0, total: 4, byAssetType: { endpoint: 3, identity: 1 } },
    socActions: { eventsAnalyzed: 58_700, signalsGenerated: 0, investigations: 0, incidentsReported: 1 },
    escalations: { open: 0, overdue: 0, resolved: 0 },
    mttdMinutes: 12,
    mttrMinutes: 84,
    agents: { total: 1, protected: 1, unresponsive: 0, outdated: 0, isolated: 0 },
    antivirus: { protected: 1, unhealthy: 0, unmanaged: 0, incompatible: 0 },
    firewall: { enabled: 1, disabled: 0 },
    identityRisk: { score: 42, riskyIdentities: 3, privilegedWithoutMfa: 1 },
    exposureScore: 71,
    vulnerabilities: { critical: 2, high: 5, knownExploited: 1, overdueSla: 0 },
    cloudPosture: { score: 88, failingControls: 4 },
    networkHealth: { sensors: 2, healthy: 2, beaconingHosts: 0 },
    intelMatches: 7,
    attackPaths: { total: 3, toCrownJewels: 1 },
    recommendations: [{ id: "rec-1", title: "Enforce MFA on privileged identities", impact: "high", module: "ispm" }],
    triage: [],
    aiActivity: { conversations: 5, actionsProposed: 4, actionsApproved: 3 },
    automation: { runs: 10, succeeded: 9, pendingApproval: 1 },
    ...overrides,
  };
}

export function makeMsspOverview(): MsspOverview {
  return {
    organizations: 2,
    assets: 128_421,
    activeIncidents: 183,
    critical: 17,
    investigations: 54,
    analysts: 42,
    agents: 9_800,
    eventsPerDay: 1_250_000_000,
    customers: [
      { organizationId: ORG_A, name: "Acme Corp", plan: "enterprise", riskScore: 82, activeIncidents: 12, critical: 3, agents: 400, unhealthyAgents: 10, slaBreaches: 1, mrr: 12_400 },
      { organizationId: ORG_B, name: "Globex", plan: "professional", riskScore: 35, activeIncidents: 2, critical: 0, agents: 120, unhealthyAgents: 0, slaBreaches: 0, mrr: 4_100 },
    ],
  };
}
