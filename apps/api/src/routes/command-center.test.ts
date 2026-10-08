import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { POWERSHELL, api, createTenant, createTestApp, createUser, dnsEvent, login, minutesAgo, processEvent, type Json, type TestApp, type TestTenant } from "../test/harness.js";

/**
 * Command Center + MSSP overview: every number must be a real aggregation over stored
 * records. The fixture below is fully controlled, so the expected values are exact.
 */
let t: TestApp;
let tenant: TestTenant;
let o1: string;
let o2: string;
let admin: ReturnType<typeof api>;
const ids = {} as Record<string, string>;

function scaEvent(host: string, control: string, outcome: "success" | "failure"): Json {
  return {
    id: randomUUID(),
    timestamp: minutesAgo(10),
    source: { kind: "endpoint", product: "wazuh" },
    category: "configuration",
    eventType: "sca_check",
    outcome,
    asset: { hostname: host },
    labels: { control },
    provenance: { adapter: "bloody-tests", adapterVersion: "1", receivedAt: new Date().toISOString() },
  };
}

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 2 });
  [o1, o2] = tenant.orgIds as [string, string];
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  expect((await admin.patch(`/organizations/${o1}`, { mrr: 1000, name: "Alpha Bank" })).status).toBe(200);
  expect((await admin.patch(`/organizations/${o2}`, { name: "Beta Clinics" })).status).toBe(200);

  // Agents (each registers its host as an asset). Effective health: a3 has been silent for 48 h.
  const agent = async (organizationId: string, hostname: string, status: string, antivirusStatus: string, firewallEnabled: boolean, hoursAgo = 0.1) => {
    const res = await admin.post("/agents", { organizationId, hostname, platform: "windows", version: "4.9.2", engine: "wazuh", status, antivirusStatus, firewallEnabled, lastCheckinAt: new Date(Date.now() - hoursAgo * 3_600_000).toISOString() });
    expect(res.status).toBe(201);
    ids[hostname] = res.body.assetId;
  };
  await agent(o1, "a1", "protected", "protected", true);
  await agent(o1, "a2", "outdated", "unhealthy", true);
  await agent(o1, "a3", "protected", "unmanaged", false, 48);
  await agent(o1, "a4", "isolated", "protected", true);
  await agent(o2, "b1", "protected", "incompatible", false);

  const web = await admin.post("/assets", { organizationId: o1, kind: "server", name: "Internet banking", hostname: "web01", ipAddresses: ["203.0.113.15"], criticality: "high", internetFacing: true });
  const db = await admin.post("/assets", { organizationId: o1, kind: "database", name: "Core ledger", hostname: "db01", ipAddresses: ["10.0.5.20"], criticality: "crown_jewel" });
  ids.web = web.body.id;
  ids.db = db.body.id;

  // Identities: two privileged accounts without MFA (one per org).
  const identity = async (organizationId: string, principal: string, kind: string, privileged: boolean, mfaEnabled: boolean) => {
    const res = await admin.post("/identities", { organizationId, provider: "entra-id", principal, kind, privileged, mfaEnabled });
    expect(res.status).toBe(201);
    ids[principal] = res.body.id;
  };
  await identity(o1, "domain.admin@alpha.example", "user", true, false);
  await identity(o1, "it.lead@alpha.example", "user", true, true);
  await identity(o1, "teller@alpha.example", "user", false, true);
  await identity(o2, "svc-pacs", "service_account", true, false);

  await t.db.withTenant(tenant.tenantId, async (tx) => {
    const inv = t.services.inventory;
    await inv.upsertVulnerability(tx, tenant.tenantId, { assetId: ids.web!, cve: "CVE-2021-44228", title: "Log4Shell", cvss: 10, epss: 0.97, knownExploited: true, patchAvailable: true });
    await inv.upsertVulnerability(tx, tenant.tenantId, { assetId: ids.db!, cve: "CVE-2024-6387", title: "regreSSHion", cvss: 8.1, epss: 0.6, knownExploited: false, patchAvailable: true });
    await inv.upsertVulnerability(tx, tenant.tenantId, { assetId: ids.b1!, cve: "CVE-2019-0708", title: "BlueKeep", cvss: 9.8, epss: 0.97, knownExploited: true, patchAvailable: false, firstSeenAt: new Date(Date.now() - 400 * 86_400_000).toISOString() });
    await inv.setReachability(tx, tenant.tenantId, ids.web!, [ids.db!]);
  });
  t.services.attackPaths.invalidate(tenant.tenantId);

  // Incidents: C1/H1/M1 in o1, L1/H2 in o2 (H2 is closed).
  const incident = async (organizationId: string, title: string, severity: string, extra: Json = {}) => {
    const res = await admin.post("/incidents", { organizationId, title, severity, ...extra });
    expect(res.status).toBe(201);
    return res.body;
  };
  const c1 = await incident(o1, "Ransomware precursor on web01", "critical", { assetIds: [ids.web] });
  const h1 = await incident(o1, "Suspicious admin logon", "high");
  const m1 = await incident(o1, "Privileged account anomaly", "medium", { identityIds: [ids["domain.admin@alpha.example"]] });
  const l1 = await incident(o2, "Policy violation", "low");
  const h2 = await incident(o2, "Phishing click", "high");
  Object.assign(ids, { c1: c1.id, h1: h1.id, m1: m1.id, l1: l1.id, h2: h2.id });

  const lateEsc = await admin.post("/escalations", { incidentId: l1.id, title: "Customer: confirm the change window", severity: "medium", dueInMinutes: 30 });
  await t.privileged.query("UPDATE escalations SET due_at = now() - interval '5 minutes' WHERE id = $1", [lateEsc.body.id]);
  expect((await admin.post("/escalations", { incidentId: h2.id, title: "Customer: reset the clicked user", severity: "high" })).status).toBe(201);
  expect((await admin.patch(`/incidents/${h2.id}`, { status: "closed" })).status).toBe(200);

  // Telemetry: benign activity, posture checks, a network sensor and one real detection.
  const o1Events = [
    processEvent("a1", minutesAgo(40), { path: "C:\\Windows\\explorer.exe", cmd: "explorer.exe" }),
    processEvent("a2", minutesAgo(39), { path: "C:\\Windows\\System32\\svchost.exe", cmd: "svchost.exe -k netsvcs" }),
    dnsEvent("a1", minutesAgo(38), "10.0.0.11", "www.example.com"),
    scaEvent("a1", "CIS-9.1.1", "success"),
    scaEvent("a1", "CIS-18.9.4", "failure"),
    scaEvent("a2", "CIS-9.1.1", "success"),
    processEvent("a1", minutesAgo(15), { path: POWERSHELL, cmd: "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", user: "jdoe" }),
  ];
  const o2Events = [processEvent("b1", minutesAgo(30), { path: "C:\\Windows\\explorer.exe", cmd: "explorer.exe" }), processEvent("b1", minutesAgo(29), { path: "C:\\Windows\\notepad.exe", cmd: "notepad.exe" })];
  expect((await admin.post("/ingest/events", { organizationId: o1, events: o1Events })).body.accepted).toBe(7);
  expect((await admin.post("/ingest/events", { organizationId: o2, events: o2Events })).body.accepted).toBe(2);
  await t.services.bus.drain();

  // The encoded-PowerShell detection is promoted (severity high) to its own incident.
  const promoted = await t.privileged.query<{ id: string }>("SELECT id FROM incidents WHERE tenant_id = $1 AND source = 'correlation'", [tenant.tenantId]);
  expect(promoted.rows).toHaveLength(1);
  ids.p1 = promoted.rows[0]!.id;

  // Deterministic response metrics: MTTD 20/40/30 min → 30, MTTR 60/120 min → 90.
  await t.privileged.query("UPDATE incidents SET first_seen_at = detected_at - interval '20 minutes' WHERE id = $1", [ids.c1]);
  await t.privileged.query("UPDATE incidents SET first_seen_at = detected_at - interval '40 minutes' WHERE id = $1", [ids.h1]);
  await t.privileged.query("UPDATE incidents SET first_seen_at = detected_at - interval '30 minutes' WHERE id = $1", [ids.p1]);
  await t.privileged.query("UPDATE incidents SET contained_at = detected_at + interval '60 minutes' WHERE id = $1", [ids.c1]);
  await t.privileged.query("UPDATE incidents SET closed_at = detected_at + interval '120 minutes' WHERE id = $1", [ids.h2]);

  await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: null }] });
  await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t2", organizationId: o1 }] });
});

afterAll(async () => {
  await t?.close();
});

describe("GET /command-center/summary", () => {
  it("aggregates the whole tenant exactly", async () => {
    const res = await admin.get("/command-center/summary?windowDays=30");
    expect(res.status).toBe(200);
    const s = res.body;
    expect(s).toMatchObject({ organizationId: null, windowDays: 30, organizations: 2 });
    expect(s.activeIncidents).toEqual({ critical: 1, high: 2, medium: 1, low: 1, total: 5, byAssetType: { endpoint: 2, identity: 1 } });
    expect(s.socActions).toEqual({ eventsAnalyzed: 9, signalsGenerated: 1, investigations: 0, incidentsReported: 6 });
    expect(s.escalations).toEqual({ open: 2, overdue: 1, resolved: 1 });
    expect(s.mttdMinutes).toBe(30);
    expect(s.mttrMinutes).toBe(90);
    expect(s.agents).toEqual({ total: 5, protected: 2, unresponsive: 1, outdated: 1, isolated: 1 });
    expect(s.antivirus).toEqual({ protected: 2, unhealthy: 1, unmanaged: 1, incompatible: 1 });
    expect(s.firewall).toEqual({ enabled: 3, disabled: 2 });
    expect(s.vulnerabilities).toEqual({ critical: 2, high: 1, knownExploited: 2, overdueSla: 1 });
    expect(s.identityRisk.privilegedWithoutMfa).toBe(2);
    expect(s.cloudPosture).toMatchObject({ score: 67, failingControls: 1, evaluatedControls: 3 });
    expect(s.networkHealth).toEqual({ sensors: 1, healthy: 1, beaconingHosts: 0 });
    expect(s.intelMatches).toBe(0);
    expect(s.aiActivity).toEqual({ conversations: 0, actionsProposed: 0, actionsApproved: 0 });
    expect(s.automation).toEqual({ runs: 0, succeeded: 0, pendingApproval: 0 });
  });

  it("derives scores from the risk engine with explanations", async () => {
    const s = (await admin.get("/command-center/summary")).body;
    expect(s.exposureScore).toBeGreaterThan(0);
    expect(s.exposureScore).toBeLessThanOrEqual(100);
    expect(s.explanations.exposure.score).toBe(s.exposureScore);
    expect(s.explanations.exposure.factors.length).toBeGreaterThan(0);
    const total = s.explanations.exposure.factors.reduce((sum: number, f: Json) => sum + f.contribution, 0);
    expect(Math.abs(total - s.exposureScore)).toBeLessThan(0.6);

    const scores = await t.privileged.query<{ p90: number | null; risky: number }>(
      "SELECT percentile_cont(0.9) WITHIN GROUP (ORDER BY risk_score) AS p90, count(*) FILTER (WHERE risk_score >= 70)::int AS risky FROM identities WHERE tenant_id = $1 AND enabled AND risk_score IS NOT NULL",
      [tenant.tenantId],
    );
    expect(s.identityRisk.score).toBe(Math.round(Number(scores.rows[0]!.p90)));
    expect(s.identityRisk.riskyIdentities).toBe(scores.rows[0]!.risky);
    expect(s.explanations.identityRisk.topIdentities.length).toBeGreaterThan(0);

    expect(s.attackPaths.total).toBeGreaterThanOrEqual(1);
    expect(s.attackPaths.toCrownJewels).toBeGreaterThanOrEqual(1);
    expect(s.attackPaths.toCrownJewels).toBeLessThanOrEqual(s.attackPaths.total);
    expect(s.recommendations.map((r: Json) => r.id)).toEqual(expect.arrayContaining(["vuln.patch-known-exploited", "ispm.enforce-mfa-privileged", "edr.unresponsive-agents", "command_center.overdue-escalations"]));
    expect(s.recommendations.find((r: Json) => r.id === "vuln.patch-known-exploited").impact).toBe("critical");
  });

  it("orders the triage feed: overdue escalations, then severity", async () => {
    const s = (await admin.get("/command-center/summary")).body;
    expect(s.triage[0]).toMatchObject({ kind: "escalation", status: "overdue", organizationId: o2, organizationName: "Beta Clinics" });
    const incidents = s.triage.filter((i: Json) => i.kind === "incident");
    expect(incidents.map((i: Json) => i.id)).not.toContain(ids.h2);
    expect(incidents[0]).toMatchObject({ id: ids.c1, severity: "critical", title: expect.stringMatching(/^#1 /) });
  });

  it("filters to one organization", async () => {
    const res = await admin.get(`/command-center/summary?organizationId=${o2}&windowDays=7`);
    expect(res.status).toBe(200);
    const s = res.body;
    expect(s).toMatchObject({ organizationId: o2, organizations: 1, windowDays: 7 });
    expect(s.activeIncidents).toMatchObject({ total: 1, low: 1, critical: 0 });
    expect(s.socActions).toMatchObject({ eventsAnalyzed: 2, signalsGenerated: 0, incidentsReported: 2 });
    expect(s.agents).toEqual({ total: 1, protected: 1, unresponsive: 0, outdated: 0, isolated: 0 });
    expect(s.vulnerabilities).toEqual({ critical: 1, high: 0, knownExploited: 1, overdueSla: 1 });
    expect(s.attackPaths).toEqual({ total: 0, toCrownJewels: 0 });
    expect(s.triage.every((i: Json) => i.organizationId === o2)).toBe(true);
  });

  it("validates the window", async () => {
    expect((await admin.get("/command-center/summary?windowDays=0")).status).toBe(400);
    expect((await admin.get("/command-center/summary?organizationId=not-a-uuid")).status).toBe(400);
  });
});

describe("GET /mssp/overview", () => {
  it("aggregates the portfolio per customer organization", async () => {
    const res = await admin.get("/mssp/overview");
    expect(res.status).toBe(200);
    const m = res.body;
    expect(m).toMatchObject({ organizations: 2, activeIncidents: 5, critical: 1, investigations: 0, analysts: 2, agents: 5, eventsPerDay: 9, assets: 7 });
    expect(m.customers.map((c: Json) => c.name)).toEqual(["Alpha Bank", "Beta Clinics"]);
    const [alpha, beta] = m.customers;
    expect(alpha).toMatchObject({ organizationId: o1, plan: "mssp", activeIncidents: 4, critical: 1, agents: 4, unhealthyAgents: 2, slaBreaches: 0, mrr: 1000, assets: 6 });
    expect(beta).toMatchObject({ organizationId: o2, activeIncidents: 1, critical: 0, agents: 1, unhealthyAgents: 0, slaBreaches: 1, overdueEscalations: 1, mrr: 0, assets: 1 });
    for (const c of m.customers) {
      expect(c.riskScore).toBeGreaterThanOrEqual(0);
      expect(c.riskScore).toBeLessThanOrEqual(100);
      expect(c.riskSummary.length).toBeGreaterThan(10);
    }
    expect(alpha.riskScore).toBeGreaterThan(beta.riskScore);
  });
});
