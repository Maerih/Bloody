import { CreateOrganizationInput, IncidentStatus, RiskFactor, UpsertAssetInput } from "@bloody/contracts";
import { describe, expect, it } from "vitest";
import { AdapterSignal } from "../core/signals.js";
import { assertSchemaValid, ctx, fixtureJson, TENANT_ID } from "../test-support/fixtures.js";
import { mockFetch, testResolver, type Route } from "../test-support/http.js";
import { CoPilotClient } from "./client.js";
import { createCoPilotAlertAdapter } from "./events.js";
import { CoPilotSync, mapAgentStatus, planCoPilotSync, slugFromCustomerCode, versionBelow, type CoPilotSyncPlan } from "./sync.js";

const NOW = () => new Date("2026-10-07T12:00:00.000Z");
const userCustomers = fixtureJson<Record<string, string[]>>("copilot/user-customers.json");

function mainPortalRoutes(): Route[] {
  return [
    { method: "POST", path: "/api/auth/token", json: { access_token: "copilot-jwt-0123456789", token_type: "bearer" } },
    { method: "GET", path: "/api/auth/me/customers", json: { success: true, customer_codes: ["*"], scope: "deployment" } },
    { method: "GET", path: "/api/customers", json: fixtureJson("copilot/customers.json") },
    { method: "GET", path: "/api/agents", json: fixtureJson("copilot/agents.json") },
    { method: "GET", path: "/api/incidents/db_operations/alerts", json: fixtureJson("copilot/alerts.json") },
    { method: "GET", path: "/api/incidents/db_operations/cases", json: fixtureJson("copilot/cases.json") },
    { method: "GET", path: "/api/auth/users", json: fixtureJson("copilot/users.json") },
    {
      method: "GET",
      path: /^\/api\/auth\/users\/\d+\/customers$/,
      respond: (call) => ({ success: true, customer_codes: userCustomers[call.url.pathname.split("/")[4] ?? ""] ?? [] }),
    },
  ];
}

async function runMainSync(): Promise<{ plan: CoPilotSyncPlan; calls: ReturnType<typeof mockFetch>["calls"] }> {
  const { fetch, calls } = mockFetch(mainPortalRoutes());
  const client = new CoPilotClient({ baseUrl: "https://copilot.mssp.example", username: "bloody-sync", password: "s3cret-pass", fetch, resolveHost: testResolver });
  const { plan } = await new CoPilotSync(client, { tenantId: TENANT_ID, integrationId: "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d", minWazuhVersion: "4.7.0", snapshot: { now: NOW } }).run();
  return { plan, calls };
}

describe("CoPilotClient (REST API only)", () => {
  it("authenticates with the OAuth2 password form and uses the bearer token for reads", async () => {
    const { calls } = await runMainSync();
    const login = calls.find((c) => c.url.pathname === "/api/auth/token");
    expect(login?.method).toBe("POST");
    expect(login?.headers["content-type"]).toBe("application/x-www-form-urlencoded");
    expect(new URLSearchParams(login?.body ?? "").get("username")).toBe("bloody-sync");
    expect(login?.headers["authorization"]).toBeUndefined();
    const reads = calls.filter((c) => c.method === "GET");
    expect(reads.every((c) => c.headers["authorization"] === "Bearer copilot-jwt-0123456789")).toBe(true);
    expect(calls.filter((c) => c.url.pathname === "/api/auth/token")).toHaveLength(1);
    expect(calls.every((c) => c.method === "GET" || c.url.pathname === "/api/auth/token")).toBe(true);
    const alerts = calls.find((c) => c.url.pathname === "/api/incidents/db_operations/alerts");
    expect(alerts?.url.searchParams.get("page")).toBe("1");
    expect(alerts?.url.searchParams.get("page_size")).toBe("200");
  });

  it("refuses accounts that need interactive 2FA", async () => {
    const { fetch } = mockFetch([{ method: "POST", path: "/api/auth/token", json: { access_token: "temp-token-0123456789", token_type: "bearer", requires_2fa: true } }]);
    const client = new CoPilotClient({ baseUrl: "https://copilot.mssp.example", username: "u", password: "p", fetch, resolveHost: testResolver });
    await expect(client.listCustomers()).rejects.toThrow(/2FA/);
  });
});

describe("CoPilotSync plan (MSSP / main portal)", () => {
  it("customers → organizations: parents first, contract-valid slugs, missing parents reported", async () => {
    const { plan } = await runMainSync();
    expect(plan.planVersion).toBe(1);
    expect(plan.tenantId).toBe(TENANT_ID);
    expect(plan.source).toMatchObject({ engine: "copilot", portal: "main", fetchedAt: "2026-10-07T12:00:00.000Z", integrationId: "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d" });
    expect(plan.organizations.map((o) => [o.externalRef, o.data.slug, o.parentExternalRef])).toEqual([
      ["copilot:customer:ACME", "acme", null],
      ["copilot:customer:ACME_EU", "acme-eu", "copilot:customer:ACME"],
      ["copilot:customer:GLOBEX", "globex", null],
      ["copilot:customer:ORPHAN", "orphan", null],
    ]);
    for (const o of plan.organizations) expect(CreateOrganizationInput.safeParse(o.data).success).toBe(true);
    expect(plan.organizations[0]).toMatchObject({ data: { name: "Acme Corporation", retentionDays: 90 }, contact: { name: "Jane Doe", phone: "+1-555-0100", country: "US" }, organizationId: null });
    expect(plan.warnings.map((w) => w.code)).toContain("missing_parent");
  });

  it("agents → assets + agents with status mapping, criticality and tenant-scope enforcement", async () => {
    const { plan } = await runMainSync();
    const agent = (id: string) => plan.agents.find((a) => a.externalRef === `copilot:agent:${id}`);
    const asset = (id: string) => plan.assets.find((a) => a.externalRef === `copilot:asset:${id}`);
    expect(plan.agents).toHaveLength(5);
    expect(agent("001")).toMatchObject({ organizationRef: "copilot:customer:ACME", assetRef: "copilot:asset:001", data: { platform: "windows", status: "protected", engine: "wazuh+velociraptor" } });
    expect(agent("002")?.data.status).toBe("unresponsive");
    expect(agent("003")).toMatchObject({ data: { status: "isolated" }, statusReason: "agent is quarantined in CoPilot" });
    expect(agent("004")?.data.status).toBe("outdated");
    expect(agent("005")).toMatchObject({ data: { status: "pending", platform: "macos", lastCheckinAt: null } });
    expect(agent("001")?.data).not.toHaveProperty("firewallEnabled");
    expect(asset("001")?.data).toMatchObject({ kind: "domain_controller", criticality: "crown_jewel", ipAddresses: ["10.10.0.5"] });
    expect(asset("003")?.data.kind).toBe("server");
    expect(asset("004")?.data.criticality).toBe("crown_jewel");
    expect(asset("001")?.explanation.join(" ")).toContain("critical asset");
    for (const a of plan.assets) expect(UpsertAssetInput.safeParse(a.data).success).toBe(true);
    expect(plan.agents.some((a) => a.externalRef === "copilot:agent:006")).toBe(false);
    expect(plan.warnings.some((w) => w.code === "unknown_customer" && w.ref === "copilot:agent:006")).toBe(true);
  });

  it("alerts → alerts with explainable risk, status/verdict mapping and asset links", async () => {
    const { plan } = await runMainSync();
    const alert = (id: number) => plan.alerts.find((a) => a.externalRef === `copilot:alert:${id}`);
    expect(plan.alerts).toHaveLength(4);
    const mimikatz = alert(101);
    expect(mimikatz).toMatchObject({
      organizationRef: "copilot:customer:ACME",
      assetRefs: ["copilot:asset:001"],
      incidentRef: "copilot:case:900",
      assignee: "analyst1",
      escalated: true,
      data: { severity: "critical", status: "promoted", riskScore: 100, source: "copilot:wazuh", firstSeenAt: "2026-10-07T09:00:00.000Z", lastSeenAt: "2026-10-07T09:20:00.000Z" },
    });
    expect(mimikatz?.riskFactors.map((f) => f.key)).toEqual(["severity", "escalated", "critical_asset"]);
    for (const f of mimikatz?.riskFactors ?? []) expect(RiskFactor.safeParse(f).success).toBe(true);
    expect(mimikatz?.data.attack).toEqual([{ id: "T1003.001", name: "LSASS Memory", tactic: "Credential Access" }]);
    expect(mimikatz?.indicators.map((i) => i.type).sort()).toEqual(["ip", "sha256"]);
    expect(alert(102)?.data.status).toBe("triaged");
    expect(alert(103)).toMatchObject({ verdict: "false_positive", data: { status: "false_positive", riskScore: 0, confidence: 0.05 } });
    expect(alert(104)).toMatchObject({ assetRefs: [], assetHints: ["unknown-laptop"], data: { severity: "high", source: "copilot:office365" } });
    expect(alert(104)?.explanation.join(" ")).toContain("no CoPilot severity");
    expect(alert(105)).toBeUndefined();
  });

  it("cases → incidents; PENDING_CUSTOMER and escalations → escalations", async () => {
    const { plan } = await runMainSync();
    const inc = (id: number) => plan.incidents.find((i) => i.externalRef === `copilot:case:${id}`);
    expect(inc(900)).toMatchObject({
      alertRefs: ["copilot:alert:101"],
      assetRefs: ["copilot:asset:001"],
      data: { severity: "critical", status: "investigating", riskScore: 100, detectedAt: "2026-10-07T09:10:00.000Z", closedAt: null },
    });
    expect(inc(901)).toMatchObject({ data: { severity: "medium", status: "investigating" } });
    expect(inc(902)).toMatchObject({ data: { status: "false_positive", closedAt: "2026-10-07T10:00:00.000Z", riskScore: 0 } });
    for (const i of plan.incidents) {
      expect(IncidentStatus.safeParse(i.data.status).success).toBe(true);
      expect(i.data.title.length).toBeGreaterThanOrEqual(3);
    }
    expect(plan.escalations.map((e) => [e.externalRef, e.kind, e.data.status, e.data.dueAt])).toEqual([
      ["copilot:escalation:case:900", "soc_escalation", "open", "2026-10-07T13:10:00.000Z"],
      ["copilot:escalation:case:901", "customer_action", "open", "2026-10-09T15:00:00.000Z"],
      ["copilot:escalation:alert:102", "customer_action", "open", "2026-10-08T08:00:00.000Z"],
    ]);
  });

  it("customer-portal users → customer_viewer bindings only; staff and wildcard users never mapped", async () => {
    const { plan } = await runMainSync();
    expect(plan.roleBindings.map((b) => [b.user.username, b.organizationRef, b.role])).toEqual([
      ["jane.ciso", "copilot:customer:ACME", "customer_viewer"],
      ["jane.ciso", "copilot:customer:ACME_EU", "customer_viewer"],
      ["max.it", "copilot:customer:ACME_EU", "customer_viewer"],
    ]);
    expect(plan.roleBindings[0]?.externalRef).toBe("copilot:binding:7:ACME");
    const codes = plan.warnings.map((w) => w.code);
    expect(codes).toEqual(expect.arrayContaining(["wildcard_customer_user", "staff_users_not_mapped"]));
  });

  it("emits automation signals for SOC, MSSP and customer audiences (emails/chat)", async () => {
    const { plan } = await runMainSync();
    for (const s of plan.signals) expect(AdapterSignal.safeParse(s).success).toBe(true);
    expect(plan.signals.map((s) => s.event).sort()).toEqual([
      "agent.unresponsive",
      "agent.unresponsive",
      "escalation.created",
      "escalation.created",
      "escalation.created",
      "incident.created",
      "incident.created",
    ]);
    const customerAction = plan.signals.find((s) => s.dedupKey === "copilot:escalation:alert:102");
    expect(customerAction).toMatchObject({ title: "Action required: Suspicious PowerShell download cradle", audience: ["customer", "soc"], emit: "on_create" });
    const dcIncident = plan.signals.find((s) => s.dedupKey === "copilot-case:900");
    expect(dcIncident?.audience).toEqual(["soc", "customer"]);
    expect(plan.signals.find((s) => s.dedupKey === "copilot-case:901")?.audience).toEqual(["soc"]);
    const offline = plan.signals.find((s) => s.subject.ref === "copilot:agent:002");
    expect(offline).toMatchObject({ title: "acme-ws-17 stopped reporting", emit: "on_change", facts: { hostname: "acme-ws-17", status: "unresponsive" } });
  });

  it("builds a sync report per organization for MSSP portfolio and customer reports", async () => {
    const { plan } = await runMainSync();
    expect(plan.report.totals).toMatchObject({ organizations: 4, agents: 5, alerts: 4, incidents: 3, escalations: 3, roleBindings: 3 });
    expect(plan.report.agents).toEqual({ protected: 1, unresponsive: 1, outdated: 1, isolated: 1, pending: 1 });
    const acme = plan.report.perOrganization.find((o) => o.organizationRef === "copilot:customer:ACME");
    expect(acme).toMatchObject({ coverage: 0.333, criticalAssets: 1, openAlerts: 1, openIncidents: 1, awaitingCustomer: 1 });
    expect(acme?.headline).toBe("Acme Corporation: 3 agents (33% healthy), 1 open alert (1 high/critical), 1 open incident, 1 awaiting customer action");
    expect(plan.report.headline).toContain("4 customers, 5 agents (2 need attention)");
  });
});

describe("CoPilotSync (customer side / customer portal)", () => {
  it("logs in through the customer portal and maps onto the customer's existing organization", async () => {
    const globexOnly = (key: "agents" | "alerts" | "cases") => {
      const data = fixtureJson<Record<string, Array<{ customer_code?: string | null }>>>(`copilot/${key}.json`);
      return { ...data, [key]: (data[key] ?? []).filter((x) => x.customer_code === "GLOBEX") };
    };
    const { fetch, calls } = mockFetch([
      { method: "POST", path: "/api/auth/token/customer-portal", json: { access_token: "portal-jwt-0123456789", token_type: "bearer" } },
      { method: "GET", path: "/api/auth/me/customers", json: { success: true, customer_codes: ["GLOBEX"], scope: "assigned" } },
      { method: "GET", path: "/api/agents", json: globexOnly("agents") },
      { method: "GET", path: "/api/incidents/db_operations/alerts", json: globexOnly("alerts") },
      { method: "GET", path: "/api/incidents/db_operations/cases", json: globexOnly("cases") },
    ]);
    const client = new CoPilotClient({ baseUrl: "https://copilot.mssp.example", username: "it@globex", password: "pw", portal: "customer", fetch, resolveHost: testResolver });
    const orgId = "3c2b1a09-8f7e-4d6c-9b5a-4f3e2d1c0b0a";
    const { plan } = await new CoPilotSync(client, { tenantId: TENANT_ID, organizationOverrides: { GLOBEX: orgId }, snapshot: { now: NOW } }).run();
    expect(calls.some((c) => c.url.pathname === "/api/customers" || c.url.pathname === "/api/auth/users")).toBe(false);
    expect(calls.find((c) => c.url.pathname === "/api/agents")?.url.searchParams.getAll("customer_codes")).toEqual(["GLOBEX"]);
    expect(plan.source.portal).toBe("customer");
    expect(plan.organizations).toEqual([expect.objectContaining({ externalRef: "copilot:customer:GLOBEX", organizationId: orgId })]);
    expect(plan.agents.map((a) => a.externalRef)).toEqual(["copilot:agent:005"]);
    expect(plan.alerts.map((a) => a.externalRef)).toEqual(["copilot:alert:104"]);
    expect(plan.incidents.map((i) => i.externalRef)).toEqual(["copilot:case:901"]);
    expect(plan.roleBindings).toEqual([]);
  });
});

describe("CoPilot helpers and alert adapter", () => {
  it("slugs, versions and stale-agent detection", () => {
    const taken = new Set<string>();
    expect(slugFromCustomerCode("ACME_EU", taken)).toBe("acme-eu");
    expect(slugFromCustomerCode("acme-eu", taken)).toMatch(/^acme-eu-[0-9a-f]{6}$/);
    expect(slugFromCustomerCode("X")).toBe("x-cust");
    expect(versionBelow("Wazuh v4.5.2", "4.7.0")).toBe(true);
    expect(versionBelow("v4.9.0", "4.7.0")).toBe(false);
    const stale = mapAgentStatus({ agent_id: "1", wazuh_agent_status: "active", wazuh_last_seen: "2026-10-05T00:00:00" }, NOW(), { staleAfterHours: 24 });
    expect(stale.status).toBe("unresponsive");
    expect(stale.reason).toContain("60 h ago");
  });

  it("plans are pure: the same snapshot yields the same plan", () => {
    const snapshot = {
      fetchedAt: "2026-10-07T12:00:00.000Z",
      baseUrl: "https://copilot.mssp.example/",
      portal: "main" as const,
      scope: "*" as const,
      customers: fixtureJson<{ customers: never[] }>("copilot/customers.json").customers,
      agents: fixtureJson<{ agents: never[] }>("copilot/agents.json").agents,
      alerts: [],
      cases: [],
      users: [],
      warnings: [],
    };
    expect(planCoPilotSync(snapshot, { tenantId: TENANT_ID })).toEqual(planCoPilotSync(snapshot, { tenantId: TENANT_ID }));
  });

  it("CoPilot alerts can also be ingested as canonical detection events", () => {
    const alerts = fixtureJson<{ alerts: unknown[] }>("copilot/alerts.json").alerts;
    const events = createCoPilotAlertAdapter().normalize(alerts, ctx());
    expect(events).toHaveLength(5);
    assertSchemaValid(events);
    expect(events[0]).toMatchObject({ category: "detection", eventType: "copilot.alert.wazuh", severity: "critical", asset: { hostname: "acme-dc01", agentId: "001" } });
    expect(events[3]?.severity).toBe("high");
  });
});
