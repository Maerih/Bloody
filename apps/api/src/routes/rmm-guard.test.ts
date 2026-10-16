import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let other: TestTenant;
let admin: ReturnType<typeof api>;
let analyst: ReturnType<typeof api>;
let otherAdmin: ReturnType<typeof api>;
let token: string;
let org: string;

const report = (software: Array<{ name: string; version?: string }>, processes: Array<{ name: string; path?: string }> = []) => ({
  software: software.map((s) => ({ publisher: null, ...s })),
  services: [],
  users: [],
  processes: processes.map((p, i) => ({ pid: 1000 + i, user: "amina", ...p })),
  ports: [],
  antivirus: [],
  firewall: { enabled: true, detail: null },
});
const inventory = (body: object) =>
  t.app.inject({ method: "POST", url: "/api/v1/agent/inventory", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, payload: JSON.stringify(body) });

beforeAll(async () => {
  t = await createTestApp({ deps: { hostResolver: false } });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  other = await createTenant(t, { orgs: 1, plan: "mssp" });
  org = tenant.orgIds[0]!;
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  otherAdmin = api(t.app, { token: (await login(t.app, other.admin.email)).token });
  const a = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: null }] });
  analyst = api(t.app, { token: (await login(t.app, a.email)).token });
  const key = (await admin.get("/agents/enrollment")).body.accountKey;
  const enrolled = await t.app.inject({ method: "POST", url: "/api/v1/agent/enroll", headers: { "content-type": "application/json" }, payload: JSON.stringify({ accountKey: key, organizationKey: "org-1", hostname: "kb-ws-11", platform: "windows", version: "1.1.0" }) });
  token = enrolled.json().token;
});
afterAll(async () => {
  await t?.close();
});

describe("RMM Guard", () => {
  it("finds remote-access tools in host inventory and alerts once per new unapproved tool", async () => {
    const seen: Array<{ subject: { label: string }; data: { tool: { key: string } } }> = [];
    const off = t.services.domainEvents.subscribe("test-rmm", async (e) => {
      if (e.event === "rmm.unapproved_detected") seen.push(e as never);
    });
    const empty = (await admin.get(`/rmm-guard/overview?organizationId=${org}`)).body;
    expect(empty).toMatchObject({ findings: [], approved: [], endpointsWithInventory: 0, appControl: "off" });
    expect(empty.catalog.length).toBeGreaterThan(20);

    const host = report([{ name: "AnyDesk", version: "8.0.14" }, { name: "Google Chrome" }], [{ name: "TeamViewer_Service.exe", path: "C:\\Program Files\\TeamViewer\\TeamViewer_Service.exe" }]);
    expect((await inventory(host)).statusCode).toBe(200);
    expect((await inventory(host)).statusCode).toBe(200);
    await new Promise((r) => setTimeout(r, 50));
    expect(seen.map((e) => e.data.tool.key).sort()).toEqual(["anydesk", "teamviewer"]);
    expect(seen[0]!.subject.label).toMatch(/ on kb-ws-11$/);

    const o = (await admin.get(`/rmm-guard/overview?organizationId=${org}`)).body;
    expect(o.endpointsWithInventory).toBe(1);
    expect(o.findings).toHaveLength(2);
    const anydesk = o.findings.find((f: { tool: { key: string } }) => f.tool.key === "anydesk");
    expect(anydesk).toMatchObject({ approved: false, endpoints: [{ hostname: "kb-ws-11", evidence: [{ kind: "software", value: "AnyDesk 8.0.14" }] }] });
    // Analysts can look; other accounts cannot.
    expect((await analyst.get(`/rmm-guard/overview?organizationId=${org}`)).status).toBe(200);
    expect((await otherAdmin.get(`/rmm-guard/overview?organizationId=${org}`)).status).toBe(404);
    off();
  });

  it("approving a tool marks it approved and stops alerts for it", async () => {
    expect((await analyst.put(`/rmm-guard/settings/${org}`, { approved: ["anydesk"] })).status).toBe(403);
    expect((await otherAdmin.put(`/rmm-guard/settings/${org}`, { approved: ["anydesk"] })).status).toBe(404);
    const saved = await admin.put(`/rmm-guard/settings/${org}`, { approved: ["anydesk", "anydesk", "not_a_tool"] });
    expect(saved.body).toEqual({ approved: ["anydesk"] });
    const o = (await admin.get(`/rmm-guard/overview?organizationId=${org}`)).body;
    expect(o.findings.map((f: { tool: { key: string }; approved: boolean }) => [f.tool.key, f.approved])).toEqual([["teamviewer", false], ["anydesk", true]]);
  });

  it("blocks unapproved tools through App Control rules, skipping duplicates", async () => {
    expect((await analyst.post("/rmm-guard/block", { organizationId: org, tools: ["teamviewer"] })).status).toBe(403);
    expect((await admin.post("/rmm-guard/block", { organizationId: org, tools: ["anydesk"] })).status).toBe(409);
    expect((await admin.post("/rmm-guard/block", { organizationId: org, tools: ["bogus_tool"] })).status).toBe(400);
    const first = await admin.post("/rmm-guard/block", { organizationId: org, tools: ["teamviewer"] });
    expect(first.status).toBe(200);
    expect(first.body).toMatchObject({ created: 5, skipped: 0, appControl: "off" });
    expect((await admin.post("/rmm-guard/block", { organizationId: org, tools: ["teamviewer"] })).body).toMatchObject({ created: 0, skipped: 5 });
    const rules = (await admin.get(`/app-control/overview?organizationId=${org}`)).body.rules;
    expect(rules).toHaveLength(5);
    expect(rules.every((r: { action: string; note: string }) => r.action === "block" && r.note === "RMM Guard: TeamViewer")).toBe(true);
    expect(rules.find((r: { value: string }) => r.value === "teamviewerd")).toMatchObject({ platform: "any" });
    const audit = await t.privileged.query("SELECT action FROM audit_log WHERE tenant_id = $1 AND action LIKE 'rmm_guard.%' ORDER BY seq", [tenant.tenantId]);
    expect(audit.rows.map((r) => r.action)).toEqual(["rmm_guard.approved_changed", "rmm_guard.blocked", "rmm_guard.blocked"]);
  });
});
