import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type Json, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let other: TestTenant;
let admin: ReturnType<typeof api>;
let analyst: ReturnType<typeof api>;
let otherAdmin: ReturnType<typeof api>;
let token: string;
let org: string;

const agentCall = (method: "GET" | "POST", url: string, body?: object) =>
  t.app.inject({ method, url: `/api/v1${url}`, headers: { authorization: `Bearer ${token}`, ...(body ? { "content-type": "application/json" } : {}) }, ...(body ? { payload: JSON.stringify(body) } : {}) });

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
  const enrolled = await t.app.inject({ method: "POST", url: "/api/v1/agent/enroll", headers: { "content-type": "application/json" }, payload: JSON.stringify({ accountKey: key, organizationKey: "org-1", hostname: "kb-ws-09", platform: "windows", version: "1.1.0" }) });
  token = enrolled.json().token;
});
afterAll(async () => {
  await t?.close();
});

describe("App Control", () => {
  let blockId: string;

  it("starts off; admins set the mode and add rules, with guard rails", async () => {
    const o = (await admin.get(`/app-control/overview?organizationId=${org}`)).body;
    expect(o).toMatchObject({ mode: "off", rules: [], stats: { agents: 1, blocked24h: 0 } });
    expect((await admin.put(`/app-control/settings/${org}`, { mode: "audit" })).body).toMatchObject({ mode: "audit" });
    const block = await admin.post("/app-control/rules", { organizationId: org, action: "block", kind: "name", value: "AnyDesk.exe", note: "Unapproved remote access" });
    expect(block.status).toBe(201);
    blockId = block.body.id;
    expect((await admin.post("/app-control/rules", { organizationId: org, action: "block", kind: "name", value: "anydesk.exe" })).status).toBe(409);
    expect((await admin.post("/app-control/rules", { organizationId: null, action: "allow", kind: "path", value: "C:\\Program Files\\Helpdesk\\*" })).status).toBe(201);
    const core = await admin.post("/app-control/rules", { organizationId: org, action: "block", kind: "name", value: "lsass.exe" });
    expect(core.status).toBe(400);
    expect((await analyst.post("/app-control/rules", { organizationId: org, action: "block", kind: "name", value: "x.exe" })).status).toBe(403);
    expect((await analyst.put(`/app-control/settings/${org}`, { mode: "enforce" })).status).toBe(403);
    // Another account cannot touch this organization.
    expect((await otherAdmin.put(`/app-control/settings/${org}`, { mode: "enforce" })).status).toBe(404);
    expect((await otherAdmin.post("/app-control/rules", { organizationId: org, action: "block", kind: "name", value: "y.exe" })).status).toBe(404);
    const audit = await t.privileged.query("SELECT action FROM audit_log WHERE tenant_id = $1 AND action LIKE 'app_control.%' ORDER BY seq", [tenant.tenantId]);
    expect(audit.rows.map((r) => r.action)).toEqual(["app_control.mode_changed", "app_control.rule_added", "app_control.rule_added"]);
  });

  it("hands the agent its policy, re-announced through the heartbeat etag", async () => {
    const hb1 = (await agentCall("POST", "/agent/heartbeat", { hostname: "kb-ws-09", version: "1.1.0" })).json();
    const lines = (await agentCall("GET", "/agent/app-control?format=lines")).body;
    expect(lines).toContain(`etag ${hb1.appControlEtag}\nmode audit\n`);
    expect(lines).toContain(`rule ${blockId} block name any AnyDesk.exe`);
    expect(lines).toContain("allow path any C:\\Program Files\\Helpdesk\\*");
    const json = (await agentCall("GET", "/agent/app-control")).json();
    expect(json.rules).toHaveLength(2);
    await admin.put(`/app-control/settings/${org}`, { mode: "enforce" });
    const hb2 = (await agentCall("POST", "/agent/heartbeat", { hostname: "kb-ws-09", version: "1.1.0" })).json();
    expect(hb2.appControlEtag).not.toBe(hb1.appControlEtag);
    // Off: no rules are sent at all.
    await admin.put(`/app-control/settings/${org}`, { mode: "off" });
    expect((await agentCall("GET", "/agent/app-control")).json()).toMatchObject({ mode: "off", rules: [] });
    await admin.put(`/app-control/settings/${org}`, { mode: "enforce" });
  });

  it("lists programs seen on endpoints with what the policy does to them", async () => {
    await agentCall("POST", "/agent/inventory", {
      processes: [
        { pid: 10, name: "AnyDesk.exe", path: "C:\\Users\\amina\\Downloads\\AnyDesk.exe" },
        { pid: 11, name: "anydesk.exe", path: "C:\\Program Files\\Helpdesk\\anydesk.exe" },
        { pid: 12, name: "chrome.exe", path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" },
        { pid: 13, name: "System" },
      ],
    });
    const items = (await admin.get(`/app-control/inventory?organizationId=${org}`)).body.items as Json[];
    const verdict = (path: string) => items.find((i) => i.path === path)?.verdict;
    expect(items).toHaveLength(3); // processes without a path are not programs
    expect(verdict("C:\\Users\\amina\\Downloads\\AnyDesk.exe")).toBe("blocked");
    expect(verdict("C:\\Program Files\\Helpdesk\\anydesk.exe")).toBe("allowed");
    expect(verdict("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")).toBe("none");
    expect((await admin.get(`/app-control/inventory?organizationId=${org}&q=chrome`)).body.items).toHaveLength(1);
  });

  it("records what the agent blocked and shows it as activity", async () => {
    const res = await agentCall("POST", "/agent/app-control/events", {
      events: [{ name: "AnyDesk.exe", path: "C:\\Users\\amina\\Downloads\\AnyDesk.exe", ruleId: blockId, verdict: "blocked", occurredAt: new Date().toISOString() }],
    });
    expect(res.json()).toEqual({ stored: 1 });
    const events = (await admin.get(`/app-control/events?organizationId=${org}`)).body.items;
    expect(events[0]).toMatchObject({ hostname: "kb-ws-09", name: "AnyDesk.exe", verdict: "blocked", ruleId: blockId });
    expect((await admin.get(`/app-control/overview?organizationId=${org}`)).body.stats).toMatchObject({ blocked24h: 1, programs: 3 });
    expect((await otherAdmin.get(`/app-control/events?organizationId=${org}`)).status).toBe(404);
  });

  it("removes rules (events keep their history)", async () => {
    expect((await admin.delete(`/app-control/rules/${blockId}`)).status).toBe(204);
    expect((await admin.get(`/app-control/overview?organizationId=${org}`)).body.rules).toHaveLength(1);
    expect((await admin.get(`/app-control/events?organizationId=${org}`)).body.items[0].ruleId).toBeNull();
  });
});
