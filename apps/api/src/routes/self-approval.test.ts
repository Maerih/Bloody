import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let admin: ReturnType<typeof api>;
let assetId: string;

const json = (method: "POST", url: string, body: object, token?: string) =>
  t.app.inject({ method, url: `/api/v1${url}`, headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, payload: JSON.stringify(body) });

beforeAll(async () => {
  t = await createTestApp({ deps: { hostResolver: false } });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const key = (await admin.get("/agents/enrollment")).body.accountKey;
  const enrolled = (await json("POST", "/agent/enroll", { accountKey: key, organizationKey: "org-1", hostname: "solo-ws", platform: "linux", version: "1.1.0" })).json();
  await json("POST", "/agent/heartbeat", { hostname: "solo-ws", version: "1.1.0", platformIps: ["10.1.1.1"] }, enrolled.token);
  assetId = (await t.privileged.query("SELECT asset_id FROM agents WHERE hostname = 'solo-ws'")).rows[0].asset_id;
});
afterAll(async () => {
  await t?.close();
});

const request = () =>
  admin.post("/response/actions", { action: "isolate_endpoint", organizationId: tenant.orgIds[0], target: { kind: "asset", id: assetId, label: "solo-ws" }, parameters: { mode: "lan" }, reason: "Suspicious PowerShell" });

describe("sole approver", () => {
  it("lets the only approver approve their own isolation with a justification, audited", async () => {
    const req = await request();
    expect(req.body.status).toBe("pending_approval");
    expect((await admin.get(`/response/approvers?organizationId=${tenant.orgIds[0]}`)).body).toMatchObject({ others: 0, selfApprovalAllowed: true, minJustification: 20 });
    const short = await admin.post(`/response/actions/${req.body.id}/approve`, { comment: "ok" });
    expect(short.status).toBe(400);
    expect(short.body.error.code).toBe("justification_required");
    const ok = await admin.post(`/response/actions/${req.body.id}/approve`, { comment: "Only analyst on duty, host beaconing to C2" });
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ status: "running", executor: "sciat:agent" });
    const audit = await t.privileged.query("SELECT details FROM audit_log WHERE tenant_id = $1 AND action = 'response.self_approved'", [tenant.tenantId]);
    expect(audit.rows).toHaveLength(1);
    expect(audit.rows[0].details).toMatchObject({ comment: "Only analyst on duty, host beaconing to C2" });
  });

  it("restores four-eyes as soon as someone else can approve", async () => {
    await createUser(t, tenant.tenantId, { roles: [{ role: "incident_responder", organizationId: null }] });
    expect((await admin.get(`/response/approvers?organizationId=${tenant.orgIds[0]}`)).body).toMatchObject({ others: 1, selfApprovalAllowed: false });
    const req = await request();
    const res = await admin.post(`/response/actions/${req.body.id}/approve`, { comment: "Only analyst on duty, host beaconing to C2" });
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe("self_approval");
  });
});
