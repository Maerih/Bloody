import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let org: string;
let requester: ReturnType<typeof api>;
let approver: ReturnType<typeof api>;

let token: string;
let assetId: string;

const agentCall = (url: string, body: object) =>
  t.app.inject({ method: "POST", url: `/api/v1${url}`, headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, payload: JSON.stringify(body) });
const harden = (who: ReturnType<typeof api>, check: string) =>
  who.post("/response/actions", { action: "harden_endpoint", organizationId: org, target: { kind: "asset", id: assetId }, parameters: { check }, reason: "Close the SMBv1 gap found by Attack Reduction" });

beforeAll(async () => {
  t = await createTestApp({ deps: { hostResolver: false } });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  org = tenant.orgIds[0]!;
  const admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const r = await createUser(t, tenant.tenantId, { roles: [{ role: "incident_responder", organizationId: null }], displayName: "Responder A" });
  const a = await createUser(t, tenant.tenantId, { roles: [{ role: "incident_responder", organizationId: null }], displayName: "Responder B" });
  requester = api(t.app, { token: (await login(t.app, r.email)).token });
  approver = api(t.app, { token: (await login(t.app, a.email)).token });
  const key = (await admin.get("/agents/enrollment")).body.accountKey;
  const enrolled = await t.app.inject({ method: "POST", url: "/api/v1/agent/enroll", headers: { "content-type": "application/json" }, payload: JSON.stringify({ accountKey: key, organizationKey: "org-1", hostname: "kb-ws-51", platform: "windows", version: "1.2.0" }) });
  token = enrolled.json().token;
  await agentCall("/agent/heartbeat", { hostname: "kb-ws-51", version: "1.2.0" });
  assetId = (await t.privileged.query("SELECT asset_id FROM agents WHERE hostname = 'kb-ws-51'")).rows[0].asset_id;
});
afterAll(async () => {
  await t?.close();
});

describe("harden_endpoint: the SCIAT Agent applies an Attack Reduction fix", () => {
  it("only accepts fixes the agent can apply on that platform", async () => {
    expect((await harden(requester, "win_bitlocker")).status).toBe(400);
    expect((await harden(requester, "linux_aslr")).status).toBe(400);
    expect((await harden(requester, "nonsense")).status).toBe(400);
  });

  it("needs approval, then goes to the agent as a built-in fix and completes from its result", async () => {
    const created = await harden(requester, "win_smb1");
    expect(created.status).toBeLessThan(300);
    expect(created.body).toMatchObject({ action: "harden_endpoint", status: "pending_approval", parameters: { check: "win_smb1" } });
    // Nothing reaches the endpoint before approval.
    expect((await agentCall("/agent/heartbeat", { hostname: "kb-ws-51", version: "1.2.0" })).json().commands).toEqual([]);

    const approved = await approver.post(`/response/actions/${created.body.id}/approve`, { comment: "ok" });
    expect(approved.status).toBe(200);
    expect(approved.body).toMatchObject({ status: "running" });

    const hb = (await agentCall("/agent/heartbeat", { hostname: "kb-ws-51", version: "1.2.0" })).json();
    expect(hb.commands).toHaveLength(1);
    expect(hb.commands[0]).toMatchObject({ kind: "harden", args: ["harden", "win_smb1"] });
    expect(hb.commandLines[0]).toBe(`${hb.commands[0].id} harden win_smb1`);

    expect((await agentCall(`/agent/commands/${hb.commands[0].id}/result`, { status: "succeeded", output: "SMBv1 server disabled" })).statusCode).toBe(200);
    const done = (await requester.get(`/response/actions/${created.body.id}`)).body;
    expect(done).toMatchObject({ status: "succeeded" });
    expect(JSON.stringify(done)).toContain("Hardening applied by the SCIAT Agent: SMBv1 is disabled");
    const audit = await t.privileged.query("SELECT outcome FROM audit_log WHERE tenant_id = $1 AND action = 'response.harden_endpoint'", [tenant.tenantId]);
    expect(audit.rows.map((r) => r.outcome)).toEqual(["success"]);
  });
});
