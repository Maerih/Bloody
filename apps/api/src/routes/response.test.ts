import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type Json, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let org: string;
let requester: ReturnType<typeof api>;
let approver: ReturnType<typeof api>;
let viewer: ReturnType<typeof api>;
let other: ReturnType<typeof api>;
let assetId: string;

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 1 });
  org = tenant.orgIds[0]!;
  const r = await createUser(t, tenant.tenantId, { roles: [{ role: "incident_responder", organizationId: null }], displayName: "Responder A" });
  const a = await createUser(t, tenant.tenantId, { roles: [{ role: "incident_responder", organizationId: null }], displayName: "Responder B" });
  const v = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: null }], displayName: "Tier One" });
  requester = api(t.app, { token: (await login(t.app, r.email)).token });
  approver = api(t.app, { token: (await login(t.app, a.email)).token });
  viewer = api(t.app, { token: (await login(t.app, v.email)).token });
  const admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const asset = await admin.post("/assets", { organizationId: org, kind: "endpoint", name: "ws-finance-07", hostname: "ws-finance-07", criticality: "high" });
  expect(asset.status).toBe(201);
  assetId = asset.body.id;
  const otherTenant = await createTenant(t, { orgs: 1 });
  other = api(t.app, { token: (await login(t.app, otherTenant.admin.email)).token });
});
afterAll(async () => {
  await t?.close();
});

const isolate = () => ({
  action: "isolate_endpoint",
  organizationId: org,
  target: { kind: "asset", id: assetId, label: "ws-finance-07" },
  reason: "Confirmed credential theft on this host",
});

describe("response actions & approval gate", () => {
  it("always holds high-risk actions for approval", async () => {
    const res = await requester.post("/response/actions", isolate());
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ action: "isolate_endpoint", status: "pending_approval" });
  });

  it("refuses self-approval and lets a different responder approve", async () => {
    const created = (await requester.post("/response/actions", isolate())).body as Json;
    const self = await requester.post(`/response/actions/${created.id}/approve`, { comment: "lgtm" });
    expect(self.status).toBeGreaterThanOrEqual(400);
    expect((await requester.get(`/response/actions/${created.id}`)).body.status).toBe("pending_approval");

    const ok = await approver.post(`/response/actions/${created.id}/approve`, { comment: "approved" });
    expect(ok.status).toBe(200);
    expect(ok.body.status).not.toBe("pending_approval");
    expect(ok.body.approvedBy).toBeTruthy();
  });

  it("lets an approver reject, and the action never executes", async () => {
    const created = (await requester.post("/response/actions", isolate())).body as Json;
    const res = await approver.post(`/response/actions/${created.id}/reject`, { comment: "not enough evidence" });
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("rejected");
  });

  it("denies approval to roles without response:approve", async () => {
    const created = (await requester.post("/response/actions", isolate())).body as Json;
    expect((await viewer.post(`/response/actions/${created.id}/approve`, {})).status).toBe(403);
  });

  it("lists pending approvals in the unified queue", async () => {
    const created = (await requester.post("/response/actions", isolate())).body as Json;
    const queue = await approver.get("/response/approvals");
    expect(queue.status).toBe(200);
    expect(queue.body.items.some((i: Json) => i.kind === "response_action" && (i.subjectId === created.id || JSON.stringify(i).includes(created.id)))).toBe(true);
  });

  it("does not leak actions to another tenant", async () => {
    const created = (await requester.post("/response/actions", isolate())).body as Json;
    expect((await other.get(`/response/actions/${created.id}`)).status).toBe(404);
    expect((await other.post(`/response/actions/${created.id}/approve`, {})).status).toBe(404);
    expect(JSON.stringify((await other.get("/response/actions")).body)).not.toContain(created.id);
  });

  it("writes audit records for request and decision", async () => {
    const created = (await requester.post("/response/actions", isolate())).body as Json;
    await approver.post(`/response/actions/${created.id}/reject`, { comment: "dup" });
    const rows = await t.db.withTenant(tenant.tenantId, async (tx) =>
      (await tx.query<{ action: string }>("SELECT action FROM audit_log WHERE target_id = $1", [created.id])).rows.map((r) => r.action),
    );
    expect(rows.some((a) => a.includes("request"))).toBe(true);
    expect(rows.some((a) => a.includes("reject"))).toBe(true);
  });
});
