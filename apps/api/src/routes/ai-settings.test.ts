import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let admin: ReturnType<typeof api>;
let analyst: ReturnType<typeof api>;
const ollama = { name: "Local Ollama", kind: "ollama", endpoint: "http://127.0.0.1:11434", model: "llama3.1:8b" };

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 1, plan: "enterprise" });
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const u = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t2", organizationId: null }] });
  analyst = api(t.app, { token: (await login(t.app, u.email)).token });
});
afterAll(async () => {
  await t?.close();
});

describe("AI private-endpoint setting", () => {
  it("blocks loopback providers by default", async () => {
    expect((await admin.get("/ai/settings")).body).toMatchObject({ allowPrivateEndpoints: false, effectiveAllowPrivateEndpoints: false });
    const res = await admin.post("/ai/providers", ollama);
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("unsafe_endpoint");
  });

  it("lets an admin allow local models, then the provider can be added", async () => {
    const res = await admin.patch("/ai/settings", { allowPrivateEndpoints: true });
    expect(res.status).toBe(200);
    expect(res.body.effectiveAllowPrivateEndpoints).toBe(true);
    expect((await admin.post("/ai/providers", ollama)).status).toBe(201);
  });

  it("still blocks cloud-metadata addresses even when private endpoints are allowed", async () => {
    const res = await admin.post("/ai/providers", { ...ollama, name: "meta", kind: "openai_compatible", endpoint: "http://169.254.169.254/v1" });
    expect(res.status).toBe(400);
  });

  it("is admin-only and audited", async () => {
    expect((await analyst.patch("/ai/settings", { allowPrivateEndpoints: false })).status).toBe(403);
    const rows = await t.db.withTenant(tenant.tenantId, async (tx) => (await tx.query<{ action: string }>("SELECT action FROM audit_log WHERE action = 'ai_settings.updated'")).rows);
    expect(rows.length).toBe(1);
  });
});
