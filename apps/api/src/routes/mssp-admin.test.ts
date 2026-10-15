import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, uniq, type Json, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let admin: ReturnType<typeof api>;
let analystId: string;
let analystClient: ReturnType<typeof api>;

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const a = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: tenant.orgIds[0]! }], displayName: "Scoped Analyst" });
  analystId = a.id;
  analystClient = api(t.app, { token: (await login(t.app, a.email)).token });
});
afterAll(async () => {
  await t?.close();
});

describe("MSSP customer provisioning", () => {
  let provisioned: Json;
  const slug = uniq("acme").toLowerCase();

  it("provisions an organization, customer admin, viewer, analyst and default notifications in one call", async () => {
    const res = await admin.post("/mssp/customers", {
      name: "Acme Manufacturing",
      slug,
      retentionDays: 90,
      industry: "Manufacturing",
      admin: { email: `admin@${slug}.example`, displayName: "Acme IT" },
      viewers: [{ email: `ciso@${slug}.example` }],
      analysts: [{ userId: analystId, role: "soc_analyst_t2" }],
      defaultNotifications: true,
    });
    expect(res.status).toBe(201);
    provisioned = res.body;
    expect(provisioned.organization).toMatchObject({ name: "Acme Manufacturing", slug, status: "active" });
    expect(provisioned.viewers).toHaveLength(1);
    expect(provisioned.analysts).toHaveLength(1);
    expect(provisioned.channels.length).toBeGreaterThan(0);
  });

  it("shows the new customer in the MSSP overview and analyst list", async () => {
    const overview = await admin.get("/mssp/overview");
    expect(overview.status).toBe(200);
    expect(JSON.stringify(overview.body)).toContain("Acme Manufacturing");
    const analysts = await admin.get(`/mssp/customers/${provisioned.organization.id}/analysts`);
    expect(analysts.status).toBe(200);
    expect(JSON.stringify(analysts.body)).toContain(analystId);
  });

  it("rejects duplicate e-mails and non-admin callers", async () => {
    const dup = await admin.post("/mssp/customers", { name: "Dup", slug: uniq("dup").toLowerCase(), admin: { email: "same@x.example" }, viewers: [{ email: "same@x.example" }] });
    expect(dup.status).toBe(400);
    const denied = await analystClient.post("/mssp/customers", { name: "Nope", slug: uniq("nope").toLowerCase(), admin: { email: "n@x.example" } });
    expect(denied.status).toBe(403);
  });

  it("audits the provisioning", async () => {
    const rows = await t.db.withTenant(tenant.tenantId, async (tx) =>
      (await tx.query<{ action: string }>("SELECT action FROM audit_log WHERE target_id = $1", [provisioned.organization.id])).rows.map((r) => r.action),
    );
    expect(rows).toContain("mssp.customer_provisioned");
  });
});
