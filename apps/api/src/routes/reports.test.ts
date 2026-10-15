import { REPORT_TYPES } from "@bloody/contracts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, login, type Json, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let org: string;
let token: string;
let admin: ReturnType<typeof api>;
let other: ReturnType<typeof api>;

async function generate(body: Record<string, unknown>) {
  return t.app.inject({ method: "POST", url: "/api/v1/reports/generate", headers: { authorization: `Bearer ${token}` }, payload: body });
}

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  org = tenant.orgIds[0]!;
  token = (await login(t.app, tenant.admin.email)).token;
  admin = api(t.app, { token });
  const o = await createTenant(t, { orgs: 1 });
  other = api(t.app, { token: (await login(t.app, o.admin.email)).token });
});
afterAll(async () => {
  await t?.close();
});

describe("reporting", () => {
  it("lists every report type for every audience", async () => {
    const res = await admin.get("/reports/types");
    expect(res.status).toBe(200);
    const keys = JSON.stringify(res.body);
    for (const r of REPORT_TYPES) expect(keys).toContain(r.key);
  });

  it.each(REPORT_TYPES.filter((r) => r.key !== "incident").map((r) => r.key))("generates the %s report as HTML", async (type) => {
    const res = await generate({ type, format: "html", periodDays: 30 });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toContain("text/html");
    expect(res.payload).toContain("<html");
  });

  it("renders PDF, CSV and JSON", async () => {
    const pdf = await generate({ type: "executive", format: "pdf", periodDays: 30 });
    expect(pdf.statusCode).toBe(200);
    expect(pdf.rawPayload.subarray(0, 4).toString()).toBe("%PDF");
    const csv = await generate({ type: "soc_operations", format: "csv", periodDays: 30 });
    expect(csv.statusCode).toBe(200);
    expect(csv.headers["content-type"]).toContain("text/csv");
    const json = await generate({ type: "vulnerability", format: "json", periodDays: 30 });
    expect(json.statusCode).toBe(200);
    expect(() => JSON.parse(json.payload)).not.toThrow();
  });

  it("applies MSSP white-label branding", async () => {
    const res = await generate({ type: "customer_monthly", format: "html", organizationId: org, periodDays: 30, branding: { name: "Acme MDR", primaryColor: "#0055aa" } });
    expect(res.statusCode).toBe(200);
    expect(res.payload).toContain("Acme MDR");
  });

  it("manages schedules and keeps them per tenant", async () => {
    const created = await admin.post("/reports/schedules", { type: "executive", name: "Weekly exec", cron: "0 7 * * 1", format: "pdf", periodDays: 7, channelIds: [], enabled: true });
    expect(created.status).toBe(201);
    const id = (created.body as Json).id;
    expect((await admin.get("/reports/schedules")).body.items.some((s: Json) => s.id === id)).toBe(true);
    expect((await other.get(`/reports/schedules/${id}`)).status).toBe(404);
    expect(JSON.stringify((await other.get("/reports/schedules")).body)).not.toContain(id);
    expect((await admin.patch(`/reports/schedules/${id}`, { enabled: false })).body.enabled).toBe(false);
    expect((await admin.delete(`/reports/schedules/${id}`)).status).toBeLessThan(300);
  });

  it("rejects an invalid cron expression", async () => {
    const res = await admin.post("/reports/schedules", { type: "executive", name: "Bad", cron: "not a cron", format: "pdf", periodDays: 7, channelIds: [], enabled: true });
    expect(res.status).toBe(400);
  });
});

describe("entitlements", () => {
  it("returns 402 for modules outside the plan", async () => {
    const small = await createTenant(t, { orgs: 1, plan: "essentials" });
    const client = api(t.app, { token: (await login(t.app, small.admin.email)).token });
    const res = await client.get("/ai/providers");
    expect(res.status).toBe(402);
    expect(JSON.stringify(res.body)).toContain("ENTITLEMENT");
    const ent = await client.get("/entitlements");
    expect(ent.status).toBe(200);
  });

  it("reports usage against plan limits", async () => {
    const res = await admin.get("/billing/usage");
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body)).toMatch(/endpoints|organizations/);
  });
});
