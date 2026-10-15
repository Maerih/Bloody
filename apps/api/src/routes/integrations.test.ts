import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, login, type Json, type TestApp, type TestTenant } from "../test/harness.js";

const FIXTURES = fileURLToPath(new URL("../../../../packages/adapters/fixtures/copilot/", import.meta.url));
const fixture = (name: string): unknown => JSON.parse(readFileSync(`${FIXTURES}${name}.json`, "utf8"));
const userCustomers = fixture("user-customers") as Record<string, string[]>;
const SECRET = "copilot-sync-password-must-not-leak";

/** Fake SOCFortress CoPilot REST API (only the endpoints Bloody's connector reads). */
const fakeCopilot = (async (input: string | URL | Request) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  const p = url.pathname;
  const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  if (p === "/api/auth/token") return json({ access_token: "copilot-jwt-0123456789", token_type: "bearer" });
  if (p === "/api/auth/me/customers") return json({ success: true, customer_codes: ["*"], scope: "deployment" });
  if (p === "/api/customers") return json(fixture("customers"));
  if (p === "/api/agents") return json(fixture("agents"));
  if (p === "/api/incidents/db_operations/alerts") return json(fixture("alerts"));
  if (p === "/api/incidents/db_operations/cases") return json(fixture("cases"));
  if (p === "/api/auth/users") return json(fixture("users"));
  const m = /^\/api\/auth\/users\/(\d+)\/customers$/.exec(p);
  if (m) return json({ success: true, customer_codes: userCustomers[m[1]!] ?? [] });
  return new Response("not found", { status: 404 });
}) as typeof fetch;

let t: TestApp;
let tenant: TestTenant;
let admin: ReturnType<typeof api>;
let other: ReturnType<typeof api>;
let integrationId: string;

async function counts() {
  return t.db.withTenant(tenant.tenantId, async (tx) => {
    const q = async (sql: string) => Number((await tx.query<{ n: string }>(sql)).rows[0]!.n);
    return {
      orgs: await q("SELECT count(*)::text AS n FROM organizations"),
      agents: await q("SELECT count(*)::text AS n FROM agents"),
      alerts: await q("SELECT count(*)::text AS n FROM alerts"),
      incidents: await q("SELECT count(*)::text AS n FROM incidents"),
    };
  });
}

beforeAll(async () => {
  t = await createTestApp({ deps: { fetch: fakeCopilot, hostResolver: false } });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const o = await createTenant(t, { orgs: 1, plan: "mssp" });
  other = api(t.app, { token: (await login(t.app, o.admin.email)).token });
});
afterAll(async () => {
  await t?.close();
});

describe("integrations — SOCFortress CoPilot", () => {
  it("lists the open-source engine catalog including CoPilot", async () => {
    const res = await admin.get("/integrations/catalog");
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body)).toContain("copilot");
  });

  it("creates the integration with a write-only credential", async () => {
    const res = await admin.post("/integrations", {
      kind: "copilot",
      name: "CoPilot (MSSP)",
      endpoint: "https://copilot.mssp.example",
      config: { username: "bloody-sync", portal: "main" },
      credential: SECRET,
    });
    expect(res.status).toBe(201);
    integrationId = res.body.id;
    expect(JSON.stringify(res.body)).not.toContain(SECRET);
    expect(JSON.stringify((await admin.get(`/integrations/${integrationId}`)).body)).not.toContain(SECRET);
  });

  it("syncs customers, agents, alerts and cases into Bloody", async () => {
    const before = await counts();
    const res = await admin.post(`/integrations/${integrationId}/sync`, {});
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("succeeded");
    const after = await counts();
    expect(after.orgs).toBeGreaterThan(before.orgs);
    expect(after.agents).toBeGreaterThan(before.agents);
  });

  it("is idempotent: a second sync creates no duplicates", async () => {
    const before = await counts();
    const res = await admin.post(`/integrations/${integrationId}/sync`, {});
    expect(res.status).toBe(200);
    expect(await counts()).toEqual(before);
  });

  it("keeps the integration invisible to other tenants", async () => {
    expect((await other.get(`/integrations/${integrationId}`)).status).toBe(404);
    expect((await other.post(`/integrations/${integrationId}/sync`, {})).status).toBe(404);
  });
});
