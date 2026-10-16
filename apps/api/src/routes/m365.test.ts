import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type Json, type TestApp, type TestTenant } from "../test/harness.js";

const graphCalls: string[] = [];
let secretOk = "right-secret";
/** Fake Microsoft sign-in + Graph: MFA and security defaults on, one external forwarding rule. */
const fakeMicrosoft = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(String(input instanceof Request ? input.url : input));
  graphCalls.push(url.host + url.pathname);
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  if (url.host === "login.microsoftonline.com") {
    return new URLSearchParams(String(init?.body)).get("client_secret") === secretOk ? json(200, { access_token: "t", expires_in: 3600 }) : json(401, { error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret provided." });
  }
  const path = url.pathname.replace(/^\/v1\.0/, "");
  const routes: Record<string, unknown> = {
    "/organization": { value: [{ displayName: "Nile Health", verifiedDomains: [{ name: "nile.example" }] }] },
    "/policies/identitySecurityDefaultsEnforcementPolicy": { isEnabled: true },
    "/users": { value: [{ id: "u1", userPrincipalName: "rx@nile.example", accountEnabled: true, mail: "rx@nile.example" }] },
    "/users/u1/mailFolders/inbox/messageRules": { value: [{ displayName: "fwd", isEnabled: true, actions: { redirectTo: [{ emailAddress: { address: "x@attacker.example" } }] } }] },
  };
  return path in routes ? json(200, routes[path]) : json(403, { error: { code: "Authorization_RequestDenied", message: "Insufficient privileges" } });
}) as typeof fetch;
const fakeDns = { resolveTxt: async () => [] as string[][], resolveCname: async () => [] as string[] };

let t: TestApp;
let tenant: TestTenant;
let admin: ReturnType<typeof api>;
let analyst: ReturnType<typeof api>;
let otherAdmin: ReturnType<typeof api>;
let org: string;

beforeAll(async () => {
  t = await createTestApp({ deps: { fetch: fakeMicrosoft, dns: fakeDns, hostResolver: false } });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  org = tenant.orgIds[0]!;
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const a = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: null }] });
  analyst = api(t.app, { token: (await login(t.app, a.email)).token });
  const o = await createTenant(t, { orgs: 1, plan: "mssp" });
  otherAdmin = api(t.app, { token: (await login(t.app, o.admin.email)).token });
});
afterAll(async () => {
  await t?.close();
});

const connect = (secret: string) =>
  admin.post("/m365/connections", { organizationId: org, directoryTenantId: "nilehealth.onmicrosoft.com", clientId: "11111111-2222-3333-4444-555555555555", clientSecret: secret });

describe("Microsoft 365 hardening", () => {
  it("explains what to grant before anything is connected", async () => {
    const o = (await admin.get(`/m365/overview?organizationId=${org}`)).body;
    expect(o).toMatchObject({ connection: null, assessment: null, history: [] });
    expect(o.permissions.map((p: Json) => p.name)).toContain("Policy.Read.All");
    expect(o.checks).toBeGreaterThanOrEqual(20);
  });

  it("reports a wrong secret on the connection instead of failing", async () => {
    const res = await connect("wrong-secret");
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ assessment: null, connection: { status: "error" } });
    expect(res.body.error).toMatch(/AADSTS7000215/);
  });

  it("connects, assesses right away and keeps the secret out of every response", async () => {
    const res = await connect("right-secret");
    expect(res.status).toBe(201);
    expect(res.body.connection).toMatchObject({ status: "connected", displayName: "Nile Health" });
    const a = res.body.assessment;
    const by = Object.fromEntries((a.results as Json[]).map((r) => [r.id, r]));
    expect(by["m365.mfa_all_users"].status).toBe("pass"); // security defaults
    expect(by["m365.inbox_rules_external_forwarding"]).toMatchObject({ status: "fail", evidence: ['rx@nile.example: "fwd" → x@attacker.example'] });
    expect(by["m365.user_consent"].status).toBe("unknown");
    expect(by["m365.user_consent"].evidence[0]).toMatch(/Policy\.Read\.All/);
    expect(a.score).toBeGreaterThan(0);
    expect(JSON.stringify(res.body)).not.toContain("right-secret");
    const stored = await t.privileged.query("SELECT count(*)::int AS n FROM secrets WHERE tenant_id = $1 AND purpose = 'm365.client_secret'", [tenant.tenantId]);
    expect(stored.rows[0].n).toBe(1); // the replaced secret was deleted
    expect(graphCalls.every((c) => c.startsWith("login.microsoftonline.com/") || c.startsWith("graph.microsoft.com/"))).toBe(true);
  });

  it("re-assesses on demand and keeps history; access is per organization and account", async () => {
    const o = (await admin.get(`/m365/overview?organizationId=${org}`)).body;
    const again = await analyst.post(`/m365/connections/${o.connection.id}/assess`, {});
    expect(again.status).toBe(200);
    expect((await admin.get(`/m365/overview?organizationId=${org}`)).body.history).toHaveLength(2);
    expect((await analyst.post("/m365/connections", { organizationId: org, directoryTenantId: "x.onmicrosoft.com", clientId: "11111111-2222-3333-4444-555555555555", clientSecret: "whatever1" })).status).toBe(403);
    expect((await otherAdmin.get(`/m365/overview?organizationId=${org}`)).status).toBe(404);
    expect((await otherAdmin.post(`/m365/connections/${o.connection.id}/assess`, {})).status).toBe(404);
    expect((await admin.post("/m365/connections", { organizationId: org, directoryTenantId: "not a tenant", clientId: "x", clientSecret: "whatever1" })).status).toBe(400);
  });

  it("the scheduler re-assesses stale connections daily", async () => {
    await t.privileged.query("UPDATE m365_connections SET last_assessed_at = now() - interval '2 days' WHERE tenant_id = $1", [tenant.tenantId]);
    expect(await t.services.m365.assessDue(tenant.tenantId)).toBe(1);
    expect(await t.services.m365.assessDue(tenant.tenantId)).toBe(0);
  });

  it("disconnects and removes the stored secret", async () => {
    const o = (await admin.get(`/m365/overview?organizationId=${org}`)).body;
    expect((await admin.delete(`/m365/connections/${o.connection.id}`)).status).toBe(204);
    const stored = await t.privileged.query("SELECT count(*)::int AS n FROM secrets WHERE tenant_id = $1 AND purpose = 'm365.client_secret'", [tenant.tenantId]);
    expect(stored.rows[0].n).toBe(0);
    const audit = await t.privileged.query("SELECT action FROM audit_log WHERE tenant_id = $1 AND action LIKE 'm365.%' ORDER BY seq", [tenant.tenantId]);
    expect(audit.rows.map((r) => r.action)).toEqual(expect.arrayContaining(["m365.connected", "m365.disconnected"]));
  });
});
