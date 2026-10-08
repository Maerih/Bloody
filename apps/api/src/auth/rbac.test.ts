import type { Principal } from "@bloody/contracts";
import type { FastifyRequest } from "fastify";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { HttpError } from "../http/errors.js";
import { api, createTenant, createTestApp, createUser, login, uniq, type Json, type TestApp, type TestTenant } from "../test/harness.js";
import { canGrantRole, orgScopeFor, requirePermission, resolveOrgFilter } from "./rbac.js";
import type { AuthContext } from "./types.js";

const ORG1 = "11111111-1111-4111-8111-111111111111";
const ORG2 = "22222222-2222-4222-8222-222222222222";

function ctx(bindings: Principal["bindings"], boundOrganizationId: string | null = null): AuthContext {
  const principal: Principal = { kind: boundOrganizationId ? "service" : "user", id: "u", tenantId: "t", bindings };
  return { principal, method: "bearer", tenantId: "t", boundOrganizationId, sessionId: null, csrfProtected: false };
}
const req = (auth: AuthContext) => ({ auth, auditState: { recorded: false } }) as unknown as FastifyRequest;
const status = (fn: () => unknown): number | "ok" => {
  try {
    fn();
    return "ok";
  } catch (err) {
    return err instanceof HttpError ? err.statusCode : -1;
  }
};

describe("RBAC primitives", () => {
  it("resolves organization scopes per permission", () => {
    const pod = ctx([
      { role: "soc_analyst_t2", organizationId: ORG1 },
      { role: "customer_viewer", organizationId: ORG2 },
    ]);
    expect(orgScopeFor(pod, "incident:write")).toEqual([ORG1]);
    expect([...(orgScopeFor(pod, "incident:read") as string[])].sort()).toEqual([ORG1, ORG2].sort());
    expect(orgScopeFor(pod, "audit:read")).toEqual([]);
    expect(orgScopeFor(ctx([{ role: "soc_analyst_t1", organizationId: null }]), "incident:read")).toBe("all");
    // An org-bound API key is narrowed to its organization even with a tenant-wide role.
    expect(orgScopeFor(ctx([{ role: "api_service", organizationId: null }], ORG1), "asset:read")).toEqual([ORG1]);
  });

  it("gates tenant-level actions on tenant-wide bindings only", () => {
    const orgAdmin = ctx([{ role: "org_admin", organizationId: ORG1 }]);
    expect(status(() => requirePermission(req(orgAdmin), "org:write", ORG1))).toBe("ok");
    expect(status(() => requirePermission(req(orgAdmin), "org:write", null))).toBe(403);
    expect(status(() => requirePermission(req(orgAdmin), "org:write", ORG2))).toBe(403);
    expect(status(() => resolveOrgFilter(req(orgAdmin), "incident:read", ORG2))).toBe(403);
    expect(resolveOrgFilter(req(orgAdmin), "incident:read", undefined)).toEqual([ORG1]);
    expect(resolveOrgFilter(req(ctx([{ role: "mssp_admin", organizationId: null }])), "incident:read", undefined)).toBeNull();
    const key = ctx([{ role: "api_service", organizationId: null }], ORG1);
    expect(status(() => requirePermission(req(key), "event:ingest", ORG2))).toBe(403);
    expect(status(() => requirePermission(req(key), "event:ingest", ORG1))).toBe("ok");
  });

  it("only lets principals grant roles whose permissions they hold", () => {
    const orgAdmin = ctx([{ role: "org_admin", organizationId: ORG1 }]).principal;
    expect(canGrantRole(orgAdmin, "soc_analyst_t2", ORG1)).toBe(true);
    expect(canGrantRole(orgAdmin, "soc_analyst_t2", ORG2)).toBe(false);
    expect(canGrantRole(orgAdmin, "soc_analyst_t2", null)).toBe(false);
    expect(canGrantRole(orgAdmin, "mssp_admin", ORG1)).toBe(false);
    const t2 = ctx([{ role: "soc_analyst_t2", organizationId: null }]).principal;
    expect(canGrantRole(t2, "soc_analyst_t1", null)).toBe(true);
    expect(canGrantRole(t2, "incident_responder", null)).toBe(false); // response:approve is not t2's
  });
});

let t: TestApp;
let tenant: TestTenant;
let o1: string;
let o2: string;
let admin: ReturnType<typeof api>;
const fx = {} as { inc1: Json; inc2: Json; asset1: Json; asset2: Json; inv2: Json; esc1: Json };

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 2 });
  [o1, o2] = tenant.orgIds as [string, string];
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  fx.asset1 = (await admin.post("/assets", { organizationId: o1, kind: "server", name: uniq("o1-app-server"), hostname: uniq("o1-app") })).body;
  fx.asset2 = (await admin.post("/assets", { organizationId: o2, kind: "server", name: uniq("o2-db-server"), hostname: uniq("o2-db") })).body;
  fx.inc1 = (await admin.post("/incidents", { organizationId: o1, title: "Org 1 incident", severity: "high", assetIds: [fx.asset1.id] })).body;
  fx.inc2 = (await admin.post("/incidents", { organizationId: o2, title: "Org 2 incident", severity: "critical", assetIds: [fx.asset2.id] })).body;
  fx.inv2 = (await admin.post("/investigations", { incidentId: fx.inc2.id, title: "Org 2 investigation" })).body;
  fx.esc1 = (await admin.post("/escalations", { incidentId: fx.inc1.id, title: "Customer: approve isolation", severity: "high" })).body;
  expect([fx.asset1.id, fx.asset2.id, fx.inc1.id, fx.inc2.id, fx.inv2.id, fx.esc1.id].every(Boolean)).toBe(true);
});

afterAll(async () => {
  await t?.close();
});

async function as(roles: Array<{ role: Principal["bindings"][number]["role"]; organizationId: string | null }>, organizationId: string | null = null) {
  const user = await createUser(t, tenant.tenantId, { roles, organizationId });
  return { user, client: api(t.app, { token: (await login(t.app, user.email)).token }) };
}

describe("RBAC denials through the API", () => {
  it("customer viewers read their incidents and answer escalations but change nothing else", async () => {
    const { user, client } = await as([{ role: "customer_viewer", organizationId: o1 }], o1);
    expect((await client.get("/incidents")).body.items.map((i: Json) => i.id)).toEqual([fx.inc1.id]);
    expect((await client.patch(`/incidents/${fx.inc1.id}`, { status: "closed" })).status).toBe(403);
    expect((await client.post("/assets", { organizationId: o1, kind: "endpoint", name: "x" })).status).toBe(403);
    expect((await client.get("/alerts")).status).toBe(403);
    expect((await client.get("/audit")).status).toBe(403);
    expect((await client.get("/users")).status).toBe(403);
    expect((await client.get(`/investigations/${fx.inv2.id}`)).status).toBe(403);
    const ack = await client.post(`/escalations/${fx.esc1.id}/acknowledge`, { note: "Approved — isolate the host." });
    expect(ack.status).toBe(200);
    expect(ack.body).toMatchObject({ status: "acknowledged", acknowledgedBy: `user:${user.id}` });

    const denied = await t.privileged.query("SELECT action, outcome, details FROM audit_log WHERE tenant_id = $1 AND actor_id = $2 AND outcome = 'denied' ORDER BY seq", [tenant.tenantId, user.id]);
    expect(denied.rows.map((r) => r.action)).toEqual(expect.arrayContaining(["patch /api/v1/incidents/:id", "post /api/v1/assets"]));
    expect(denied.rows.find((r) => r.action === "post /api/v1/assets")!.details).toMatchObject({ status: 403, deniedPermission: "asset:write" });
  });

  it("tier-1 analysts work incidents but cannot administer the tenant", async () => {
    const { client } = await as([{ role: "soc_analyst_t1", organizationId: null }]);
    expect((await client.patch(`/incidents/${fx.inc1.id}`, { status: "triage" })).status).toBe(200);
    expect((await client.post("/organizations", { name: "Shadow org", slug: uniq("shadow") })).status).toBe(403);
    expect((await client.post("/api-keys", { name: "k", organizationId: null })).status).toBe(403);
    expect((await client.post("/users", { email: `${uniq("x")}@example.test`, roles: [] })).status).toBe(403);
    expect((await client.get("/audit")).status).toBe(403);
    expect((await client.post("/teams", { name: "nope" })).status).toBe(403);
  });

  it("executives get read-only risk views", async () => {
    const { client } = await as([{ role: "executive", organizationId: null }]);
    expect((await client.get("/incidents")).status).toBe(200);
    expect((await client.get("/command-center/summary")).status).toBe(200);
    expect((await client.patch(`/incidents/${fx.inc1.id}`, { severity: "low" })).status).toBe(403);
    expect((await client.get("/assets")).status).toBe(403);
    expect((await client.get("/identities")).status).toBe(403);
  });

  it("delegated org admins manage only their organization and cannot escalate", async () => {
    const { client } = await as([{ role: "org_admin", organizationId: o1 }], o1);
    expect((await client.patch(`/organizations/${o1}`, { name: "Renamed by its admin" })).status).toBe(200);
    expect((await client.patch(`/organizations/${o2}`, { name: "Hijacked" })).status).toBe(404);
    expect((await client.patch(`/organizations/${o1}`, { mrr: 1 })).status).toBe(403); // billing is tenant-level
    expect((await client.post("/organizations", { name: "New", slug: uniq("new") })).status).toBe(403);
    const escalate = await client.post("/users", { email: `${uniq("evil")}@example.test`, organizationId: o1, roles: [{ role: "mssp_admin", organizationId: null }] });
    expect(escalate.status).toBe(403);
    const crossOrg = await client.post("/users", { email: `${uniq("x")}@example.test`, organizationId: o1, roles: [{ role: "soc_analyst_t1", organizationId: o2 }] });
    expect(crossOrg.status).toBe(403);
    const ok = await client.post("/users", { email: `${uniq("analyst")}@example.test`, organizationId: o1, roles: [{ role: "soc_analyst_t1", organizationId: o1 }], password: "Str0ng-Passw0rd!" });
    expect(ok.status).toBe(201);
    expect(ok.body.bindings).toEqual([{ role: "soc_analyst_t1", organizationId: o1 }]);
    expect((await client.get(`/users/${tenant.admin.id}`)).status).toBe(404);
  });
});

describe("organization-scoped analysts", () => {
  it("see and change only their organization's records", async () => {
    const { client } = await as([{ role: "soc_analyst_t2", organizationId: o1 }]);
    const list = await client.get("/incidents?status=all");
    expect(list.body.items.map((i: Json) => i.id)).toEqual([fx.inc1.id]);
    expect((await client.get(`/incidents/${fx.inc2.id}`)).status).toBe(404);
    expect((await client.patch(`/incidents/${fx.inc2.id}`, { status: "closed" })).status).toBe(404);
    expect((await client.get(`/incidents?organizationId=${o2}`)).status).toBe(403);
    expect((await client.post("/incidents", { organizationId: o2, title: "not mine", severity: "low" })).status).toBe(403);
    expect((await client.get(`/investigations/${fx.inv2.id}`)).status).toBe(404);
    expect((await client.get(`/assets/${fx.asset2.id}`)).status).toBe(404);
    expect((await client.get("/assets")).body.items.map((a: Json) => a.id)).toEqual([fx.asset1.id]);
    expect((await client.get(`/command-center/summary?organizationId=${o2}`)).status).toBe(403);

    const summary = await client.get("/command-center/summary");
    expect(summary.status).toBe(200);
    expect(summary.body.organizations).toBe(1);
    expect(summary.body.activeIncidents.total).toBe(1);
    expect(summary.body.activeIncidents.critical).toBe(0);
    expect(summary.body.triage.every((i: Json) => i.organizationId === o1)).toBe(true);

    const orgs = await client.get("/organizations");
    expect(orgs.body.items.map((o: Json) => o.id)).toEqual([o1]);
    const me = await client.get("/auth/me");
    expect(me.body.organizations.map((o: Json) => o.id)).toEqual([o1]);
    const mssp = await client.get("/mssp/overview");
    expect(mssp.body.customers.map((c: Json) => c.organizationId)).toEqual([o1]);

    expect((await client.get(`/search?q=${encodeURIComponent(fx.asset2.name)}`)).body.items).toEqual([]);
    expect((await client.get(`/search?q=${encodeURIComponent(fx.asset1.name)}`)).body.items.map((h: Json) => h.id)).toContain(fx.asset1.id);
  });

  it("cannot be assigned incidents of organizations they cannot see", async () => {
    const { user } = await as([{ role: "soc_analyst_t2", organizationId: o1 }]);
    const bad = await admin.patch(`/incidents/${fx.inc2.id}`, { assigneeId: user.id });
    expect(bad.status).toBe(400);
    const ok = await admin.patch(`/incidents/${fx.inc1.id}`, { assigneeId: user.id });
    expect(ok.status).toBe(200);
    expect(ok.body.assigneeId).toBe(user.id);
    expect(ok.body.acknowledgedAt).not.toBeNull();
  });
});
