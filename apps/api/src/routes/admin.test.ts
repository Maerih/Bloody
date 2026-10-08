import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { totp } from "../security/totp.js";
import { TEST_PASSWORD, api, call, createTenant, createTestApp, createUser, login, uniq, type Json, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let o1: string;
let o2: string;
let admin: ReturnType<typeof api>;

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 2 });
  [o1, o2] = tenant.orgIds as [string, string];
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
});
afterAll(async () => {
  await t?.close();
});

describe("organizations", () => {
  it("creates, reads with stats, pages, renames and re-parents without cycles", async () => {
    const parent = await admin.post("/organizations", { name: "Holding Group", slug: uniq("holding"), retentionDays: 365, industry: "Finance", mrr: 2500, plan: "enterprise" });
    expect(parent.status).toBe(201);
    expect(parent.body).toMatchObject({ name: "Holding Group", retentionDays: 365, mrr: 2500, plan: "enterprise", status: "active", parentOrganizationId: null });
    const child = await admin.post("/organizations", { name: "Holding Subsidiary", slug: uniq("sub"), parentOrganizationId: parent.body.id });
    expect(child.status).toBe(201);
    expect((await admin.patch(`/organizations/${parent.body.id}`, { parentOrganizationId: child.body.id })).status).toBe(400);
    expect((await admin.patch(`/organizations/${parent.body.id}`, { parentOrganizationId: parent.body.id })).status).toBe(400);

    const detail = await admin.get(`/organizations/${parent.body.id}`);
    expect(detail.body.stats).toEqual({ assets: 0, agents: 0, identities: 0, activeIncidents: 0, users: 0, childOrganizations: 1 });

    const page1 = await admin.get("/organizations?limit=2");
    expect(page1.body.items).toHaveLength(2);
    const page2 = await admin.get(`/organizations?limit=2&cursor=${page1.body.nextCursor}`);
    const names = [...page1.body.items, ...page2.body.items].map((o: Json) => o.name);
    expect(names).toEqual([...names].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())));
    expect(new Set(names).size).toBe(4);
    expect((await admin.get("/organizations?q=holding")).body.items).toHaveLength(2);
    expect((await admin.post("/organizations", { name: "Bad slug", slug: "Not Valid!" })).status).toBe(400);
    expect((await admin.post("/organizations", { name: "x", slug: uniq("x"), unknownField: 1 })).status).toBe(400);
  });

  it("enforces the plan's organization quota", async () => {
    const trial = await createTenant(t, { plan: "trial", kind: "enterprise", orgs: 1 });
    const client = api(t.app, { token: (await login(t.app, trial.admin.email)).token });
    const res = await client.post("/organizations", { name: "Second org", slug: uniq("second") });
    expect(res.status).toBe(402);
    expect(res.body.error).toMatchObject({ code: "quota_exceeded", details: { limit: 1, plan: "trial" } });
    const me = await client.get("/auth/me");
    expect(me.body.plan).toBe("trial");
    expect(me.body.entitlements.find((e: Json) => e.module === "edr")).toMatchObject({ state: "trial" });
    expect(me.body.entitlements.find((e: Json) => e.module === "cspm")).toMatchObject({ state: "available" });
  });
});

describe("users and role bindings", () => {
  it("creates invited users, activates them with a password and manages bindings", async () => {
    const email = `${uniq("new.analyst")}@example.test`;
    const created = await admin.post("/users", { email: email.toUpperCase(), displayName: "New Analyst", roles: [{ role: "soc_analyst_t1", organizationId: o1 }] });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ email, status: "invited", bindings: [{ role: "soc_analyst_t1", organizationId: o1 }] });
    const id = created.body.id;
    expect((await call(t.app, "POST", "/auth/login", { body: { email, password: TEST_PASSWORD } })).status).toBe(401);
    expect((await admin.post(`/users/${id}/password`, { password: "weak" })).status).toBe(400);
    expect((await admin.post(`/users/${id}/password`, { password: TEST_PASSWORD })).status).toBe(204);
    const session = await login(t.app, email);
    expect((await admin.get(`/users/${id}`)).body.status).toBe("active");

    const granted = await admin.post(`/users/${id}/roles`, { role: "threat_hunter", organizationId: o2 });
    expect(granted.status).toBe(201);
    expect(granted.body.bindings).toEqual(expect.arrayContaining([{ role: "threat_hunter", organizationId: o2 }]));
    // Bindings are re-read on every request: the new grant is effective for the live session.
    const me = await api(t.app, { token: session.token }).get("/auth/me");
    expect(me.body.principal.bindings).toEqual(expect.arrayContaining([{ role: "threat_hunter", organizationId: o2 }]));
    expect((await admin.delete(`/users/${id}/roles?role=threat_hunter&organizationId=${o2}`)).status).toBe(204);
    expect((await admin.delete(`/users/${id}/roles?role=threat_hunter&organizationId=${o2}`)).status).toBe(404);
    expect((await admin.post(`/users/${tenant.admin.id}/roles`, { role: "ciso", organizationId: null })).body.error.code).toBe("self_modification");

    const list = await admin.get(`/users?q=${encodeURIComponent(email)}`);
    expect(list.body.items).toHaveLength(1);
    expect((await admin.get(`/users?organizationId=${o1}`)).body.items.map((u: Json) => u.id)).toContain(id);
    expect((await admin.post("/users", { email, roles: [] })).status).toBe(409);
  });

  it("disabling a user revokes their sessions immediately", async () => {
    const user = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: null }] });
    const s = await login(t.app, user.email);
    expect((await admin.patch(`/users/${user.id}`, { status: "disabled" })).body).toMatchObject({ status: "disabled", disabled: true });
    expect((await api(t.app, { token: s.token }).get("/auth/me")).status).toBe(401);
    expect((await call(t.app, "POST", "/auth/login", { body: { email: user.email, password: TEST_PASSWORD } })).status).toBe(401);
    expect((await admin.patch(`/users/${tenant.admin.id}`, { status: "disabled" })).status).toBe(400);
  });
});

describe("teams", () => {
  it("grant their roles to members, and members inherit them", async () => {
    const member = await createUser(t, tenant.tenantId, { roles: [] });
    const s = await login(t.app, member.email);
    const client = api(t.app, { token: s.token });
    expect((await client.get("/incidents")).status).toBe(403);

    const team = await admin.post("/teams", { name: "Pod East", description: "Follow-the-sun pod" });
    expect(team.status).toBe(201);
    expect((await admin.post(`/teams/${team.body.id}/roles`, { role: "soc_analyst_t2", organizationId: o1 })).status).toBe(201);
    const added = await admin.post(`/teams/${team.body.id}/members`, { userId: member.id, memberRole: "lead" });
    expect(added.status).toBe(201);
    expect(added.body.members).toEqual([expect.objectContaining({ userId: member.id, memberRole: "lead" })]);
    expect((await client.get("/incidents")).status).toBe(200);
    expect((await client.get(`/incidents?organizationId=${o2}`)).status).toBe(403);
    const user = await admin.get(`/users/${member.id}`);
    expect(user.body.teams).toEqual([{ id: team.body.id, name: "Pod East", memberRole: "lead" }]);

    expect((await admin.patch(`/teams/${team.body.id}`, { name: "Pod East & Central" })).body.name).toBe("Pod East & Central");
    expect((await admin.get("/teams")).body.items.find((x: Json) => x.id === team.body.id).bindings).toEqual([{ role: "soc_analyst_t2", organizationId: o1 }]);
    expect((await admin.delete(`/teams/${team.body.id}/members/${member.id}`)).status).toBe(204);
    expect((await client.get("/incidents")).status).toBe(403);
    expect((await admin.delete(`/teams/${team.body.id}/roles?role=soc_analyst_t2&organizationId=${o1}`)).status).toBe(204);
    expect((await admin.delete(`/teams/${team.body.id}`)).status).toBe(204);
    expect((await admin.patch(`/teams/${team.body.id}`, { name: "gone" })).status).toBe(404);
  });
});

describe("own account: sessions, password and MFA step-up", () => {
  it("lists and revokes sessions, changes the password and steps up with TOTP", async () => {
    const user = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t2", organizationId: null }] });
    const s1 = await login(t.app, user.email);
    const s2 = await login(t.app, user.email);
    const c1 = api(t.app, { token: s1.token });
    const sessions = await c1.get("/auth/sessions");
    expect(sessions.body.items).toHaveLength(2);
    expect(sessions.body.items.filter((x: Json) => x.current)).toHaveLength(1);
    const other = sessions.body.items.find((x: Json) => !x.current);
    expect((await c1.delete(`/auth/sessions/${other.id}`)).status).toBe(204);
    expect((await api(t.app, { token: s2.token }).get("/auth/me")).status).toBe(401);

    expect((await c1.post("/auth/password", { currentPassword: "wrong", newPassword: "N3w-Passw0rd!x" })).status).toBe(401);
    expect((await c1.post("/auth/password", { currentPassword: TEST_PASSWORD, newPassword: "short" })).status).toBe(400);
    expect((await c1.post("/auth/password", { currentPassword: TEST_PASSWORD, newPassword: "N3w-Passw0rd!x" })).status).toBe(204);
    expect((await call(t.app, "POST", "/auth/login", { body: { email: user.email, password: TEST_PASSWORD } })).status).toBe(401);
    const s3 = await login(t.app, user.email, "N3w-Passw0rd!x");
    expect((await c1.get("/auth/me")).status).toBe(200); // the session that changed it survives

    expect(s3.userId).toBe(user.id);
  });

  it("enrolls, steps up and disables TOTP as time advances", async () => {
    // Every accepted code consumes its 30 s step, so the clock is driven explicitly.
    let offset = 0;
    const clocked = await createTestApp({ deps: { now: () => Date.now() + offset } });
    try {
      const user = await createUser(clocked, tenant.tenantId, { roles: [{ role: "soc_analyst_t2", organizationId: null }] });
      const c = api(clocked.app, { token: (await login(clocked.app, user.email)).token });
      const { secret } = (await c.post("/auth/mfa/totp/enroll")).body;
      const { secret: secret2 } = (await c.post("/auth/mfa/totp/enroll")).body; // re-enrolling before confirmation replaces the secret
      expect(secret2).not.toBe(secret);
      const code = () => totp(secret2, Date.now() + offset);
      expect((await c.post("/auth/mfa/totp/confirm", { code: totp(secret, Date.now()) })).status).toBe(400);
      expect((await c.post("/auth/mfa/totp/confirm", { code: code() })).status).toBe(200);
      expect((await c.post("/auth/mfa/totp/enroll")).status).toBe(409);
      expect((await c.post("/auth/mfa/verify", { code: code() })).status).toBe(400); // same step: replay
      offset += 30_000;
      expect((await c.post("/auth/mfa/verify", { code: "000000" })).status).toBe(400);
      expect((await c.post("/auth/mfa/verify", { code: code() })).body).toEqual({ mfaVerified: true });
      offset += 30_000;
      expect((await c.post("/auth/mfa/totp/disable", { code: code() })).body).toEqual({ mfaEnabled: false });
      expect((await api(clocked.app, { token: (await login(clocked.app, tenant.admin.email)).token }).get(`/users/${user.id}`)).body.mfaEnabled).toBe(false);
      const trail = await clocked.privileged.query("SELECT action, outcome FROM audit_log WHERE tenant_id = $1 AND actor_id = $2 AND action LIKE 'auth.mfa%' ORDER BY seq", [tenant.tenantId, user.id]);
      expect(trail.rows.map((r) => `${r.action}:${r.outcome}`)).toEqual([
        "auth.mfa_enrollment_started:success",
        "auth.mfa_enrollment_started:success",
        "auth.mfa_enabled:success",
        "auth.mfa_step_up:failure",
        "auth.mfa_step_up:failure",
        "auth.mfa_step_up:success",
        "auth.mfa_disabled:success",
      ]);
    } finally {
      await clocked.close();
    }
  });
});

describe("inventory: assets, agents, identities", () => {
  it("manages assets with filters, keyset pagination and explainable risk", async () => {
    const mk = (name: string, extra: Json = {}) => admin.post("/assets", { organizationId: o1, kind: "server", name, hostname: name.toLowerCase(), ...extra });
    const web = await mk("Web-01", { internetFacing: true, criticality: "high", ipAddresses: ["198.51.100.10"], tags: ["dmz"] });
    expect(web.status).toBe(201);
    expect(web.body.riskScore).toBeGreaterThanOrEqual(0);
    expect(web.body.risk.factors.length).toBeGreaterThan(0);
    await mk("Db-01", { kind: "database", criticality: "crown_jewel" });
    await mk("App-01");
    expect((await mk("Web-01")).status).toBe(409); // hostname unique per organization
    expect((await admin.post("/assets", { organizationId: o1, kind: "server", name: "bad ip", ipAddresses: ["999.1.1.1"] })).status).toBe(400);

    expect((await admin.get(`/assets?organizationId=${o1}&internetFacing=true`)).body.items.map((a: Json) => a.name)).toEqual(["Web-01"]);
    expect((await admin.get("/assets?criticality=crown_jewel,high")).body.items).toHaveLength(2);
    expect((await admin.get("/assets?q=198.51.100.10")).body.items.map((a: Json) => a.name)).toEqual(["Web-01"]);
    expect((await admin.get("/assets?q=dmz")).body.items.map((a: Json) => a.name)).toEqual(["Web-01"]);
    const p1 = await admin.get("/assets?sort=name&limit=2");
    const p2 = await admin.get(`/assets?sort=name&limit=2&cursor=${p1.body.nextCursor}`);
    expect([...p1.body.items, ...p2.body.items].map((a: Json) => a.name)).toEqual(["App-01", "Db-01", "Web-01"]);
    expect(p2.body.nextCursor).toBeNull();

    const patched = await admin.patch(`/assets/${web.body.id}`, { criticality: "crown_jewel", owner: "Digital" });
    expect(patched.body).toMatchObject({ criticality: "crown_jewel", owner: "Digital" });
    const detail = await admin.get(`/assets/${web.body.id}`);
    expect(detail.body).toMatchObject({ agents: [], vulnerabilities: [], alerts: [], incidents: [] });
    const audit = await t.privileged.query("SELECT details FROM audit_log WHERE tenant_id = $1 AND action = 'asset.updated' AND target_id = $2", [tenant.tenantId, web.body.id]);
    expect(audit.rows[0].details.changed.criticality).toEqual({ from: "high", to: "crown_jewel" });
  });

  it("registers agents idempotently and reports effective health", async () => {
    const body = { organizationId: o2, hostname: "nurse-ws-01", platform: "windows", version: "4.9.2", engine: "wazuh", status: "protected", antivirusStatus: "protected", firewallEnabled: true, os: "Windows 11", ipAddresses: ["10.30.20.11"] };
    const first = await admin.post("/agents", body);
    expect(first.status).toBe(201);
    expect(first.body.assetId).toBeTruthy();
    const heartbeat = await admin.post("/agents", { ...body, version: "4.9.3", lastCheckinAt: new Date(Date.now() - 30 * 3_600_000).toISOString() });
    expect(heartbeat.status).toBe(200);
    expect(heartbeat.body).toMatchObject({ id: first.body.id, version: "4.9.3", status: "protected" }); // last_checkin keeps the newest value
    await t.privileged.query("UPDATE agents SET last_checkin_at = now() - interval '30 hours' WHERE id = $1", [first.body.id]);
    const list = await admin.get(`/agents?organizationId=${o2}`);
    expect(list.body.items).toEqual([expect.objectContaining({ hostname: "nurse-ws-01", status: "unresponsive", reportedStatus: "protected" })]);
    expect((await admin.get("/agents?status=unresponsive")).body.items).toHaveLength(1);
    expect((await admin.get(`/assets/${first.body.assetId}`)).body.agents[0].status).toBe("unresponsive");
    const registered = await t.privileged.query("SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1 AND action = 'agent.registered'", [tenant.tenantId]);
    expect(registered.rows[0].n).toBe(1);
  });

  it("upserts identities, scores them from evidence and exposes graph access", async () => {
    const res = await admin.post("/identities", { organizationId: o1, provider: "entra-id", principal: "Domain.Admin@corp.example", privileged: true, mfaEnabled: false, displayName: "Domain Admin" });
    expect(res.status).toBe(201);
    // No evidence of attack yet: likelihood is zero, but the privilege is already explained.
    expect(res.body.risk.factors.find((f: Json) => f.key === "privilege")).toMatchObject({ value: 1 });
    const failures = Array.from({ length: 12 }, (_, i) => ({
      timestamp: new Date(Date.now() - (20 - i) * 60_000).toISOString(),
      source: { kind: "identity", product: "entra-id" },
      category: "authentication",
      eventType: "sign_in",
      outcome: "failure",
      identity: { provider: "entra-id", principal: "domain.admin@corp.example", sourceIp: "203.0.113.50", outcome: "failure" },
    }));
    expect((await admin.post("/ingest/events", { organizationId: o1, events: failures })).body.accepted).toBe(12);
    await t.services.bus.drain();
    const rescored = await admin.post("/identities", { organizationId: o1, provider: "entra-id", principal: "domain.admin@corp.example", privileged: true, mfaEnabled: false });
    expect(rescored.body.id).toBe(res.body.id);
    expect(rescored.body.riskScore).toBeGreaterThan(0);
    expect(rescored.body.risk.factors.find((f: Json) => f.key === "risky_sign_ins").contribution).toBeGreaterThan(0);
    const again = await admin.post("/identities", { organizationId: o1, provider: "ENTRA-ID", principal: "domain.admin@corp.example", privileged: true, mfaEnabled: true });
    expect(again.body.id).toBe(res.body.id);
    expect(again.body.riskScore).toBeLessThan(rescored.body.riskScore);
    expect(again.body.risk.factors.find((f: Json) => f.key === "mfa").contribution).toBeLessThan(0);
    const asset = (await admin.get("/assets?q=Db-01")).body.items[0];
    await t.db.withTenant(tenant.tenantId, (tx) => t.services.inventory.setIdentityAccess(tx, tenant.tenantId, res.body.id, [{ assetId: asset.id, level: "admin" }]));
    const detail = await admin.get(`/identities/${res.body.id}`);
    expect(detail.status).toBe(200);
    expect(JSON.stringify(detail.body)).toContain(asset.id);
    const patched = await admin.patch(`/identities/${res.body.id}`, { enabled: false });
    expect(patched.body.enabled).toBe(false);
    expect((await admin.get(`/identities?organizationId=${o1}&privileged=true`)).body.items.map((i: Json) => i.id)).toContain(res.body.id);
    expect((await admin.get("/identities?mfa=false&privileged=true")).body.items.map((i: Json) => i.id)).not.toContain(res.body.id);
  });
});
