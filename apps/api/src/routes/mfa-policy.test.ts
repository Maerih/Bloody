import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { totp } from "../security/totp.js";
import { TEST_PASSWORD, api, call, createApiKey, createTenant, createTestApp, createUser, login, type TestApp } from "../test/harness.js";

let t: TestApp;

beforeAll(async () => {
  t = await createTestApp();
});
afterAll(async () => {
  await t?.close();
});

/** A code the server has not seen yet (rewinds the replay guard instead of waiting 30 seconds). */
async function unusedCode(userId: string, secret: string): Promise<string> {
  await t.privileged.query("UPDATE mfa_totp SET last_used_step = last_used_step - 3 WHERE user_id = $1", [userId]);
  return totp(secret, Date.now());
}

/** A user with an authenticator app, signed in with it; returns the client and the TOTP secret. */
async function withAuthenticator(tenantId: string, role: "mssp_admin" | "soc_analyst_t2" = "mssp_admin") {
  const user = await createUser(t, tenantId, { roles: [{ role, organizationId: null }] });
  const first = api(t.app, { token: (await login(t.app, user.email)).token });
  const secret: string = (await first.post("/auth/mfa/totp/enroll")).body.secret;
  expect((await first.post("/auth/mfa/totp/confirm", { code: totp(secret, Date.now()) })).status).toBe(200);
  const res = await call(t.app, "POST", "/auth/login", { body: { email: user.email, password: TEST_PASSWORD, totp: totp(secret, Date.now() + 30_000) } });
  expect(res.status).toBe(200);
  return { user, secret, token: res.body.token as string, client: api(t.app, { token: res.body.token }) };
}

describe("turning MFA off yourself", () => {
  it("needs a valid code and updates the profile", async () => {
    const tenant = await createTenant(t, { orgs: 1 });
    const { user, secret, client } = await withAuthenticator(tenant.tenantId, "soc_analyst_t2");
    expect((await client.get("/auth/me")).body.user.mfaEnabled).toBe(true);
    // Setting up a second authenticator over a working one is refused.
    expect((await client.post("/auth/mfa/totp/enroll")).status).toBe(409);

    const bad = await client.post("/auth/mfa/totp/disable", { code: "000000" });
    expect(bad.status).toBe(400);
    expect(bad.body.error.code).toBe("invalid_mfa_code");
    expect((await client.post("/auth/mfa/totp/disable", { code: await unusedCode(user.id, secret) })).body).toEqual({ mfaEnabled: false });
    expect((await client.get("/auth/me")).body.user.mfaEnabled).toBe(false);
  });
});

describe("requiring MFA for everyone", () => {
  it("only an administrator who uses MFA can switch it on", async () => {
    const tenant = await createTenant(t, { orgs: 1 });
    const analyst = api(t.app, { token: (await login(t.app, (await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t2", organizationId: null }] })).email)).token });
    expect((await analyst.put("/auth/mfa/policy", { requireMfa: true })).status).toBe(403);

    const plainAdmin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
    const before = await plainAdmin.get("/auth/mfa/policy");
    expect(before.status).toBe(200);
    expect(before.body.requireMfa).toBe(false);
    expect(before.body.usersWithoutMfa).toBeGreaterThanOrEqual(2);
    const lockout = await plainAdmin.put("/auth/mfa/policy", { requireMfa: true });
    expect(lockout.status).toBe(409);
    expect(lockout.body.error.code).toBe("mfa_setup_first");

    const { client } = await withAuthenticator(tenant.tenantId);
    expect((await client.put("/auth/mfa/policy", { requireMfa: true })).body).toEqual({ requireMfa: true });
    expect((await client.get("/auth/mfa/policy")).body.requireMfa).toBe(true);
    const audit = await t.privileged.query("SELECT details FROM audit_log WHERE tenant_id = $1 AND action = 'auth.mfa_policy_changed'", [tenant.tenantId]);
    expect(audit.rows[0]?.details).toMatchObject({ requireMfa: true });
  });

  it("holds people without MFA at the setup screen until they set it up", async () => {
    const tenant = await createTenant(t, { orgs: 1 });
    const { client: admin, token: adminToken } = await withAuthenticator(tenant.tenantId);
    expect((await admin.put("/auth/mfa/policy", { requireMfa: true })).status).toBe(200);

    // Signing in with a password still works, so they can reach the setup screen.
    const analyst = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t2", organizationId: null }] });
    const client = api(t.app, { token: (await login(t.app, analyst.email)).token });
    const me = await client.get("/auth/me");
    expect(me.status).toBe(200);
    expect(me.body.user.mfaSetupRequired).toBe(true);
    expect(me.body.account.requireMfa).toBe(true);
    const held = await client.get("/users");
    expect(held.status).toBe(403);
    expect(held.body.error.code).toBe("mfa_enrollment_required");
    expect((await client.post("/auth/mfa/verify", { code: "123456" })).body.error.code).toBe("mfa_enrollment_required");

    const secret: string = (await client.post("/auth/mfa/totp/enroll")).body.secret;
    expect((await client.post("/auth/mfa/totp/confirm", { code: totp(secret, Date.now()) })).status).toBe(200);
    expect((await client.get("/auth/me")).body.user.mfaSetupRequired).toBe(false);
    expect((await client.get("/users")).status).toBe(200);

    // While the account requires MFA it cannot be turned off.
    const off = await client.post("/auth/mfa/totp/disable", { code: await unusedCode(analyst.id, secret) });
    expect(off.status).toBe(409);
    expect(off.body.error.code).toBe("mfa_required_by_policy");

    // Administrators already signed in, and API keys, keep working.
    expect((await admin.get("/users")).status).toBe(200);
    const { key } = await createApiKey(t.app, adminToken, { organizationId: null });
    const viaKey = await api(t.app, { apiKey: key }).get("/assets");
    expect(viaKey.body).not.toMatchObject({ error: { code: "mfa_enrollment_required" } });
    expect(viaKey.status).toBe(200);

    // Switching the policy off releases everyone straight away.
    expect((await admin.put("/auth/mfa/policy", { requireMfa: false })).status).toBe(200);
    const other = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t2", organizationId: null }] });
    expect((await api(t.app, { token: (await login(t.app, other.email)).token }).get("/users")).status).toBe(200);
  });
});

describe("administrator MFA reset (lost phone)", () => {
  it("removes the authenticator, signs the person out and is audited", async () => {
    const tenant = await createTenant(t, { orgs: 1 });
    const { user: adminUser, client: admin } = await withAuthenticator(tenant.tenantId);
    const { user: target, secret, client: targetClient } = await withAuthenticator(tenant.tenantId, "soc_analyst_t2");

    expect((await targetClient.delete(`/users/${adminUser.id}/mfa`)).status).toBe(403);
    expect((await admin.delete(`/users/${adminUser.id}/mfa`)).status).toBe(400);

    expect((await admin.delete(`/users/${target.id}/mfa`)).status).toBe(204);
    expect((await targetClient.get("/auth/me")).status).toBe(401);
    const row = await t.privileged.query<{ mfa_enabled: boolean }>("SELECT mfa_enabled FROM users WHERE id = $1", [target.id]);
    expect(row.rows[0]!.mfa_enabled).toBe(false);
    expect((await t.privileged.query("SELECT 1 FROM mfa_totp WHERE user_id = $1", [target.id])).rowCount).toBe(0);
    const audit = await t.privileged.query("SELECT outcome FROM audit_log WHERE tenant_id = $1 AND action = 'user.mfa_reset' AND target_id = $2", [tenant.tenantId, target.id]);
    expect(audit.rows[0]?.outcome).toBe("success");

    // The old authenticator no longer works; the password alone signs them in to set up a new one.
    const res = await call(t.app, "POST", "/auth/login", { body: { email: target.email, password: TEST_PASSWORD, totp: totp(secret, Date.now() + 90_000) } });
    expect(res.status).toBe(200);
    expect(res.body.mfaRequired).toBeUndefined();
    expect((await admin.delete(`/users/${target.id}/mfa`)).body.error.code).toBe("mfa_not_enabled");
  });
});
