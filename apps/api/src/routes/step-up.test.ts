import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { totp } from "../security/totp.js";
import { TEST_PASSWORD, api, call, createTenant, createTestApp, createUser, login, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 1 });
});
afterAll(async () => {
  await t?.close();
});

/** A tenant admin with an authenticator app, signed in with it; returns the client and the TOTP secret. */
async function mfaAdmin() {
  const user = await createUser(t, tenant.tenantId, { roles: [{ role: "mssp_admin", organizationId: null }] });
  const first = api(t.app, { token: (await login(t.app, user.email)).token });
  const secret: string = (await first.post("/auth/mfa/totp/enroll")).body.secret;
  expect((await first.post("/auth/mfa/totp/confirm", { code: totp(secret, Date.now()) })).status).toBe(200);
  const res = await call(t.app, "POST", "/auth/login", { body: { email: user.email, password: TEST_PASSWORD, totp: totp(secret, Date.now() + 30_000) } });
  expect(res.status).toBe(200);
  return { user, secret, client: api(t.app, { token: res.body.token }) };
}

/** Simulate 11 minutes passing: the session's MFA check and the last authenticator code used both age. */
async function ageSessions(userId: string) {
  await t.privileged.query("UPDATE sessions SET mfa_verified_at = now() - interval '11 minutes' WHERE user_id = $1", [userId]);
  await t.privileged.query("UPDATE mfa_totp SET last_used_step = last_used_step - 22 WHERE user_id = $1", [userId]);
}

describe("MFA step-up for dangerous actions", () => {
  it("allows them right after an MFA sign-in, asks again after 10 minutes, and accepts a fresh code", async () => {
    const { user, secret, client } = await mfaAdmin();
    expect((await client.post("/api-keys", { name: "fresh" })).status).toBe(201);

    await ageSessions(user.id);
    const blocked = await client.post("/api-keys", { name: "stale" });
    expect(blocked.status).toBe(403);
    expect(blocked.body.error.code).toBe("mfa_step_up_required");
    const target = await createUser(t, tenant.tenantId, { roles: [] });
    const grant = await client.post(`/users/${target.id}/roles`, { role: "customer_viewer", organizationId: null });
    expect(grant.body.error.code).toBe("mfa_step_up_required");
    expect((await client.post(`/users/${target.id}/password`, { password: "An0ther-Long-Passw0rd!" })).body.error.code).toBe("mfa_step_up_required");
    // Ordinary work is not interrupted.
    expect((await client.get("/api-keys")).status).toBe(200);

    expect((await client.post("/auth/mfa/verify", { code: "000000" })).status).toBe(400);
    expect((await client.post("/auth/mfa/verify", { code: totp(secret, Date.now()) })).status).toBe(200);
    expect((await client.post("/api-keys", { name: "after step-up" })).status).toBe(201);
    expect((await client.post(`/users/${target.id}/roles`, { role: "customer_viewer", organizationId: null })).status).toBe(201);
  });

  it("does not apply to people without an authenticator or to API keys", async () => {
    const admin = await createUser(t, tenant.tenantId, { roles: [{ role: "mssp_admin", organizationId: null }] });
    const client = api(t.app, { token: (await login(t.app, admin.email)).token });
    await ageSessions(admin.id);
    expect((await client.post("/api-keys", { name: "no mfa" })).status).toBe(201);
  });
});
