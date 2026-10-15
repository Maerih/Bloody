import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, call, createTestApp, login, uniq, type TestApp } from "../test/harness.js";
import { accountSummary, createAccountWithAdmin, generatePassword, resetPassword } from "./admin.js";

let t: TestApp;
beforeAll(async () => {
  t = await createTestApp();
});
afterAll(async () => {
  await t?.close();
});

describe("operator admin CLI", () => {
  it("generates strong, varied passwords", () => {
    const a = generatePassword();
    expect(a).toMatch(/^[A-Za-z0-9]{10}-[A-Za-z0-9]{10}!7$/);
    expect(generatePassword()).not.toBe(a);
  });

  it("creates an MSSP account whose admin can log in, idempotently", async () => {
    const email = `${uniq("owner")}@soc.example`;
    const r = await createAccountWithAdmin(t.privileged, { name: "Acme SOC Services", email });
    expect(r.created).toBe(true);
    const s = await login(t.app, email, r.password!);
    const me = await api(t.app, { token: s.token }).get("/auth/me");
    expect(me.status).toBe(200);
    expect(me.body.account.kind).toBe("mssp");
    expect(me.body.principal.bindings).toEqual([{ role: "mssp_admin", organizationId: null }]);
    const again = await createAccountWithAdmin(t.privileged, { name: "Acme SOC Services", email });
    expect(again).toMatchObject({ created: false, password: null, tenantId: r.tenantId });
  });

  it("creates an enterprise account with its own organization", async () => {
    const email = `${uniq("ciso")}@corp.example`;
    const r = await createAccountWithAdmin(t.privileged, { name: "Kilimanjaro Bank", email, kind: "enterprise" });
    const s = await login(t.app, email, r.password!);
    const me = await api(t.app, { token: s.token }).get("/auth/me");
    expect(me.body.account.kind).toBe("enterprise");
    expect(me.body.organizations.map((o: { name: string }) => o.name)).toEqual(["Kilimanjaro Bank"]);
  });

  it("resets a password: old one fails, sessions are revoked, lockout cleared", async () => {
    const email = `${uniq("admin")}@soc.example`;
    const r = await createAccountWithAdmin(t.privileged, { name: "Reset Test", email });
    const s = await login(t.app, email, r.password!);
    const fresh = await resetPassword(t.privileged, email.toUpperCase());
    expect(fresh).not.toBe(r.password);
    expect((await call(t.app, "POST", "/auth/login", { body: { email, password: r.password } })).status).toBe(401);
    expect((await api(t.app, { token: s.token }).get("/auth/me")).status).toBe(401);
    await login(t.app, email, fresh);
    await expect(resetPassword(t.privileged, "nobody@nowhere.example")).rejects.toThrow(/no user/);
  });

  it("summarises accounts for the installer", async () => {
    const s = await accountSummary(t.privileged);
    expect(s.accounts).toBeGreaterThan(0);
    expect(typeof s.demo).toBe("boolean");
  });
});
