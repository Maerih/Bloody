import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { MailServerService } from "../services/mail-server.js";
import { api, createApiKey, createTenant, createTestApp, createUser, login, type TestApp, type TestTenant } from "../test/harness.js";

type Json = Record<string, any>;
let t: TestApp;
let tenant: TestTenant;
let admin: ReturnType<typeof api>;
let adminToken: string;
const sentMail: Json[] = [];
const SERVER = { host: "smtp.mail.example.com", port: 587, encryption: "starttls", username: "soc@example.com", password: "app-password-123", fromAddress: "soc@example.com", fromName: "Example SOC" };

beforeAll(async () => {
  t = await createTestApp({
    deps: {
      emailTransport: {
        async sendMail(mail: Json) {
          sentMail.push(mail);
          return { messageId: "<test@sciat>" };
        },
      } as never,
    },
  });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  adminToken = (await login(t.app, tenant.admin.email)).token;
  admin = api(t.app, { token: adminToken });
});
afterAll(async () => {
  await t?.close();
});

describe("Settings → Email server", () => {
  it("saves the server with a write-only password and sends account mail from it", async () => {
    expect((await admin.get("/settings/email-server")).body).toMatchObject({ source: "platform", account: null });
    const saved = await admin.put("/settings/email-server", SERVER);
    expect(saved.status).toBe(200);
    expect(saved.body).toMatchObject({ source: "account", account: { host: "smtp.mail.example.com", port: 587, encryption: "starttls", username: "soc@example.com", hasPassword: true, fromAddress: "soc@example.com", fromName: "Example SOC" } });
    expect(JSON.stringify(saved.body)).not.toContain("app-password-123");
    const stored = await t.privileged.query("SELECT settings->'mailServer' AS m FROM accounts WHERE id = $1", [tenant.tenantId]);
    expect(JSON.stringify(stored.rows[0]!.m)).not.toContain("app-password-123");
    expect(stored.rows[0]!.m.passwordRef).toMatch(/^sec_/);

    const test = await admin.post("/settings/email-server/test", { to: "me@example.com" });
    expect(test.status).toBe(200);
    expect(sentMail.at(-1)).toMatchObject({ to: "me@example.com", from: { address: "soc@example.com", name: "Example SOC" } });

    // Notification e-mail channels without their own server use the account's.
    const ch = await admin.post("/notifications/channels", { name: "SOC mail", kind: "email", config: { to: ["soc-team@example.com"] } });
    expect(ch.status).toBe(201);
    expect((await admin.post(`/notifications/channels/${ch.body.id}/test`)).body.ok).toBe(true);
    expect(JSON.stringify(sentMail.at(-1)!.from)).toContain("soc@example.com");

    const audit = await t.privileged.query("SELECT action, details FROM audit_log WHERE tenant_id = $1 AND action LIKE 'settings.email_server%' ORDER BY seq", [tenant.tenantId]);
    expect(audit.rows.map((r) => r.action)).toEqual(["settings.email_server_changed", "settings.email_server_tested"]);
    expect(JSON.stringify(audit.rows)).not.toContain("app-password-123");
  });

  it("asks for the password again when the server or user changes, and keeps it otherwise", async () => {
    const { password: _p, ...withoutPassword } = SERVER;
    expect((await admin.put("/settings/email-server", { ...withoutPassword, port: 2525 })).status).toBe(200);
    const moved = await admin.put("/settings/email-server", { ...withoutPassword, host: "smtp.attacker.example" });
    expect(moved.status).toBe(400);
    expect(moved.body.error.message).toMatch(/password again/);
    expect((await admin.put("/settings/email-server", { ...SERVER, host: "smtp.other.example" })).status).toBe(200);
    // No sign-in: the stored password is removed.
    const anon = await admin.put("/settings/email-server", { ...withoutPassword, username: null });
    expect(anon.body.account).toMatchObject({ username: null, hasPassword: false });
  });

  it("refuses this machine and cloud metadata as mail servers", async () => {
    for (const host of ["127.0.0.1", "localhost", "169.254.169.254", "metadata.google.internal"]) {
      const res = await admin.put("/settings/email-server", { ...SERVER, host });
      expect(res.status, host).toBe(400);
    }
    // Internal relays (e.g. on-premises Exchange) follow INTEGRATIONS_ALLOW_PRIVATE_NETWORKS (on here).
    expect((await admin.put("/settings/email-server", { ...SERVER, host: "10.0.0.5" })).status).toBe(200);
    expect((await admin.put("/settings/email-server", { ...SERVER, host: "https://smtp.example.com" })).status).toBe(400);
    // The same rule for a notification channel's own mail server.
    const ch = await admin.post("/notifications/channels", { name: "Loop", kind: "email", config: { to: ["a@example.com"], smtp: { host: "127.0.0.1", port: 25, fromAddress: "a@example.com" } } });
    expect(ch.status).toBe(400);
    expect((await admin.put("/settings/email-server", { ...SERVER, encryption: "none" })).status).toBe(400);
  });

  it("is limited to account administrators, and API keys cannot change it", async () => {
    const orgAdmin = await createUser(t, tenant.tenantId, { roles: [{ role: "org_admin", organizationId: tenant.orgIds[0]! }] });
    const oa = api(t.app, { token: (await login(t.app, orgAdmin.email)).token });
    expect((await oa.get("/settings/email-server")).status).toBe(403);
    expect((await oa.put("/settings/email-server", SERVER)).status).toBe(403);
    const key = await createApiKey(t.app, adminToken, { organizationId: null, roles: ["mssp_admin"] });
    const res = await api(t.app, { apiKey: key.key }).put("/settings/email-server", SERVER);
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe("person_required");
  });

  it("goes back to the platform default and deletes the stored password", async () => {
    await admin.put("/settings/email-server", SERVER);
    const ref = (await t.privileged.query("SELECT settings->'mailServer'->>'passwordRef' AS r FROM accounts WHERE id = $1", [tenant.tenantId])).rows[0]!.r;
    const res = await admin.delete("/settings/email-server");
    expect(res.body).toMatchObject({ source: "platform", account: null });
    expect((await t.privileged.query("SELECT 1 FROM secrets WHERE ref = $1", [ref])).rowCount).toBe(0);
  });
});

describe("mail server connections", () => {
  const svc = (allowPrivateNetworks: boolean, address: string) =>
    new MailServerService({
      db: t.db,
      secretStore: null as never,
      platform: null,
      override: null,
      allowPrivateNetworks,
      lookup: (_host, _opts, cb) => cb(null, [{ address, family: 4 }]),
    });

  it("connects to the address it checked and verifies the certificate against the host name", async () => {
    const tr = (await svc(false, "93.184.215.14").transportFor({ host: "smtp.mail.example.com", port: 465, secure: true, fromAddress: "a@example.com" }, false)) as unknown as { options: Json };
    expect(tr.options).toMatchObject({ host: "93.184.215.14", port: 465, secure: true, tls: { servername: "smtp.mail.example.com", rejectUnauthorized: true } });
  });

  it("refuses a name that resolves to an internal address unless private networks are allowed", async () => {
    await expect(svc(false, "10.0.0.5").transportFor({ host: "10.0.0.5", port: 587, secure: false, fromAddress: "a@example.com" }, false)).rejects.toThrow(/not allowed/);
    await expect(svc(true, "127.0.0.1").transportFor({ host: "smtp.mail.example.com", port: 587, secure: false, fromAddress: "a@example.com" }, false)).rejects.toThrow(/blocked/);
    await expect(svc(false, "10.1.2.3").transportFor({ host: "smtp.mail.example.com", port: 587, secure: false, fromAddress: "a@example.com" }, false)).rejects.toThrow(/blocked/);
    await expect(svc(false, "169.254.169.254").transportFor({ host: "smtp.mail.example.com", port: 587, secure: false, fromAddress: "a@example.com" }, false)).rejects.toThrow(/blocked/);
    await expect(svc(true, "10.1.2.3").transportFor({ host: "smtp.mail.example.com", port: 587, secure: false, fromAddress: "a@example.com" }, false)).resolves.toBeTruthy();
  });
});
