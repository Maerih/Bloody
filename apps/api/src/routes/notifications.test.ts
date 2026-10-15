import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, login, type Json, type TestApp, type TestTenant } from "../test/harness.js";

const HOOK_URL = "https://hooks.example.test/bloody/secret-path-123";
const sentHttp: { url: string; headers: Record<string, string>; body: string }[] = [];
const sentMail: Json[] = [];

let t: TestApp;
let tenant: TestTenant;
let org: string;
let admin: ReturnType<typeof api>;
let other: ReturnType<typeof api>;
let webhookId: string;

beforeAll(async () => {
  t = await createTestApp({
    deps: {
      hostResolver: false,
      httpTransport: {
        async request(req) {
          sentHttp.push({ url: req.url, headers: req.headers, body: req.body });
          return { status: 200, headers: {}, body: "ok" };
        },
      },
      emailTransport: {
        async sendMail(mail: Json) {
          sentMail.push(mail);
          return { messageId: "<test@bloody>", accepted: [mail.to], rejected: [] };
        },
      } as never,
    },
  });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  org = tenant.orgIds[0]!;
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const o = await createTenant(t, { orgs: 1 });
  other = api(t.app, { token: (await login(t.app, o.admin.email)).token });
});
afterAll(async () => {
  await t?.close();
});

describe("notification channels", () => {
  it("creates a signed webhook channel without echoing its URL or secret", async () => {
    const res = await admin.post("/notifications/channels", { name: "SOC webhook", kind: "webhook", config: { url: HOOK_URL, secret: "hmac-signing-secret-xyz" } });
    expect(res.status).toBe(201);
    webhookId = res.body.id;
    const text = JSON.stringify(res.body) + JSON.stringify((await admin.get("/notifications/channels")).body);
    expect(text).not.toContain("secret-path-123");
    expect(text).not.toContain("hmac-signing-secret-xyz");
  });

  it("sends a signed test message", async () => {
    const res = await admin.post(`/notifications/channels/${webhookId}/test`, {});
    expect(res.status).toBe(200);
    const last = sentHttp.at(-1)!;
    expect(last.url).toBe(HOOK_URL);
    expect(Object.keys(last.headers).map((h) => h.toLowerCase())).toContain("x-bloody-signature");
  });

  it("sends a test email", async () => {
    const ch = await admin.post("/notifications/channels", { name: "CISO email", kind: "email", config: { to: ["ciso@customer.example"] } });
    expect(ch.status).toBe(201);
    const res = await admin.post(`/notifications/channels/${ch.body.id}/test`, {});
    expect(res.status).toBe(200);
    expect(JSON.stringify(sentMail.at(-1))).toContain("ciso@customer.example");
  });

  it("keeps channels per tenant", async () => {
    expect((await other.get(`/notifications/channels/${webhookId}`)).status).toBe(404);
  });
});

describe("automation rules", () => {
  it("notifies the webhook when an incident is created", async () => {
    const rule = await admin.post("/automations", {
      name: "Critical incidents to SOC",
      event: "incident.created",
      channelIds: [webhookId],
      template: { subject: "New incident {{incident.title}}", body: "Severity {{incident.severity}}" },
    });
    expect(rule.status).toBe(201);
    const before = sentHttp.length;
    const inc = await admin.post("/incidents", { organizationId: org, title: "Ransomware on FS-01", severity: "critical", summary: "Mass rename detected" });
    expect(inc.status).toBe(201);
    await t.services.bus.drain();
    for (let i = 0; i < 50 && sentHttp.length === before; i++) await new Promise((r) => setTimeout(r, 50));
    expect(sentHttp.length).toBeGreaterThan(before);
    expect(sentHttp.slice(before).map((h) => h.body).join("\n")).toContain("Ransomware on FS-01");
  });
});

describe("playbooks", () => {
  it("creates, versions and runs a manual playbook", async () => {
    const created = await admin.post("/playbooks", {
      name: "Triage helper",
      organizationId: org,
      enabled: true,
      trigger: { on: "manual" },
      conditions: [],
      steps: [{ id: "s1", action: "notify_analyst", parameters: { message: "Please triage" } }],
    });
    expect(created.status).toBe(201);
    const id = created.body.id;
    const run = await admin.post(`/playbooks/${id}/run`, { organizationId: org });
    expect(run.status).toBeLessThan(300);
    const runs = await admin.get("/playbooks/runs");
    expect(runs.status).toBe(200);
    expect(JSON.stringify(runs.body)).toContain(id);
    expect((await other.get(`/playbooks/${id}`)).status).toBe(404);
  });
});
