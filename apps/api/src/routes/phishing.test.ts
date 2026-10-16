import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let other: TestTenant;
let admin: ReturnType<typeof api>;
let analyst: ReturnType<typeof api>;
let otherAdmin: ReturnType<typeof api>;
let org: string;
const mails: Array<{ from: { name: string; address: string }; to: { address: string }; subject: string; text: string; html: string; headers: Record<string, string> }> = [];

const caught = (token: string) => t.app.inject({ method: "POST", url: `/api/v1/caught/${token}` });
const tokenIn = (text: string) => /\/caught\/(p_[A-Za-z0-9_-]+)/.exec(text)![1]!;
const launch = (who: ReturnType<typeof api>, extra: object = {}) =>
  who.post("/awareness/phishing/campaigns", { organizationId: org, name: "Q4 mailbox test", template: "mailbox_full", reference: "MSA-2026-014 §6 phishing simulations", attest: true, ...extra });

beforeAll(async () => {
  t = await createTestApp({ deps: { hostResolver: false, emailTransport: { sendMail: async (m: never) => (mails.push(m), { messageId: "x" }) } as never } });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  other = await createTenant(t, { orgs: 1, plan: "mssp" });
  org = tenant.orgIds[0]!;
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  otherAdmin = api(t.app, { token: (await login(t.app, other.admin.email)).token });
  const a = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: null }] });
  analyst = api(t.app, { token: (await login(t.app, a.email)).token });
  await admin.post("/awareness/learners", { organizationId: org, name: "Amina Mushi", email: "amina@kb.example" });
  await admin.post("/awareness/learners", { organizationId: org, name: "Joseph Mrema", email: "joseph@kb.example" });
});
afterAll(async () => {
  await t?.close();
});

describe("phishing simulations", () => {
  it("lists generic templates", async () => {
    const items = (await admin.get("/awareness/phishing/templates")).body.items;
    expect(items.length).toBeGreaterThanOrEqual(5);
    expect(items[0]).toMatchObject({ key: "mailbox_full", fromName: "IT Service Desk", redFlags: expect.any(Array) });
  });

  it("needs an attested authorization and org:write to launch", async () => {
    expect((await launch(admin, { attest: false })).status).toBe(400);
    expect((await launch(admin, { reference: "" })).status).toBe(400);
    expect((await launch(admin, { template: "real_bank" })).status).toBe(400);
    expect((await launch(analyst)).status).toBe(403);
    expect((await launch(otherAdmin)).status).toBe(404);
    expect(mails).toHaveLength(0);
  });

  it("sends from the platform address under a generic name, marked as a simulation", async () => {
    const res = await launch(admin);
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ recipients: 2, sent: 2, failed: 0 });
    expect(mails).toHaveLength(2);
    const m = mails.find((x) => x.to.address === "amina@kb.example")!;
    expect(m.from.name).toBe("IT Service Desk");
    expect(m.from.address).not.toMatch(/kb\.example/);
    expect(m.subject).toBe("Action required: your mailbox is 98% full");
    expect(m.headers["X-SCIAT-Simulation"]).toBe(`phishing; campaign=${res.body.id}`);
    expect(m.text).toContain("Dear Amina Mushi");
    expect(m.text).toMatch(/\/caught\/p_[A-Za-z0-9_-]{76}/);
    expect(m.html).toContain('<a href="');
    const audit = await t.privileged.query("SELECT details FROM audit_log WHERE tenant_id = $1 AND action = 'awareness.phishing_launched'", [tenant.tenantId]);
    expect(audit.rows[0].details).toMatchObject({ reference: "MSA-2026-014 §6 phishing simulations", attested: true, recipients: 2 });
  });

  it("a click reveals the simulation, is recorded once per person and enrols them in the lesson", async () => {
    const token = tokenIn(mails.find((x) => x.to.address === "amina@kb.example")!.text);
    // The email link itself is only a page: fetching it does nothing; the page POSTs.
    expect((await t.app.inject({ method: "GET", url: `/api/v1/caught/${token}` })).statusCode).toBe(404);
    const r = await caught(token);
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({
      organization: { name: expect.any(String) },
      learner: { name: "Amina Mushi" },
      email: { fromName: "IT Service Desk", subject: "Action required: your mailbox is 98% full" },
      lesson: { title: "Spotting phishing emails and messages" },
      trainingUrl: expect.stringMatching(/\/learn\/p_/),
    });
    expect(r.json().redFlags.length).toBeGreaterThan(1);
    // The follow-up training link works.
    const learn = r.json().trainingUrl.split("/learn/")[1];
    expect((await t.app.inject({ method: "GET", url: `/api/v1/learn/${learn}` })).json()).toMatchObject({ assignment: { title: "Follow-up: Q4 mailbox test" } });
    // Visiting again (or a page refresh) keeps the same training link working.
    expect((await caught(token)).json().trainingUrl).toBe(r.json().trainingUrl);
    expect((await t.app.inject({ method: "GET", url: `/api/v1/learn/${learn}` })).statusCode).toBe(200);
    expect((await caught(`${token.slice(0, -2)}xx`)).statusCode).toBe(404);
    // Someone who did not click has no follow-up training behind their link.
    const josephToken = tokenIn(mails.find((x) => x.to.address === "joseph@kb.example")!.text);
    expect((await t.app.inject({ method: "GET", url: `/api/v1/learn/${josephToken}` })).statusCode).toBe(404);

    const c = (await admin.get(`/awareness/phishing/campaigns?organizationId=${org}`)).body;
    expect(c.canEmail).toBe(true);
    const targets = c.campaigns[0].targets;
    expect(targets.find((x: { learnerEmail: string }) => x.learnerEmail === "amina@kb.example")).toMatchObject({ sentAt: expect.any(String), clickedAt: expect.any(String) });
    expect(targets.find((x: { learnerEmail: string }) => x.learnerEmail === "joseph@kb.example").clickedAt).toBeNull();
    const clicks = await t.privileged.query("SELECT click_count FROM sat_phish_targets WHERE clicked_at IS NOT NULL");
    expect(clicks.rows.map((x) => x.click_count)).toEqual([2]);
    // One follow-up assignment, holding only the person who clicked.
    const o = (await admin.get(`/awareness/overview?organizationId=${org}`)).body;
    const follow = o.assignments.filter((a: { title: string }) => a.title.startsWith("Follow-up"));
    expect(follow).toHaveLength(1);
    expect(follow[0].enrolments.map((e: { learnerEmail: string }) => e.learnerEmail)).toEqual(["amina@kb.example"]);
    expect((await otherAdmin.get(`/awareness/phishing/campaigns?organizationId=${org}`)).status).toBe(404);
  });
});
