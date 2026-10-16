import { LESSONS } from "@bloody/contracts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let other: TestTenant;
let admin: ReturnType<typeof api>;
let analyst: ReturnType<typeof api>;
let otherAdmin: ReturnType<typeof api>;
let org: string;
const mails: Array<{ to: { address: string }; subject: string; text: string }> = [];

const learn = (method: "GET" | "POST", url: string, body?: object) =>
  t.app.inject({ method, url: `/api/v1${url}`, ...(body ? { headers: { "content-type": "application/json" }, payload: JSON.stringify(body) } : {}) });
const tokenOf = (url: string) => url.split("/learn/")[1]!;
const answersFor = (key: string, wrong = 0) => {
  const l = LESSONS.find((x) => x.key === key)!;
  return Object.fromEntries(l.quiz.map((q, i) => [q.id, i < wrong ? (q.correct + 1) % q.options.length : q.correct]));
};

beforeAll(async () => {
  t = await createTestApp({
    deps: {
      hostResolver: false,
      emailTransport: { sendMail: async (m: never) => (mails.push(m), { messageId: "x" }) } as never,
    },
  });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  other = await createTenant(t, { orgs: 1, plan: "mssp" });
  org = tenant.orgIds[0]!;
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  otherAdmin = api(t.app, { token: (await login(t.app, other.admin.email)).token });
  const a = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: null }] });
  analyst = api(t.app, { token: (await login(t.app, a.email)).token });
  await t.db.withTenant(tenant.tenantId, (tx) =>
    tx.query(
      `INSERT INTO identities (tenant_id, organization_id, kind, provider, principal, display_name) VALUES
         ($1, $2, 'user', 'entra-id', 'Amina.Mushi@kb.example', 'Amina Mushi'),
         ($1, $2, 'user', 'entra-id', 'svc-backup', 'Backup service'),
         ($1, $2, 'service_account', 'entra-id', 'app@kb.example', 'App')`,
      [tenant.tenantId, org],
    ),
  );
});
afterAll(async () => {
  await t?.close();
});

describe("Security Awareness Training", () => {
  let assignmentId: string;
  let links: Array<{ enrolmentId: string; email: string; url: string }>;

  it("builds the learner list from the directory and by hand", async () => {
    expect((await admin.post("/awareness/learners/import", { organizationId: org })).body).toEqual({ added: 1 });
    expect((await admin.post("/awareness/learners/import", { organizationId: org })).body).toEqual({ added: 0 });
    expect((await admin.post("/awareness/learners", { organizationId: org, name: "Joseph Mrema", email: "Joseph@KB.example" })).status).toBe(201);
    expect((await admin.post("/awareness/learners", { organizationId: org, name: "Joseph again", email: "joseph@kb.example" })).status).toBe(409);
    expect((await analyst.post("/awareness/learners", { organizationId: org, name: "X", email: "x@kb.example" })).status).toBe(403);
    expect((await otherAdmin.post("/awareness/learners", { organizationId: org, name: "X", email: "x@kb.example" })).status).toBe(404);
    const o = (await admin.get(`/awareness/overview?organizationId=${org}`)).body;
    expect(o.learners.map((l: { email: string; source: string }) => [l.email, l.source])).toEqual([
      ["amina.mushi@kb.example", "directory"],
      ["joseph@kb.example", "manual"],
    ]);
    expect(o.canEmail).toBe(true);
    expect((await analyst.get(`/awareness/overview?organizationId=${org}`)).status).toBe(200);
    expect((await otherAdmin.get(`/awareness/overview?organizationId=${org}`)).status).toBe(404);
  });

  it("assigns lessons with a personal link per learner and emails invitations", async () => {
    expect((await admin.post("/awareness/assignments", { organizationId: org, title: "Q4", lessons: ["nope"] })).status).toBe(400);
    const created = await admin.post("/awareness/assignments", { organizationId: org, title: "Q4 phishing & fraud", lessons: ["phishing", "payment_fraud"], dueAt: new Date(Date.now() + 14 * 86_400_000).toISOString() });
    expect(created.status).toBe(201);
    assignmentId = created.body.id;
    links = created.body.links;
    expect(links).toHaveLength(2);
    expect(links[0]!.url).toMatch(/\/learn\/l_[A-Za-z0-9_-]{76}$/);
    // Only a hash is stored.
    const stored = await t.privileged.query("SELECT token_hash FROM sat_enrolments WHERE assignment_id = $1", [assignmentId]);
    expect(stored.rows.every((r) => !links.some((l) => l.url.includes(r.token_hash)))).toBe(true);

    const sent = await admin.post(`/awareness/assignments/${assignmentId}/invite`, {});
    expect(sent.body).toEqual({ sent: 2, failed: 0 });
    expect(mails.map((m) => m.to.address).sort()).toEqual(["amina.mushi@kb.example", "joseph@kb.example"]);
    expect(mails[0]!.subject).toBe("Security awareness training: Q4 phishing & fraud");
    expect(mails[0]!.text).toContain("Spotting phishing emails and messages");
    // Invitations carry fresh links: the ones returned at creation no longer work.
    expect((await learn("GET", `/learn/${tokenOf(links[0]!.url)}`)).statusCode).toBe(404);
    const fromMail = mails.find((m) => m.to.address === links[0]!.email)!.text.match(/\/learn\/(\S+)/)![1]!;
    links[0]!.url = `x/learn/${fromMail}`;
  });

  it("lets the learner read lessons and pass quizzes without an account, and tracks completion", async () => {
    const token = tokenOf(links[0]!.url);
    const view = await learn("GET", `/learn/${token}`);
    expect(view.statusCode).toBe(200);
    expect(view.json()).toMatchObject({ assignment: { title: "Q4 phishing & fraud", completedAt: null }, lessons: [{ key: "phishing", progress: null }, { key: "payment_fraud", progress: null }] });
    expect(view.body).not.toContain('"correct"');

    const fail = (await learn("POST", `/learn/${token}/lessons/phishing/quiz`, { answers: answersFor("phishing", 2) })).json();
    expect(fail).toMatchObject({ score: 50, passed: false, completed: false });
    expect(fail.questions[0]).toMatchObject({ correct: false, explain: expect.any(String) });
    expect((await learn("POST", `/learn/${token}/lessons/phishing/quiz`, { answers: answersFor("phishing") })).json()).toMatchObject({ score: 100, passed: true, completed: false });
    expect((await learn("POST", `/learn/${token}/lessons/sim_swap/quiz`, { answers: answersFor("sim_swap") })).statusCode).toBe(404);
    expect((await learn("POST", `/learn/${token}/lessons/payment_fraud/quiz`, { answers: answersFor("payment_fraud", 1) })).json()).toMatchObject({ score: 75, passed: true, completed: true });

    const o = (await admin.get(`/awareness/overview?organizationId=${org}`)).body;
    expect(o.summary).toMatchObject({ learners: 2, enrolments: 2, completed: 1, completionRate: 50, overdue: 0 });
    const e = o.assignments[0].enrolments.find((x: { learnerEmail: string }) => x.learnerEmail === links[0]!.email);
    expect(e).toMatchObject({ lessonsPassed: 2, averageScore: 88, completedAt: expect.any(String), invitedAt: expect.any(String) });
  });

  it("refuses bad or tampered links, and a new link replaces the old one", async () => {
    const token = tokenOf(links[1]!.url);
    expect((await learn("GET", "/learn/not-a-token")).statusCode).toBe(404);
    expect((await learn("GET", `/learn/${token.slice(0, -1)}${token.endsWith("A") ? "B" : "A"}`)).statusCode).toBe(404);
    const fresh = await admin.post(`/awareness/enrolments/${links[1]!.enrolmentId}/link`, {});
    expect(fresh.status).toBe(200);
    expect((await learn("GET", `/learn/${tokenOf(fresh.body.url)}`)).statusCode).toBe(200);
    expect((await otherAdmin.post(`/awareness/enrolments/${links[1]!.enrolmentId}/link`, {})).status).toBe(404);
    const audit = await t.privileged.query("SELECT action FROM audit_log WHERE tenant_id = $1 AND action LIKE 'awareness.%' ORDER BY seq", [tenant.tenantId]);
    expect(audit.rows.map((r) => r.action)).toEqual([
      "awareness.learners_imported",
      "awareness.learners_imported",
      "awareness.learner_added",
      "awareness.assignment_created",
      "awareness.invitations_sent",
      "awareness.link_created",
    ]);
  });
});

describe("training reminders", () => {
  it("reminds unfinished people when training is due soon or overdue, at most weekly, and can be turned off", async () => {
    const created = await admin.post("/awareness/assignments", { organizationId: org, title: "Due soon", lessons: ["sim_swap"], dueAt: new Date(Date.now() + 2 * 86_400_000).toISOString() });
    expect(created.status).toBe(201);
    const id = created.body.id;
    const before = mails.length;
    expect(await t.services.awareness.remindDue(tenant.tenantId)).toBe(2);
    const sent = mails.slice(before);
    expect(sent.map((m) => m.subject)).toEqual(['Reminder: security awareness training "Due soon"', 'Reminder: security awareness training "Due soon"']);
    expect(sent[0]!.text).toContain("It replaces the link in earlier emails.");
    // The link in the reminder works.
    const token = sent[0]!.text.match(/\/learn\/(l_[A-Za-z0-9_-]+)/)![1]!;
    expect((await learn("GET", `/learn/${token}`)).statusCode).toBe(200);
    // Not again within a week.
    expect(await t.services.awareness.remindDue(tenant.tenantId)).toBe(0);
    // A week later, overdue: reminded again with an "Overdue" subject.
    await t.privileged.query("UPDATE sat_enrolments SET reminded_at = now() - interval '8 days' WHERE assignment_id = $1", [id]);
    await t.privileged.query("UPDATE sat_assignments SET due_at = now() - interval '1 day' WHERE id = $1", [id]);
    const b2 = mails.length;
    expect(await t.services.awareness.remindDue(tenant.tenantId)).toBe(2);
    expect(mails[b2]!.subject).toBe('Overdue: security awareness training "Due soon"');
    // Turned off by an administrator: no more reminders.
    await t.privileged.query("UPDATE sat_enrolments SET reminded_at = now() - interval '8 days' WHERE assignment_id = $1", [id]);
    expect((await analyst.patch(`/awareness/assignments/${id}`, { reminders: false })).status).toBe(403);
    expect((await admin.patch(`/awareness/assignments/${id}`, { reminders: false })).body).toEqual({ reminders: false });
    expect(await t.services.awareness.remindDue(tenant.tenantId)).toBe(0);
    const o = (await admin.get(`/awareness/overview?organizationId=${org}`)).body;
    expect(o.assignments.find((a: { id: string }) => a.id === id)).toMatchObject({ reminders: false, enrolments: [expect.objectContaining({ remindedAt: expect.any(String) }), expect.anything()] });
  });
});
