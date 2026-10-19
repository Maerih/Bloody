import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createApiKey, createTenant, createTestApp, createUser, login, type TestApp, type TestTenant } from "../test/harness.js";

const client = async (role: Parameters<typeof createUser>[2]["roles"][number]["role"], organizationId: string | null) => {
  const u = await createUser(t, tenant.tenantId, { roles: [{ role, organizationId }] });
  return { user: u, api: api(t.app, { token: (await login(t.app, u.email)).token }) };
};

/** Regression tests for findings of the October 2026 authorization review. */
let t: TestApp;
let tenant: TestTenant;
let admin: ReturnType<typeof api>;
let adminToken: string;
let o1: string;
let o2: string;

const alertIn = async (org: string) =>
  (
    await t.privileged.query(
      `INSERT INTO alerts (id, tenant_id, organization_id, title, severity, status, source, rule_id, event_ids, attack, confidence, risk_score, explanation, entities, indicators, first_seen_at, last_seen_at)
       VALUES (gen_random_uuid(), $1, $2, 'Suspicious PowerShell', 'medium', 'new', 'rule', 'rule-ps-encoded', '{}', '[]', 0.8, 50, '{}', $3::jsonb, '[]', now(), now()) RETURNING id`,
      [tenant.tenantId, org, JSON.stringify([{ kind: "asset", key: "host:kb-ws-01", label: "kb-ws-01" }])],
    )
  ).rows[0].id as string;

beforeAll(async () => {
  t = await createTestApp({ deps: { hostResolver: false } });
  tenant = await createTenant(t, { orgs: 2, plan: "mssp" });
  [o1, o2] = [tenant.orgIds[0]!, tenant.orgIds[1]!];
  adminToken = (await login(t.app, tenant.admin.email)).token;
  admin = api(t.app, { token: adminToken });
});
afterAll(async () => {
  await t?.close();
});

describe("authorization review regressions", () => {
  it("does not auto-suppress a detection when one alert gets the same verdict repeatedly", async () => {
    const u = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: o1 }] });
    const analyst = api(t.app, { token: (await login(t.app, u.email)).token });
    const suppressions = async () => (await t.privileged.query("SELECT source FROM detection_suppressions WHERE organization_id = $1", [o1])).rows;
    const first = await alertIn(o1);
    for (let i = 0; i < 4; i++) expect((await analyst.post(`/alerts/${first}/feedback`, { verdict: "false_positive" })).status).toBeLessThan(300);
    expect(await suppressions()).toEqual([]);
    // Verdicts on three different alerts are the real signal.
    for (const id of [await alertIn(o1), await alertIn(o1)]) await analyst.post(`/alerts/${id}/feedback`, { verdict: "false_positive" });
    expect(await suppressions()).toEqual([{ source: "feedback" }]);
  });

  it("only assigns investigations to people who can see that organization", async () => {
    const other = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t2", organizationId: o2 }] });
    const mine = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t2", organizationId: o1 }] });
    const bad = await admin.post("/investigations", { organizationId: o1, title: "Check host", leadId: other.id });
    expect(bad.status).toBe(400);
    const inv = await admin.post("/investigations", { organizationId: o1, title: "Check host", leadId: mine.id });
    expect(inv.status).toBe(201);
    expect((await admin.patch(`/investigations/${inv.body.id}`, { leadId: other.id })).status).toBe(400);
    expect((await admin.post(`/investigations/${inv.body.id}/tasks`, { title: "Collect logs", assigneeId: other.id })).status).toBe(400);
    expect((await admin.post(`/investigations/${inv.body.id}/tasks`, { title: "Collect logs", assigneeId: mine.id })).status).toBe(201);
  });

  it("never hands the agent enrollment key to an API key", async () => {
    const key = await createApiKey(t.app, adminToken, { organizationId: null, roles: ["api_service"] });
    const res = await api(t.app, { apiKey: key.key }).get("/agents/enrollment");
    expect(res.status).toBe(403);
    expect(JSON.stringify(res.body)).not.toMatch(/sak_/);
    expect((await admin.get("/agents/enrollment")).body.accountKey).toMatch(/^sak_/);
  });

  it("needs settings:write to change automatic agent updates", async () => {
    const eng = await createUser(t, tenant.tenantId, { roles: [{ role: "security_engineer", organizationId: null }] });
    const engineer = api(t.app, { token: (await login(t.app, eng.email)).token });
    expect((await engineer.put("/agents/auto-update", { enabled: false })).status).toBe(403);
    expect((await engineer.get("/agents/auto-update")).status).toBe(200);
    expect((await admin.put("/agents/auto-update", { enabled: false })).status).toBe(200);
  });
});

describe("authorization review regressions (second round)", () => {
  it("an organization's threat-intel import cannot revoke indicators of other scopes", async () => {
    // A tenant-wide feed indicator, then an organization imports a feed that deletes the same attribute.
    expect((await admin.post("/intel/indicators/import", { format: "misp", organizationId: null, payload: [{ type: "ip-dst", value: "203.0.113.66", uuid: "shared-uuid-1", to_ids: true }] })).status).toBeLessThan(300);
    const shared = (await admin.get("/intel/indicators?q=203.0.113.66")).body.items[0];
    expect(shared).toMatchObject({ organizationId: null, revoked: false });
    const { api: hunter } = await client("threat_hunter", o1);
    const res = await hunter.post("/intel/indicators/import", { format: "misp", organizationId: o1, payload: [{ type: "ip-dst", value: "203.0.113.66", uuid: "shared-uuid-1", deleted: true }] });
    expect(res.status).toBeLessThan(300);
    expect((await admin.get(`/intel/indicators/${shared.id}`)).body.revoked).toBe(false);
  });

  it("medium- and high-risk actions from someone without response:execute wait for approval", async () => {
    const asset = (await admin.post("/assets", { organizationId: o1, kind: "endpoint", name: "kb-ws-77", hostname: "kb-ws-77" })).body.id;
    const { api: t1 } = await client("soc_analyst_t1", o1);
    const r = await t1.post("/response/actions", { action: "release_endpoint", organizationId: o1, target: { kind: "asset", id: asset }, reason: "Host cleaned, releasing" });
    expect(r.status).toBe(202);
    expect(r.body.status).toBe("pending_approval");
    // A manual playbook run by them holds its medium-risk step too.
    const pb = await admin.post("/playbooks", { name: "Release helper", organizationId: o1, enabled: true, trigger: { on: "manual" }, conditions: [], steps: [{ id: "s1", action: "release_endpoint", parameters: { assetId: asset } }] });
    expect(pb.status).toBe(201);
    const run = await t1.post(`/playbooks/${pb.body.id}/run`, { organizationId: o1 });
    expect(run.status).toBeLessThan(300);
    expect(run.body.execution.status).toBe("waiting_approval");
  });

  it("whoever wrote a playbook version cannot approve its steps", async () => {
    const { user: authorUser, api: author } = await client("org_admin", o1);
    const { api: runner } = await client("incident_responder", o1);
    const { api: approver } = await client("incident_responder", o1);
    const pb = await author.post("/playbooks", { name: "Notify with sign-off", organizationId: o1, enabled: true, trigger: { on: "manual" }, conditions: [], steps: [{ id: "s1", action: "notify_analyst", parameters: { message: "check" }, requireApproval: true }] });
    expect(pb.status).toBe(201);
    expect((await runner.post(`/playbooks/${pb.body.id}/run`, { organizationId: o1 })).status).toBeLessThan(300);
    const pending = (await approver.get(`/response/approvals?organizationId=${o1}&kind=playbook_step`)).body.items;
    const mine = pending.find((a: { subject: { playbookId?: string } }) => a.subject?.playbookId === pb.body.id);
    expect(mine).toBeTruthy();
    const self = await author.post(`/response/approvals/${mine.id}/approve`, {});
    expect(self.status).toBe(403);
    expect(self.body.error.code).toBe("self_approval");
    expect(authorUser.id).toBeTruthy();
    expect((await approver.post(`/response/approvals/${mine.id}/approve`, {})).status).toBe(200);
  });

  it("API keys cannot change enforcement or record a scan authorization", async () => {
    const key = await createApiKey(t.app, adminToken, { organizationId: o1, roles: ["api_service"] });
    const bot = api(t.app, { apiKey: key.key });
    const res = await bot.put(`/app-control/settings/${o1}`, { mode: "enforce" });
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe("person_required");
    expect((await bot.put(`/exposure/authorization/${o1}`, { reference: "MSA", attest: true })).status).toBe(403);
    expect((await bot.post("/rmm-guard/block", { organizationId: o1, tools: ["anydesk"] })).status).toBe(403);
  });

  it("an organization admin cannot take over a user with wider access through a team", async () => {
    const victim = await createUser(t, tenant.tenantId, { organizationId: o1, roles: [{ role: "soc_analyst_t1", organizationId: o1 }] });
    const team = await admin.post("/teams", { name: uniqName("Tier 2"), organizationId: null });
    expect(team.status).toBe(201);
    const bd = await admin.post(`/teams/${team.body.id}/roles`, { role: "soc_analyst_t2", organizationId: null });
    expect(bd.status).toBeLessThan(300);
    expect((await admin.post(`/teams/${team.body.id}/members`, { userId: victim.id })).status).toBeLessThan(300);
    const { api: orgAdmin } = await client("org_admin", o1);
    expect((await orgAdmin.post(`/users/${victim.id}/password`, { password: "Another-Str0ng-Passphrase!" })).status).toBe(403);
  });

  it("nobody resets their own password without the current one", async () => {
    const res = await admin.post(`/users/${tenant.admin.id}/password`, { password: "Another-Str0ng-Passphrase!" });
    expect(res.status).toBe(400);
  });

  it("stored credentials are not sent to a new destination", async () => {
    const prov = await admin.post("/ai/providers", { name: "Hosted", kind: "openai_compatible", endpoint: "https://llm.example.com/v1", model: "m", apiKey: "sk-secret-1", organizationId: null });
    expect(prov.status).toBe(201);
    expect((await admin.patch(`/ai/providers/${prov.body.id}`, { endpoint: "https://attacker.example.net/v1" })).status).toBe(400);
    expect((await admin.patch(`/ai/providers/${prov.body.id}`, { endpoint: "https://attacker.example.net/v1", apiKey: "sk-new" })).status).toBe(200);
    const ch = await admin.post("/notifications/channels", { name: "SIEM hook", kind: "webhook", organizationId: null, config: { url: "https://hooks.example.com/in", authorization: "Bearer topsecret" } });
    expect(ch.status).toBe(201);
    expect((await admin.patch(`/notifications/channels/${ch.body.id}`, { config: { url: "https://attacker.example.net/in" } })).status).toBe(400);
  });

  it("the shared demo account cannot change itself", async () => {
    const { api: demo } = await client("demo_viewer", null);
    expect((await demo.post("/auth/mfa/totp/enroll", {})).status).toBe(403);
    expect((await demo.post("/auth/password", { currentPassword: "x", newPassword: "Another-Str0ng-Passphrase!" })).status).toBe(403);
  });

  it("customer-scoped readers do not see tenant-wide integration configuration", async () => {
    const created = await admin.post("/integrations", { kind: "wazuh", name: uniqName("Wazuh"), organizationId: null, endpoint: "https://wazuh.example.com:55000", config: { username: "wazuh-api" }, enabled: false });
    expect(created.status).toBe(201);
    const { api: reader } = await client("security_engineer", o1);
    const seen = (await reader.get("/integrations")).body.items.find((i: { id: string }) => i.id === created.body.id);
    expect(seen).toMatchObject({ endpoint: null, config: {} });
    expect((await admin.get("/integrations")).body.items.find((i: { id: string }) => i.id === created.body.id).endpoint).toBe("https://wazuh.example.com:55000");
  });
});

let n = 0;
function uniqName(base: string): string {
  n += 1;
  return `${base} ${Date.now()}-${n}`;
}
