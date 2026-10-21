import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let admin: ReturnType<typeof api>;
let token: string;
let assetId: string;
let agentId: string;

const post = (url: string, body: object, tok?: string) =>
  t.app.inject({ method: "POST", url: `/api/v1${url}`, headers: { "content-type": "application/json", ...(tok ? { authorization: `Bearer ${tok}` } : {}) }, payload: JSON.stringify(body) });

const inventory = (autoruns: object[]) => ({
  software: [{ name: "AnyDesk", version: "8.0.14", publisher: "AnyDesk Software GmbH" }],
  services: [],
  users: [{ name: "amina", admin: true, enabled: true, loggedIn: true }],
  processes: [],
  ports: [],
  antivirus: [{ name: "Microsoft Defender Antivirus", enabled: true, upToDate: true, realTimeProtection: true, tamperProtection: true, signatureAgeDays: 0 }],
  firewall: { enabled: false, detail: null },
  hardening: { smb1_enabled: true, lsa_run_as_ppl: 0, uac_enabled: true },
  autoruns,
  patches: { source: "windows_update", pending: [{ title: "2026-10 Cumulative Update", id: "KB5066835", security: true, severity: "critical" }], rebootRequired: true, lastCheckedAt: new Date().toISOString() },
});
const onedrive = { kind: "run_key", location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", name: "OneDrive", command: "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background", signed: true };
const beacon = { kind: "scheduled_task", location: "\\Microsoft\\Windows\\Update", name: "WinUpdateSvc", command: "powershell.exe -w hidden -enc SQBFAFgA", signed: false };

beforeAll(async () => {
  t = await createTestApp({ deps: { hostResolver: false } });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const key = (await admin.get("/agents/enrollment")).body.accountKey;
  const enrolled = (await post("/agent/enroll", { accountKey: key, organizationKey: "org-1", hostname: "kb-fin-07", platform: "windows", os: "Microsoft Windows 11 Pro 10.0.26200", version: "1.5.0" })).json();
  token = enrolled.token;
  agentId = enrolled.agentId;
  assetId = (await t.privileged.query("SELECT asset_id FROM agents WHERE id = $1", [agentId])).rows[0].asset_id;
  // First report sets the baseline; the second adds a hidden encoded PowerShell task.
  await post("/agent/inventory", inventory([onedrive]), token);
  await post("/agent/inventory", inventory([onedrive, beacon]), token);
  await post("/agent/heartbeat", { hostname: "kb-fin-07", version: "1.5.0", isolation: { state: "isolated", mode: "full" } }, token);
  const org = tenant.orgIds[0]!;
  await t.privileged.query(
    `INSERT INTO alerts (id, tenant_id, organization_id, asset_id, title, severity, status, source, rule_id, event_ids, attack, confidence, risk_score, explanation, entities, indicators, first_seen_at, last_seen_at)
     VALUES (gen_random_uuid(), $1, $2, $3, 'Encoded PowerShell launched by a scheduled task', 'high', 'new', 'rule', 'rule-ps', '{}', '[]', 0.9, 70, '{}', '[]', '[]', now() - interval '1 hour', now())`,
    [tenant.tenantId, org, assetId],
  );
  await t.privileged.query(
    `INSERT INTO response_actions (tenant_id, organization_id, action, target, parameters, reason, status, risk, requested_by, requested_via, approved_by, decided_at, executor, started_at, finished_at, created_at)
     VALUES ($1, $2, 'isolate_endpoint', $3::jsonb, '{"mode":"full"}', 'Beaconing to a bare IP address', 'succeeded', 'high', $4, 'user', $4, now() - interval '50 minutes', 'sciat:agent', now() - interval '50 minutes', now() - interval '49 minutes', now() - interval '55 minutes')`,
    [tenant.tenantId, org, JSON.stringify({ kind: "asset", id: assetId, label: "kb-fin-07" }), tenant.admin.id],
  );
});
afterAll(async () => {
  await t?.close();
});

describe("computer dossier", () => {
  it("brings together the agent, isolation, patching, hardening, persistence, remote access and a timeline", async () => {
    const res = await admin.get(`/assets/${assetId}/dossier`);
    expect(res.status).toBe(200);
    const d = res.body;
    expect(d).toMatchObject({ assetId, hostname: "kb-fin-07", agents: [{ id: agentId, engine: "sciat", version: "1.5.0", status: "isolated", isolation: { mode: "full", source: "endpoint" } }] });
    expect(d.patching).toMatchObject({ securityCount: 1, criticalCount: 1, rebootRequired: true });
    expect(d.hardening.score).toBeLessThan(100);
    expect(d.hardening.checks.find((c: { title: string }) => c.title === "Host firewall is on")).toMatchObject({ status: "fail" });
    expect(d.footholds.find((f: { name: string }) => f.name === "WinUpdateSvc")).toMatchObject({ level: "high", isNew: true, verdict: null });
    expect(d.remoteAccess).toEqual([expect.objectContaining({ name: "AnyDesk", approved: false })]);
    const titles = d.activity.map((e: { title: string }) => e.title);
    expect(titles).toEqual(
      expect.arrayContaining([
        "SCIAT Agent installed (version 1.5.0)",
        "New autostart entry: WinUpdateSvc",
        "The computer reported it is isolated",
        "Encoded PowerShell launched by a scheduled task",
        "Isolation (full) requested",
        "Isolation (full) approved",
        "Isolated from the network",
      ]),
    );
    const requested = d.activity.find((e: { title: string }) => e.title === "Isolation (full) requested");
    expect(requested).toMatchObject({ kind: "isolation", detail: "Beaconing to a bare IP address", actor: expect.any(String) });
    expect(requested.actor).not.toMatch(/^[0-9a-f-]{36}$/); // a person's name, not an id
    // Newest first.
    expect([...d.activity].map((e: { at: string }) => e.at)).toEqual([...d.activity].map((e: { at: string }) => e.at).sort().reverse());
  });

  it("leaves out what the reader may not see", async () => {
    const viewer = await createUser(t, tenant.tenantId, { roles: [{ role: "customer_viewer", organizationId: tenant.orgIds[0]! }] });
    const v = api(t.app, { token: (await login(t.app, viewer.email)).token });
    const d = (await v.get(`/assets/${assetId}/dossier`)).body;
    const kinds = new Set(d.activity.map((e: { kind: string }) => e.kind));
    expect(kinds.has("alert")).toBe(false); // no alert:read
    expect(kinds.has("isolation")).toBe(true);
    const other = await createTenant(t, { orgs: 1 });
    expect((await api(t.app, { token: (await login(t.app, other.admin.email)).token }).get(`/assets/${assetId}/dossier`)).status).toBe(404);
  });
});

describe("single-computer report", () => {
  const generate = (body: object) => admin.post("/reports/generate", body);
  it("generates the report about one computer as PDF and HTML", async () => {
    const pdf = await t.app.inject({ method: "POST", url: "/api/v1/reports/generate", headers: { "content-type": "application/json", authorization: `Bearer ${(await login(t.app, tenant.admin.email)).token}` }, payload: JSON.stringify({ type: "endpoint_posture", format: "pdf", periodDays: 30, options: { assetId } }) });
    expect(pdf.statusCode).toBe(200);
    expect(pdf.headers["content-type"]).toBe("application/pdf");
    expect(pdf.rawPayload.subarray(0, 5).toString()).toBe("%PDF-");
    expect(String(pdf.headers["content-disposition"])).toMatch(/kb-fin-07/i);
    const html = await t.app.inject({ method: "POST", url: "/api/v1/reports/generate", headers: { "content-type": "application/json", authorization: `Bearer ${(await login(t.app, tenant.admin.email)).token}` }, payload: JSON.stringify({ type: "endpoint_posture", format: "html", periodDays: 30, options: { assetId } }) });
    const text = html.payload;
    for (const s of ["Computer report: kb-fin-07", "WinUpdateSvc", "AnyDesk", "Isolated from the network", "KB5066835", "Host firewall is on"]) expect(text).toContain(s);
  });

  it("refuses another report type, and computers outside the caller's organizations", async () => {
    expect((await generate({ type: "executive", format: "pdf", options: { assetId } })).status).toBe(400);
    const other = await createTenant(t, { orgs: 1 });
    const o = api(t.app, { token: (await login(t.app, other.admin.email)).token });
    expect((await o.post("/reports/generate", { type: "endpoint_posture", format: "pdf", options: { assetId } })).status).toBe(404);
  });
});
