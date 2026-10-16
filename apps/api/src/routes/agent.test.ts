import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let admin: ReturnType<typeof api>;
let analyst: ReturnType<typeof api>;
let other: TestTenant;
let otherAdmin: ReturnType<typeof api>;

const enroll = (body: object) => t.app.inject({ method: "POST", url: "/api/v1/agent/enroll", headers: { "content-type": "application/json" }, payload: JSON.stringify(body) });
const heartbeat = (token: string, body: object) =>
  t.app.inject({ method: "POST", url: "/api/v1/agent/heartbeat", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, payload: JSON.stringify(body) });
const beat = (hostname: string) => ({ hostname, version: "1.0.0" });
const host = (hostname: string, extra: object = {}) => ({ hostname, platform: "linux", os: "Ubuntu 24.04 LTS", version: "1.0.0", ips: ["10.0.0.5"], ...extra });

beforeAll(async () => {
  t = await createTestApp({ deps: { hostResolver: false } });
  tenant = await createTenant(t, { orgs: 2, plan: "mssp" });
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const a = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: null }] });
  analyst = api(t.app, { token: (await login(t.app, a.email)).token });
  other = await createTenant(t, { orgs: 1, plan: "trial" });
  otherAdmin = api(t.app, { token: (await login(t.app, other.admin.email)).token });
});
afterAll(async () => {
  await t?.close();
});

describe("SCIAT Agent", () => {
  let accountKey: string;
  let token: string;

  it("shows admins the account key and one organization key per customer", async () => {
    const res = await admin.get("/agents/enrollment");
    expect(res.status).toBe(200);
    accountKey = res.body.accountKey;
    expect(accountKey).toMatch(/^sak_[0-9a-f]{32}_/);
    expect(res.body.organizations.map((o: { key: string }) => o.key).sort()).toEqual(["org-1", "org-2"]);
    expect(res.body.platformUrl).toMatch(/^http:\/\//);
    expect((await admin.get("/agents/enrollment")).body.accountKey).toBe(accountKey); // stable until regenerated
    expect((await analyst.get("/agents/enrollment")).status).toBe(403);
  });

  it("enrolls an endpoint into the chosen organization and issues its own token", async () => {
    const res = await enroll({ accountKey, organizationKey: "org-2", ...host("ws-sciat-01") });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toMatchObject({ organizationId: tenant.orgIds[1], pollSeconds: 60 });
    token = body.token;
    expect(token).toMatch(/^sat_/);
    const agents = (await admin.get(`/agents?organizationId=${tenant.orgIds[1]}`)).body;
    const list = (agents.items ?? agents) as Array<{ hostname: string; engine: string; status: string }>;
    expect(list.find((x) => x.hostname === "ws-sciat-01")).toMatchObject({ engine: "sciat", status: "protected" });
    // The token itself is never stored, only its hash.
    const stored = await t.privileged.query("SELECT agent_token_hash FROM agents WHERE id = $1", [body.agentId]);
    expect(stored.rows[0].agent_token_hash).not.toContain(token.split("_")[3]);
  });

  it("refuses bad keys, unknown organizations and keys of another account", async () => {
    expect((await enroll({ accountKey: accountKey.slice(0, -2) + "xx", organizationKey: "org-2", ...host("x1") })).statusCode).toBe(401);
    expect((await enroll({ accountKey: "nonsense-key-123", organizationKey: "org-2", ...host("x1") })).statusCode).toBe(401);
    const unknown = await enroll({ accountKey, organizationKey: "no-such-org", ...host("x1") });
    expect(unknown.statusCode).toBe(404);
    expect(unknown.json().error.code).toBe("unknown_organization");
    // Another tenant's key cannot enroll into this tenant's organizations (same slug "org-1").
    const otherKey = (await otherAdmin.get("/agents/enrollment")).body.accountKey;
    const cross = await enroll({ accountKey: otherKey, organizationKey: "org-1", ...host("cross-01") });
    expect(cross.json().organizationId).toBe(other.orgIds[0]);
    const mine = await t.privileged.query("SELECT count(*)::int AS n FROM agents WHERE tenant_id = $1 AND hostname = 'cross-01'", [tenant.tenantId]);
    expect(mine.rows[0].n).toBe(0);
  });

  it("heartbeats keep the agent alive and record host facts; forged tokens are refused", async () => {
    await t.privileged.query("UPDATE agents SET last_checkin_at = now() - interval '2 hours' WHERE hostname = 'ws-sciat-01'");
    const res = await heartbeat(token, { hostname: "ws-sciat-01", os: "Ubuntu 24.04 LTS", version: "1.0.1", ips: ["10.0.0.6"], uptimeSeconds: 3600, isolation: { state: "not_isolated" }, engines: { "wazuh-agent": "active" } });
    expect(res.statusCode).toBe(200);
    expect(res.json().pollSeconds).toBe(60);
    const { rows } = await t.privileged.query("SELECT version, host_info, last_checkin_at > now() - interval '1 minute' AS fresh FROM agents WHERE hostname = 'ws-sciat-01'");
    expect(rows[0]).toMatchObject({ version: "1.0.1", fresh: true });
    expect(rows[0].host_info).toMatchObject({ ips: ["10.0.0.6"], engines: { "wazuh-agent": "active" } });

    const parts = token.split("_");
    expect((await heartbeat(`${parts[0]}_${parts[1]}_${parts[2]}_${"A".repeat(43)}`, beat("ws-sciat-01"))).statusCode).toBe(401);
    expect((await heartbeat("", beat("ws-sciat-01"))).statusCode).toBe(401);
  });

  it("re-enrolling the same host replaces its token; regenerating the key keeps enrolled agents", async () => {
    const again = (await enroll({ accountKey, organizationKey: "org-2", ...host("ws-sciat-01") })).json();
    expect((await heartbeat(token, beat("ws-sciat-01"))).statusCode).toBe(401);
    token = again.token;
    expect((await analyst.post("/agents/enrollment/regenerate", {})).status).toBe(403);
    const rotated = await admin.post("/agents/enrollment/regenerate", {});
    expect(rotated.status).toBe(200);
    expect(rotated.body.accountKey).not.toBe(accountKey);
    expect((await enroll({ accountKey, organizationKey: "org-2", ...host("ws-sciat-02") })).statusCode).toBe(401);
    expect((await heartbeat(token, beat("ws-sciat-01"))).statusCode).toBe(200);
    accountKey = rotated.body.accountKey;
    const audit = await t.privileged.query("SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1 AND action = 'agent.account_key_rotated'", [tenant.tenantId]);
    expect(audit.rows[0].n).toBe(1);
  });

  it("new endpoints count against the plan", async () => {
    const otherKey = (await otherAdmin.get("/agents/enrollment")).body.accountKey;
    const existing = (await t.privileged.query("SELECT count(*)::int AS n FROM agents WHERE tenant_id = $1", [other.tenantId])).rows[0].n as number;
    for (let i = existing; i < 25; i++) {
      await t.privileged.query("INSERT INTO agents (tenant_id, organization_id, hostname, platform, version, engine, status) VALUES ($1, $2, $3, 'linux', '1', 'wazuh', 'protected')", [other.tenantId, other.orgIds[0], `filler-${i}`]);
    }
    const full = await enroll({ accountKey: otherKey, organizationKey: "org-1", ...host("one-too-many") });
    expect(full.statusCode).toBe(402);
    // Re-enrolling a machine that is already counted still works.
    expect((await enroll({ accountKey: otherKey, organizationKey: "org-1", ...host("cross-01") })).statusCode).toBe(200);
  });

  it("serves installers with this platform's address and only the listed agent files", async () => {
    const linux = await t.app.inject({ method: "GET", url: "/api/v1/agent/install/linux", headers: { host: "10.1.2.3:8443" } });
    expect(linux.statusCode).toBe(200);
    expect(linux.body).toContain("PLATFORM_URL=\"${SCIAT_PLATFORM_URL:-http://10.1.2.3:8443}\"");
    expect(linux.body).toContain("Description=SCIAT Agent");
    expect(linux.body).not.toMatch(/sak_[0-9a-f]{32}/); // no secrets baked in
    const win = await t.app.inject({ method: "GET", url: "/api/v1/agent/install/windows", headers: { host: "soc.example.com" } });
    expect(win.body).toContain("[string]$PlatformUrl = 'http://soc.example.com'");
    expect(win.body).toContain("-DisplayName 'SCIAT Agent'");
    expect((await t.app.inject({ method: "GET", url: "/api/v1/agent/install/solaris" })).statusCode).toBe(400);
    expect((await t.app.inject({ method: "GET", url: "/api/v1/agent/files/sciat-agent.sh" })).body).toContain("SCIAT Agent");
    expect((await t.app.inject({ method: "GET", url: "/api/v1/agent/files/SciatAgentService.cs" })).body).toContain('ServiceName = "SCIATAgent"');
    expect((await t.app.inject({ method: "GET", url: "/api/v1/agent/files/..%2F..%2Fpackage.json" })).statusCode).toBe(404);
    expect((await t.app.inject({ method: "GET", url: "/api/v1/agent/files/constructor" })).statusCode).toBe(404);
  });
});

describe("SCIAT Agent isolation (agent-executed)", () => {
  let token: string;
  let other: string;
  let assetId: string;
  let approver: ReturnType<typeof api>;
  const action = (id: string) => admin.get(`/response/actions/${id}`).then((r) => r.body);
  const result = (tok: string, id: string, body: object) =>
    t.app.inject({ method: "POST", url: `/api/v1/agent/commands/${id}/result`, headers: { "content-type": "application/json", authorization: `Bearer ${tok}` }, payload: JSON.stringify(body) });
  const isolate = (mode: "lan" | "full") =>
    admin.post("/response/actions", {
      action: "isolate_endpoint",
      organizationId: tenant.orgIds[1],
      target: { kind: "asset", id: assetId, label: "ws-iso-01" },
      parameters: { mode },
      reason: "Ransomware spreading from this host, isolate it now",
      emergency: true,
    });
  const agentRow = async () => (await t.privileged.query("SELECT status, isolation FROM agents WHERE hostname = 'ws-iso-01'")).rows[0];

  beforeAll(async () => {
    const key = (await admin.get("/agents/enrollment")).body.accountKey;
    token = (await enroll({ accountKey: key, organizationKey: "org-2", ...host("ws-iso-01") })).json().token;
    other = (await enroll({ accountKey: key, organizationKey: "org-2", ...host("ws-iso-02") })).json().token;
    assetId = (await t.privileged.query("SELECT asset_id FROM agents WHERE hostname = 'ws-iso-01'")).rows[0].asset_id;
    const a = await createUser(t, tenant.tenantId, { roles: [{ role: "incident_responder", organizationId: null }] });
    approver = api(t.app, { token: (await login(t.app, a.email)).token });
  });

  it("refuses until the agent has reported the platform address it must keep reaching", async () => {
    const res = await isolate("full");
    expect(res.body).toMatchObject({ status: "failed", error: { code: "agent_not_ready" } });
  });

  it("queues isolation for the agent, delivers it once and completes when the agent reports", async () => {
    await heartbeat(token, { ...beat("ws-iso-01"), platformIps: ["10.9.9.9"], dnsServers: ["10.0.0.53"] });
    const res = await isolate("full");
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ status: "running", executor: "sciat:agent" });

    const hb = (await heartbeat(token, beat("ws-iso-01"))).json();
    expect(hb.commands).toHaveLength(1);
    const cmd = hb.commands[0];
    expect(cmd.kind).toBe("isolate");
    expect(cmd.args.slice(0, 4)).toEqual(["isolate", "full", "allow=10.9.9.9", "dns=10.0.0.53"]);
    expect(hb.commandLines[0]).toBe([cmd.id, ...cmd.args].join(" "));
    expect((await heartbeat(token, beat("ws-iso-01"))).json().commands).toHaveLength(0); // delivered once
    expect((await heartbeat(other, beat("ws-iso-02"))).json().commands).toHaveLength(0); // only for its agent

    expect((await result(other, cmd.id, { status: "succeeded" })).statusCode).toBe(404);
    expect((await result(token, cmd.id, { status: "succeeded", output: "isolated\nmode=full" })).statusCode).toBe(200);
    expect(await action(res.body.id)).toMatchObject({ status: "succeeded", executor: "sciat:agent" });
    expect(await agentRow()).toMatchObject({ status: "isolated", isolation: { mode: "full" } });
    // A late duplicate report changes nothing.
    expect((await result(token, cmd.id, { status: "failed", output: "late" })).statusCode).toBe(200);
    expect((await action(res.body.id)).status).toBe("succeeded");
  });

  it("release (approved when the policy asks) goes to the agent; a failure on the endpoint is reported", async () => {
    const req = await admin.post("/response/actions", {
      action: "release_endpoint",
      organizationId: tenant.orgIds[1],
      target: { kind: "asset", id: assetId, label: "ws-iso-01" },
      reason: "Host reimaged and verified clean",
    });
    if (req.body.status === "pending_approval") expect((await approver.post(`/response/actions/${req.body.id}/approve`, { comment: "ok" })).status).toBe(200);
    expect((await action(req.body.id)).status).toBe("running");
    const cmd = (await heartbeat(token, beat("ws-iso-01"))).json().commands[0];
    expect(cmd.args).toEqual(["release"]);
    await result(token, cmd.id, { status: "failed", output: "nft: permission denied" });
    expect(await action(req.body.id)).toMatchObject({ status: "failed", error: { code: "agent_failed", message: "nft: permission denied" } });
    expect((await agentRow()).status).toBe("isolated");
  });

  it("fails the action when the agent never collects the command", async () => {
    const res = await isolate("lan");
    expect(res.body).toMatchObject({ status: "running" }); // platform addresses kept from an earlier check-in
    await t.privileged.query("UPDATE agent_commands SET expires_at = now() - interval '1 second' WHERE response_action_id = $1", [res.body.id]);
    expect(await t.services.responses.expireAgentCommands(tenant.tenantId)).toBe(1);
    expect(await action(res.body.id)).toMatchObject({ status: "failed", error: { code: "agent_unreachable" } });
    expect((await heartbeat(token, beat("ws-iso-01"))).json().commands).toHaveLength(0);
  });
});
