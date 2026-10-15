import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type Json, type TestApp, type TestTenant } from "../test/harness.js";

/** Fake Wazuh manager API: records every active-response command it receives. */
const commands: Array<{ agents: string | null; body: Json }> = [];
const fakeWazuh = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  if (url.pathname === "/security/user/authenticate") return json({ data: { token: "wazuh-jwt-0123456789" } });
  if (url.pathname === "/active-response") {
    const raw = input instanceof Request ? await input.text() : String(init?.body ?? "");
    const agents = url.searchParams.get("agents_list");
    commands.push({ agents, body: JSON.parse(raw) as Json });
    return json({ data: { affected_items: (agents ?? "").split(",").filter(Boolean), failed_items: [] } });
  }
  return new Response("not found", { status: 404 });
}) as typeof fetch;

let t: TestApp;
let tenant: TestTenant;
let org: string;
let requester: ReturnType<typeof api>;
let approver: ReturnType<typeof api>;
let admin: ReturnType<typeof api>;
let assetId: string;

beforeAll(async () => {
  t = await createTestApp({ deps: { fetch: fakeWazuh, hostResolver: false } });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  org = tenant.orgIds[0]!;
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const r = await createUser(t, tenant.tenantId, { roles: [{ role: "incident_responder", organizationId: null }], displayName: "Responder A" });
  const a = await createUser(t, tenant.tenantId, { roles: [{ role: "incident_responder", organizationId: null }], displayName: "Responder B" });
  requester = api(t.app, { token: (await login(t.app, r.email)).token });
  approver = api(t.app, { token: (await login(t.app, a.email)).token });

  const integ = await admin.post("/integrations", {
    kind: "wazuh",
    name: "Wazuh manager",
    endpoint: "https://wazuh.mssp.example:55000",
    config: { username: "bloody", activeResponse: { isolationAllow: ["10.0.0.5", "203.0.113.10"] } },
    credential: "wazuh-api-password",
  });
  expect(integ.status).toBe(201);

  const agent = await admin.post("/agents", { organizationId: org, hostname: "ws-sales-03", platform: "linux", version: "4.9.0", engine: "wazuh", status: "protected" });
  expect(agent.status).toBeLessThan(300);
  assetId = agent.body.assetId;
  expect(assetId).toBeTruthy();
  await t.db.withTenant(tenant.tenantId, (tx) => tx.query(`UPDATE agents SET engine_refs = '{"wazuh":"007"}'::jsonb WHERE id = $1`, [agent.body.id]));
});
afterAll(async () => {
  await t?.close();
});

async function requestAndApprove(action: string, parameters: Json): Promise<Json> {
  const created = await requester.post("/response/actions", { action, organizationId: org, target: { kind: "asset", id: assetId, label: "ws-sales-03" }, parameters, reason: "Contain lateral movement from this host" });
  expect(created.status).toBeLessThan(300);
  if (created.body.status !== "pending_approval") return created.body as Json;
  const ok = await approver.post(`/response/actions/${created.body.id}/approve`, { comment: "approved" });
  expect(ok.status).toBe(200);
  return ok.body as Json;
}

const agentOfAsset = async (): Promise<Json> => (await admin.get(`/assets/${assetId}`)).body.agents[0] as Json;

describe("endpoint isolation (LAN / full) with release from the platform", () => {
  it("rejects an unknown isolation mode", async () => {
    const res = await requester.post("/response/actions", { action: "isolate_endpoint", organizationId: org, target: { kind: "asset", id: assetId }, parameters: { mode: "wifi" }, reason: "bad mode" });
    expect(res.status).toBe(400);
  });

  it("LAN-isolates through Wazuh, keeping the platform reachable", async () => {
    const done = await requestAndApprove("isolate_endpoint", { mode: "lan" });
    expect(done.status).toBe("succeeded");
    const cmd = commands.at(-1)!;
    expect(cmd.agents).toBe("007");
    expect(cmd.body.command).toBe("!bloody-isolate");
    const args = cmd.body.arguments as string[];
    expect(args.slice(0, 3)).toEqual(["isolate", "lan", "allow=10.0.0.5,203.0.113.10"]);
    // The manager address is carved out of the blocked LAN ranges.
    expect(args.find((a) => a.startsWith("block4="))).toContain("10.0.0.0-10.0.0.4,10.0.0.6-10.255.255.255");

    const agent = await agentOfAsset();
    expect(agent.status).toBe("isolated");
    expect(agent.isolation).toMatchObject({ mode: "lan", actionId: done.id });
  });

  it("keeps the agent isolated across heartbeats", async () => {
    await admin.post("/agents", { organizationId: org, hostname: "ws-sales-03", platform: "linux", version: "4.9.0", engine: "wazuh", status: "protected" });
    expect((await agentOfAsset()).status).toBe("isolated");
  });

  it("releases the endpoint from the platform", async () => {
    const done = await requestAndApprove("release_endpoint", {});
    expect(done.status).toBe("succeeded");
    expect(commands.at(-1)!.body.arguments).toEqual(["release"]);
    const agent = await agentOfAsset();
    expect(agent.status).toBe("protected");
    expect(agent.isolation).toBeNull();
  });

  it("full isolation is recorded with its mode", async () => {
    const done = await requestAndApprove("isolate_endpoint", { mode: "full" });
    expect(done.status).toBe("succeeded");
    expect((commands.at(-1)!.body.arguments as string[]).slice(0, 2)).toEqual(["isolate", "full"]);
    expect((await agentOfAsset()).isolation).toMatchObject({ mode: "full" });
  });
});
