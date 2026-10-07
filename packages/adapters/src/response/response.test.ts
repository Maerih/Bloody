import { describe, expect, it } from "vitest";
import { EngineClient } from "../http/client.js";
import { mockFetch, testResolver } from "../test-support/http.js";
import type { ResponseExecutionRequest } from "./types.js";
import { createVelociraptorResponse } from "./velociraptor.js";
import { createWazuhActiveResponse, createWazuhApiClient, wazuhHealthCheck } from "./wazuh.js";
import { createWebhookBlockConnector, verifyWebhookSignature, WEBHOOK_SIGNATURE_HEADER, WEBHOOK_TIMESTAMP_HEADER } from "./webhook.js";

const TENANT = "6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b";
const ORG = "7a2e3d4c-5b6a-4f7e-8d9c-0b1a2c3d4e5f";
const ACTION_ID = "9b8a7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
const clock = () => new Date("2026-10-07T12:00:00.000Z");

function req(overrides: Partial<ResponseExecutionRequest>): ResponseExecutionRequest {
  return {
    actionId: ACTION_ID,
    tenantId: TENANT,
    organizationId: ORG,
    action: "block_ip",
    target: { kind: "indicator", id: "203.0.113.45" },
    parameters: {},
    reason: "C2 traffic confirmed in incident INC-42",
    requestedBy: "user:analyst-1",
    requestedVia: "user",
    approvedBy: "user:responder-2",
    ...overrides,
  };
}

describe("Wazuh active response", () => {
  const ar = createWazuhActiveResponse();
  const ok = { data: { affected_items: ["001", "002"], total_affected_items: 2, total_failed_items: 0, failed_items: [] }, message: "AR command was sent to all agents", error: 0 };

  it("supports stock scripts only by default", () => {
    expect(ar.supported).toEqual(["block_ip", "disable_identity"]);
    expect(createWazuhActiveResponse({ isolateCommand: "!bloody-isolate", releaseCommand: "!bloody-release" }).supported).toContain("isolate_endpoint");
    expect(() => createWazuhActiveResponse({ isolateCommand: "rm -rf /" })).toThrow();
  });

  it("block_ip: PUT /active-response with agents_list, audited and hashed", async () => {
    const { fetch, calls } = mockFetch([{ method: "PUT", path: "/active-response", json: ok }]);
    const client = new EngineClient({ engine: "wazuh", baseUrl: "https://wazuh.acme.example:55000", fetch, resolveHost: testResolver });
    const r = await ar.execute(req({ parameters: { agents: ["001", "002"] } }), { client, clock });
    expect(r.outcome).toBe("succeeded");
    expect(r.status).toBe("succeeded");
    expect(r.affected).toEqual(["001", "002"]);
    expect(r.engineRef).toBe("wazuh-agents:001,002");
    expect(calls[0]?.url.searchParams.get("agents_list")).toBe("001,002");
    expect(calls[0]?.headers["idempotency-key"]).toBe(ACTION_ID);
    expect(JSON.parse(calls[0]?.body ?? "{}")).toEqual({ command: "!firewall-drop", arguments: [], alert: { data: { srcip: "203.0.113.45", bloody_action_id: ACTION_ID } } });
    expect(r.call?.bodySha256).toMatch(/^[0-9a-f]{64}$/);
    expect(r.audit).toMatchObject({
      action: "response.block_ip",
      actor: "user:analyst-1",
      approvedBy: "user:responder-2",
      risk: "high",
      engine: "wazuh",
      connector: "wazuh.active_response",
      outcome: "succeeded",
      tenantId: TENANT,
      organizationId: ORG,
    });
    expect(r.summary).toBe("Wazuh active response sent to 2 agents");
  });

  it("enforces approval, four-eyes and target safety before any engine call", async () => {
    const { fetch, calls } = mockFetch([{ method: "PUT", path: "/active-response", json: ok }]);
    const client = new EngineClient({ engine: "wazuh", baseUrl: "https://wazuh.acme.example", fetch, resolveHost: testResolver });
    const noApproval = await ar.execute(req({ approvedBy: null, parameters: { agents: ["001"] } }), { client, clock });
    expect(noApproval).toMatchObject({ outcome: "rejected", status: "rejected", error: { code: "approval_required" } });
    const selfApproved = await ar.execute(req({ approvedBy: "user:analyst-1", parameters: { agents: ["001"] } }), { client, clock });
    expect(selfApproved.error?.code).toBe("self_approval");
    const loopback = await ar.execute(req({ target: { kind: "indicator", id: "127.0.0.1" }, parameters: { agents: ["001"] } }), { client, clock });
    expect(loopback.error?.code).toBe("invalid_target");
    const fleet = await ar.execute(req({ parameters: { scope: "all" } }), { client, clock });
    expect(fleet.error?.message).toContain("fleet-wide");
    const root = await ar.execute(req({ action: "disable_identity", target: { kind: "identity", id: "root" }, parameters: { agents: ["001"] } }), { client, clock });
    expect(root.error?.message).toContain("built-in account");
    const unsupported = await ar.execute(req({ action: "isolate_endpoint", target: { kind: "asset", id: "001" } }), { client, clock });
    expect(unsupported.error?.code).toBe("unsupported_action");
    expect(calls).toHaveLength(0);
  });

  it("dry run returns the exact call for the approval screen without sending it", async () => {
    const { fetch, calls } = mockFetch([]);
    const client = new EngineClient({ engine: "wazuh", baseUrl: "https://wazuh.acme.example", fetch, resolveHost: testResolver });
    const r = await ar.execute(req({ approvedBy: null, dryRun: true, parameters: { agents: ["001"] } }), { client, clock });
    expect(r).toMatchObject({ outcome: "dry_run", status: "pending_approval" });
    expect(r.call).toMatchObject({ method: "PUT", url: "https://wazuh.acme.example/active-response?agents_list=001", status: null });
    expect(calls).toHaveLength(0);
  });

  it("partial failures and isolation reversal", async () => {
    const custom = createWazuhActiveResponse({ isolateCommand: "!bloody-isolate", releaseCommand: "!bloody-release" });
    const { fetch } = mockFetch([
      { method: "PUT", path: "/active-response", json: { data: { affected_items: ["003"], failed_items: [{ error: { code: 1707, message: "Cannot send request, agent is not active" }, id: ["004"] }] }, error: 2 } },
    ]);
    const client = new EngineClient({ engine: "wazuh", baseUrl: "https://wazuh.acme.example", fetch, resolveHost: testResolver });
    const r = await custom.execute(req({ action: "isolate_endpoint", target: { kind: "asset", id: "003" }, parameters: { agents: ["004"] } }), { client, clock });
    expect(r.outcome).toBe("partial");
    expect(r.status).toBe("failed");
    expect(r.failed).toEqual([{ id: "004", reason: "Cannot send request, agent is not active" }]);
    expect(r.reversal).toEqual({ action: "release_endpoint", parameters: { agents: ["003"] } });
  });

  it("Wazuh API client logs in with Basic, then uses the JWT; health reports agent counts", async () => {
    const { fetch, calls } = mockFetch([
      { method: "POST", path: "/security/user/authenticate", json: { data: { token: "jwt-token-123456" }, error: 0 } },
      { method: "GET", path: "/", json: { data: { title: "Wazuh API REST", api_version: "4.9.0" }, error: 0 } },
      { method: "GET", path: "/agents/summary/status", json: { data: { connection: { active: 8, disconnected: 1, never_connected: 1, pending: 0, total: 10 } } } },
    ]);
    const client = createWazuhApiClient({ baseUrl: "https://wazuh.acme.example:55000", username: "bloody", password: "pw", fetch, resolveHost: testResolver });
    const h = await wazuhHealthCheck(client);
    expect(h).toMatchObject({ status: "healthy", version: "4.9.0", details: { agentsActive: 8, agentsTotal: 10 } });
    expect(calls[0]?.headers["authorization"]).toMatch(/^Basic /);
    expect(calls[1]?.headers["authorization"]).toBe("Bearer jwt-token-123456");
    expect(calls.filter((c) => c.url.pathname === "/security/user/authenticate")).toHaveLength(1);
  });
});

describe("Velociraptor collections", () => {
  const velo = createVelociraptorResponse();
  const client = (routes: Parameters<typeof mockFetch>[0]) => {
    const m = mockFetch(routes);
    return { ...m, client: new EngineClient({ engine: "velociraptor", baseUrl: "https://velo.acme.example:8001", fetch: m.fetch, resolveHost: testResolver }) };
  };

  it("isolation schedules the quarantine artifact for the platform and offers a reversal", async () => {
    const { client: c, calls } = client([{ method: "POST", path: "/api/v1/CollectArtifact", json: { flow_id: "F.CQ1A2B3C", request: { client_id: "C.4f3e2d1c0b0a9988" } } }]);
    const r = await velo.execute(req({ action: "isolate_endpoint", target: { kind: "asset", id: "C.4f3e2d1c0b0a9988", label: "WS-ALICE" }, parameters: { platform: "windows" } }), { client: c, clock });
    expect(r).toMatchObject({ outcome: "succeeded", engineRef: "F.CQ1A2B3C", affected: ["C.4f3e2d1c0b0a9988"] });
    const body = JSON.parse(calls[0]?.body ?? "{}") as Record<string, unknown>;
    expect(body).toMatchObject({ client_id: "C.4f3e2d1c0b0a9988", artifacts: ["Windows.Remediation.Quarantine"], urgent: true });
    expect(r.reversal).toEqual({ action: "release_endpoint", parameters: { clientId: "C.4f3e2d1c0b0a9988", platform: "windows" } });
    const rel = await velo.execute(req({ action: "release_endpoint", target: { kind: "asset", id: "C.4f3e2d1c0b0a9988" }, parameters: { platform: "windows" } }), { client: c, clock });
    expect(rel.outcome).toBe("succeeded");
    expect(JSON.parse(calls[1]?.body ?? "{}")).toMatchObject({ specs: [{ artifact: "Windows.Remediation.Quarantine", parameters: { env: [{ key: "RemovePolicy", value: "Y" }] } }] });
  });

  it("evidence collection is allow-listed; YARA rule text is not copied into audit", async () => {
    const { client: c, calls } = client([{ method: "POST", path: "/api/v1/CollectArtifact", json: { flow_id: "F.2", request: { client_id: "C.4f3e2d1c0b0a9988" } } }]);
    const bad = await velo.execute(req({ action: "collect_evidence", approvedBy: null, target: { kind: "asset", id: "C.4f3e2d1c0b0a9988" }, parameters: { artifacts: ["Windows.System.PowerShell"] } }), { client: c, clock });
    expect(bad.outcome).toBe("rejected");
    expect(bad.error?.message).toContain("allow-list");
    const rule = "rule x { strings: $a = \"evil\" condition: $a }";
    const yara = await velo.execute(req({ action: "run_yara_scan", approvedBy: null, target: { kind: "asset", id: "C.4f3e2d1c0b0a9988" }, parameters: { yaraRule: rule, pathGlob: "C:/Users/**/*.exe" } }), { client: c, clock });
    expect(yara.outcome).toBe("succeeded");
    expect(JSON.stringify(yara.call?.body)).not.toContain("evil");
    expect(JSON.parse(calls[0]?.body ?? "{}")).toMatchObject({ specs: [{ artifact: "Generic.Detection.Yara.Glob" }] });
    const badClient = await velo.execute(req({ action: "collect_evidence", approvedBy: null, target: { kind: "asset", id: "not-a-client" }, parameters: { artifacts: ["Generic.Client.Info"] } }), { client: c, clock });
    expect(badClient.error?.code).toBe("invalid_target");
  });
});

describe("Firewall / DNS block webhook", () => {
  const secret = "0123456789abcdef0123456789abcdef";
  const hook = createWebhookBlockConnector({ secret, path: "/hooks/block", protectedValues: ["*.acme.example", "198.51.100.53"], clock });

  it("posts a signed, verifiable instruction and returns an unblock reversal", async () => {
    const { fetch, calls } = mockFetch([{ method: "POST", path: "/hooks/block", json: { status: "applied", ref: "rule-881" } }]);
    const client = new EngineClient({ engine: "webhook", baseUrl: "https://relay.acme-fw.example", fetch, resolveHost: testResolver });
    const r = await hook.execute(req({ parameters: { ttlSeconds: 3600 } }), { client, clock });
    expect(r).toMatchObject({ outcome: "succeeded", engineRef: "rule-881", affected: ["203.0.113.45"], reversal: { action: "block_ip", parameters: { operation: "unblock" } } });
    const call = calls[0];
    expect(call?.headers["content-type"]).toBe("application/json");
    expect(verifyWebhookSignature(secret, call?.headers[WEBHOOK_TIMESTAMP_HEADER], call?.body ?? "", call?.headers[WEBHOOK_SIGNATURE_HEADER], { now: clock() })).toBe(true);
    expect(verifyWebhookSignature("wrong-secret-wrong-secret", call?.headers[WEBHOOK_TIMESTAMP_HEADER], call?.body ?? "", call?.headers[WEBHOOK_SIGNATURE_HEADER], { now: clock() })).toBe(false);
    expect(verifyWebhookSignature(secret, call?.headers[WEBHOOK_TIMESTAMP_HEADER], call?.body ?? "", call?.headers[WEBHOOK_SIGNATURE_HEADER], { now: new Date("2026-10-07T13:00:00Z") })).toBe(false);
    expect(JSON.parse(call?.body ?? "{}")).toMatchObject({ version: 1, action: "block_ip", operation: "block", indicator: { type: "ip", value: "203.0.113.45" }, ttlSeconds: 3600, approvedBy: "user:responder-2" });
    expect(r.call?.bodySha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("refuses internal, protected and top-level targets", async () => {
    const { fetch, calls } = mockFetch([]);
    const client = new EngineClient({ engine: "webhook", baseUrl: "https://relay.acme-fw.example", fetch, resolveHost: testResolver });
    for (const target of ["10.0.0.8", "198.51.100.53", "169.254.169.254"]) {
      const r = await hook.execute(req({ target: { kind: "indicator", id: target } }), { client, clock });
      expect(r.outcome).toBe("rejected");
    }
    for (const domain of ["portal.acme.example", "com", "fileserver.corp"]) {
      const r = await hook.execute(req({ action: "block_domain", target: { kind: "indicator", id: domain } }), { client, clock });
      expect(r.outcome).toBe("rejected");
    }
    expect(calls).toHaveLength(0);
    expect(() => createWebhookBlockConnector({ secret: "short" })).toThrow();
  });

  it("relay errors become failed results with the engine error code", async () => {
    const { fetch } = mockFetch([{ method: "POST", path: "/hooks/block", status: 500, json: { error: "firewall unreachable" } }]);
    const client = new EngineClient({ engine: "webhook", baseUrl: "https://relay.acme-fw.example", fetch, resolveHost: testResolver });
    const r = await hook.execute(req({ action: "block_domain", target: { kind: "indicator", id: "cdn-update.badcdn.net" } }), { client, clock });
    expect(r).toMatchObject({ outcome: "failed", status: "failed", error: { code: "http" } });
    expect(r.call?.status).toBe(500);
    expect(r.audit.outcome).toBe("failed");
  });
});
