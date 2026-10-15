import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, login, type Json, type TestApp, type TestTenant } from "../test/harness.js";

const SECRET = "sk-test-SECRET-should-never-leak-123";
const seenAuth: string[] = [];
let script: Json[] = [];

/** Fake OpenAI-compatible endpoint: replays `script` (one completion per call). */
const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = String(input);
  const headers = new Headers(init?.headers);
  seenAuth.push(headers.get("authorization") ?? "");
  if (url.endsWith("/models")) return new Response(JSON.stringify({ data: [{ id: "fake-model" }] }), { status: 200, headers: { "content-type": "application/json" } });
  const next = script.shift() ?? { role: "assistant", content: "Done." };
  const body = { id: "x", object: "chat.completion", model: "fake-model", choices: [{ index: 0, finish_reason: next.tool_calls ? "tool_calls" : "stop", message: next }], usage: { prompt_tokens: 10, completion_tokens: 5 } };
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}) as typeof fetch;

let t: TestApp;
let tenant: TestTenant;
let org: string;
let admin: ReturnType<typeof api>;
let other: ReturnType<typeof api>;
let providerId: string;

beforeAll(async () => {
  t = await createTestApp({ deps: { fetch: fakeFetch, hostResolver: false } });
  tenant = await createTenant(t, { orgs: 1, plan: "enterprise" });
  org = tenant.orgIds[0]!;
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const o = await createTenant(t, { orgs: 1, plan: "enterprise" });
  other = api(t.app, { token: (await login(t.app, o.admin.email)).token });
});
afterAll(async () => {
  await t?.close();
});

describe("AI SOC providers and chat", () => {
  it("stores the API key write-only", async () => {
    const res = await admin.post("/ai/providers", {
      name: "Test LLM",
      kind: "openai_compatible",
      endpoint: "https://llm.test/v1",
      model: "fake-model",
      apiKey: SECRET,
      isDefault: true,
      maxToolTier: "recommend",
      allowCloudData: true,
    });
    expect(res.status).toBe(201);
    providerId = res.body.id;
    expect(res.body.hasCredential).toBe(true);
    expect(JSON.stringify(res.body)).not.toContain(SECRET);
    expect(JSON.stringify((await admin.get("/ai/providers")).body)).not.toContain(SECRET);
    expect(JSON.stringify((await admin.get(`/ai/providers/${providerId}`)).body)).not.toContain(SECRET);
  });

  it("tests the connection using the stored secret server-side", async () => {
    const res = await admin.post(`/ai/providers/${providerId}/test`, {});
    expect(res.status).toBe(200);
    expect(seenAuth.some((h) => h.includes(SECRET))).toBe(true);
    expect(JSON.stringify(res.body)).not.toContain(SECRET);
  });

  it("answers a chat turn", async () => {
    script = [{ role: "assistant", content: "No active critical incidents." }];
    const res = await admin.post("/ai/chat", { organizationId: org, message: "Summarise today's incidents" });
    expect(res.status).toBe(200);
    expect(JSON.stringify(res.body)).toContain("No active critical incidents.");
  });

  it("never lets the model execute above its tool tier", async () => {
    script = [
      {
        role: "assistant",
        content: null,
        tool_calls: [
          {
            id: "call_1",
            type: "function",
            function: {
              name: "request_response_action",
              arguments: JSON.stringify({ action: "isolate_endpoint", organizationId: org, target: { kind: "asset", id: "00000000-0000-0000-0000-000000000000" }, reason: "model wants to isolate" }),
            },
          },
        ],
      },
      { role: "assistant", content: "I cannot do that without approval." },
    ];
    const res = await admin.post("/ai/chat", { organizationId: org, message: "Isolate the host now" });
    expect(res.status).toBe(200);
    const text = JSON.stringify(res.body);
    expect(text).toMatch(/denied|pending_approval|not permitted|tier/i);
    const executed = await t.db.withTenant(tenant.tenantId, async (tx) =>
      (await tx.query<{ n: string }>("SELECT count(*)::text AS n FROM response_actions WHERE status IN ('running','succeeded','queued')")).rows[0]!.n,
    );
    expect(executed).toBe("0");
  });

  it("isolates providers and conversations per tenant", async () => {
    expect((await other.get(`/ai/providers/${providerId}`)).status).toBe(404);
    expect(JSON.stringify((await other.get("/ai/providers")).body)).not.toContain(providerId);
    const convs = (await admin.get("/ai/conversations")).body.items as Json[];
    expect(convs.length).toBeGreaterThan(0);
    expect((await other.get(`/ai/conversations/${convs[0].id}`)).status).toBe(404);
  });
});
