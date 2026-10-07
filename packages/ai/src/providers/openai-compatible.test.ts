import type { AiMessage } from "@bloody/contracts";
import { describe, expect, it } from "vitest";
import { fakeFetch, sseChunks } from "../test-support/fake-fetch.js";
import { FixedClock, noSleep, providerConfig, sequentialIds } from "../test-support/fixtures.js";
import { createProvider } from "./factory.js";
import { INVALID_TOOL_ARGUMENTS_KEY } from "./messages.js";
import type { ToolSpec } from "./types.js";

const TOOLS: ToolSpec[] = [{ name: "get_incident", description: "Fetch incident", parameters: { type: "object", properties: { incidentId: { type: "string" } }, required: ["incidentId"] } }];
const HISTORY: AiMessage[] = [
  { role: "system", content: "policy" },
  { role: "user", content: "Investigate incident 7" },
  { role: "assistant", content: "", toolCalls: [{ id: "call_1", name: "get_incident", arguments: { incidentId: "7" } }] },
  { role: "tool", toolCallId: "call_1", content: '{"status":"completed"}' },
];
const opts = { governance: false as const, sleep: noSleep, clock: new FixedClock(), ids: sequentialIds() };

describe("OpenAI-compatible providers", () => {
  it("maps messages, tools and sampling for OpenAI", async () => {
    const { fetch, requests } = fakeFetch([
      {
        json: {
          model: "gpt-4.1-2025",
          choices: [{ finish_reason: "tool_calls", message: { role: "assistant", content: null, tool_calls: [{ id: "call_2", type: "function", function: { name: "get_incident", arguments: '{"incidentId":"8"}' } }] } }],
          usage: { prompt_tokens: 120, completion_tokens: 15 },
        },
      },
    ]);
    const p = createProvider(providerConfig({ kind: "openai", model: "gpt-4.1", temperature: 0.3, maxOutputTokens: 900 }), "sk-test", fetch, opts);
    const res = await p.chat({ messages: HISTORY, tools: TOOLS });
    const req = requests[0]!;
    expect(req.url).toBe("https://api.openai.com/v1/chat/completions");
    expect(req.headers.authorization).toBe("Bearer sk-test");
    expect(req.body).toMatchObject({
      model: "gpt-4.1",
      temperature: 0.3,
      max_completion_tokens: 900,
      tool_choice: "auto",
      tools: [{ type: "function", function: { name: "get_incident", parameters: TOOLS[0]!.parameters } }],
      messages: [
        { role: "system", content: "policy" },
        { role: "user", content: "Investigate incident 7" },
        { role: "assistant", content: null, tool_calls: [{ id: "call_1", type: "function", function: { name: "get_incident", arguments: '{"incidentId":"7"}' } }] },
        { role: "tool", tool_call_id: "call_1", content: '{"status":"completed"}' },
      ],
    });
    expect(res.message.toolCalls).toEqual([{ id: "call_2", name: "get_incident", arguments: { incidentId: "8" } }]);
    expect(res.finishReason).toBe("tool_calls");
    expect(res.usage).toEqual({ inputTokens: 120, outputTokens: 15 });
    expect(res.model).toBe("gpt-4.1-2025");
    expect(res.servedBy).toMatchObject({ kind: "openai", model: "gpt-4.1-2025" });
  });

  it("uses max_tokens and default local endpoints for vLLM / LM Studio, and no auth without a key", async () => {
    const { fetch, requests } = fakeFetch([{ json: { choices: [{ finish_reason: "stop", message: { content: "done" } }] } }]);
    const vllm = createProvider(providerConfig({ kind: "vllm", credentialRef: null }), null, fetch, { ...opts, allowPrivateEndpoints: true });
    const res = await vllm.chat({ messages: [{ role: "user", content: "hi" }], toolChoice: "none", tools: TOOLS });
    expect(requests[0]!.url).toBe("http://localhost:8000/v1/chat/completions");
    expect(requests[0]!.headers.authorization).toBeUndefined();
    expect(requests[0]!.body).toMatchObject({ max_tokens: 1024, tool_choice: "none" });
    expect(res.usage.estimated).toBe(true);
    const lm = createProvider(providerConfig({ kind: "lmstudio", credentialRef: null }), null, fetch, { ...opts, allowPrivateEndpoints: true });
    await lm.chat({ messages: [{ role: "user", content: "hi" }] });
    expect(requests[1]!.url).toBe("http://localhost:1234/v1/chat/completions");
  });

  it("targets Mistral's API", async () => {
    const { fetch, requests } = fakeFetch([{ json: { choices: [{ finish_reason: "stop", message: { content: "ok" } }], usage: { prompt_tokens: 1, completion_tokens: 1 } } }]);
    await createProvider(providerConfig({ kind: "mistral", model: "mistral-large-latest" }), "mk", fetch, opts).chat({ messages: [{ role: "user", content: "x" }] });
    expect(requests[0]!.url).toBe("https://api.mistral.ai/v1/chat/completions");
    expect(requests[0]!.body).toMatchObject({ model: "mistral-large-latest", max_tokens: 1024 });
  });

  it("marks invalid JSON tool arguments", async () => {
    const { fetch } = fakeFetch([{ json: { choices: [{ finish_reason: "tool_calls", message: { tool_calls: [{ id: "x", function: { name: "get_incident", arguments: "{not json" } }] } }] } }]);
    const res = await createProvider(providerConfig(), "k", fetch, opts).chat({ messages: [{ role: "user", content: "x" }] });
    expect(res.message.toolCalls![0]!.arguments).toEqual({ [INVALID_TOOL_ARGUMENTS_KEY]: "{not json" });
  });

  it("streams text deltas and assembles streamed tool calls", async () => {
    const chunks = sseChunks(
      [
        { model: "gpt-4.1", choices: [{ index: 0, delta: { role: "assistant", content: "Looking " } }] },
        { choices: [{ index: 0, delta: { content: "it up" } }] },
        { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "call_9", type: "function", function: { name: "get_incident", arguments: '{"inci' } }] } }] },
        { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: 'dentId":"9"}' } }] }, finish_reason: "tool_calls" }] },
        { choices: [], usage: { prompt_tokens: 50, completion_tokens: 9 } },
      ],
      { done: true },
    );
    const { fetch, requests } = fakeFetch([{ chunks }]);
    const deltas: string[] = [];
    const res = await createProvider(providerConfig({ kind: "openai" }), "k", fetch, opts).chat({ messages: [{ role: "user", content: "x" }], tools: TOOLS, onDelta: (t) => deltas.push(t) });
    expect(requests[0]!.body).toMatchObject({ stream: true, stream_options: { include_usage: true } });
    expect(deltas.join("")).toBe("Looking it up");
    expect(res.message).toEqual({ role: "assistant", content: "Looking it up", toolCalls: [{ id: "call_9", name: "get_incident", arguments: { incidentId: "9" } }] });
    expect(res.usage).toEqual({ inputTokens: 50, outputTokens: 9 });
    expect(res.finishReason).toBe("tool_calls");
  });

  it("lists models and reports health", async () => {
    const { fetch, requests } = fakeFetch([{ json: { data: [{ id: "gpt-test", owned_by: "openai" }, { id: "other", max_model_len: 32768 }] } }]);
    const p = createProvider(providerConfig({ kind: "openai", model: "gpt-test" }), "k", fetch, opts);
    const health = await p.healthCheck();
    expect(requests[0]!.url).toBe("https://api.openai.com/v1/models");
    expect(health).toMatchObject({ ok: true, modelAvailable: true, modelsListed: 2, kind: "openai" });
    const failing = createProvider(providerConfig({ kind: "openai" }), "k", fakeFetch([{ status: 401, json: { error: { message: "bad key" } } }]).fetch, opts);
    expect(await failing.healthCheck()).toMatchObject({ ok: false, error: { code: "auth_failed" } });
  });
});

describe("Azure OpenAI", () => {
  it("uses the deployment URL, api-version and api-key header", async () => {
    const { fetch, requests } = fakeFetch([{ json: { choices: [{ finish_reason: "stop", message: { content: "ok" } }], usage: { prompt_tokens: 3, completion_tokens: 1 } } }]);
    const p = createProvider(providerConfig({ kind: "azure_openai", endpoint: "https://acme-ai.openai.azure.com/?api-version=2025-01-01-preview", model: "soc-gpt4o" }), "azure-key", fetch, opts);
    await p.chat({ messages: [{ role: "user", content: "x" }], tools: TOOLS });
    const req = requests[0]!;
    expect(req.url).toBe("https://acme-ai.openai.azure.com/openai/deployments/soc-gpt4o/chat/completions?api-version=2025-01-01-preview");
    expect(req.headers["api-key"]).toBe("azure-key");
    expect(req.headers.authorization).toBeUndefined();
    expect((req.body as Record<string, unknown>).model).toBeUndefined();
    expect(req.body).toMatchObject({ max_tokens: 1024, tools: [{ type: "function" }] });
  });

  it("defaults the api-version and requires an endpoint and key", async () => {
    const { fetch, requests } = fakeFetch([{ json: { choices: [{ message: { content: "pong" } }] } }]);
    const p = createProvider(providerConfig({ kind: "azure_openai", endpoint: "https://acme.openai.azure.com", model: "dep" }), "k", fetch, opts);
    expect(await p.healthCheck()).toMatchObject({ ok: true, modelAvailable: true });
    expect(requests[0]!.url).toContain("api-version=2024-10-21");
    expect(requests[0]!.body).toMatchObject({ max_tokens: 1 });
    expect(() => createProvider(providerConfig({ kind: "azure_openai", endpoint: null }), "k", fetch, opts)).toThrow(/endpoint/);
    expect(() => createProvider(providerConfig({ kind: "azure_openai", endpoint: "https://acme.openai.azure.com" }), null, fetch, opts)).toThrow(/credential/);
  });
});
