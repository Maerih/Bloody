import { describe, expect, it } from "vitest";
import { fakeFetch } from "../test-support/fake-fetch.js";
import { FixedClock, noSleep, providerConfig, sequentialIds } from "../test-support/fixtures.js";
import { createProvider } from "./factory.js";

const opts = { governance: false as const, sleep: noSleep, clock: new FixedClock(), ids: sequentialIds(), allowPrivateEndpoints: true };
const tools = [{ name: "get_asset", description: "Asset", parameters: { type: "object", properties: { assetId: { type: "string" } } } }];

describe("Ollama provider", () => {
  it("maps /api/chat requests (tools, tool_name, num_ctx) and parses tool calls", async () => {
    const { fetch, requests } = fakeFetch([
      {
        json: {
          model: "qwen2.5:14b",
          message: { role: "assistant", content: "", tool_calls: [{ function: { name: "get_asset", arguments: { assetId: "a-1" } } }] },
          done: true,
          done_reason: "stop",
          prompt_eval_count: 321,
          eval_count: 17,
        },
      },
    ]);
    const p = createProvider(providerConfig({ kind: "ollama", endpoint: "http://gpu-box.internal:11434/v1", model: "qwen2.5:14b", credentialRef: null, contextWindow: 16384, maxOutputTokens: 700 }), null, fetch, opts);
    const res = await p.chat({
      messages: [
        { role: "user", content: "check" },
        { role: "assistant", content: "", toolCalls: [{ id: "c1", name: "get_asset", arguments: { assetId: "a-0" } }] },
        { role: "tool", toolCallId: "c1", content: '{"ok":true}' },
      ],
      tools,
    });
    const req = requests[0]!;
    expect(req.url).toBe("http://gpu-box.internal:11434/api/chat");
    expect(req.body).toMatchObject({
      model: "qwen2.5:14b",
      stream: false,
      options: { num_ctx: 16384, num_predict: 700, temperature: 0.2 },
      tools: [{ type: "function", function: { name: "get_asset" } }],
      messages: [
        { role: "user", content: "check" },
        { role: "assistant", content: "", tool_calls: [{ function: { name: "get_asset", arguments: { assetId: "a-0" } } }] },
        { role: "tool", content: '{"ok":true}', tool_name: "get_asset" },
      ],
    });
    expect(res.message.toolCalls).toHaveLength(1);
    expect(res.message.toolCalls![0]).toMatchObject({ name: "get_asset", arguments: { assetId: "a-1" } });
    expect(res.message.toolCalls![0]!.id).toMatch(/^call_/);
    expect(res.usage).toEqual({ inputTokens: 321, outputTokens: 17 });
    expect(res.finishReason).toBe("tool_calls");
  });

  it("streams NDJSON and omits tools when toolChoice is none", async () => {
    const lines = [
      { model: "llama3.1:8b", message: { role: "assistant", content: "Hel" }, done: false },
      { model: "llama3.1:8b", message: { role: "assistant", content: "lo" }, done: false },
      { model: "llama3.1:8b", message: { role: "assistant", content: "" }, done: true, done_reason: "length", prompt_eval_count: 9, eval_count: 2 },
    ].map((l) => JSON.stringify(l) + "\n");
    const { fetch, requests } = fakeFetch([{ chunks: [lines[0]!, lines[1]!.slice(0, 10), lines[1]!.slice(10) + lines[2]!] }]);
    const deltas: string[] = [];
    const res = await createProvider(providerConfig({ kind: "ollama", credentialRef: null, model: "llama3.1:8b" }), null, fetch, opts).chat({
      messages: [{ role: "user", content: "hi" }],
      tools,
      toolChoice: "none",
      onDelta: (t) => deltas.push(t),
    });
    expect((requests[0]!.body as Record<string, unknown>).tools).toBeUndefined();
    expect(requests[0]!.body).toMatchObject({ stream: true });
    expect(deltas).toEqual(["Hel", "lo"]);
    expect(res.message.content).toBe("Hello");
    expect(res.finishReason).toBe("length");
    expect(res.usage).toEqual({ inputTokens: 9, outputTokens: 2 });
  });

  it("lists models from /api/tags and matches ':latest'", async () => {
    const { fetch, requests } = fakeFetch([{ json: { models: [{ name: "llama3.1:latest", size: 4_900_000_000, details: { family: "llama", parameter_size: "8.0B" } }] } }]);
    const p = createProvider(providerConfig({ kind: "ollama", credentialRef: null, model: "llama3.1" }), null, fetch, opts);
    const health = await p.healthCheck();
    expect(requests[0]!.url).toBe("http://localhost:11434/api/tags");
    expect(health).toMatchObject({ ok: true, modelAvailable: true });
    expect(await p.listModels()).toEqual([{ id: "llama3.1:latest", family: "llama", parameterSize: "8.0B", sizeBytes: 4_900_000_000 }]);
  });
});
