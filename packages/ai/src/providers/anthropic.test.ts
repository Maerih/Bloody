import { describe, expect, it } from "vitest";
import { fakeFetch, sseChunks } from "../test-support/fake-fetch.js";
import { FixedClock, noSleep, providerConfig, sequentialIds } from "../test-support/fixtures.js";
import { ANTHROPIC_API_VERSION, toAnthropicMessages } from "./anthropic.js";
import { createProvider } from "./factory.js";

const opts = { governance: false as const, sleep: noSleep, clock: new FixedClock(), ids: sequentialIds() };
const tools = [{ name: "search_events", description: "SIEM", parameters: { type: "object", properties: { query: { type: "string" } }, required: ["query"] } }];

describe("Anthropic provider", () => {
  it("maps system, tool_use and tool_result blocks and merges consecutive user turns", () => {
    const { system, messages } = toAnthropicMessages([
      { role: "system", content: "base policy" },
      { role: "system", content: "tenant policy" },
      { role: "user", content: "context block" },
      { role: "user", content: "question" },
      { role: "assistant", content: "Let me search.", toolCalls: [{ id: "toolu_1", name: "search_events", arguments: { query: "x" } }, { id: "toolu_2", name: "search_events", arguments: { query: "y" } }] },
      { role: "tool", toolCallId: "toolu_1", content: "r1" },
      { role: "tool", toolCallId: "toolu_2", content: "r2" },
    ]);
    expect(system).toBe("base policy\n\ntenant policy");
    expect(messages).toEqual([
      { role: "user", content: [{ type: "text", text: "context block" }, { type: "text", text: "question" }] },
      {
        role: "assistant",
        content: [
          { type: "text", text: "Let me search." },
          { type: "tool_use", id: "toolu_1", name: "search_events", input: { query: "x" } },
          { type: "tool_use", id: "toolu_2", name: "search_events", input: { query: "y" } },
        ],
      },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_1", content: "r1" }, { type: "tool_result", tool_use_id: "toolu_2", content: "r2" }] },
    ]);
  });

  it("sends the Messages API request and parses tool_use", async () => {
    const { fetch, requests } = fakeFetch([
      {
        json: {
          id: "msg_1",
          type: "message",
          role: "assistant",
          model: "claude-sonnet-4-5-20250929",
          content: [
            { type: "text", text: "Searching SIEM." },
            { type: "tool_use", id: "toolu_9", name: "search_events", input: { query: "process.name:mimikatz.exe" } },
          ],
          stop_reason: "tool_use",
          usage: { input_tokens: 812, output_tokens: 44 },
        },
      },
    ]);
    const p = createProvider(providerConfig({ kind: "anthropic", model: "claude-sonnet-4-5", temperature: 1.6 }), "sk-ant-test", fetch, opts);
    const res = await p.chat({ messages: [{ role: "system", content: "policy" }, { role: "user", content: "hunt" }], tools, toolChoice: "none" });
    const req = requests[0]!;
    expect(req.url).toBe("https://api.anthropic.com/v1/messages");
    expect(req.headers["x-api-key"]).toBe("sk-ant-test");
    expect(req.headers["anthropic-version"]).toBe(ANTHROPIC_API_VERSION);
    expect(req.body).toMatchObject({
      model: "claude-sonnet-4-5",
      max_tokens: 1024,
      temperature: 1,
      system: "policy",
      tools: [{ name: "search_events", description: "SIEM", input_schema: tools[0]!.parameters }],
      tool_choice: { type: "none" },
      messages: [{ role: "user", content: [{ type: "text", text: "hunt" }] }],
    });
    expect(res.message).toEqual({ role: "assistant", content: "Searching SIEM.", toolCalls: [{ id: "toolu_9", name: "search_events", arguments: { query: "process.name:mimikatz.exe" } }] });
    expect(res.finishReason).toBe("tool_calls");
    expect(res.usage).toEqual({ inputTokens: 812, outputTokens: 44 });
    expect(res.model).toBe("claude-sonnet-4-5-20250929");
  });

  it("streams text and tool input JSON deltas", async () => {
    const events = [
      { type: "message_start", message: { model: "claude-haiku-4-5", usage: { input_tokens: 100, output_tokens: 1 } } },
      { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } },
      { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "Check" } },
      { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "ing." } },
      { type: "content_block_stop", index: 0 },
      { type: "content_block_start", index: 1, content_block: { type: "tool_use", id: "toolu_s", name: "search_events", input: {} } },
      { type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: '{"query":' } },
      { type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: '"user:root"}' } },
      { type: "content_block_stop", index: 1 },
      { type: "message_delta", delta: { stop_reason: "tool_use" }, usage: { output_tokens: 30 } },
      { type: "message_stop" },
    ];
    const { fetch, requests } = fakeFetch([{ chunks: sseChunks(events, { eventNames: true }) }]);
    const deltas: string[] = [];
    const res = await createProvider(providerConfig({ kind: "anthropic" }), "k", fetch, opts).chat({ messages: [{ role: "user", content: "x" }], tools, onDelta: (t) => deltas.push(t) });
    expect(requests[0]!.body).toMatchObject({ stream: true });
    expect(deltas.join("")).toBe("Checking.");
    expect(res.message.toolCalls).toEqual([{ id: "toolu_s", name: "search_events", arguments: { query: "user:root" } }]);
    expect(res.usage).toEqual({ inputTokens: 100, outputTokens: 30 });
  });

  it("surfaces overloaded stream errors", async () => {
    const { fetch } = fakeFetch([{ chunks: sseChunks([{ type: "error", error: { type: "overloaded_error", message: "Overloaded" } }]) }]);
    await expect(createProvider(providerConfig({ kind: "anthropic" }), "k", fetch, opts).chat({ messages: [{ role: "user", content: "x" }], onDelta: () => undefined })).rejects.toMatchObject({
      code: "overloaded",
    });
  });

  it("lists models", async () => {
    const { fetch, requests } = fakeFetch([{ json: { data: [{ id: "claude-sonnet-4-5", display_name: "Claude Sonnet 4.5", type: "model" }] } }]);
    expect(await createProvider(providerConfig({ kind: "anthropic" }), "k", fetch, opts).listModels()).toEqual([{ id: "claude-sonnet-4-5", name: "Claude Sonnet 4.5" }]);
    expect(requests[0]!.url).toBe("https://api.anthropic.com/v1/models?limit=100");
  });
});
