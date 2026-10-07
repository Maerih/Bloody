import { describe, expect, it } from "vitest";
import { fakeFetch } from "../test-support/fake-fetch.js";
import { FixedClock, noSleep, providerConfig, sequentialIds } from "../test-support/fixtures.js";
import { parseBedrockSecret, regionFromEndpoint, toBedrockMessages } from "./bedrock.js";
import { createProvider } from "./factory.js";
import { signSigV4 } from "./sigv4.js";

const clock = new FixedClock(new Date("2026-10-07T12:00:00.000Z"));
const opts = { governance: false as const, sleep: noSleep, clock, ids: sequentialIds() };
const SECRET = JSON.stringify({ accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", sessionToken: "SESSION", region: "eu-west-1" });
const tools = [{ name: "get_identity", description: "Identity", parameters: { type: "object", properties: { identityId: { type: "string" } } } }];

describe("Bedrock Converse provider", () => {
  it("parses credentials and regions", () => {
    expect(parseBedrockSecret("AKID:SECRET")).toEqual({ kind: "sigv4", credentials: { accessKeyId: "AKID", secretAccessKey: "SECRET" }, region: null });
    expect(parseBedrockSecret("AKID:SECRET:TOKEN")).toMatchObject({ credentials: { sessionToken: "TOKEN" } });
    expect(parseBedrockSecret('{"apiKey":"ABSKabc","region":"us-west-2"}')).toEqual({ kind: "bearer", token: "ABSKabc", region: "us-west-2" });
    expect(parseBedrockSecret("ABSKxyz")).toMatchObject({ kind: "bearer" });
    expect(() => parseBedrockSecret("garbage")).toThrow(/format/);
    expect(regionFromEndpoint("https://bedrock-runtime.ap-southeast-2.amazonaws.com")).toBe("ap-southeast-2");
    expect(regionFromEndpoint("https://bedrock-runtime-fips.us-east-1.amazonaws.com")).toBe("us-east-1");
  });

  it("maps messages with toolUse/toolResult and system blocks", () => {
    const { system, messages } = toBedrockMessages([
      { role: "system", content: "policy" },
      { role: "user", content: "who is this" },
      { role: "assistant", content: "", toolCalls: [{ id: "tu1", name: "get_identity", arguments: { identityId: "i-1" } }] },
      { role: "tool", toolCallId: "tu1", content: '{"ok":1}' },
    ]);
    expect(system).toBe("policy");
    expect(messages).toEqual([
      { role: "user", content: [{ text: "who is this" }] },
      { role: "assistant", content: [{ toolUse: { toolUseId: "tu1", name: "get_identity", input: { identityId: "i-1" } } }] },
      { role: "user", content: [{ toolResult: { toolUseId: "tu1", content: [{ text: '{"ok":1}' }] } }] },
    ]);
  });

  it("sends a SigV4-signed Converse request and parses tool use", async () => {
    const { fetch, requests } = fakeFetch([
      {
        json: {
          output: { message: { role: "assistant", content: [{ text: "Looking up." }, { toolUse: { toolUseId: "tooluse_1", name: "get_identity", input: { identityId: "i-9" } } }] } },
          stopReason: "tool_use",
          usage: { inputTokens: 410, outputTokens: 33, totalTokens: 443 },
        },
      },
    ]);
    const model = "anthropic.claude-3-5-sonnet-20240620-v1:0";
    const p = createProvider(providerConfig({ kind: "aws_bedrock", endpoint: null, model }), SECRET, fetch, opts);
    const res = await p.chat({ messages: [{ role: "system", content: "policy" }, { role: "user", content: "who" }], tools });
    const req = requests[0]!;
    expect(req.url).toBe("https://bedrock-runtime.eu-west-1.amazonaws.com/model/anthropic.claude-3-5-sonnet-20240620-v1%3A0/converse");
    expect(req.headers["x-amz-date"]).toBe("20261007T120000Z");
    expect(req.headers["x-amz-security-token"]).toBe("SESSION");
    expect(req.headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20261007\/eu-west-1\/bedrock\/aws4_request, SignedHeaders=accept;content-type;host;x-amz-date;x-amz-security-token, Signature=[0-9a-f]{64}$/);
    // Independently recompute the signature for the exact request that was sent.
    const expected = signSigV4({
      method: "POST",
      url: req.url,
      headers: { accept: "application/json", "content-type": "application/json" },
      body: req.rawBody!,
      region: "eu-west-1",
      service: "bedrock",
      credentials: { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", sessionToken: "SESSION" },
      now: clock.now(),
    });
    expect(req.headers.authorization).toBe(expected.headers.authorization);
    expect(expected.canonicalRequest).toContain("/model/anthropic.claude-3-5-sonnet-20240620-v1%253A0/converse");
    expect(req.body).toMatchObject({
      system: [{ text: "policy" }],
      messages: [{ role: "user", content: [{ text: "who" }] }],
      inferenceConfig: { maxTokens: 1024, temperature: 0.2 },
      toolConfig: { tools: [{ toolSpec: { name: "get_identity", description: "Identity", inputSchema: { json: tools[0]!.parameters } } }], toolChoice: { auto: {} } },
    });
    expect(res.message).toEqual({ role: "assistant", content: "Looking up.", toolCalls: [{ id: "tooluse_1", name: "get_identity", arguments: { identityId: "i-9" } }] });
    expect(res.usage).toEqual({ inputTokens: 410, outputTokens: 33 });
    expect(res.finishReason).toBe("tool_calls");
  });

  it("keeps toolConfig (without toolChoice) when finalizing with tool history", async () => {
    const { fetch, requests } = fakeFetch([{ json: { output: { message: { role: "assistant", content: [{ text: "done" }] } }, stopReason: "end_turn", usage: { inputTokens: 1, outputTokens: 1 } } }]);
    const p = createProvider(providerConfig({ kind: "aws_bedrock", endpoint: "https://bedrock-runtime.us-east-1.amazonaws.com", model: "amazon.nova-pro-v1:0" }), "AKID:SECRET", fetch, opts);
    await p.chat({
      messages: [
        { role: "user", content: "q" },
        { role: "assistant", content: "", toolCalls: [{ id: "t", name: "get_identity", arguments: {} }] },
        { role: "tool", toolCallId: "t", content: "r" },
      ],
      tools,
      toolChoice: "none",
    });
    const body = requests[0]!.body as { toolConfig: Record<string, unknown> };
    expect(body.toolConfig.tools).toBeDefined();
    expect(body.toolConfig.toolChoice).toBeUndefined();
    expect(requests[0]!.headers["x-amz-security-token"]).toBeUndefined();
  });

  it("supports Bedrock API keys and lists foundation models on the control plane", async () => {
    const { fetch, requests } = fakeFetch([{ json: { modelSummaries: [{ modelId: "amazon.nova-pro-v1:0", modelName: "Nova Pro", providerName: "Amazon" }] } }]);
    const p = createProvider(providerConfig({ kind: "aws_bedrock", endpoint: null, model: "us.amazon.nova-pro-v1:0" }), '{"apiKey":"ABSKtoken","region":"us-east-1"}', fetch, opts);
    const health = await p.healthCheck();
    expect(requests[0]!.url).toBe("https://bedrock.us-east-1.amazonaws.com/foundation-models?byOutputModality=TEXT");
    expect(requests[0]!.headers.authorization).toBe("Bearer ABSKtoken");
    expect(health).toMatchObject({ ok: true, modelAvailable: true });
  });

  it("requires a resolvable region", () => {
    const { fetch } = fakeFetch([]);
    expect(() => createProvider(providerConfig({ kind: "aws_bedrock", endpoint: null }), "AKID:SECRET", fetch, opts)).toThrow(/region/);
  });
});
