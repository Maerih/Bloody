import { z } from "zod";
import { describe, expect, it } from "vitest";
import { fakeFetch } from "../test-support/fake-fetch.js";
import { FixedClock, noSleep, providerConfig, sequentialIds } from "../test-support/fixtures.js";
import { zodToJsonSchema } from "../tools/json-schema.js";
import { createProvider } from "./factory.js";
import { toGeminiSchema } from "./gemini.js";

const opts = { governance: false as const, sleep: noSleep, clock: new FixedClock(), ids: sequentialIds() };

describe("Gemini provider", () => {
  it("converts JSON schema to Gemini's OpenAPI subset", () => {
    const schema = zodToJsonSchema(
      z.object({
        incidentId: z.string().uuid().describe("Incident id"),
        severity: z.enum(["low", "high"]).optional(),
        note: z.string().nullable(),
        mode: z.literal("search"),
        limit: z.number().int().min(1).max(50).default(10),
        params: z.record(z.unknown()),
        since: z.string().datetime({ offset: true }),
      }),
    );
    const g = toGeminiSchema(schema);
    expect(g).toEqual({
      type: "object",
      properties: {
        incidentId: { type: "string", description: "Incident id" },
        severity: { type: "string", enum: ["low", "high"] },
        note: { type: "string", nullable: true },
        mode: { type: "string", enum: ["search"] },
        limit: { type: "integer", minimum: 1, maximum: 50 },
        params: { type: "object" },
        since: { type: "string", format: "date-time" },
      },
      required: ["incidentId", "note", "mode", "params", "since"],
    });
  });

  it("maps contents, function calls/responses, system instruction and replays thought signatures", async () => {
    const { fetch, requests } = fakeFetch([
      {
        json: {
          candidates: [
            {
              content: {
                role: "model",
                parts: [
                  { text: "thinking", thought: true },
                  { text: "Fetching the asset." },
                  { functionCall: { name: "get_asset", args: { assetId: "a-1" } }, thoughtSignature: "sig-123" },
                ],
              },
              finishReason: "STOP",
            },
          ],
          usageMetadata: { promptTokenCount: 200, candidatesTokenCount: 20, thoughtsTokenCount: 5 },
          modelVersion: "gemini-2.5-flash-001",
        },
      },
      { json: { candidates: [{ content: { role: "model", parts: [{ text: "Asset is healthy." }] }, finishReason: "STOP" }], usageMetadata: { promptTokenCount: 260, candidatesTokenCount: 8 } } },
    ]);
    const p = createProvider(providerConfig({ kind: "google", model: "models/gemini-2.5-flash" }), "g-key", fetch, opts);
    const tools = [{ name: "get_asset", description: "Asset", parameters: { type: "object", properties: { assetId: { type: "string", format: "uuid" } }, required: ["assetId"], additionalProperties: false } }];
    const first = await p.chat({ messages: [{ role: "system", content: "policy" }, { role: "user", content: "check asset" }], tools });
    const req = requests[0]!;
    expect(req.url).toBe("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent");
    expect(req.url).not.toContain("g-key");
    expect(req.headers["x-goog-api-key"]).toBe("g-key");
    expect(req.body).toMatchObject({
      systemInstruction: { parts: [{ text: "policy" }] },
      contents: [{ role: "user", parts: [{ text: "check asset" }] }],
      tools: [{ functionDeclarations: [{ name: "get_asset", description: "Asset", parameters: { type: "object", properties: { assetId: { type: "string" } }, required: ["assetId"] } }] }],
      toolConfig: { functionCallingConfig: { mode: "AUTO" } },
      generationConfig: { temperature: 0.2, maxOutputTokens: 1024 },
    });
    expect(first.message.content).toBe("Fetching the asset.");
    const call = first.message.toolCalls![0]!;
    expect(call).toMatchObject({ name: "get_asset", arguments: { assetId: "a-1" } });
    expect(first.usage).toEqual({ inputTokens: 200, outputTokens: 25 });
    expect(first.model).toBe("gemini-2.5-flash-001");

    await p.chat({
      messages: [{ role: "user", content: "check asset" }, first.message, { role: "tool", toolCallId: call.id, content: '{"status":"completed","data":{"health":"ok"}}' }],
      tools,
      toolChoice: "none",
    });
    expect(requests[1]!.body).toMatchObject({
      toolConfig: { functionCallingConfig: { mode: "NONE" } },
      contents: [
        { role: "user", parts: [{ text: "check asset" }] },
        { role: "model", parts: [{ text: "Fetching the asset." }, { functionCall: { name: "get_asset", args: { assetId: "a-1" } }, thoughtSignature: "sig-123" }] },
        { role: "user", parts: [{ functionResponse: { name: "get_asset", response: { status: "completed", data: { health: "ok" } } } }] },
      ],
    });
  });

  it("reports safety blocks as content_filter", async () => {
    const { fetch } = fakeFetch([{ json: { promptFeedback: { blockReason: "SAFETY" }, usageMetadata: { promptTokenCount: 3 } } }]);
    const res = await createProvider(providerConfig({ kind: "google", model: "gemini-2.5-pro" }), "k", fetch, opts).chat({ messages: [{ role: "user", content: "x" }] });
    expect(res.finishReason).toBe("content_filter");
  });

  it("lists generateContent-capable models", async () => {
    const { fetch } = fakeFetch([
      {
        json: {
          models: [
            { name: "models/gemini-2.5-pro", displayName: "Gemini 2.5 Pro", inputTokenLimit: 1048576, outputTokenLimit: 65536, supportedGenerationMethods: ["generateContent", "countTokens"] },
            { name: "models/text-embedding-004", supportedGenerationMethods: ["embedContent"] },
          ],
        },
      },
    ]);
    expect(await createProvider(providerConfig({ kind: "google", model: "gemini-2.5-pro" }), "k", fetch, opts).listModels()).toEqual([
      { id: "gemini-2.5-pro", name: "Gemini 2.5 Pro", contextWindow: 1048576, maxOutputTokens: 65536 },
    ]);
  });
});
