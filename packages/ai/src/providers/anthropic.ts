import type { AiMessage } from "@bloody/contracts";
import { AiProviderError } from "../errors.js";
import { asArray, asNumber, asString, isRecord, safeJsonParse } from "../util/json.js";
import { BaseProvider, type ProviderCommon } from "./base.js";
import { SseDecoder, joinUrl } from "./http.js";
import { makeToolCallId, parseToolArguments, splitSystem, type AiToolCall } from "./messages.js";
import type { ChatRequest, ChatResponse, FinishReason, ModelInfo } from "./types.js";

/**
 * Anthropic Messages API (`POST /v1/messages`, `x-api-key`, `anthropic-version`).
 * System messages become the top-level `system` field, tool calls are `tool_use` blocks and
 * tool results are `tool_result` blocks inside a user turn. Consecutive same-role turns are
 * merged because the API requires alternating user/assistant turns.
 */

export const ANTHROPIC_API_VERSION = "2023-06-01";

export type AnthropicBlock =
  | { type: "text"; text: string }
  | { type: "tool_use"; id: string; name: string; input: Record<string, unknown> }
  | { type: "tool_result"; tool_use_id: string; content: string };

export interface AnthropicWireMessage {
  role: "user" | "assistant";
  content: AnthropicBlock[];
}

export function toAnthropicMessages(messages: readonly AiMessage[]): { system: string; messages: AnthropicWireMessage[] } {
  const { system, rest } = splitSystem(messages);
  const out: AnthropicWireMessage[] = [];
  for (const m of rest) {
    let role: "user" | "assistant";
    const blocks: AnthropicBlock[] = [];
    if (m.role === "tool") {
      role = "user";
      blocks.push({ type: "tool_result", tool_use_id: m.toolCallId ?? "", content: m.content || "(empty)" });
    } else if (m.role === "assistant") {
      role = "assistant";
      if (m.content.trim()) blocks.push({ type: "text", text: m.content });
      for (const c of m.toolCalls ?? []) blocks.push({ type: "tool_use", id: c.id, name: c.name, input: c.arguments });
    } else {
      role = "user";
      if (m.content.trim()) blocks.push({ type: "text", text: m.content });
    }
    if (blocks.length === 0) continue;
    const prev = out[out.length - 1];
    if (prev && prev.role === role) {
      // tool_result blocks must lead a user turn; keep them ahead of text when merging
      if (role === "user") {
        const results = [...prev.content, ...blocks].filter((b) => b.type === "tool_result");
        const others = [...prev.content, ...blocks].filter((b) => b.type !== "tool_result");
        prev.content = [...results, ...others];
      } else {
        prev.content.push(...blocks);
      }
    } else {
      out.push({ role, content: blocks });
    }
  }
  if (out.length === 0 || out[0]!.role !== "user") out.unshift({ role: "user", content: [{ type: "text", text: "(conversation start)" }] });
  return { system, messages: out };
}

function mapStop(reason: unknown, hasToolCalls: boolean): FinishReason {
  if (hasToolCalls || reason === "tool_use") return "tool_calls";
  switch (reason) {
    case "end_turn":
    case "stop_sequence":
    case "pause_turn":
    case undefined:
    case null:
      return "stop";
    case "max_tokens":
      return "length";
    case "refusal":
      return "content_filter";
    default:
      return "other";
  }
}

export class AnthropicProvider extends BaseProvider {
  private readonly baseUrl: string;
  private readonly apiKey: string;

  constructor(common: ProviderCommon, options: { baseUrl: string; apiKey: string }) {
    super(common);
    this.baseUrl = options.baseUrl.replace(/\/+$/, "").replace(/\/v1$/, "");
    this.apiKey = options.apiKey;
  }

  private headers(): Record<string, string> {
    return { "content-type": "application/json", accept: "application/json", "x-api-key": this.apiKey, "anthropic-version": ANTHROPIC_API_VERSION };
  }

  buildBody(req: ChatRequest, stream: boolean): Record<string, unknown> {
    const { temperature, maxOutputTokens } = this.sampling(req);
    const { system, messages } = toAnthropicMessages(req.messages);
    const body: Record<string, unknown> = {
      model: this.model,
      max_tokens: maxOutputTokens,
      temperature: Math.min(1, Math.max(0, temperature)),
      messages,
    };
    if (system) body.system = system;
    if (req.tools && req.tools.length > 0) {
      body.tools = req.tools.map((t) => ({ name: t.name, description: t.description, input_schema: t.parameters }));
      body.tool_choice = { type: req.toolChoice === "none" ? "none" : "auto" };
    }
    if (stream) body.stream = true;
    return body;
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const started = this.nowMs();
    const stream = typeof req.onDelta === "function";
    const url = joinUrl(this.baseUrl, "v1/messages");
    const body = JSON.stringify(this.buildBody(req, stream));
    let content = "";
    const toolCalls: AiToolCall[] = [];
    let model: string | undefined;
    let stopReason: unknown;
    let inputTokens: number | undefined;
    let outputTokens: number | undefined;

    if (stream) {
      const sse = new SseDecoder();
      const blocks = new Map<number, { type: string; id: string; name: string; json: string }>();
      const handle = (data: string): void => {
        const parsed = safeJsonParse(data);
        if (!parsed.ok || !isRecord(parsed.value)) return;
        const ev = parsed.value;
        switch (ev.type) {
          case "message_start": {
            const msg = isRecord(ev.message) ? ev.message : {};
            model = asString(msg.model) ?? model;
            const usage = isRecord(msg.usage) ? msg.usage : {};
            inputTokens = asNumber(usage.input_tokens) ?? inputTokens;
            outputTokens = asNumber(usage.output_tokens) ?? outputTokens;
            break;
          }
          case "content_block_start": {
            const block = isRecord(ev.content_block) ? ev.content_block : {};
            const index = asNumber(ev.index) ?? blocks.size;
            blocks.set(index, { type: asString(block.type) ?? "text", id: asString(block.id) ?? "", name: asString(block.name) ?? "", json: "" });
            const text = asString(block.text);
            if (text) {
              content += text;
              req.onDelta!(text);
            }
            break;
          }
          case "content_block_delta": {
            const delta = isRecord(ev.delta) ? ev.delta : {};
            const index = asNumber(ev.index) ?? 0;
            if (delta.type === "text_delta" && typeof delta.text === "string") {
              content += delta.text;
              req.onDelta!(delta.text);
            } else if (delta.type === "input_json_delta" && typeof delta.partial_json === "string") {
              const b = blocks.get(index);
              if (b) b.json += delta.partial_json;
            }
            break;
          }
          case "message_delta": {
            const delta = isRecord(ev.delta) ? ev.delta : {};
            if (delta.stop_reason !== undefined) stopReason = delta.stop_reason;
            const usage = isRecord(ev.usage) ? ev.usage : {};
            outputTokens = asNumber(usage.output_tokens) ?? outputTokens;
            inputTokens = asNumber(usage.input_tokens) ?? inputTokens;
            break;
          }
          case "error": {
            const err = isRecord(ev.error) ? ev.error : {};
            throw new AiProviderError({
              code: err.type === "overloaded_error" ? "overloaded" : "upstream_error",
              message: `Anthropic stream error: ${asString(err.message) ?? "unknown"}`,
              providerKind: this.kind,
              providerId: this.id,
            });
          }
          default:
            break;
        }
      };
      await this.http.stream(
        { url, method: "POST", headers: { ...this.headers(), accept: "text/event-stream" }, body, ...(req.signal ? { signal: req.signal } : {}) },
        (line) => {
          const ev = sse.push(line);
          if (ev) handle(ev.data);
        },
      );
      const last = sse.flush();
      if (last) handle(last.data);
      for (const [, b] of [...blocks.entries()].sort((x, y) => x[0] - y[0])) {
        if (b.type === "tool_use" && b.name) {
          toolCalls.push({ id: b.id || makeToolCallId("toolu", this.common.ids), name: b.name, arguments: parseToolArguments(b.json || "{}") });
        }
      }
    } else {
      const res = await this.http.json({ url, method: "POST", headers: this.headers(), body, ...(req.signal ? { signal: req.signal } : {}) });
      if (!isRecord(res.data) || !Array.isArray(res.data.content)) throw this.invalid("Anthropic response has no content", res.status);
      model = asString(res.data.model);
      stopReason = res.data.stop_reason;
      const usage = isRecord(res.data.usage) ? res.data.usage : {};
      inputTokens = asNumber(usage.input_tokens);
      outputTokens = asNumber(usage.output_tokens);
      for (const block of asArray(res.data.content)) {
        if (!isRecord(block)) continue;
        if (block.type === "text" && typeof block.text === "string") content += block.text;
        else if (block.type === "tool_use") {
          const name = asString(block.name);
          if (name) toolCalls.push({ id: asString(block.id) || makeToolCallId("toolu", this.common.ids), name, arguments: parseToolArguments(block.input) });
        }
      }
    }

    const message: AiMessage = { role: "assistant", content };
    if (toolCalls.length > 0) message.toolCalls = toolCalls;
    return {
      message,
      usage: this.usageOrEstimate(req, content, inputTokens, outputTokens),
      model: model ?? this.model,
      finishReason: mapStop(stopReason, toolCalls.length > 0),
      servedBy: this.servedBy(model),
      latencyMs: this.nowMs() - started,
    };
  }

  async listModels(signal?: AbortSignal): Promise<ModelInfo[]> {
    const res = await this.http.json({ url: joinUrl(this.baseUrl, "v1/models?limit=100"), method: "GET", headers: this.headers(), ...(signal ? { signal } : {}) });
    const data = isRecord(res.data) ? asArray(res.data.data) : [];
    return data.filter(isRecord).flatMap((m): ModelInfo[] => {
      const id = asString(m.id);
      if (!id) return [];
      const info: ModelInfo = { id };
      const name = asString(m.display_name);
      if (name) info.name = name;
      return [info];
    });
  }
}
