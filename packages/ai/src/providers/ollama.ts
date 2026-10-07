import type { AiMessage } from "@bloody/contracts";
import { AiProviderError } from "../errors.js";
import { asArray, asNumber, asString, isRecord, safeJsonParse } from "../util/json.js";
import { BaseProvider, type ProviderCommon } from "./base.js";
import { joinUrl } from "./http.js";
import { makeToolCallId, parseToolArguments, toFunctionTools, toolNameForCall, type AiToolCall } from "./messages.js";
import type { ChatRequest, ChatResponse, FinishReason, ModelInfo } from "./types.js";

/**
 * Ollama native API: `POST /api/chat` (tools supported, NDJSON streaming) and `GET /api/tags`.
 * `num_ctx` is set from the provider's context window — Ollama otherwise silently truncates
 * long SOC prompts to its small default context.
 */

export interface OllamaWireMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  tool_calls?: Array<{ function: { name: string; arguments: Record<string, unknown> } }>;
  tool_name?: string;
}

export function toOllamaMessages(messages: readonly AiMessage[]): OllamaWireMessage[] {
  return messages.map((m): OllamaWireMessage => {
    const out: OllamaWireMessage = { role: m.role, content: m.content };
    if (m.role === "assistant" && m.toolCalls && m.toolCalls.length > 0) {
      out.tool_calls = m.toolCalls.map((c) => ({ function: { name: c.name, arguments: c.arguments } }));
    }
    if (m.role === "tool") {
      const name = toolNameForCall(messages, m.toolCallId);
      if (name) out.tool_name = name;
    }
    return out;
  });
}

/** Strip "/v1" or "/api" suffixes users often paste (those are the OpenAI-compatible routes). */
export function normalizeOllamaBase(endpoint: string): string {
  return endpoint.replace(/\/+$/, "").replace(/\/(v1|api)$/, "");
}

function mapDone(reason: unknown, hasToolCalls: boolean): FinishReason {
  if (hasToolCalls) return "tool_calls";
  if (reason === "length") return "length";
  if (reason === "stop" || reason === undefined || reason === null) return "stop";
  return "other";
}

export class OllamaProvider extends BaseProvider {
  private readonly baseUrl: string;
  private readonly apiKey: string | null;

  constructor(common: ProviderCommon, options: { baseUrl: string; apiKey: string | null }) {
    super(common);
    this.baseUrl = normalizeOllamaBase(options.baseUrl);
    this.apiKey = options.apiKey;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "content-type": "application/json", accept: "application/json" };
    if (this.apiKey) h.authorization = `Bearer ${this.apiKey}`; // reverse-proxied Ollama
    return h;
  }

  buildBody(req: ChatRequest, stream: boolean): Record<string, unknown> {
    const { temperature, maxOutputTokens } = this.sampling(req);
    const body: Record<string, unknown> = {
      model: this.model,
      messages: toOllamaMessages(req.messages),
      stream,
      options: { temperature, num_predict: maxOutputTokens, num_ctx: this.common.contextWindow },
    };
    // Ollama has no tool_choice; "none" is honoured by not offering tools.
    if (req.tools && req.tools.length > 0 && req.toolChoice !== "none") body.tools = toFunctionTools(req.tools);
    return body;
  }

  private parseToolCalls(raw: unknown): AiToolCall[] {
    return asArray(raw)
      .filter(isRecord)
      .map((tc) => {
        const fn = isRecord(tc.function) ? tc.function : {};
        return { id: asString(tc.id) || makeToolCallId("call", this.common.ids), name: asString(fn.name) ?? "", arguments: parseToolArguments(fn.arguments) };
      })
      .filter((c) => c.name.length > 0);
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const started = this.nowMs();
    const stream = typeof req.onDelta === "function";
    const url = joinUrl(this.baseUrl, "api/chat");
    const body = JSON.stringify(this.buildBody(req, stream));
    let content = "";
    let toolCalls: AiToolCall[] = [];
    let model: string | undefined;
    let doneReason: unknown;
    let inputTokens: number | undefined;
    let outputTokens: number | undefined;

    const absorb = (chunk: Record<string, unknown>): void => {
      if (typeof chunk.error === "string") {
        throw new AiProviderError({ code: "upstream_error", message: `Ollama error: ${chunk.error}`, providerKind: this.kind, providerId: this.id });
      }
      model = asString(chunk.model) ?? model;
      const msg = isRecord(chunk.message) ? chunk.message : {};
      const text = asString(msg.content) ?? "";
      if (text) {
        content += text;
        if (stream) req.onDelta!(text);
      }
      toolCalls = toolCalls.concat(this.parseToolCalls(msg.tool_calls));
      if (chunk.done === true) {
        doneReason = chunk.done_reason;
        inputTokens = asNumber(chunk.prompt_eval_count);
        outputTokens = asNumber(chunk.eval_count);
      }
    };

    if (stream) {
      await this.http.stream({ url, method: "POST", headers: this.headers(), body, ...(req.signal ? { signal: req.signal } : {}) }, (line) => {
        if (!line.trim()) return;
        const parsed = safeJsonParse(line);
        if (parsed.ok && isRecord(parsed.value)) absorb(parsed.value);
      });
    } else {
      const res = await this.http.json({ url, method: "POST", headers: this.headers(), body, ...(req.signal ? { signal: req.signal } : {}) });
      if (!isRecord(res.data) || !isRecord(res.data.message)) throw this.invalid("Ollama response has no message", res.status);
      absorb({ ...res.data, done: true });
    }

    const message: AiMessage = { role: "assistant", content };
    if (toolCalls.length > 0) message.toolCalls = toolCalls;
    return {
      message,
      usage: this.usageOrEstimate(req, content, inputTokens, outputTokens),
      model: model ?? this.model,
      finishReason: mapDone(doneReason, toolCalls.length > 0),
      servedBy: this.servedBy(model),
      latencyMs: this.nowMs() - started,
    };
  }

  async listModels(signal?: AbortSignal): Promise<ModelInfo[]> {
    const res = await this.http.json({ url: joinUrl(this.baseUrl, "api/tags"), method: "GET", headers: this.headers(), ...(signal ? { signal } : {}) });
    const models = isRecord(res.data) ? asArray(res.data.models) : [];
    return models.filter(isRecord).flatMap((m): ModelInfo[] => {
      const id = asString(m.name) ?? asString(m.model);
      if (!id) return [];
      const info: ModelInfo = { id };
      const details = isRecord(m.details) ? m.details : {};
      const family = asString(details.family);
      if (family) info.family = family;
      const size = asString(details.parameter_size);
      if (size) info.parameterSize = size;
      const bytes = asNumber(m.size);
      if (bytes !== undefined) info.sizeBytes = bytes;
      return [info];
    });
  }
}
