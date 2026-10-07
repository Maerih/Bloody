import type { AiMessage, AiProviderKind } from "@bloody/contracts";
import { AiAbortError, AiProviderError } from "../errors.js";
import type { IdGenerator } from "../util/ids.js";
import { asArray, asNumber, asString, isRecord, safeJsonParse } from "../util/json.js";
import { BaseProvider, type ProviderCommon } from "./base.js";
import { HttpClient, SseDecoder, joinUrl } from "./http.js";
import { makeToolCallId, parseToolArguments, toFunctionTools, type AiToolCall } from "./messages.js";
import type { ChatRequest, ChatResponse, FinishReason, HealthStatus, ModelInfo } from "./types.js";

/**
 * OpenAI Chat Completions wire format (`POST {base}/chat/completions`). Used natively by OpenAI,
 * vLLM, LM Studio, Mistral and any generic OpenAI-compatible server, and (with a different URL
 * and auth header) by Azure OpenAI.
 */

export interface OpenAiWireMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string | null;
  tool_calls?: Array<{ id: string; type: "function"; function: { name: string; arguments: string } }>;
  tool_call_id?: string;
}

export function toOpenAiMessages(messages: readonly AiMessage[]): OpenAiWireMessage[] {
  return messages.map((m): OpenAiWireMessage => {
    switch (m.role) {
      case "system":
      case "user":
        return { role: m.role, content: m.content };
      case "assistant": {
        const calls = m.toolCalls ?? [];
        const out: OpenAiWireMessage = { role: "assistant", content: m.content || (calls.length > 0 ? null : "") };
        if (calls.length > 0) {
          out.tool_calls = calls.map((c) => ({ id: c.id, type: "function", function: { name: c.name, arguments: JSON.stringify(c.arguments) } }));
        }
        return out;
      }
      case "tool":
        return { role: "tool", tool_call_id: m.toolCallId ?? "", content: m.content };
    }
  });
}

/** Reasoning models (o-series, gpt-5) reject custom temperature. */
function isReasoningModel(model: string | null): boolean {
  return !!model && /^(o\d|gpt-5)/i.test(model);
}

const STREAM_USAGE_KINDS: ReadonlySet<AiProviderKind> = new Set(["openai", "azure_openai", "vllm"]);

export function buildOpenAiBody(
  kind: AiProviderKind,
  model: string | null,
  req: ChatRequest,
  temperature: number,
  maxOutputTokens: number,
  stream: boolean,
): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  if (model) body.model = model;
  body.messages = toOpenAiMessages(req.messages);
  if (!isReasoningModel(model)) body.temperature = temperature;
  if (kind === "openai") body.max_completion_tokens = maxOutputTokens;
  else body.max_tokens = maxOutputTokens;
  if (req.tools && req.tools.length > 0) {
    body.tools = toFunctionTools(req.tools);
    body.tool_choice = req.toolChoice ?? "auto";
  }
  if (stream) {
    body.stream = true;
    if (STREAM_USAGE_KINDS.has(kind)) body.stream_options = { include_usage: true };
  }
  return body;
}

export function mapOpenAiFinish(reason: unknown, hasToolCalls: boolean): FinishReason {
  if (hasToolCalls) return "tool_calls";
  switch (reason) {
    case "stop":
    case "end_turn":
      return "stop";
    case "length":
      return "length";
    case "tool_calls":
    case "function_call":
      return "tool_calls";
    case "content_filter":
      return "content_filter";
    default:
      return reason === null || reason === undefined ? "stop" : "other";
  }
}

function contentText(content: unknown): string {
  if (typeof content === "string") return content;
  return asArray(content)
    .map((p) => (isRecord(p) && typeof p.text === "string" ? p.text : ""))
    .join("");
}

export interface ParsedCompletion {
  message: AiMessage;
  finishReason: FinishReason;
  model: string | undefined;
  inputTokens: number | undefined;
  outputTokens: number | undefined;
}

export function parseOpenAiCompletion(data: unknown, ids: IdGenerator): ParsedCompletion | null {
  if (!isRecord(data)) return null;
  const choice = asArray(data.choices)[0];
  if (!isRecord(choice) || !isRecord(choice.message)) return null;
  const msg = choice.message;
  const toolCalls: AiToolCall[] = asArray(msg.tool_calls)
    .filter(isRecord)
    .map((tc) => {
      const fn = isRecord(tc.function) ? tc.function : {};
      return { id: asString(tc.id) || makeToolCallId("call", ids), name: asString(fn.name) ?? "", arguments: parseToolArguments(fn.arguments) };
    })
    .filter((c) => c.name.length > 0);
  const message: AiMessage = { role: "assistant", content: contentText(msg.content) };
  if (toolCalls.length > 0) message.toolCalls = toolCalls;
  const usage = isRecord(data.usage) ? data.usage : {};
  return {
    message,
    finishReason: mapOpenAiFinish(choice.finish_reason, toolCalls.length > 0),
    model: asString(data.model),
    inputTokens: asNumber(usage.prompt_tokens),
    outputTokens: asNumber(usage.completion_tokens),
  };
}

/** Consume an OpenAI-format SSE stream, emitting text deltas and assembling tool calls. */
export async function streamOpenAiCompletion(
  http: HttpClient,
  request: { url: string; headers: Record<string, string>; body: string; signal?: AbortSignal },
  onDelta: (text: string) => void,
  ids: IdGenerator,
): Promise<ParsedCompletion> {
  const sse = new SseDecoder();
  let content = "";
  let finish: unknown = undefined;
  let model: string | undefined;
  let inputTokens: number | undefined;
  let outputTokens: number | undefined;
  const calls = new Map<number, { id: string; name: string; args: string }>();

  const handle = (data: string): void => {
    if (data.trim() === "[DONE]") return;
    const parsed = safeJsonParse(data);
    if (!parsed.ok || !isRecord(parsed.value)) return;
    const chunk = parsed.value;
    if (isRecord(chunk.error)) {
      throw new AiProviderError({
        code: "upstream_error",
        message: `AI provider stream error: ${asString(chunk.error.message) ?? "unknown"}`,
        providerKind: http.kind,
        providerId: http.providerId,
      });
    }
    model = asString(chunk.model) ?? model;
    if (isRecord(chunk.usage)) {
      inputTokens = asNumber(chunk.usage.prompt_tokens) ?? inputTokens;
      outputTokens = asNumber(chunk.usage.completion_tokens) ?? outputTokens;
    }
    for (const choice of asArray(chunk.choices)) {
      if (!isRecord(choice)) continue;
      const delta = isRecord(choice.delta) ? choice.delta : {};
      const text = contentText(delta.content);
      if (text) {
        content += text;
        onDelta(text);
      }
      for (const tc of asArray(delta.tool_calls)) {
        if (!isRecord(tc)) continue;
        const index = asNumber(tc.index) ?? 0;
        const entry = calls.get(index) ?? { id: "", name: "", args: "" };
        if (asString(tc.id)) entry.id = asString(tc.id)!;
        const fn = isRecord(tc.function) ? tc.function : {};
        if (asString(fn.name)) entry.name += asString(fn.name)!;
        if (asString(fn.arguments)) entry.args += asString(fn.arguments)!;
        calls.set(index, entry);
      }
      if (choice.finish_reason !== undefined && choice.finish_reason !== null) finish = choice.finish_reason;
    }
  };

  await http.stream(
    { url: request.url, method: "POST", headers: { ...request.headers, accept: "text/event-stream" }, body: request.body, ...(request.signal ? { signal: request.signal } : {}) },
    (line) => {
      const ev = sse.push(line);
      if (ev) handle(ev.data);
    },
  );
  const last = sse.flush();
  if (last) handle(last.data);

  const toolCalls: AiToolCall[] = [...calls.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([, c]) => ({ id: c.id || makeToolCallId("call", ids), name: c.name, arguments: parseToolArguments(c.args) }))
    .filter((c) => c.name.length > 0);
  const message: AiMessage = { role: "assistant", content };
  if (toolCalls.length > 0) message.toolCalls = toolCalls;
  return { message, finishReason: mapOpenAiFinish(finish, toolCalls.length > 0), model, inputTokens, outputTokens };
}

export interface OpenAiCompatibleOptions {
  baseUrl: string;
  apiKey: string | null;
  extraHeaders?: Record<string, string>;
}

export class OpenAiCompatibleProvider extends BaseProvider {
  private readonly baseUrl: string;
  private readonly apiKey: string | null;
  private readonly extraHeaders: Record<string, string>;

  constructor(common: ProviderCommon, options: OpenAiCompatibleOptions) {
    super(common);
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.extraHeaders = options.extraHeaders ?? {};
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "content-type": "application/json", accept: "application/json", ...this.extraHeaders };
    if (this.apiKey) h.authorization = `Bearer ${this.apiKey}`;
    return h;
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const started = this.nowMs();
    const { temperature, maxOutputTokens } = this.sampling(req);
    const stream = typeof req.onDelta === "function";
    const body = JSON.stringify(buildOpenAiBody(this.kind, this.model, req, temperature, maxOutputTokens, stream));
    const url = joinUrl(this.baseUrl, "chat/completions");
    let parsed: ParsedCompletion | null;
    if (stream) {
      parsed = await streamOpenAiCompletion(this.http, { url, headers: this.headers(), body, ...(req.signal ? { signal: req.signal } : {}) }, req.onDelta!, this.common.ids);
    } else {
      const res = await this.http.json({ url, method: "POST", headers: this.headers(), body, ...(req.signal ? { signal: req.signal } : {}) });
      parsed = parseOpenAiCompletion(res.data, this.common.ids);
      if (!parsed) throw this.invalid("Chat completion response has no choices", res.status);
    }
    return {
      message: parsed.message,
      usage: this.usageOrEstimate(req, parsed.message.content, parsed.inputTokens, parsed.outputTokens),
      model: parsed.model ?? this.model,
      finishReason: parsed.finishReason,
      servedBy: this.servedBy(parsed.model),
      latencyMs: this.nowMs() - started,
    };
  }

  async listModels(signal?: AbortSignal): Promise<ModelInfo[]> {
    const res = await this.http.json({ url: joinUrl(this.baseUrl, "models"), method: "GET", headers: this.headers(), ...(signal ? { signal } : {}) });
    const data = isRecord(res.data) ? asArray(res.data.data) : asArray(res.data);
    return data.filter(isRecord).flatMap((m): ModelInfo[] => {
      const id = asString(m.id);
      if (!id) return [];
      const info: ModelInfo = { id };
      const owner = asString(m.owned_by);
      if (owner) info.ownedBy = owner;
      const ctx = asNumber(m.max_model_len) ?? asNumber(m.context_length) ?? asNumber(m.max_context_length);
      if (ctx) info.contextWindow = ctx;
      return [info];
    });
  }
}

/** Azure OpenAI resource URL + api-version, parsed from the configured endpoint. */
export function parseAzureEndpoint(endpoint: string, defaultApiVersion = AZURE_OPENAI_DEFAULT_API_VERSION): { resourceBase: string; apiVersion: string } {
  const url = new URL(endpoint);
  const apiVersion = url.searchParams.get("api-version") ?? defaultApiVersion;
  const idx = url.pathname.indexOf("/openai");
  const path = (idx >= 0 ? url.pathname.slice(0, idx) : url.pathname).replace(/\/+$/, "");
  return { resourceBase: `${url.protocol}//${url.host}${path}`, apiVersion };
}

export const AZURE_OPENAI_DEFAULT_API_VERSION = "2024-10-21";

/**
 * Azure OpenAI: `POST {resource}/openai/deployments/{deployment}/chat/completions?api-version=…`
 * with the `api-key` header. The configured `model` is the deployment name.
 */
export class AzureOpenAiProvider extends BaseProvider {
  private readonly resourceBase: string;
  private readonly apiVersion: string;
  private readonly apiKey: string;

  constructor(common: ProviderCommon, options: { endpoint: string; apiKey: string; apiVersion?: string }) {
    super(common);
    const parsed = parseAzureEndpoint(options.endpoint, options.apiVersion);
    this.resourceBase = parsed.resourceBase;
    this.apiVersion = parsed.apiVersion;
    this.apiKey = options.apiKey;
  }

  private headers(): Record<string, string> {
    return { "content-type": "application/json", accept: "application/json", "api-key": this.apiKey };
  }

  chatUrl(): string {
    return `${this.resourceBase}/openai/deployments/${encodeURIComponent(this.model)}/chat/completions?api-version=${encodeURIComponent(this.apiVersion)}`;
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const started = this.nowMs();
    const { temperature, maxOutputTokens } = this.sampling(req);
    const stream = typeof req.onDelta === "function";
    const body = JSON.stringify(buildOpenAiBody(this.kind, null, req, temperature, maxOutputTokens, stream));
    let parsed: ParsedCompletion | null;
    if (stream) {
      parsed = await streamOpenAiCompletion(this.http, { url: this.chatUrl(), headers: this.headers(), body, ...(req.signal ? { signal: req.signal } : {}) }, req.onDelta!, this.common.ids);
    } else {
      const res = await this.http.json({ url: this.chatUrl(), method: "POST", headers: this.headers(), body, ...(req.signal ? { signal: req.signal } : {}) });
      parsed = parseOpenAiCompletion(res.data, this.common.ids);
      if (!parsed) throw this.invalid("Azure OpenAI response has no choices", res.status);
    }
    return {
      message: parsed.message,
      usage: this.usageOrEstimate(req, parsed.message.content, parsed.inputTokens, parsed.outputTokens),
      model: parsed.model ?? this.model,
      finishReason: parsed.finishReason,
      servedBy: this.servedBy(parsed.model),
      latencyMs: this.nowMs() - started,
    };
  }

  /** Lists deployments (data-plane deployments API); falls back to the configured deployment. */
  async listModels(signal?: AbortSignal): Promise<ModelInfo[]> {
    try {
      const res = await this.http.json({
        url: `${this.resourceBase}/openai/deployments?api-version=2022-12-01`,
        method: "GET",
        headers: this.headers(),
        ...(signal ? { signal } : {}),
      });
      const data = isRecord(res.data) ? asArray(res.data.data) : [];
      return data.filter(isRecord).flatMap((d): ModelInfo[] => {
        const id = asString(d.id);
        if (!id) return [];
        const info: ModelInfo = { id };
        const model = asString(d.model);
        if (model) info.family = model;
        return [info];
      });
    } catch (err) {
      if (err instanceof AiProviderError && err.code === "not_found") return [{ id: this.model }];
      throw err;
    }
  }

  /** Deployment listing is not available on every API version, so probe the deployment itself. */
  override async healthCheck(signal?: AbortSignal): Promise<HealthStatus> {
    const started = this.nowMs();
    try {
      await this.chat({ messages: [{ role: "user", content: "ping" }], maxOutputTokens: 1, temperature: 0, dataClass: "public", ...(signal ? { signal } : {}) });
      return {
        ok: true,
        kind: this.kind,
        providerId: this.id,
        model: this.model,
        latencyMs: this.nowMs() - started,
        modelAvailable: true,
        modelsListed: null,
        checkedAt: this.common.clock.now().toISOString(),
      };
    } catch (err) {
      if (err instanceof AiAbortError) throw err;
      const base = await super.healthCheck(signal).catch(() => null);
      return {
        ok: false,
        kind: this.kind,
        providerId: this.id,
        model: this.model,
        latencyMs: this.nowMs() - started,
        modelAvailable: base?.modelAvailable ?? null,
        modelsListed: base?.modelsListed ?? null,
        error: { code: err instanceof AiProviderError ? err.code : "internal_error", message: err instanceof Error ? err.message : String(err) },
        checkedAt: this.common.clock.now().toISOString(),
      };
    }
  }
}
