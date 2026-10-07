import type { AiMessage } from "@bloody/contracts";
import { asArray, asNumber, asString, isRecord } from "../util/json.js";
import type { JsonSchema } from "../tools/json-schema.js";
import { BaseProvider, type ProviderCommon } from "./base.js";
import { makeToolCallId, parseToolArguments, splitSystem, toolNameForCall, toolResultValue, type AiToolCall } from "./messages.js";
import type { ChatRequest, ChatResponse, FinishReason, ModelInfo } from "./types.js";

/**
 * Google Gemini API (`POST /v1beta/models/{model}:generateContent`, `x-goog-api-key` header so
 * the key never appears in URLs/logs). Tools are `functionDeclarations`; parameters are mapped
 * onto the OpenAPI subset Gemini accepts. Thought signatures returned with function calls are
 * cached per provider instance and replayed on the next turn, as Gemini requires for multi-step
 * tool use.
 */

const GEMINI_STRING_FORMATS = new Set(["date-time", "enum"]);
const GEMINI_KEYS = new Set([
  "type",
  "format",
  "description",
  "nullable",
  "enum",
  "properties",
  "required",
  "items",
  "minItems",
  "maxItems",
  "minimum",
  "maximum",
  "minLength",
  "maxLength",
  "pattern",
  "anyOf",
  "title",
]);

/** Convert a JSON Schema (as produced by zodToJsonSchema) into Gemini's OpenAPI-subset schema. */
export function toGeminiSchema(schema: JsonSchema, depth = 0): JsonSchema {
  if (depth > 32 || !isRecord(schema)) return {};
  let s: Record<string, unknown> = { ...schema };

  // const → enum, ["string","null"] → nullable string, anyOf [X, null] → nullable X
  if (s.const !== undefined) {
    if (typeof s.const === "string") s.enum = [s.const];
    delete s.const;
  }
  if (Array.isArray(s.type)) {
    const types = (s.type as unknown[]).filter((t) => t !== "null");
    if (types.length < (s.type as unknown[]).length) s.nullable = true;
    s.type = types[0] ?? "string";
  }
  if (Array.isArray(s.anyOf)) {
    const branches = (s.anyOf as unknown[]).filter(isRecord);
    const nonNull = branches.filter((b) => b.type !== "null");
    if (nonNull.length < branches.length) s.nullable = true;
    if (nonNull.length === 1) {
      const { anyOf: _drop, ...rest } = s;
      s = { ...nonNull[0], ...rest };
      delete s.anyOf;
    } else {
      s.anyOf = nonNull;
    }
  }

  const out: JsonSchema = {};
  for (const [key, value] of Object.entries(s)) {
    if (!GEMINI_KEYS.has(key)) continue;
    switch (key) {
      case "format":
        if (s.type === "string" && typeof value === "string" && GEMINI_STRING_FORMATS.has(value)) out.format = value;
        break;
      case "enum": {
        const values = asArray(value).filter((v): v is string => typeof v === "string");
        if (values.length > 0 && values.length === asArray(value).length) {
          out.enum = values;
          if (!out.type && !s.type) out.type = "string";
        }
        break;
      }
      case "properties":
        if (isRecord(value)) {
          const props: Record<string, unknown> = {};
          for (const [name, prop] of Object.entries(value)) if (isRecord(prop)) props[name] = toGeminiSchema(prop, depth + 1);
          out.properties = props;
        }
        break;
      case "items":
        if (isRecord(value)) out.items = toGeminiSchema(value, depth + 1);
        break;
      case "anyOf":
        out.anyOf = asArray(value)
          .filter(isRecord)
          .map((b) => toGeminiSchema(b, depth + 1));
        break;
      case "required":
        if (Array.isArray(value) && value.length > 0) out.required = value;
        break;
      default:
        out[key] = value;
    }
  }
  if (out.type === "object" && out.properties && Object.keys(out.properties as object).length === 0) delete out.properties;
  return out;
}

type GeminiPart =
  | { text: string }
  | { functionCall: { name: string; args: Record<string, unknown>; id?: string }; thoughtSignature?: string }
  | { functionResponse: { name: string; response: Record<string, unknown>; id?: string } };

export interface GeminiContent {
  role: "user" | "model";
  parts: GeminiPart[];
}

export function toGeminiContents(messages: readonly AiMessage[], signatures?: ReadonlyMap<string, string>): { system: string; contents: GeminiContent[] } {
  const { system, rest } = splitSystem(messages);
  const contents: GeminiContent[] = [];
  for (const m of rest) {
    const parts: GeminiPart[] = [];
    let role: "user" | "model";
    if (m.role === "assistant") {
      role = "model";
      if (m.content.trim()) parts.push({ text: m.content });
      for (const c of m.toolCalls ?? []) {
        const part: GeminiPart = { functionCall: { name: c.name, args: c.arguments, ...(c.id.startsWith("gemini_") ? {} : { id: c.id }) } };
        const sig = signatures?.get(c.id);
        if (sig) (part as { thoughtSignature?: string }).thoughtSignature = sig;
        parts.push(part);
      }
    } else if (m.role === "tool") {
      role = "user";
      const name = toolNameForCall(messages, m.toolCallId) ?? "tool";
      const value = toolResultValue(m.content);
      const callId = m.toolCallId && !m.toolCallId.startsWith("gemini_") ? m.toolCallId : undefined;
      parts.push({ functionResponse: { name, response: isRecord(value) ? value : { result: value }, ...(callId ? { id: callId } : {}) } });
    } else {
      role = "user";
      if (m.content.trim()) parts.push({ text: m.content });
    }
    if (parts.length === 0) continue;
    const prev = contents[contents.length - 1];
    if (prev && prev.role === role) prev.parts.push(...parts);
    else contents.push({ role, parts });
  }
  return { system, contents };
}

function mapFinish(reason: unknown, hasToolCalls: boolean): FinishReason {
  if (hasToolCalls) return "tool_calls";
  switch (reason) {
    case "STOP":
    case undefined:
    case null:
      return "stop";
    case "MAX_TOKENS":
      return "length";
    case "SAFETY":
    case "RECITATION":
    case "BLOCKLIST":
    case "PROHIBITED_CONTENT":
    case "SPII":
      return "content_filter";
    default:
      return "other";
  }
}

const SIGNATURE_CACHE_LIMIT = 512;

export class GeminiProvider extends BaseProvider {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly signatures = new Map<string, string>();

  constructor(common: ProviderCommon, options: { baseUrl: string; apiKey: string }) {
    super(common);
    this.baseUrl = options.baseUrl.replace(/\/+$/, "").replace(/\/v1(beta)?$/, "");
    this.apiKey = options.apiKey;
  }

  private headers(): Record<string, string> {
    return { "content-type": "application/json", accept: "application/json", "x-goog-api-key": this.apiKey };
  }

  private modelPath(): string {
    return encodeURIComponent(this.model.replace(/^models\//, ""));
  }

  buildBody(req: ChatRequest): Record<string, unknown> {
    const { temperature, maxOutputTokens } = this.sampling(req);
    const { system, contents } = toGeminiContents(req.messages, this.signatures);
    const body: Record<string, unknown> = { contents, generationConfig: { temperature, maxOutputTokens } };
    if (system) body.systemInstruction = { parts: [{ text: system }] };
    if (req.tools && req.tools.length > 0) {
      body.tools = [{ functionDeclarations: req.tools.map((t) => ({ name: t.name, description: t.description, parameters: toGeminiSchema(t.parameters) })) }];
      body.toolConfig = { functionCallingConfig: { mode: req.toolChoice === "none" ? "NONE" : "AUTO" } };
    }
    return body;
  }

  private remember(callId: string, signature: string): void {
    if (this.signatures.size >= SIGNATURE_CACHE_LIMIT) {
      const oldest = this.signatures.keys().next().value;
      if (oldest !== undefined) this.signatures.delete(oldest);
    }
    this.signatures.set(callId, signature);
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const started = this.nowMs();
    const url = `${this.baseUrl}/v1beta/models/${this.modelPath()}:generateContent`;
    const res = await this.http.json({ url, method: "POST", headers: this.headers(), body: JSON.stringify(this.buildBody(req)), ...(req.signal ? { signal: req.signal } : {}) });
    if (!isRecord(res.data)) throw this.invalid("Gemini response is not an object", res.status);
    const data = res.data;
    const candidate = asArray(data.candidates)[0];
    let content = "";
    const toolCalls: AiToolCall[] = [];
    let finish: unknown = undefined;
    if (isRecord(candidate)) {
      finish = candidate.finishReason;
      const parts = isRecord(candidate.content) ? asArray(candidate.content.parts) : [];
      for (const part of parts) {
        if (!isRecord(part)) continue;
        if (typeof part.text === "string" && part.thought !== true) content += part.text;
        if (isRecord(part.functionCall)) {
          const name = asString(part.functionCall.name);
          if (!name) continue;
          const id = asString(part.functionCall.id) || makeToolCallId("gemini", this.common.ids);
          const sig = asString(part.thoughtSignature);
          if (sig) this.remember(id, sig);
          toolCalls.push({ id, name, arguments: parseToolArguments(part.functionCall.args) });
        }
      }
    } else if (isRecord(data.promptFeedback) && data.promptFeedback.blockReason) {
      finish = "SAFETY";
    } else {
      throw this.invalid("Gemini response has no candidates", res.status);
    }
    const usage = isRecord(data.usageMetadata) ? data.usageMetadata : {};
    const prompt = asNumber(usage.promptTokenCount);
    const candidates = asNumber(usage.candidatesTokenCount);
    const thoughts = asNumber(usage.thoughtsTokenCount) ?? 0;
    const model = asString(data.modelVersion);
    const message: AiMessage = { role: "assistant", content };
    if (toolCalls.length > 0) message.toolCalls = toolCalls;
    if (req.onDelta && content) req.onDelta(content);
    return {
      message,
      usage: this.usageOrEstimate(req, content, prompt, candidates !== undefined ? candidates + thoughts : undefined),
      model: model ?? this.model,
      finishReason: mapFinish(finish, toolCalls.length > 0),
      servedBy: this.servedBy(model),
      latencyMs: this.nowMs() - started,
    };
  }

  async listModels(signal?: AbortSignal): Promise<ModelInfo[]> {
    const res = await this.http.json({ url: `${this.baseUrl}/v1beta/models?pageSize=200`, method: "GET", headers: this.headers(), ...(signal ? { signal } : {}) });
    const models = isRecord(res.data) ? asArray(res.data.models) : [];
    return models.filter(isRecord).flatMap((m): ModelInfo[] => {
      const name = asString(m.name);
      if (!name) return [];
      const methods = asArray(m.supportedGenerationMethods);
      if (methods.length > 0 && !methods.includes("generateContent")) return [];
      const info: ModelInfo = { id: name.replace(/^models\//, "") };
      const display = asString(m.displayName);
      if (display) info.name = display;
      const input = asNumber(m.inputTokenLimit);
      if (input) info.contextWindow = input;
      const output = asNumber(m.outputTokenLimit);
      if (output) info.maxOutputTokens = output;
      return [info];
    });
  }
}
