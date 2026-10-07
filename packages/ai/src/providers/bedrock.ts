import type { AiMessage } from "@bloody/contracts";
import { AiConfigError } from "../errors.js";
import { asArray, asNumber, asString, isRecord, safeJsonParse } from "../util/json.js";
import { BaseProvider, type ProviderCommon } from "./base.js";
import type { HttpRequest } from "./http.js";
import { makeToolCallId, parseToolArguments, splitSystem, type AiToolCall } from "./messages.js";
import { signSigV4, type AwsCredentials } from "./sigv4.js";
import type { ChatRequest, ChatResponse, FinishReason, ModelInfo } from "./types.js";

/**
 * Amazon Bedrock via the model-agnostic Converse API
 * (`POST https://bedrock-runtime.{region}.amazonaws.com/model/{modelId}/converse`), signed
 * with SigV4 (service "bedrock") or authenticated with a Bedrock API key (Bearer).
 *
 * Credential secret formats accepted:
 *   {"accessKeyId":"…","secretAccessKey":"…","sessionToken":"…","region":"eu-west-1"}
 *   {"apiKey":"ABSK…","region":"us-east-1"}
 *   "AKID:SECRET" or "AKID:SECRET:SESSION_TOKEN"
 *   "ABSK…" (Bedrock API key)
 */

export type BedrockAuth = { kind: "sigv4"; credentials: AwsCredentials; region: string | null } | { kind: "bearer"; token: string; region: string | null };

const REGION_RE = /^[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-\d{1,2}$/;

export function parseBedrockSecret(secret: string): BedrockAuth {
  const trimmed = secret.trim();
  if (trimmed.startsWith("{")) {
    const parsed = safeJsonParse(trimmed);
    if (!parsed.ok || !isRecord(parsed.value)) throw new AiConfigError("invalid_credential", "Bedrock credential JSON is malformed");
    const v = parsed.value;
    const region = asString(v.region) ?? null;
    const apiKey = asString(v.apiKey) ?? asString(v.bearerToken);
    if (apiKey) return { kind: "bearer", token: apiKey, region };
    const accessKeyId = asString(v.accessKeyId);
    const secretAccessKey = asString(v.secretAccessKey);
    if (!accessKeyId || !secretAccessKey) throw new AiConfigError("invalid_credential", "Bedrock credential JSON needs accessKeyId and secretAccessKey (or apiKey)");
    const sessionToken = asString(v.sessionToken);
    return { kind: "sigv4", credentials: { accessKeyId, secretAccessKey, ...(sessionToken ? { sessionToken } : {}) }, region };
  }
  if (/^(ABSK|bedrock-api-key-)/.test(trimmed)) return { kind: "bearer", token: trimmed, region: null };
  const parts = trimmed.split(":");
  if (parts.length >= 2 && parts[0] && parts[1]) {
    const sessionToken = parts.slice(2).join(":");
    return { kind: "sigv4", credentials: { accessKeyId: parts[0], secretAccessKey: parts[1], ...(sessionToken ? { sessionToken } : {}) }, region: null };
  }
  throw new AiConfigError("invalid_credential", "Unrecognised Bedrock credential format");
}

/** Region from an endpoint like https://bedrock-runtime.eu-west-1.amazonaws.com or a VPC endpoint. */
export function regionFromEndpoint(endpoint: string | null): string | null {
  if (!endpoint) return null;
  try {
    const host = new URL(endpoint).hostname;
    const m = /(?:^|\.)bedrock-runtime(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com$/.exec(host) ?? /\.bedrock-runtime\.([a-z0-9-]+)\.vpce\.amazonaws\.com$/.exec(host);
    return m?.[1] ?? null;
  } catch {
    return null;
  }
}

export function resolveBedrockRegion(endpoint: string | null, auth: BedrockAuth): string {
  const region = regionFromEndpoint(endpoint) ?? auth.region ?? null;
  if (!region || !REGION_RE.test(region)) {
    throw new AiConfigError("region_required", "Bedrock region could not be determined (set the endpoint to https://bedrock-runtime.<region>.amazonaws.com or add \"region\" to the credential)");
  }
  return region;
}

type BedrockBlock =
  | { text: string }
  | { toolUse: { toolUseId: string; name: string; input: Record<string, unknown> } }
  | { toolResult: { toolUseId: string; content: Array<{ text: string }> } };

export interface BedrockWireMessage {
  role: "user" | "assistant";
  content: BedrockBlock[];
}

export function toBedrockMessages(messages: readonly AiMessage[]): { system: string; messages: BedrockWireMessage[] } {
  const { system, rest } = splitSystem(messages);
  const out: BedrockWireMessage[] = [];
  for (const m of rest) {
    const blocks: BedrockBlock[] = [];
    let role: "user" | "assistant";
    if (m.role === "assistant") {
      role = "assistant";
      if (m.content.trim()) blocks.push({ text: m.content });
      for (const c of m.toolCalls ?? []) blocks.push({ toolUse: { toolUseId: c.id, name: c.name, input: c.arguments } });
    } else if (m.role === "tool") {
      role = "user";
      blocks.push({ toolResult: { toolUseId: m.toolCallId ?? "", content: [{ text: m.content || "(empty)" }] } });
    } else {
      role = "user";
      if (m.content.trim()) blocks.push({ text: m.content });
    }
    if (blocks.length === 0) continue;
    const prev = out[out.length - 1];
    if (prev && prev.role === role) {
      if (role === "user") {
        const all = [...prev.content, ...blocks];
        prev.content = [...all.filter((b) => "toolResult" in b), ...all.filter((b) => !("toolResult" in b))];
      } else {
        prev.content.push(...blocks);
      }
    } else {
      out.push({ role, content: blocks });
    }
  }
  if (out.length === 0 || out[0]!.role !== "user") out.unshift({ role: "user", content: [{ text: "(conversation start)" }] });
  return { system, messages: out };
}

function mapStop(reason: unknown, hasToolCalls: boolean): FinishReason {
  if (hasToolCalls || reason === "tool_use") return "tool_calls";
  switch (reason) {
    case "end_turn":
    case "stop_sequence":
    case undefined:
    case null:
      return "stop";
    case "max_tokens":
    case "model_context_window_exceeded":
      return "length";
    case "guardrail_intervened":
    case "content_filtered":
      return "content_filter";
    default:
      return "other";
  }
}

export class BedrockProvider extends BaseProvider {
  readonly region: string;
  private readonly runtimeBase: string;
  private readonly auth: BedrockAuth;

  constructor(common: ProviderCommon, options: { endpoint: string | null; secret: string }) {
    super(common);
    this.auth = parseBedrockSecret(options.secret);
    this.region = resolveBedrockRegion(options.endpoint, this.auth);
    this.runtimeBase = (options.endpoint ?? `https://bedrock-runtime.${this.region}.amazonaws.com`).replace(/\/+$/, "");
  }

  converseUrl(): string {
    return `${this.runtimeBase}/model/${encodeURIComponent(this.model)}/converse`;
  }

  /** Signs each attempt with a fresh timestamp (retries must not reuse a stale signature). */
  private request(method: "GET" | "POST", url: string, body: string, signal?: AbortSignal): HttpRequest {
    const base: Record<string, string> = { accept: "application/json" };
    if (method === "POST") base["content-type"] = "application/json";
    const req: HttpRequest = { url, method, headers: base, ...(method === "POST" ? { body } : {}), ...(signal ? { signal } : {}) };
    if (this.auth.kind === "bearer") {
      req.headers = { ...base, authorization: `Bearer ${this.auth.token}` };
      return req;
    }
    const credentials = this.auth.credentials;
    req.prepareHeaders = (headers) => {
      const { "user-agent": ua, ...rest } = headers;
      const signed = signSigV4({ method, url, headers: rest, body, region: this.region, service: "bedrock", credentials, now: this.common.clock.now() });
      return ua ? { ...signed.headers, "user-agent": ua } : signed.headers;
    };
    return req;
  }

  buildBody(req: ChatRequest): Record<string, unknown> {
    const { temperature, maxOutputTokens } = this.sampling(req);
    const { system, messages } = toBedrockMessages(req.messages);
    const body: Record<string, unknown> = { messages, inferenceConfig: { maxTokens: maxOutputTokens, temperature: Math.min(1, Math.max(0, temperature)) } };
    if (system) body.system = [{ text: system }];
    const historyHasTools = messages.some((m) => m.content.some((b) => "toolUse" in b || "toolResult" in b));
    if (req.tools && req.tools.length > 0 && (req.toolChoice !== "none" || historyHasTools)) {
      // Converse has no "none" tool choice, and requires toolConfig whenever the history holds tool blocks.
      body.toolConfig = {
        tools: req.tools.map((t) => ({ toolSpec: { name: t.name, description: t.description, inputSchema: { json: t.parameters } } })),
        ...(req.toolChoice === "none" ? {} : { toolChoice: { auto: {} } }),
      };
    }
    return body;
  }

  async chat(req: ChatRequest): Promise<ChatResponse> {
    const started = this.nowMs();
    const body = JSON.stringify(this.buildBody(req));
    const res = await this.http.json(this.request("POST", this.converseUrl(), body, req.signal));
    if (!isRecord(res.data) || !isRecord(res.data.output)) throw this.invalid("Bedrock Converse response has no output", res.status);
    const msg = isRecord(res.data.output.message) ? res.data.output.message : {};
    let content = "";
    const toolCalls: AiToolCall[] = [];
    for (const block of asArray(msg.content)) {
      if (!isRecord(block)) continue;
      if (typeof block.text === "string") content += block.text;
      if (isRecord(block.toolUse)) {
        const name = asString(block.toolUse.name);
        if (name) toolCalls.push({ id: asString(block.toolUse.toolUseId) || makeToolCallId("tooluse", this.common.ids), name, arguments: parseToolArguments(block.toolUse.input) });
      }
    }
    const usage = isRecord(res.data.usage) ? res.data.usage : {};
    const message: AiMessage = { role: "assistant", content };
    if (toolCalls.length > 0) message.toolCalls = toolCalls;
    if (req.onDelta && content) req.onDelta(content);
    return {
      message,
      usage: this.usageOrEstimate(req, content, asNumber(usage.inputTokens), asNumber(usage.outputTokens)),
      model: this.model,
      finishReason: mapStop(res.data.stopReason, toolCalls.length > 0),
      servedBy: this.servedBy(),
      latencyMs: this.nowMs() - started,
    };
  }

  /** Foundation models with text output, from the Bedrock control plane (ListFoundationModels). */
  async listModels(signal?: AbortSignal): Promise<ModelInfo[]> {
    const url = `https://bedrock.${this.region}.amazonaws.com/foundation-models?byOutputModality=TEXT`;
    const res = await this.http.json(this.request("GET", url, "", signal));
    const summaries = isRecord(res.data) ? asArray(res.data.modelSummaries) : [];
    return summaries.filter(isRecord).flatMap((m): ModelInfo[] => {
      const id = asString(m.modelId);
      if (!id) return [];
      const info: ModelInfo = { id };
      const name = asString(m.modelName);
      if (name) info.name = name;
      const owner = asString(m.providerName);
      if (owner) info.ownedBy = owner;
      return [info];
    });
  }

  /** Inference profiles ("us.anthropic…") are not listed as foundation models; match their base id. */
  protected override matchesModel(listed: string): boolean {
    const configured = this.model.replace(/^(us|eu|apac|global|us-gov)\./, "");
    return listed === this.model || listed === configured;
  }
}
