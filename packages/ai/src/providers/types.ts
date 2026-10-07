import type { AiMessage, AiProviderKind } from "@bloody/contracts";
import type { RedactionStats, RedactionVault } from "../safety/redact.js";
import type { JsonSchema } from "../tools/json-schema.js";

/** Minimal fetch surface (satisfied by the global `fetch`) — injected so providers are testable. */
export interface FetchInitLike {
  method: string;
  headers: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
  redirect?: "error" | "manual" | "follow";
}

export interface FetchResponseLike {
  status: number;
  ok: boolean;
  headers: { get(name: string): string | null };
  body: ReadableStream<Uint8Array> | null;
  text(): Promise<string>;
}

export type FetchLike = (url: string, init: FetchInitLike) => Promise<FetchResponseLike>;

/** A tool the model may call. `parameters` is a JSON Schema object (see zodToJsonSchema). */
export interface ToolSpec {
  name: string;
  description: string;
  parameters: JsonSchema;
}

export interface AiUsage {
  inputTokens: number;
  outputTokens: number;
  /** True when the provider did not report usage and Bloody estimated it. */
  estimated?: boolean;
}

export type FinishReason = "stop" | "tool_calls" | "length" | "content_filter" | "other";

/**
 * Classification of the data in the request. "tenant" (default) = contains customer data and is
 * subject to `allowCloudData`; "public" = no tenant data (e.g. connectivity probes).
 */
export type DataClass = "tenant" | "public";

export interface ChatRequest {
  messages: AiMessage[];
  tools?: ToolSpec[];
  /** "none" forces a final text answer while keeping tool definitions (needed for tool history). */
  toolChoice?: "auto" | "none";
  temperature?: number;
  maxOutputTokens?: number;
  signal?: AbortSignal;
  /** Streaming callback; providers without streaming emit the whole answer once. */
  onDelta?: (text: string) => void;
  dataClass?: DataClass;
  /** Shared redaction vault so placeholders stay stable across the steps of one AI run. */
  redactionVault?: RedactionVault;
}

export interface ProviderAttempt {
  providerId: string | null;
  kind: AiProviderKind;
  model: string;
  ok: boolean;
  error?: { code: string; message: string };
}

export interface ServedBy {
  providerId: string | null;
  kind: AiProviderKind;
  model: string;
}

export interface ChatResponse {
  /** Assistant message (may include toolCalls). */
  message: AiMessage;
  usage: AiUsage;
  /** Model identifier reported by the provider (or the configured one). */
  model: string;
  finishReason: FinishReason;
  servedBy: ServedBy;
  latencyMs: number;
  /** Redactions applied to the outgoing request (governed providers only). */
  redactions?: RedactionStats;
  /** Provider attempts in order (fallback chains only). */
  attempts?: ProviderAttempt[];
  fallbackUsed?: boolean;
}

export interface ModelInfo {
  id: string;
  name?: string;
  family?: string;
  parameterSize?: string;
  contextWindow?: number;
  maxOutputTokens?: number;
  sizeBytes?: number;
  ownedBy?: string;
}

export interface HealthStatus {
  ok: boolean;
  kind: AiProviderKind;
  providerId: string | null;
  model: string;
  latencyMs: number;
  /** null when the provider cannot list models (availability unknown). */
  modelAvailable: boolean | null;
  modelsListed: number | null;
  error?: { code: string; message: string };
  checkedAt: string;
}

export interface AiProvider {
  readonly kind: AiProviderKind;
  /** Provider configuration id (null for ad-hoc providers). */
  readonly id: string | null;
  readonly model: string;
  chat(req: ChatRequest): Promise<ChatResponse>;
  listModels(signal?: AbortSignal): Promise<ModelInfo[]>;
  healthCheck(signal?: AbortSignal): Promise<HealthStatus>;
}
