import type { AiProviderConfig } from "@bloody/contracts";
import { AiConfigError } from "../errors.js";
import { classifyEgress } from "../safety/egress.js";
import { assertSafeEndpoint, assertSafeEndpointResolved, type HostResolver } from "../safety/ssrf.js";
import { systemClock, uuidGenerator, type Clock, type IdGenerator, type SleepFn } from "../util/ids.js";
import { AnthropicProvider } from "./anthropic.js";
import type { ProviderCommon } from "./base.js";
import { BedrockProvider } from "./bedrock.js";
import { DEFAULT_ENDPOINTS, credentialRequirement } from "./defaults.js";
import { GeminiProvider } from "./gemini.js";
import { GovernedProvider, type GovernanceOptions } from "./governed.js";
import { HttpClient } from "./http.js";
import { OllamaProvider } from "./ollama.js";
import { AzureOpenAiProvider, OpenAiCompatibleProvider } from "./openai-compatible.js";
import type { AiProvider, FetchLike, HealthStatus } from "./types.js";

export interface ProviderRuntimeOptions {
  /** Tenant setting: allow loopback/private endpoints (self-hosted models). Default false. */
  allowPrivateEndpoints?: boolean;
  timeoutMs?: number;
  maxRetries?: number;
  retryBaseMs?: number;
  retryMaxMs?: number;
  maxResponseBytes?: number;
  sleep?: SleepFn;
  random?: () => number;
  clock?: Clock;
  ids?: IdGenerator;
  userAgent?: string;
  /** Data-governance wrapper (policy + redaction). Pass false only for raw, non-tenant usage. */
  governance?: false | GovernanceOptions;
}

export type ProviderConfigInput = Pick<
  AiProviderConfig,
  "id" | "name" | "kind" | "endpoint" | "model" | "contextWindow" | "temperature" | "maxOutputTokens" | "enabled" | "allowCloudData" | "redactSensitive"
>;

/** Configured endpoint or the kind's default (null for Bedrock = derived from the region). */
export function resolveEndpoint(config: Pick<AiProviderConfig, "kind" | "endpoint">): string | null {
  return config.endpoint ?? DEFAULT_ENDPOINTS[config.kind];
}

function validateConfig(config: ProviderConfigInput, secret: string | null, allowPrivate: boolean): string | null {
  const endpoint = resolveEndpoint(config);
  if (endpoint) {
    assertSafeEndpoint(endpoint, { allowPrivate, requireHttps: classifyEgress(config.kind, endpoint) === "cloud" });
  } else if (config.kind !== "aws_bedrock") {
    throw new AiConfigError("endpoint_required", `Provider kind '${config.kind}' requires an endpoint`);
  }
  if (credentialRequirement(config.kind) === "required" && !secret) {
    throw new AiConfigError("credential_required", `Provider kind '${config.kind}' requires an API credential`);
  }
  return endpoint;
}

/**
 * Build a provider for a tenant configuration. The endpoint is checked by the SSRF guard
 * (private ranges only with the tenant setting; metadata endpoints never), and the result is
 * wrapped in the data-governance layer unless `governance: false`.
 */
export function createProvider(config: ProviderConfigInput, secret: string | null, fetchImpl: FetchLike, options: ProviderRuntimeOptions = {}): AiProvider {
  const endpoint = validateConfig(config, secret, options.allowPrivateEndpoints ?? false);
  const http = new HttpClient({
    fetch: fetchImpl,
    providerKind: config.kind,
    providerId: config.id,
    ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
    ...(options.maxRetries !== undefined ? { maxRetries: options.maxRetries } : {}),
    ...(options.retryBaseMs !== undefined ? { retryBaseMs: options.retryBaseMs } : {}),
    ...(options.retryMaxMs !== undefined ? { retryMaxMs: options.retryMaxMs } : {}),
    ...(options.maxResponseBytes !== undefined ? { maxResponseBytes: options.maxResponseBytes } : {}),
    ...(options.sleep ? { sleep: options.sleep } : {}),
    ...(options.random ? { random: options.random } : {}),
    ...(options.userAgent ? { userAgent: options.userAgent } : {}),
  });
  const common: ProviderCommon = {
    id: config.id,
    kind: config.kind,
    model: config.model,
    temperature: config.temperature,
    maxOutputTokens: config.maxOutputTokens,
    contextWindow: config.contextWindow,
    http,
    ids: options.ids ?? uuidGenerator,
    clock: options.clock ?? systemClock,
  };

  let provider: AiProvider;
  switch (config.kind) {
    case "openai":
    case "mistral":
    case "vllm":
    case "lmstudio":
    case "openai_compatible":
      provider = new OpenAiCompatibleProvider(common, { baseUrl: endpoint!, apiKey: secret });
      break;
    case "ollama":
      provider = new OllamaProvider(common, { baseUrl: endpoint!, apiKey: secret });
      break;
    case "anthropic":
      provider = new AnthropicProvider(common, { baseUrl: endpoint!, apiKey: secret! });
      break;
    case "google":
      provider = new GeminiProvider(common, { baseUrl: endpoint!, apiKey: secret! });
      break;
    case "azure_openai":
      provider = new AzureOpenAiProvider(common, { endpoint: endpoint!, apiKey: secret! });
      break;
    case "aws_bedrock":
      provider = new BedrockProvider(common, { endpoint, secret: secret! });
      break;
  }
  if (options.governance === false) return provider;
  return new GovernedProvider(provider, config, options.governance ?? {});
}

/**
 * Connectivity test for `POST /ai/providers/:id/test`: validates the endpoint including DNS
 * resolution (rejects names that resolve to internal/metadata addresses), then lists models.
 * Sends no tenant data. Never throws for provider failures — returns `ok: false` instead.
 */
export async function testProviderConnection(
  config: ProviderConfigInput,
  secret: string | null,
  fetchImpl: FetchLike,
  options: ProviderRuntimeOptions & { hostResolver?: HostResolver } = {},
  signal?: AbortSignal,
): Promise<HealthStatus> {
  const clock = options.clock ?? systemClock;
  try {
    const endpoint = resolveEndpoint(config);
    if (endpoint) {
      await assertSafeEndpointResolved(
        endpoint,
        { allowPrivate: options.allowPrivateEndpoints ?? false, requireHttps: classifyEgress(config.kind, endpoint) === "cloud" },
        ...(options.hostResolver ? [options.hostResolver] : []),
      );
    }
    const provider = createProvider(config, secret, fetchImpl, { ...options, governance: false });
    return await provider.healthCheck(signal);
  } catch (err) {
    const e = err instanceof Error ? err : new Error(String(err));
    return {
      ok: false,
      kind: config.kind,
      providerId: config.id,
      model: config.model,
      latencyMs: 0,
      modelAvailable: null,
      modelsListed: null,
      error: { code: (err as { code?: string }).code ?? "internal_error", message: e.message },
      checkedAt: clock.now().toISOString(),
    };
  }
}
