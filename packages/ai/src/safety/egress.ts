import { LOCAL_AI_PROVIDERS, type AiProviderConfig, type AiProviderKind } from "@bloody/contracts";
import { AiPolicyError } from "../errors.js";
import { classifyHost } from "./ssrf.js";

/**
 * Data-egress classification. A provider is "local" when tenant data stays on infrastructure
 * the customer controls (Ollama, vLLM, LM Studio, self-hosted OpenAI-compatible servers) and
 * "cloud" otherwise. A self-hosted kind pointed at a well-known AI SaaS API (e.g. an
 * `openai_compatible` provider configured with api.groq.com) is treated as cloud, so the
 * `allowCloudData` switch cannot be bypassed by picking a "local" provider kind.
 */
export type DataEgress = "local" | "cloud";

export const KNOWN_CLOUD_AI_HOST_SUFFIXES = [
  "api.openai.com",
  "openai.azure.com",
  "cognitiveservices.azure.com",
  "services.ai.azure.com",
  "inference.ai.azure.com",
  "api.anthropic.com",
  "generativelanguage.googleapis.com",
  "aiplatform.googleapis.com",
  "amazonaws.com",
  "api.mistral.ai",
  "api.groq.com",
  "api.together.xyz",
  "api.fireworks.ai",
  "openrouter.ai",
  "api.deepseek.com",
  "api.x.ai",
  "api.cohere.ai",
  "api.cohere.com",
  "api.perplexity.ai",
  "api.deepinfra.com",
  "integrate.api.nvidia.com",
  "huggingface.co",
  "api.cerebras.ai",
] as const;

export function isLocalProviderKind(kind: AiProviderKind): boolean {
  return LOCAL_AI_PROVIDERS.includes(kind);
}

function hostMatchesSuffix(host: string, suffix: string): boolean {
  return host === suffix || host.endsWith(`.${suffix}`);
}

export function classifyEgress(kind: AiProviderKind, endpoint: string | null): DataEgress {
  if (!isLocalProviderKind(kind)) return "cloud";
  if (!endpoint) return "local";
  let host: string;
  try {
    host = new URL(endpoint).hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return "cloud"; // fail closed: an unparseable endpoint is never treated as local
  }
  if (KNOWN_CLOUD_AI_HOST_SUFFIXES.some((s) => hostMatchesSuffix(host, s))) return "cloud";
  return "local";
}

/** True when the endpoint is on loopback / private ranges (used for UI hints, not for policy). */
export function isPrivateNetworkEndpoint(endpoint: string): boolean {
  try {
    const cls = classifyHost(new URL(endpoint).hostname);
    return cls !== "public" && cls !== "public_hostname";
  } catch {
    return false;
  }
}

export type ProviderGovernanceFields = Pick<AiProviderConfig, "id" | "kind" | "endpoint" | "allowCloudData" | "enabled" | "name">;

/** Throws {@link AiPolicyError} when tenant data must not be sent to this provider. */
export function assertTenantDataAllowed(config: ProviderGovernanceFields): void {
  if (!config.enabled) {
    throw new AiPolicyError("provider_disabled", `AI provider '${config.name}' is disabled`, { details: { providerId: config.id } });
  }
  if (classifyEgress(config.kind, config.endpoint) === "cloud" && !config.allowCloudData) {
    throw new AiPolicyError(
      "cloud_data_forbidden",
      `AI provider '${config.name}' is a cloud provider and this tenant does not allow sending tenant data to cloud models (allowCloudData=false)`,
      { details: { providerId: config.id, kind: config.kind } },
    );
  }
}
