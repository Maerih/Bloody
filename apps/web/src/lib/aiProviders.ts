import {
  AiToolTier,
  LOCAL_AI_PROVIDERS,
  UpsertAiProviderInput,
  type AiProviderConfig,
  type AiProviderKind,
} from "@bloody/contracts";

/**
 * AI provider catalogue for the settings UI (labels, default endpoints, credential needs) and
 * form validation. Defaults are well-known vendor endpoints, not tenant data.
 */

export interface AiProviderKindMeta {
  label: string;
  deployment: "local" | "cloud";
  defaultEndpoint: string | null;
  endpointRequired: boolean;
  credential: "none" | "optional" | "required";
  credentialLabel: string;
  modelPlaceholder: string;
  endpointHint?: string;
}

export const AI_PROVIDER_META: Record<AiProviderKind, AiProviderKindMeta> = {
  ollama: { label: "Ollama", deployment: "local", defaultEndpoint: "http://localhost:11434", endpointRequired: true, credential: "none", credentialLabel: "API key", modelPlaceholder: "llama3.1:8b" },
  vllm: { label: "vLLM", deployment: "local", defaultEndpoint: "http://localhost:8000/v1", endpointRequired: true, credential: "optional", credentialLabel: "API key (if --api-key is set)", modelPlaceholder: "meta-llama/Llama-3.1-8B-Instruct" },
  lmstudio: { label: "LM Studio", deployment: "local", defaultEndpoint: "http://localhost:1234/v1", endpointRequired: true, credential: "none", credentialLabel: "API key", modelPlaceholder: "qwen2.5-7b-instruct" },
  openai_compatible: { label: "OpenAI-compatible endpoint", deployment: "local", defaultEndpoint: null, endpointRequired: true, credential: "optional", credentialLabel: "API key", modelPlaceholder: "model name served by the endpoint", endpointHint: "Base URL of the /v1 API, e.g. http://llm.internal:8080/v1" },
  openai: { label: "OpenAI", deployment: "cloud", defaultEndpoint: "https://api.openai.com/v1", endpointRequired: false, credential: "required", credentialLabel: "API key", modelPlaceholder: "gpt-4o" },
  anthropic: { label: "Anthropic", deployment: "cloud", defaultEndpoint: "https://api.anthropic.com", endpointRequired: false, credential: "required", credentialLabel: "API key", modelPlaceholder: "claude-sonnet-4-5" },
  google: { label: "Google (Gemini)", deployment: "cloud", defaultEndpoint: "https://generativelanguage.googleapis.com", endpointRequired: false, credential: "required", credentialLabel: "API key", modelPlaceholder: "gemini-2.5-pro" },
  azure_openai: { label: "Azure OpenAI", deployment: "cloud", defaultEndpoint: null, endpointRequired: true, credential: "required", credentialLabel: "API key", modelPlaceholder: "deployment name", endpointHint: "https://<resource>.openai.azure.com" },
  aws_bedrock: { label: "AWS Bedrock", deployment: "cloud", defaultEndpoint: "https://bedrock-runtime.us-east-1.amazonaws.com", endpointRequired: true, credential: "required", credentialLabel: "AWS credentials (accessKeyId:secretAccessKey)", modelPlaceholder: "anthropic.claude-3-5-sonnet-20241022-v2:0", endpointHint: "Regional bedrock-runtime endpoint" },
  mistral: { label: "Mistral", deployment: "cloud", defaultEndpoint: "https://api.mistral.ai/v1", endpointRequired: false, credential: "required", credentialLabel: "API key", modelPlaceholder: "mistral-large-latest" },
};

export const LOCAL_KINDS: AiProviderKind[] = LOCAL_AI_PROVIDERS;
export const CLOUD_KINDS = (Object.keys(AI_PROVIDER_META) as AiProviderKind[]).filter((k) => !LOCAL_AI_PROVIDERS.includes(k));

export const TOOL_TIER_META: Record<AiToolTier, { label: string; description: string; tone: "neutral" | "info" | "purple" | "warning" | "danger" }> = {
  read: { label: "READ", description: "Read platform data (incidents, assets, intel).", tone: "neutral" },
  investigate: { label: "INVESTIGATE", description: "Run searches, graph queries and hunts.", tone: "info" },
  recommend: { label: "RECOMMEND", description: "Propose actions, detections and reports — never executes.", tone: "purple" },
  require_approval: { label: "REQUIRE APPROVAL", description: "Request response actions that wait for a human approver.", tone: "warning" },
  execute: { label: "EXECUTE", description: "Execute permitted low-risk actions without a human. High-risk actions still require approval.", tone: "danger" },
};

export const TOOL_TIERS = AiToolTier.options;

/** Editable form state (strings for numeric inputs so partial typing is not lost). */
export interface AiProviderDraft {
  name: string;
  kind: AiProviderKind;
  organizationId: string | null;
  endpoint: string;
  model: string;
  /** Write-only; empty = keep the stored secret (edit) / none (create). */
  apiKey: string;
  contextWindow: string;
  temperature: string;
  maxOutputTokens: string;
  systemPolicy: string;
  maxToolTier: AiToolTier;
  isDefault: boolean;
  fallbackProviderId: string | null;
  retentionDays: string;
  redactSensitive: boolean;
  allowCloudData: boolean;
  enabled: boolean;
}

export type AiProviderDraftErrors = Partial<Record<keyof AiProviderDraft, string>>;

export function newProviderDraft(kind: AiProviderKind = "ollama", organizationId: string | null = null): AiProviderDraft {
  const meta = AI_PROVIDER_META[kind];
  return {
    name: meta.label,
    kind,
    organizationId,
    endpoint: meta.defaultEndpoint ?? "",
    model: "",
    apiKey: "",
    contextWindow: "32768",
    temperature: "0.2",
    maxOutputTokens: "2048",
    systemPolicy: "",
    maxToolTier: "recommend",
    isDefault: false,
    fallbackProviderId: null,
    retentionDays: "30",
    redactSensitive: true,
    allowCloudData: false,
    enabled: true,
  };
}

export function draftFromProvider(p: AiProviderConfig): AiProviderDraft {
  return {
    name: p.name,
    kind: p.kind,
    organizationId: p.organizationId,
    endpoint: p.endpoint ?? "",
    model: p.model,
    apiKey: "",
    contextWindow: String(p.contextWindow),
    temperature: String(p.temperature),
    maxOutputTokens: String(p.maxOutputTokens),
    systemPolicy: p.systemPolicy ?? "",
    maxToolTier: p.maxToolTier,
    isDefault: p.isDefault,
    fallbackProviderId: p.fallbackProviderId,
    retentionDays: String(p.retentionDays),
    redactSensitive: p.redactSensitive,
    allowCloudData: p.allowCloudData,
    enabled: p.enabled,
  };
}

/** Switching kind swaps the endpoint only when it still holds the previous kind's default. */
export function changeKind(draft: AiProviderDraft, kind: AiProviderKind): AiProviderDraft {
  const prev = AI_PROVIDER_META[draft.kind];
  const next = AI_PROVIDER_META[kind];
  const endpointUntouched = draft.endpoint === "" || draft.endpoint === (prev.defaultEndpoint ?? "");
  const nameUntouched = draft.name === "" || draft.name === prev.label;
  return {
    ...draft,
    kind,
    endpoint: endpointUntouched ? (next.defaultEndpoint ?? "") : draft.endpoint,
    name: nameUntouched ? next.label : draft.name,
    allowCloudData: next.deployment === "local" ? false : draft.allowCloudData,
  };
}

function parseIntStrict(value: string): number | null {
  const t = value.trim();
  return /^\d+$/.test(t) ? Number(t) : null;
}

function parseNumber(value: string): number | null {
  const t = value.trim();
  if (t === "") return null;
  const n = Number(t);
  return Number.isFinite(n) ? n : null;
}

export interface ValidationContext {
  isNew: boolean;
  /** The provider already has a stored credential (edit). */
  hasStoredCredential: boolean;
  /** Id of the provider being edited (a provider cannot fall back to itself). */
  providerId?: string;
}

export interface ValidationResult {
  errors: AiProviderDraftErrors;
  warnings: string[];
  /** Request body, present only when there are no errors. API key omitted when blank. */
  input: UpsertAiProviderInput | null;
}

/** Validate the provider form and build the POST/PATCH body (`UpsertAiProviderInput`). */
export function validateAiProviderDraft(draft: AiProviderDraft, ctx: ValidationContext): ValidationResult {
  const errors: AiProviderDraftErrors = {};
  const warnings: string[] = [];
  const meta = AI_PROVIDER_META[draft.kind];

  const name = draft.name.trim();
  if (!name) errors.name = "Name is required";
  else if (name.length > 120) errors.name = "Name must be at most 120 characters";

  const model = draft.model.trim();
  if (!model) errors.model = "Model is required";

  const endpoint = draft.endpoint.trim();
  let endpointValue: string | null = null;
  if (endpoint === "") {
    if (meta.endpointRequired) errors.endpoint = `${meta.label} needs an endpoint URL`;
  } else {
    let url: URL | null = null;
    try {
      url = new URL(endpoint);
    } catch {
      url = null;
    }
    if (!url || (url.protocol !== "http:" && url.protocol !== "https:")) errors.endpoint = "Enter a valid http(s) URL";
    else if (url.username || url.password) errors.endpoint = "Do not embed credentials in the URL — use the API key field";
    else if (meta.deployment === "cloud" && url.protocol !== "https:") errors.endpoint = "Cloud providers must use https";
    else endpointValue = endpoint.replace(/\/+$/, "");
  }

  const apiKey = draft.apiKey.trim();
  if (meta.credential === "required" && !apiKey && (ctx.isNew || !ctx.hasStoredCredential)) errors.apiKey = `${meta.credentialLabel} is required for ${meta.label}`;
  if (apiKey.length > 4000) errors.apiKey = "Credential is too long";
  if (draft.kind === "aws_bedrock" && apiKey && !/^[^:\s]+:[^:\s]+$/.test(apiKey)) errors.apiKey = "Use the form accessKeyId:secretAccessKey";

  const contextWindow = parseIntStrict(draft.contextWindow);
  if (contextWindow === null || contextWindow < 512 || contextWindow > 2_000_000) errors.contextWindow = "Context size must be a whole number between 512 and 2,000,000 tokens";

  const temperature = parseNumber(draft.temperature);
  if (temperature === null || temperature < 0 || temperature > 2) errors.temperature = "Temperature must be between 0 and 2";

  const maxOutputTokens = parseIntStrict(draft.maxOutputTokens);
  if (maxOutputTokens === null || maxOutputTokens < 16 || maxOutputTokens > 200_000) errors.maxOutputTokens = "Max output must be a whole number between 16 and 200,000 tokens";
  else if (contextWindow !== null && maxOutputTokens >= contextWindow) errors.maxOutputTokens = "Max output must be smaller than the context size";

  const retentionDays = parseIntStrict(draft.retentionDays);
  if (retentionDays === null || retentionDays > 3650) errors.retentionDays = "Retention must be between 0 and 3,650 days";

  if (draft.systemPolicy.length > 20_000) errors.systemPolicy = "System policy must be at most 20,000 characters";

  if (draft.fallbackProviderId && ctx.providerId && draft.fallbackProviderId === ctx.providerId) errors.fallbackProviderId = "A provider cannot fall back to itself";

  if (meta.deployment === "cloud" && !draft.allowCloudData) warnings.push("Tenant data is not allowed to leave the platform for this cloud provider: it will only answer questions that need no customer data.");
  if (meta.deployment === "cloud" && draft.allowCloudData && !draft.redactSensitive) warnings.push("Customer data will be sent to a cloud provider without redaction of secrets and PII.");
  if (draft.maxToolTier === "execute") warnings.push("EXECUTE lets the model run permitted low-risk actions without a human. High-risk actions always require approval.");
  if (!draft.enabled && draft.isDefault) warnings.push("A disabled provider cannot serve as the default; requests will use the fallback.");

  if (Object.keys(errors).length > 0) return { errors, warnings, input: null };

  const body = {
    name,
    kind: draft.kind,
    model,
    organizationId: draft.organizationId,
    endpoint: endpointValue,
    ...(apiKey ? { apiKey } : {}),
    contextWindow: contextWindow!,
    temperature: temperature!,
    maxOutputTokens: maxOutputTokens!,
    systemPolicy: draft.systemPolicy.trim() || null,
    maxToolTier: draft.maxToolTier,
    isDefault: draft.isDefault,
    fallbackProviderId: draft.fallbackProviderId,
    retentionDays: retentionDays!,
    redactSensitive: draft.redactSensitive,
    allowCloudData: meta.deployment === "local" ? false : draft.allowCloudData,
    enabled: draft.enabled,
  };
  const parsed = UpsertAiProviderInput.safeParse(body);
  if (!parsed.success) {
    for (const issue of parsed.error.issues) {
      const field = issue.path[0];
      if (typeof field === "string" && field in draft && !errors[field as keyof AiProviderDraft]) errors[field as keyof AiProviderDraft] = issue.message;
    }
    if (Object.keys(errors).length === 0) errors.name = "The provider configuration is invalid";
    return { errors, warnings, input: null };
  }
  return { errors, warnings, input: body as UpsertAiProviderInput };
}

/** The provider that answers for a scope: an enabled organization default, else the tenant default. */
export function effectiveProvider(providers: AiProviderConfig[], organizationId: string | null): AiProviderConfig | null {
  const enabled = providers.filter((p) => p.enabled);
  if (organizationId) {
    const org = enabled.filter((p) => p.organizationId === organizationId);
    const orgDefault = org.find((p) => p.isDefault) ?? org[0];
    if (orgDefault) return orgDefault;
  }
  const tenant = enabled.filter((p) => p.organizationId === null);
  return tenant.find((p) => p.isDefault) ?? tenant[0] ?? null;
}
