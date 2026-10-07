import type { AiProviderKind, AiToolTier } from "@bloody/contracts";
import { isLocalProviderKind } from "../safety/egress.js";

/**
 * Provider catalog for the AI configuration UI: default endpoints, credential requirements,
 * capability flags and recommended model hints. Hints are suggestions only — the UI should
 * prefer the live list from `provider.listModels()` (`GET /ai/providers/:id/models`).
 */

export const DEFAULT_ENDPOINTS: Record<AiProviderKind, string | null> = {
  ollama: "http://localhost:11434",
  lmstudio: "http://localhost:1234/v1",
  vllm: "http://localhost:8000/v1",
  openai_compatible: null,
  openai: "https://api.openai.com/v1",
  anthropic: "https://api.anthropic.com",
  google: "https://generativelanguage.googleapis.com",
  azure_openai: null,
  aws_bedrock: null,
  mistral: "https://api.mistral.ai/v1",
};

export type CredentialRequirement = "required" | "optional" | "none";

export interface ProviderCatalogEntry {
  kind: AiProviderKind;
  label: string;
  deployment: "local" | "cloud";
  defaultEndpoint: string | null;
  endpointRequired: boolean;
  endpointPlaceholder: string;
  credential: CredentialRequirement;
  credentialLabel: string;
  credentialHelp: string;
  /** What the "model" field means for this provider. */
  modelLabel: string;
  supportsToolCalling: boolean;
  supportsStreaming: boolean;
  supportsModelListing: boolean;
  /** Suggested tool tier ceiling for a fresh configuration. */
  suggestedMaxToolTier: AiToolTier;
  recommendedModels: Array<{ id: string; note: string }>;
  docsHint: string;
}

const ENTRIES: ProviderCatalogEntry[] = [
  {
    kind: "ollama",
    label: "Ollama",
    deployment: "local",
    defaultEndpoint: DEFAULT_ENDPOINTS.ollama,
    endpointRequired: false,
    endpointPlaceholder: "http://ollama.internal:11434",
    credential: "optional",
    credentialLabel: "Bearer token (only if behind an authenticating proxy)",
    credentialHelp: "Ollama has no built-in auth; protect it with a reverse proxy when it is not on localhost.",
    modelLabel: "Model tag",
    supportsToolCalling: true,
    supportsStreaming: true,
    supportsModelListing: true,
    suggestedMaxToolTier: "recommend",
    recommendedModels: [
      { id: "qwen2.5:14b", note: "Strong tool calling at modest VRAM" },
      { id: "llama3.1:8b", note: "Fast triage / summarisation" },
      { id: "llama3.3:70b", note: "Deep investigations (large GPU)" },
      { id: "mistral-small", note: "Good JSON / tool discipline" },
    ],
    docsHint: "Pull the model first (`ollama pull <tag>`); Bloody sets num_ctx from the context size.",
  },
  {
    kind: "vllm",
    label: "vLLM",
    deployment: "local",
    defaultEndpoint: DEFAULT_ENDPOINTS.vllm,
    endpointRequired: false,
    endpointPlaceholder: "http://vllm.internal:8000/v1",
    credential: "optional",
    credentialLabel: "API key (--api-key)",
    credentialHelp: "Set when vLLM was started with --api-key.",
    modelLabel: "Served model name",
    supportsToolCalling: true,
    supportsStreaming: true,
    supportsModelListing: true,
    suggestedMaxToolTier: "recommend",
    recommendedModels: [
      { id: "Qwen/Qwen2.5-32B-Instruct", note: "Start vLLM with --enable-auto-tool-choice --tool-call-parser hermes" },
      { id: "meta-llama/Llama-3.1-8B-Instruct", note: "Use --tool-call-parser llama3_json" },
    ],
    docsHint: "Tool calling requires --enable-auto-tool-choice and a matching --tool-call-parser.",
  },
  {
    kind: "lmstudio",
    label: "LM Studio",
    deployment: "local",
    defaultEndpoint: DEFAULT_ENDPOINTS.lmstudio,
    endpointRequired: false,
    endpointPlaceholder: "http://workstation.internal:1234/v1",
    credential: "optional",
    credentialLabel: "API key",
    credentialHelp: "Only needed if the LM Studio server enforces authentication.",
    modelLabel: "Model identifier",
    supportsToolCalling: true,
    supportsStreaming: true,
    supportsModelListing: true,
    suggestedMaxToolTier: "read",
    recommendedModels: [
      { id: "qwen2.5-14b-instruct", note: "Native tool-use support" },
      { id: "llama-3.1-8b-instruct", note: "Lightweight analyst assistant" },
    ],
    docsHint: "Enable the local server in LM Studio and load the model before testing.",
  },
  {
    kind: "openai_compatible",
    label: "OpenAI-compatible endpoint",
    deployment: "local",
    defaultEndpoint: null,
    endpointRequired: true,
    endpointPlaceholder: "https://llm-gateway.internal/v1",
    credential: "optional",
    credentialLabel: "API key",
    credentialHelp: "Sent as a Bearer token. Endpoints on known AI SaaS hosts are treated as cloud providers.",
    modelLabel: "Model",
    supportsToolCalling: true,
    supportsStreaming: true,
    supportsModelListing: true,
    suggestedMaxToolTier: "read",
    recommendedModels: [],
    docsHint: "Base URL must include the version path (usually /v1).",
  },
  {
    kind: "openai",
    label: "OpenAI",
    deployment: "cloud",
    defaultEndpoint: DEFAULT_ENDPOINTS.openai,
    endpointRequired: false,
    endpointPlaceholder: "https://api.openai.com/v1",
    credential: "required",
    credentialLabel: "API key",
    credentialHelp: "Project-scoped key recommended.",
    modelLabel: "Model",
    supportsToolCalling: true,
    supportsStreaming: true,
    supportsModelListing: true,
    suggestedMaxToolTier: "recommend",
    recommendedModels: [
      { id: "gpt-4.1", note: "Deep investigations" },
      { id: "gpt-4o-mini", note: "Fast triage / summaries" },
    ],
    docsHint: "Requires 'allow cloud data' for tenant data.",
  },
  {
    kind: "anthropic",
    label: "Anthropic",
    deployment: "cloud",
    defaultEndpoint: DEFAULT_ENDPOINTS.anthropic,
    endpointRequired: false,
    endpointPlaceholder: "https://api.anthropic.com",
    credential: "required",
    credentialLabel: "API key",
    credentialHelp: "Workspace API key (x-api-key).",
    modelLabel: "Model",
    supportsToolCalling: true,
    supportsStreaming: true,
    supportsModelListing: true,
    suggestedMaxToolTier: "recommend",
    recommendedModels: [
      { id: "claude-sonnet-4-5", note: "Balanced analyst model" },
      { id: "claude-haiku-4-5", note: "Fast triage / summaries" },
    ],
    docsHint: "Requires 'allow cloud data' for tenant data. Use model listing for the current catalogue.",
  },
  {
    kind: "google",
    label: "Google Gemini",
    deployment: "cloud",
    defaultEndpoint: DEFAULT_ENDPOINTS.google,
    endpointRequired: false,
    endpointPlaceholder: "https://generativelanguage.googleapis.com",
    credential: "required",
    credentialLabel: "API key",
    credentialHelp: "Gemini API key (sent as x-goog-api-key, never in the URL).",
    modelLabel: "Model",
    supportsToolCalling: true,
    supportsStreaming: false,
    supportsModelListing: true,
    suggestedMaxToolTier: "recommend",
    recommendedModels: [
      { id: "gemini-2.5-pro", note: "Long-context investigations" },
      { id: "gemini-2.5-flash", note: "Fast triage" },
    ],
    docsHint: "Requires 'allow cloud data' for tenant data.",
  },
  {
    kind: "azure_openai",
    label: "Azure OpenAI",
    deployment: "cloud",
    defaultEndpoint: null,
    endpointRequired: true,
    endpointPlaceholder: "https://<resource>.openai.azure.com/?api-version=2024-10-21",
    credential: "required",
    credentialLabel: "API key",
    credentialHelp: "Resource key (api-key header). Optional ?api-version=… on the endpoint overrides the default.",
    modelLabel: "Deployment name",
    supportsToolCalling: true,
    supportsStreaming: true,
    supportsModelListing: true,
    suggestedMaxToolTier: "recommend",
    recommendedModels: [{ id: "gpt-4o", note: "Use your deployment name, not the base model name" }],
    docsHint: "Data stays in your Azure tenancy region but is still classified as cloud egress.",
  },
  {
    kind: "aws_bedrock",
    label: "Amazon Bedrock",
    deployment: "cloud",
    defaultEndpoint: null,
    endpointRequired: false,
    endpointPlaceholder: "https://bedrock-runtime.eu-west-1.amazonaws.com",
    credential: "required",
    credentialLabel: "AWS credentials",
    credentialHelp: 'JSON {"accessKeyId","secretAccessKey","sessionToken?","region"}, "AKID:SECRET", or a Bedrock API key. Least-privilege: bedrock:InvokeModel + bedrock:ListFoundationModels.',
    modelLabel: "Model or inference profile id",
    supportsToolCalling: true,
    supportsStreaming: false,
    supportsModelListing: true,
    suggestedMaxToolTier: "recommend",
    recommendedModels: [
      { id: "anthropic.claude-3-5-sonnet-20240620-v1:0", note: "Strong tool use" },
      { id: "amazon.nova-pro-v1:0", note: "AWS-native" },
      { id: "meta.llama3-1-70b-instruct-v1:0", note: "Open-weights option" },
    ],
    docsHint: "Uses the Converse API with SigV4; enable model access in the Bedrock console first.",
  },
  {
    kind: "mistral",
    label: "Mistral AI",
    deployment: "cloud",
    defaultEndpoint: DEFAULT_ENDPOINTS.mistral,
    endpointRequired: false,
    endpointPlaceholder: "https://api.mistral.ai/v1",
    credential: "required",
    credentialLabel: "API key",
    credentialHelp: "La Plateforme API key.",
    modelLabel: "Model",
    supportsToolCalling: true,
    supportsStreaming: true,
    supportsModelListing: true,
    suggestedMaxToolTier: "recommend",
    recommendedModels: [
      { id: "mistral-large-latest", note: "Deep investigations" },
      { id: "mistral-small-latest", note: "Fast triage" },
    ],
    docsHint: "EU-hosted cloud option; still requires 'allow cloud data'.",
  },
];

export const AI_PROVIDER_CATALOG: Readonly<Record<AiProviderKind, ProviderCatalogEntry>> = Object.fromEntries(ENTRIES.map((e) => [e.kind, e])) as Record<
  AiProviderKind,
  ProviderCatalogEntry
>;

export function providerCatalogEntry(kind: AiProviderKind): ProviderCatalogEntry {
  return AI_PROVIDER_CATALOG[kind];
}

export function credentialRequirement(kind: AiProviderKind): CredentialRequirement {
  return AI_PROVIDER_CATALOG[kind].credential;
}

export function listProviderCatalog(): ProviderCatalogEntry[] {
  return ENTRIES.map((e) => ({ ...e, deployment: isLocalProviderKind(e.kind) ? "local" : "cloud" }));
}
