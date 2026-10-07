/**
 * @bloody/ai — AI SOC module of the Bloody Security Command Center.
 *
 *   Providers     model abstraction over local (Ollama, vLLM, LM Studio, OpenAI-compatible) and
 *                 cloud (OpenAI, Anthropic, Google Gemini, Azure OpenAI, AWS Bedrock, Mistral)
 *                 models — injected fetch, no vendor SDKs, timeouts/retries/size limits, fallback.
 *   Safety        SSRF guard for endpoints, data-egress policy (allowCloudData), secret/PII
 *                 redaction with reversible per-run placeholders.
 *   Tool gateway  the only path from a model to data and actions: RBAC, tool tiers
 *                 (read → investigate → recommend → require_approval → execute), approvals, audit.
 *   SOC tools     standard AI SOC catalog over the injected SocDataPort.
 *   Orchestrator  agent loop with grounding, budgets, conversation persistence, metering.
 *   Reporting     AI narratives for business/SOC/MSSP/customer reports, notification drafts,
 *                 AI activity and usage aggregates.
 */

// errors & utils
export * from "./errors.js";
export { uuidGenerator, systemClock, defaultSleep, type Clock, type IdGenerator, type SleepFn } from "./util/ids.js";
export { estimateTokens, estimateMessageTokens, estimateMessagesTokens } from "./util/tokens.js";

// safety
export * from "./safety/ip.js";
export * from "./safety/ssrf.js";
export * from "./safety/redact.js";
export * from "./safety/egress.js";

// providers
export * from "./providers/types.js";
export { HttpClient, SseDecoder, joinUrl, parseRetryAfter, extractErrorMessage, statusToCode, readBodyLimited, type HttpClientOptions, type HttpRequest } from "./providers/http.js";
export { parseToolArguments, toolNameForCall, splitSystem, INVALID_TOOL_ARGUMENTS_KEY, type AiToolCall } from "./providers/messages.js";
export { BaseProvider, type ProviderCommon } from "./providers/base.js";
export * from "./providers/openai-compatible.js";
export * from "./providers/ollama.js";
export * from "./providers/anthropic.js";
export * from "./providers/gemini.js";
export * from "./providers/sigv4.js";
export * from "./providers/bedrock.js";
export * from "./providers/defaults.js";
export * from "./providers/governed.js";
export * from "./providers/fallback.js";
export * from "./providers/factory.js";
export * from "./providers/registry.js";

// tools
export * from "./tools/json-schema.js";
export * from "./tools/types.js";
export * from "./tools/gateway.js";
export * from "./tools/soc-port.js";
export * from "./tools/compact.js";
export * from "./tools/sigma-draft.js";
export * from "./tools/remediation.js";
export * from "./tools/catalog.js";

// orchestrator
export * from "./orchestrator/policy.js";
export * from "./orchestrator/conversation-store.js";
export * from "./orchestrator/usage.js";
export * from "./orchestrator/context.js";
export * from "./orchestrator/orchestrator.js";
export * from "./orchestrator/automation.js";

// reporting
export * from "./reporting/narrative.js";
export * from "./reporting/activity.js";
