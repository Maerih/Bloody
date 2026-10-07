import { z } from "zod";
import { IsoDateTime, Uuid } from "./common.js";

/**
 * AI provider abstraction. Each organization (or the whole tenant) configures its own
 * providers; nothing in Bloody is hard-coded to a single vendor.
 */
export const AiProviderKind = z.enum([
  // local / self-hosted
  "ollama",
  "vllm",
  "lmstudio",
  "openai_compatible",
  // cloud
  "openai",
  "anthropic",
  "google",
  "azure_openai",
  "aws_bedrock",
  "mistral",
]);
export type AiProviderKind = z.infer<typeof AiProviderKind>;

export const LOCAL_AI_PROVIDERS: AiProviderKind[] = ["ollama", "vllm", "lmstudio", "openai_compatible"];

/** Tool permission tiers, ordered from least to most privileged. */
export const AiToolTier = z.enum(["read", "investigate", "recommend", "require_approval", "execute"]);
export type AiToolTier = z.infer<typeof AiToolTier>;
export const AI_TIER_RANK: Record<AiToolTier, number> = { read: 0, investigate: 1, recommend: 2, require_approval: 3, execute: 4 };

export const AiProviderConfig = z.object({
  id: Uuid,
  tenantId: Uuid,
  organizationId: Uuid.nullable(),
  name: z.string().min(1).max(120),
  kind: AiProviderKind,
  endpoint: z.string().url().nullable(),
  model: z.string().min(1),
  /** Opaque reference into the secret store; the secret itself is never returned by the API. */
  credentialRef: z.string().nullable(),
  hasCredential: z.boolean(),
  contextWindow: z.number().int().min(512).max(2_000_000),
  temperature: z.number().min(0).max(2),
  maxOutputTokens: z.number().int().min(16).max(200_000),
  systemPolicy: z.string().max(20_000).nullable(),
  /** Highest tool tier this model may invoke without a human. */
  maxToolTier: AiToolTier,
  isDefault: z.boolean(),
  fallbackProviderId: Uuid.nullable(),
  /** Prompt/response retention in days; 0 = do not retain. */
  retentionDays: z.number().int().min(0).max(3650),
  /** Redact secrets/PII before sending context to the model. */
  redactSensitive: z.boolean(),
  /** Disallow sending tenant data to cloud providers. */
  allowCloudData: z.boolean(),
  enabled: z.boolean(),
  createdAt: IsoDateTime,
  updatedAt: IsoDateTime,
});
export type AiProviderConfig = z.infer<typeof AiProviderConfig>;

export const UpsertAiProviderInput = AiProviderConfig.pick({
  name: true,
  kind: true,
  model: true,
}).extend({
  organizationId: Uuid.nullable().optional(),
  endpoint: z.string().url().nullable().optional(),
  /** Write-only. Stored in the secret store; never echoed back. */
  apiKey: z.string().min(1).max(4000).optional(),
  contextWindow: z.number().int().min(512).max(2_000_000).default(32_768),
  temperature: z.number().min(0).max(2).default(0.2),
  maxOutputTokens: z.number().int().min(16).max(200_000).default(2048),
  systemPolicy: z.string().max(20_000).nullable().optional(),
  maxToolTier: AiToolTier.default("recommend"),
  isDefault: z.boolean().default(false),
  fallbackProviderId: Uuid.nullable().optional(),
  retentionDays: z.number().int().min(0).max(3650).default(30),
  redactSensitive: z.boolean().default(true),
  allowCloudData: z.boolean().default(false),
  enabled: z.boolean().default(true),
});
export type UpsertAiProviderInput = z.input<typeof UpsertAiProviderInput>;

export const AiMessage = z.object({
  role: z.enum(["system", "user", "assistant", "tool"]),
  content: z.string(),
  toolCallId: z.string().optional(),
  toolCalls: z.array(z.object({ id: z.string(), name: z.string(), arguments: z.record(z.unknown()) })).optional(),
});
export type AiMessage = z.infer<typeof AiMessage>;

export const AiChatRequest = z.object({
  conversationId: Uuid.optional(),
  providerId: Uuid.optional(),
  organizationId: Uuid,
  message: z.string().min(1).max(20_000),
  /** Context the analyst is looking at (incident, asset, IOC…) to ground the answer. */
  context: z.object({ kind: z.enum(["incident", "investigation", "asset", "identity", "indicator", "alert", "none"]), id: z.string().optional() }).default({ kind: "none" }),
});
export type AiChatRequest = z.input<typeof AiChatRequest>;

export const AiActionStatus = z.enum(["completed", "pending_approval", "approved", "rejected", "denied", "failed"]);
export const AiActionRecord = z.object({
  id: Uuid,
  conversationId: Uuid,
  tool: z.string(),
  tier: AiToolTier,
  arguments: z.record(z.unknown()),
  status: AiActionStatus,
  result: z.unknown().nullable(),
  requestedBy: z.string(),
  approvedBy: z.string().nullable(),
  at: IsoDateTime,
});
export type AiActionRecord = z.infer<typeof AiActionRecord>;
