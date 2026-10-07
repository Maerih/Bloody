import type { AiProviderRegistry } from "../providers/registry.js";

/** The orchestrator depends only on provider resolution (DefaultAiProviderRegistry or a custom one). */
export type ProviderRegistryLike = AiProviderRegistry;
