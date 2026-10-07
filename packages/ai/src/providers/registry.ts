import { AI_TIER_RANK, type AiProviderConfig, type AiToolTier } from "@bloody/contracts";
import { AiConfigError, AiNotFoundError } from "../errors.js";
import { classifyEgress } from "../safety/egress.js";
import { assertSafeEndpointResolved, systemHostResolver, type HostResolver } from "../safety/ssrf.js";
import { createProvider, resolveEndpoint, type ProviderRuntimeOptions } from "./factory.js";
import { FallbackProvider, type FallbackEvent } from "./fallback.js";
import type { AiProvider, FetchLike } from "./types.js";

/** Where provider configurations live (Postgres `ai_providers` in the API). */
export interface AiProviderConfigSource {
  listProviders(tenantId: string): Promise<AiProviderConfig[]>;
}

/** Resolves `credentialRef` to the decrypted secret (AES-GCM secret store in the API). */
export interface AiSecretResolver {
  resolve(tenantId: string, credentialRef: string): Promise<string | null>;
}

export interface AiTenantSettings {
  /** Allow loopback / private-network AI endpoints (self-hosted deployments only). */
  allowPrivateEndpoints: boolean;
}

export interface AiTenantSettingsSource {
  get(tenantId: string): Promise<AiTenantSettings>;
}

export interface ProviderScope {
  tenantId: string;
  organizationId: string | null;
}

export interface ResolvedProvider {
  /** The selected (primary) configuration. */
  config: AiProviderConfig;
  /** Configurations actually wired into the provider, primary first. */
  chain: AiProviderConfig[];
  provider: AiProvider;
  /** Lowest maxToolTier across the chain — whichever model answers, tools stay within it. */
  effectiveMaxToolTier: AiToolTier;
  /** Configurations skipped because they could not be constructed (SSRF, missing credential…). */
  skipped: Array<{ providerId: string; code: string; message: string }>;
}

export interface AiProviderRegistry {
  resolve(scope: ProviderScope, providerId?: string | null): Promise<ResolvedProvider>;
}

function inScope(c: AiProviderConfig, scope: ProviderScope): boolean {
  return c.tenantId === scope.tenantId && c.enabled && (c.organizationId === null || c.organizationId === scope.organizationId);
}

/**
 * Pick the provider for a request: an explicit id (must be enabled and visible to the org),
 * else the org's default, else the tenant-wide default, else the first enabled org/tenant provider.
 */
export function selectProviderConfig(configs: readonly AiProviderConfig[], scope: ProviderScope, providerId?: string | null): AiProviderConfig {
  const visible = configs.filter((c) => inScope(c, scope));
  if (providerId) {
    const found = visible.find((c) => c.id === providerId);
    if (!found) throw new AiNotFoundError("provider_not_found", "AI provider not found, disabled, or not available to this organization");
    return found;
  }
  const byName = (a: AiProviderConfig, b: AiProviderConfig): number => a.name.localeCompare(b.name);
  const orgOwned = visible.filter((c) => c.organizationId !== null).sort(byName);
  const tenantWide = visible.filter((c) => c.organizationId === null).sort(byName);
  const pick = orgOwned.find((c) => c.isDefault) ?? tenantWide.find((c) => c.isDefault) ?? orgOwned[0] ?? tenantWide[0];
  if (!pick) throw new AiConfigError("no_provider_configured", "No enabled AI provider is configured for this organization");
  return pick;
}

/** Follow fallbackProviderId links (cycle-safe, scope-checked, bounded depth). */
export function buildFallbackChain(primary: AiProviderConfig, configs: readonly AiProviderConfig[], scope: ProviderScope, maxLength = 3): AiProviderConfig[] {
  const chain = [primary];
  const seen = new Set([primary.id]);
  let cur = primary;
  while (cur.fallbackProviderId && chain.length < maxLength) {
    const next = configs.find((c) => c.id === cur.fallbackProviderId);
    if (!next || seen.has(next.id) || !inScope(next, scope)) break;
    chain.push(next);
    seen.add(next.id);
    cur = next;
  }
  return chain;
}

export function minTier(tiers: readonly AiToolTier[]): AiToolTier {
  return tiers.reduce<AiToolTier>((min, t) => (AI_TIER_RANK[t] < AI_TIER_RANK[min] ? t : min), tiers[0] ?? "read");
}

export interface DefaultAiProviderRegistryDeps {
  configs: AiProviderConfigSource;
  secrets: AiSecretResolver;
  fetch: FetchLike;
  settings?: AiTenantSettingsSource;
  runtime?: Omit<ProviderRuntimeOptions, "allowPrivateEndpoints">;
  /** DNS validation of endpoints (default: system resolver). `false` disables (tests only). */
  hostResolver?: HostResolver | false;
  onFallback?: (scope: ProviderScope, event: FallbackEvent) => void;
}

export class DefaultAiProviderRegistry implements AiProviderRegistry {
  constructor(private readonly deps: DefaultAiProviderRegistryDeps) {}

  async resolve(scope: ProviderScope, providerId?: string | null): Promise<ResolvedProvider> {
    const all = (await this.deps.configs.listProviders(scope.tenantId)).filter((c) => c.tenantId === scope.tenantId);
    const primary = selectProviderConfig(all, scope, providerId);
    const candidates = buildFallbackChain(primary, all, scope);
    const settings = (await this.deps.settings?.get(scope.tenantId)) ?? { allowPrivateEndpoints: false };
    const resolver = this.deps.hostResolver === undefined ? systemHostResolver : this.deps.hostResolver;

    const providers: AiProvider[] = [];
    const used: AiProviderConfig[] = [];
    const skipped: ResolvedProvider["skipped"] = [];
    let firstError: unknown;
    for (const cfg of candidates) {
      try {
        const endpoint = resolveEndpoint(cfg);
        if (endpoint && resolver) {
          await assertSafeEndpointResolved(endpoint, { allowPrivate: settings.allowPrivateEndpoints, requireHttps: classifyEgress(cfg.kind, endpoint) === "cloud" }, resolver);
        }
        const secret = cfg.credentialRef ? await this.deps.secrets.resolve(scope.tenantId, cfg.credentialRef) : null;
        providers.push(createProvider(cfg, secret, this.deps.fetch, { ...this.deps.runtime, allowPrivateEndpoints: settings.allowPrivateEndpoints }));
        used.push(cfg);
      } catch (err) {
        firstError ??= err;
        skipped.push({ providerId: cfg.id, code: (err as { code?: string }).code ?? "internal_error", message: err instanceof Error ? err.message : String(err) });
      }
    }
    if (providers.length === 0) throw firstError;
    const provider = providers.length === 1 ? providers[0]! : new FallbackProvider(providers, (e) => this.deps.onFallback?.(scope, e));
    return { config: primary, chain: used, provider, effectiveMaxToolTier: minTier(used.map((c) => c.maxToolTier)), skipped };
  }
}
