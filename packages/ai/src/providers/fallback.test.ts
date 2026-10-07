import { describe, expect, it, vi } from "vitest";
import { AiAbortError, AiConfigError, AiNotFoundError } from "../errors.js";
import { fakeFetch, sseChunks } from "../test-support/fake-fetch.js";
import { FixedClock, ORG_A1, ORG_A2, TENANT_A, TENANT_B, noSleep, providerConfig, sequentialIds } from "../test-support/fixtures.js";
import { createProvider } from "./factory.js";
import { FallbackProvider } from "./fallback.js";
import { DefaultAiProviderRegistry, buildFallbackChain, selectProviderConfig } from "./registry.js";

const runtime = { sleep: noSleep, clock: new FixedClock(), ids: sequentialIds(), maxRetries: 1 };
const ok = (content: string) => ({ json: { choices: [{ finish_reason: "stop", message: { content } }], usage: { prompt_tokens: 1, completion_tokens: 1 } } });

describe("FallbackProvider", () => {
  it("falls back after the primary exhausts retries and records attempts", async () => {
    const primaryFetch = fakeFetch([{ status: 503, text: "down" }]);
    const primary = createProvider(providerConfig({ kind: "openai", name: "primary" }), "k", primaryFetch.fetch, runtime);
    const ollamaFetch = fakeFetch([{ json: { model: "llama3", message: { role: "assistant", content: "from fallback" }, done: true, prompt_eval_count: 1, eval_count: 1 } }]);
    const local = createProvider(providerConfig({ kind: "ollama", endpoint: "http://10.0.0.9:11434", credentialRef: null }), null, ollamaFetch.fetch, { ...runtime, allowPrivateEndpoints: true });
    const onFallback = vi.fn();
    const chain = new FallbackProvider([primary, local], onFallback);
    const res = await chain.chat({ messages: [{ role: "user", content: "hi" }] });
    expect(res.message.content).toBe("from fallback");
    expect(res.fallbackUsed).toBe(true);
    expect(res.servedBy.kind).toBe("ollama");
    expect(res.attempts).toMatchObject([{ kind: "openai", ok: false, error: { code: "upstream_error" } }, { kind: "ollama", ok: true }]);
    expect(primaryFetch.requests).toHaveLength(2); // initial + 1 retry
    expect(onFallback).toHaveBeenCalledWith(expect.objectContaining({ error: expect.objectContaining({ code: "upstream_error" }) }));
  });

  it("falls back when the primary refuses tenant data by policy", async () => {
    const cloud = createProvider(providerConfig({ kind: "anthropic", allowCloudData: false }), "k", fakeFetch([]).fetch, runtime);
    const local = createProvider(providerConfig({ kind: "openai_compatible", endpoint: "https://llm.corp.example/v1", credentialRef: null }), null, fakeFetch([ok("local answer")]).fetch, runtime);
    const res = await new FallbackProvider([cloud, local]).chat({ messages: [{ role: "user", content: "x" }] });
    expect(res.message.content).toBe("local answer");
    expect(res.attempts![0]!.error!.code).toBe("cloud_data_forbidden");
  });

  it("never falls back on caller abort or after streaming started", async () => {
    const hang = createProvider(providerConfig(), "k", fakeFetch([{ hang: true }]).fetch, runtime);
    const backup = vi.fn();
    const spy = { kind: "openai" as const, id: "b", model: "m", chat: backup, listModels: vi.fn(), healthCheck: vi.fn() };
    const ctrl = new AbortController();
    const p = new FallbackProvider([hang, spy]).chat({ messages: [{ role: "user", content: "x" }], signal: ctrl.signal });
    ctrl.abort();
    await expect(p).rejects.toBeInstanceOf(AiAbortError);
    expect(backup).not.toHaveBeenCalled();

    const broken = createProvider(providerConfig(), "k", fakeFetch([{ chunks: [...sseChunks([{ choices: [{ index: 0, delta: { content: "partial" } }] }]), "data: {\"error\":{\"message\":\"boom\"}}\n\n"] }]).fetch, runtime);
    await expect(new FallbackProvider([broken, spy]).chat({ messages: [{ role: "user", content: "x" }], onDelta: () => undefined })).rejects.toMatchObject({ code: "upstream_error" });
    expect(backup).not.toHaveBeenCalled();
  });

  it("raises all_providers_failed when every provider fails", async () => {
    const a = createProvider(providerConfig(), "k", fakeFetch([{ status: 500 }]).fetch, runtime);
    const b = createProvider(providerConfig(), "k", fakeFetch([{ status: 401 }]).fetch, runtime);
    await expect(new FallbackProvider([a, b]).chat({ messages: [{ role: "user", content: "x" }] })).rejects.toMatchObject({ code: "all_providers_failed" });
  });
});

describe("Provider registry", () => {
  const tenantDefault = providerConfig({ name: "b-tenant-default", isDefault: true });
  const orgDefault = providerConfig({ name: "a-org-default", organizationId: ORG_A1, isDefault: true });
  const otherOrg = providerConfig({ name: "other-org", organizationId: ORG_A2, isDefault: true });
  const disabled = providerConfig({ name: "disabled", enabled: false });
  const foreign = providerConfig({ name: "foreign", tenantId: TENANT_B, isDefault: true });

  it("selects org default, then tenant default, and enforces scope for explicit ids", () => {
    const all = [tenantDefault, orgDefault, otherOrg, disabled, foreign];
    expect(selectProviderConfig(all, { tenantId: TENANT_A, organizationId: ORG_A1 }).id).toBe(orgDefault.id);
    expect(selectProviderConfig([tenantDefault, otherOrg], { tenantId: TENANT_A, organizationId: ORG_A1 }).id).toBe(tenantDefault.id);
    expect(() => selectProviderConfig(all, { tenantId: TENANT_A, organizationId: ORG_A1 }, otherOrg.id)).toThrow(AiNotFoundError);
    expect(() => selectProviderConfig(all, { tenantId: TENANT_A, organizationId: ORG_A1 }, disabled.id)).toThrow(AiNotFoundError);
    expect(() => selectProviderConfig(all, { tenantId: TENANT_A, organizationId: ORG_A1 }, foreign.id)).toThrow(AiNotFoundError);
    expect(() => selectProviderConfig([], { tenantId: TENANT_A, organizationId: ORG_A1 })).toThrow(AiConfigError);
  });

  it("builds cycle-safe fallback chains", () => {
    const a = providerConfig({ name: "a" });
    const b = providerConfig({ name: "b", fallbackProviderId: a.id });
    a.fallbackProviderId = b.id;
    expect(buildFallbackChain(a, [a, b], { tenantId: TENANT_A, organizationId: ORG_A1 }).map((c) => c.name)).toEqual(["a", "b"]);
  });

  it("resolves a governed provider chain with secrets, skipping unusable fallbacks", async () => {
    const local = providerConfig({ name: "local", kind: "ollama", endpoint: "http://localhost:11434", credentialRef: null, maxToolTier: "read" });
    const brokenCloud = providerConfig({ name: "cloud-no-key", kind: "anthropic", credentialRef: "missing", fallbackProviderId: local.id });
    const primary = providerConfig({ name: "primary", kind: "openai", isDefault: true, maxToolTier: "require_approval", fallbackProviderId: brokenCloud.id });
    const secrets = { resolve: vi.fn(async (_t: string, ref: string) => (ref === "secret://test" ? "sk-live" : null)) };
    const { fetch, requests } = fakeFetch([ok("hello")]);
    const registry = new DefaultAiProviderRegistry({
      configs: { listProviders: async (t) => [primary, brokenCloud, local, foreign].filter((c) => c.tenantId === t) },
      secrets,
      fetch,
      settings: { get: async () => ({ allowPrivateEndpoints: true }) },
      hostResolver: async () => ["104.18.0.1"],
      runtime,
    });
    const resolved = await registry.resolve({ tenantId: TENANT_A, organizationId: ORG_A1 });
    expect(resolved.config.id).toBe(primary.id);
    expect(resolved.chain.map((c) => c.name)).toEqual(["primary", "local"]);
    expect(resolved.skipped).toEqual([expect.objectContaining({ providerId: brokenCloud.id, code: "credential_required" })]);
    expect(resolved.effectiveMaxToolTier).toBe("read");
    await resolved.provider.chat({ messages: [{ role: "user", content: "x" }] });
    expect(requests[0]!.headers.authorization).toBe("Bearer sk-live");
  });

  it("rejects endpoints whose DNS points at internal ranges", async () => {
    const evil = providerConfig({ kind: "openai_compatible", endpoint: "https://llm.attacker.example/v1", credentialRef: null, isDefault: true });
    const registry = new DefaultAiProviderRegistry({
      configs: { listProviders: async () => [evil] },
      secrets: { resolve: async () => null },
      fetch: fakeFetch([]).fetch,
      hostResolver: async () => ["169.254.169.254"],
      runtime,
    });
    await expect(registry.resolve({ tenantId: TENANT_A, organizationId: ORG_A1 })).rejects.toMatchObject({ code: "ssrf_blocked", reason: "metadata_endpoint" });
  });
});
