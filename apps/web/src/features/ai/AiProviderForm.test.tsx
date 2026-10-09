import type { AiProviderConfig } from "@bloody/contracts";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { changeKind, draftFromProvider, effectiveProvider, newProviderDraft, validateAiProviderDraft } from "../../lib/aiProviders";
import { ORG_A, TENANT_ID } from "../../test/fixtures";
import { mockApi, renderWithSession } from "../../test/utils";
import { AiProviderForm } from "./AiProviderForm";

const NOW = "2026-10-01T00:00:00.000Z";

function provider(overrides: Partial<AiProviderConfig> = {}): AiProviderConfig {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    tenantId: TENANT_ID,
    organizationId: null,
    name: "OpenAI",
    kind: "openai",
    endpoint: "https://api.openai.com/v1",
    model: "gpt-4o",
    credentialRef: "secret://ai/openai",
    hasCredential: true,
    contextWindow: 128_000,
    temperature: 0.2,
    maxOutputTokens: 4096,
    systemPolicy: null,
    maxToolTier: "recommend",
    isDefault: true,
    fallbackProviderId: null,
    retentionDays: 30,
    redactSensitive: true,
    allowCloudData: false,
    enabled: true,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

describe("AI provider validation", () => {
  it("prefills local defaults (Ollama at http://localhost:11434) and swaps them on kind change", () => {
    const d = newProviderDraft("ollama");
    expect(d.endpoint).toBe("http://localhost:11434");
    expect(d.name).toBe("Ollama");
    const lm = changeKind(d, "lmstudio");
    expect(lm.endpoint).toBe("http://localhost:1234/v1");
    expect(lm.name).toBe("LM Studio");
    // A user-edited endpoint survives a kind change.
    const custom = changeKind({ ...d, endpoint: "http://gpu01:11434" }, "vllm");
    expect(custom.endpoint).toBe("http://gpu01:11434");
    // Local providers never send tenant data to a cloud.
    expect(changeKind({ ...newProviderDraft("openai"), allowCloudData: true }, "ollama").allowCloudData).toBe(false);
  });

  it("requires a model and a valid endpoint", () => {
    const r = validateAiProviderDraft({ ...newProviderDraft("ollama"), endpoint: "localhost:11434" }, { isNew: true, hasStoredCredential: false });
    expect(r.input).toBeNull();
    expect(r.errors.model).toBe("Model is required");
    expect(r.errors.endpoint).toBe("Enter a valid http(s) URL");
  });

  it("rejects plain http and embedded credentials for cloud providers", () => {
    const base = { ...newProviderDraft("azure_openai"), model: "gpt-4o", apiKey: "k" };
    expect(validateAiProviderDraft({ ...base, endpoint: "http://contoso.openai.azure.com" }, { isNew: true, hasStoredCredential: false }).errors.endpoint).toBe("Cloud providers must use https");
    expect(validateAiProviderDraft({ ...base, endpoint: "https://user:pw@contoso.openai.azure.com" }, { isNew: true, hasStoredCredential: false }).errors.endpoint).toMatch(/Do not embed credentials/);
    expect(validateAiProviderDraft({ ...base, endpoint: "" }, { isNew: true, hasStoredCredential: false }).errors.endpoint).toBe("Azure OpenAI needs an endpoint URL");
  });

  it("requires a key for cloud providers unless one is already stored", () => {
    const d = { ...newProviderDraft("anthropic"), model: "claude-sonnet-4-5" };
    expect(validateAiProviderDraft(d, { isNew: true, hasStoredCredential: false }).errors.apiKey).toBe("API key is required for Anthropic");
    expect(validateAiProviderDraft(d, { isNew: false, hasStoredCredential: true }).errors.apiKey).toBeUndefined();
    expect(validateAiProviderDraft({ ...newProviderDraft("aws_bedrock"), model: "m", apiKey: "only-one-part" }, { isNew: true, hasStoredCredential: false }).errors.apiKey).toBe("Use the form accessKeyId:secretAccessKey");
  });

  it("validates numeric limits against the contract ranges", () => {
    const d = { ...newProviderDraft("ollama"), model: "llama3.1:8b" };
    const r = validateAiProviderDraft({ ...d, contextWindow: "256", temperature: "2.5", maxOutputTokens: "9", retentionDays: "-1" }, { isNew: true, hasStoredCredential: false });
    expect(r.errors.contextWindow).toMatch(/between 512 and 2,000,000/);
    expect(r.errors.temperature).toBe("Temperature must be between 0 and 2");
    expect(r.errors.maxOutputTokens).toMatch(/between 16 and 200,000/);
    expect(r.errors.retentionDays).toMatch(/between 0 and 3,650/);
    expect(validateAiProviderDraft({ ...d, contextWindow: "4096", maxOutputTokens: "8192" }, { isNew: true, hasStoredCredential: false }).errors.maxOutputTokens).toBe("Max output must be smaller than the context size");
  });

  it("forbids a provider falling back to itself and warns about risky settings", () => {
    const p = provider();
    const draft = { ...draftFromProvider(p), fallbackProviderId: p.id, maxToolTier: "execute" as const, allowCloudData: true, redactSensitive: false };
    const r = validateAiProviderDraft(draft, { isNew: false, hasStoredCredential: true, providerId: p.id });
    expect(r.errors.fallbackProviderId).toBe("A provider cannot fall back to itself");
    expect(r.warnings.some((w) => w.includes("without redaction"))).toBe(true);
    expect(r.warnings.some((w) => w.startsWith("EXECUTE"))).toBe(true);
  });

  it("builds the UpsertAiProviderInput body (trailing slash trimmed, key omitted when blank)", () => {
    const r = validateAiProviderDraft({ ...newProviderDraft("vllm", ORG_A), endpoint: "http://gpu01:8000/v1/", model: "meta-llama/Llama-3.1-8B-Instruct" }, { isNew: true, hasStoredCredential: false });
    expect(r.errors).toEqual({});
    expect(r.input).toMatchObject({ kind: "vllm", organizationId: ORG_A, endpoint: "http://gpu01:8000/v1", contextWindow: 32768, temperature: 0.2, maxToolTier: "recommend", allowCloudData: false });
    expect(r.input).not.toHaveProperty("apiKey");
  });

  it("resolves the effective provider: organization default, else tenant default", () => {
    const tenant = provider({ id: "a0000000-0000-4000-8000-000000000001", isDefault: true });
    const org = provider({ id: "a0000000-0000-4000-8000-000000000002", organizationId: ORG_A, kind: "ollama", isDefault: true });
    expect(effectiveProvider([tenant, org], ORG_A)?.id).toBe(org.id);
    expect(effectiveProvider([tenant, org], null)?.id).toBe(tenant.id);
    expect(effectiveProvider([tenant, { ...org, enabled: false }], ORG_A)?.id).toBe(tenant.id);
  });
});

describe("AiProviderForm", () => {
  it("shows field errors instead of submitting an invalid cloud provider", async () => {
    const { calls } = mockApi({});
    renderWithSession(<AiProviderForm provider={null} providers={[]} initialKind="openai" onSaved={vi.fn()} onCancel={vi.fn()} />);
    const form = screen.getByTestId("ai-provider-form");
    fireEvent.click(within(form).getByRole("button", { name: "Add provider" }));
    expect(await within(form).findByText("Model is required")).toBeInTheDocument();
    expect(within(form).getByText("API key is required for OpenAI")).toBeInTheDocument();
    expect(within(form).getByRole("alert")).toHaveTextContent("Fix the highlighted fields before saving.");
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(0);
  });

  it("creates a local Ollama provider with the prefilled endpoint", async () => {
    const saved = provider({ id: "22222222-2222-4222-8222-222222222222", name: "Ollama", kind: "ollama", endpoint: "http://localhost:11434", model: "llama3.1:8b", hasCredential: false, credentialRef: null });
    const { calls } = mockApi({ "POST /ai/providers": saved });
    const onSaved = vi.fn();
    renderWithSession(<AiProviderForm provider={null} providers={[]} initialKind="ollama" onSaved={onSaved} onCancel={vi.fn()} />);
    const form = screen.getByTestId("ai-provider-form");
    expect(within(form).getByLabelText(/^Endpoint/)).toHaveValue("http://localhost:11434");
    fireEvent.change(within(form).getByLabelText(/^Model/), { target: { value: "llama3.1:8b" } });
    fireEvent.click(within(form).getByRole("button", { name: "Add provider" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith(saved));
    const body = calls.find((c) => c.method === "POST" && c.path === "/ai/providers")!.body as Record<string, unknown>;
    expect(body).toMatchObject({ name: "Ollama", kind: "ollama", endpoint: "http://localhost:11434", model: "llama3.1:8b", maxToolTier: "recommend", redactSensitive: true, enabled: true });
    expect(body).not.toHaveProperty("apiKey");
  });

  it("keeps a stored API key write-only: shows ••• stored and never re-sends it", async () => {
    const existing = provider();
    const { calls } = mockApi({ [`PATCH /ai/providers/${existing.id}`]: ({ body }: { body: unknown }) => ({ ...existing, ...(body as object) }) });
    renderWithSession(<AiProviderForm provider={existing} providers={[existing]} onSaved={vi.fn()} onCancel={vi.fn()} />);
    const form = screen.getByTestId("ai-provider-form");
    expect(within(form).getByDisplayValue("••• stored")).toBeDisabled();
    fireEvent.change(within(form).getByLabelText(/^Temperature/), { target: { value: "0.1" } });
    fireEvent.click(within(form).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    const body = calls.find((c) => c.method === "PATCH")!.body as Record<string, unknown>;
    expect(body.temperature).toBe(0.1);
    expect(body).not.toHaveProperty("apiKey");
  });
});
