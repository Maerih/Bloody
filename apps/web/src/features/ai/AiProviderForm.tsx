import type { AiProviderConfig, AiProviderKind, AiToolTier } from "@bloody/contracts";
import { KeyRound, PlugZap, TriangleAlert } from "lucide-react";
import { useState } from "react";
import { errorMessage } from "../../api/client";
import { useSaveAiProvider, useTestAiProvider } from "../../api/hooks";
import type { AiProviderTestResult } from "../../api/types";
import { useSession } from "../../app/session";
import { Button } from "../../components/Button";
import { Checkbox, Field, Input, Select, Textarea } from "../../components/Form";
import { OrganizationSelect } from "../../components/OrganizationSelect";
import { TierBadge } from "../../components/TierBadge";
import {
  AI_PROVIDER_META,
  CLOUD_KINDS,
  LOCAL_KINDS,
  TOOL_TIERS,
  TOOL_TIER_META,
  changeKind,
  draftFromProvider,
  newProviderDraft,
  validateAiProviderDraft,
  type AiProviderDraft,
} from "../../lib/aiProviders";

export function ProviderTestResult({ result }: { result: AiProviderTestResult }) {
  return (
    <div role="status" className={result.ok ? "text-sm text-healthy" : "text-sm text-sev-critical"} data-testid="provider-test-result">
      {result.ok ? "Connection OK" : "Connection failed"}
      {result.latencyMs !== null ? ` · ${result.latencyMs} ms` : ""}
      {result.message ? ` · ${result.message}` : ""}
      {result.models.length > 0 ? <span className="block text-xs text-fg-muted">Models available: {result.models.slice(0, 8).join(", ")}{result.models.length > 8 ? "…" : ""}</span> : null}
    </div>
  );
}

/**
 * Create / edit an AI provider (local: Ollama, vLLM, LM Studio, OpenAI-compatible; cloud:
 * OpenAI, Anthropic, Google, Azure OpenAI, Bedrock, Mistral). The API key is write-only — an
 * existing key shows as "••• stored" and is only replaced when a new one is typed.
 */
export function AiProviderForm({
  provider,
  providers,
  initialKind = "ollama",
  organizationId = null,
  onSaved,
  onCancel,
}: {
  provider: AiProviderConfig | null;
  providers: AiProviderConfig[];
  initialKind?: AiProviderKind;
  organizationId?: string | null;
  onSaved: (p: AiProviderConfig) => void;
  onCancel: () => void;
}) {
  const session = useSession();
  const save = useSaveAiProvider();
  const test = useTestAiProvider();
  const [draft, setDraft] = useState<AiProviderDraft>(() => (provider ? draftFromProvider(provider) : newProviderDraft(initialKind, organizationId)));
  const [replaceKey, setReplaceKey] = useState(!provider?.hasCredential);
  const [submitted, setSubmitted] = useState(false);
  const [saved, setSaved] = useState<AiProviderConfig | null>(provider);
  const meta = AI_PROVIDER_META[draft.kind];
  const result = validateAiProviderDraft(replaceKey ? draft : { ...draft, apiKey: "" }, { isNew: !saved, hasStoredCredential: Boolean(saved?.hasCredential) && !replaceKey, ...(saved ? { providerId: saved.id } : {}) });
  const err = (k: keyof AiProviderDraft) => (submitted ? (result.errors[k] ?? null) : null);
  const set = <K extends keyof AiProviderDraft>(k: K, v: AiProviderDraft[K]) => setDraft((d) => ({ ...d, [k]: v }));
  const canConfigure = session.can("ai:configure", draft.organizationId);

  const persist = (then?: (p: AiProviderConfig) => void) => {
    setSubmitted(true);
    if (!result.input || !canConfigure) return;
    save.mutate(
      { ...(saved ? { id: saved.id } : {}), input: result.input },
      {
        onSuccess: (p) => {
          setSaved(p);
          setReplaceKey(false);
          setDraft((d) => ({ ...d, apiKey: "" }));
          if (then) then(p);
          else onSaved(p);
        },
      },
    );
  };

  const fallbacks = providers.filter((p) => p.id !== saved?.id);

  return (
    <form
      className="space-y-3"
      noValidate
      aria-label="AI provider"
      onSubmit={(e) => {
        e.preventDefault();
        persist();
      }}
      data-testid="ai-provider-form"
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <Field label="Provider type" required>
          {(p) => (
            <Select {...p} value={draft.kind} onChange={(e) => setDraft((d) => changeKind(d, e.target.value as AiProviderKind))}>
              <optgroup label="Local / self-hosted">
                {LOCAL_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {AI_PROVIDER_META[k].label}
                  </option>
                ))}
              </optgroup>
              <optgroup label="Cloud">
                {CLOUD_KINDS.map((k) => (
                  <option key={k} value={k}>
                    {AI_PROVIDER_META[k].label}
                  </option>
                ))}
              </optgroup>
            </Select>
          )}
        </Field>
        <Field label="Name" required error={err("name")}>
          {(p) => <Input {...p} value={draft.name} onChange={(e) => set("name", e.target.value)} maxLength={120} />}
        </Field>
        <Field label="Endpoint" required={meta.endpointRequired} error={err("endpoint")} hint={meta.endpointHint ?? (meta.defaultEndpoint ? `Default: ${meta.defaultEndpoint}` : undefined)} className="md:col-span-2">
          {(p) => <Input {...p} value={draft.endpoint} onChange={(e) => set("endpoint", e.target.value)} placeholder={meta.defaultEndpoint ?? "https://"} inputMode="url" />}
        </Field>
        <Field label="Model" required error={err("model")}>
          {(p) => <Input {...p} value={draft.model} onChange={(e) => set("model", e.target.value)} placeholder={meta.modelPlaceholder} />}
        </Field>
        <Field label={meta.credentialLabel} required={meta.credential === "required" && !(saved?.hasCredential && !replaceKey)} error={err("apiKey")} hint={meta.credential === "none" ? "Not needed for this provider." : "Write-only: stored encrypted in the secret store and never shown again."}>
          {(p) =>
            saved?.hasCredential && !replaceKey ? (
              <div className="flex items-center gap-2">
                <Input {...p} value="••• stored" readOnly disabled aria-label={`${meta.credentialLabel} (stored)`} />
                <Button size="sm" icon={KeyRound} onClick={() => setReplaceKey(true)}>
                  Replace
                </Button>
              </div>
            ) : (
              <Input {...p} type="password" autoComplete="new-password" value={draft.apiKey} onChange={(e) => set("apiKey", e.target.value)} disabled={meta.credential === "none"} />
            )
          }
        </Field>
        <Field label="Context size (tokens)" required error={err("contextWindow")}>
          {(p) => <Input {...p} value={draft.contextWindow} onChange={(e) => set("contextWindow", e.target.value)} inputMode="numeric" />}
        </Field>
        <Field label="Max output (tokens)" required error={err("maxOutputTokens")}>
          {(p) => <Input {...p} value={draft.maxOutputTokens} onChange={(e) => set("maxOutputTokens", e.target.value)} inputMode="numeric" />}
        </Field>
        <Field label="Temperature" required error={err("temperature")} hint="0 = deterministic, 2 = most creative. SOC work favours ≤ 0.3.">
          {(p) => <Input {...p} value={draft.temperature} onChange={(e) => set("temperature", e.target.value)} inputMode="decimal" />}
        </Field>
        <Field label="Retention (days)" required error={err("retentionDays")} hint="Prompt/response retention. 0 = do not retain.">
          {(p) => <Input {...p} value={draft.retentionDays} onChange={(e) => set("retentionDays", e.target.value)} inputMode="numeric" />}
        </Field>
        <Field label="Max tool tier" hint={TOOL_TIER_META[draft.maxToolTier].description}>
          {(p) => (
            <div className="flex items-center gap-2">
              <Select {...p} value={draft.maxToolTier} onChange={(e) => set("maxToolTier", e.target.value as AiToolTier)}>
                {TOOL_TIERS.map((t) => (
                  <option key={t} value={t}>
                    {TOOL_TIER_META[t].label}
                  </option>
                ))}
              </Select>
              <TierBadge tier={draft.maxToolTier} />
            </div>
          )}
        </Field>
        <Field label="Scope" hint="Tenant default applies to every organization; an organization provider overrides it.">
          {(p) => <OrganizationSelect {...p} value={draft.organizationId} onChange={(v) => set("organizationId", v)} permission="ai:configure" allowTenantWide tenantWideLabel="Tenant default (all organizations)" />}
        </Field>
        <Field label="Fallback provider" error={err("fallbackProviderId")} hint="Used when this provider is unavailable.">
          {(p) => (
            <Select {...p} value={draft.fallbackProviderId ?? ""} onChange={(e) => set("fallbackProviderId", e.target.value || null)}>
              <option value="">No fallback</option>
              {fallbacks.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.name} · {f.model}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="System policy" error={err("systemPolicy")} hint="Appended to Bloody's built-in safety policy (it cannot weaken it)." className="md:col-span-2">
          {(p) => <Textarea {...p} value={draft.systemPolicy} onChange={(e) => set("systemPolicy", e.target.value)} maxLength={20_000} placeholder="Answer in English. Prefer containment that keeps business-critical services running." />}
        </Field>
      </div>
      <fieldset className="grid grid-cols-1 gap-2 rounded border border-line p-3 sm:grid-cols-2">
        <legend className="px-1 text-xs font-semibold uppercase tracking-wide text-fg-muted">Privacy & routing</legend>
        <Checkbox label="Redact secrets and PII before sending context" checked={draft.redactSensitive} onChange={(e) => set("redactSensitive", e.target.checked)} />
        <Checkbox label="Allow tenant data to be sent to this cloud provider" checked={draft.allowCloudData} disabled={meta.deployment === "local"} onChange={(e) => set("allowCloudData", e.target.checked)} />
        <Checkbox label="Default model for this scope" checked={draft.isDefault} onChange={(e) => set("isDefault", e.target.checked)} />
        <Checkbox label="Enabled" checked={draft.enabled} onChange={(e) => set("enabled", e.target.checked)} />
      </fieldset>
      {result.warnings.length > 0 ? (
        <ul className="space-y-1" aria-label="Warnings">
          {result.warnings.map((w) => (
            <li key={w} className="flex items-start gap-1.5 text-xs text-sev-high">
              <TriangleAlert size={12} className="mt-0.5 shrink-0" aria-hidden /> {w}
            </li>
          ))}
        </ul>
      ) : null}
      {submitted && !result.input ? (
        <p role="alert" className="text-sm text-sev-critical">
          Fix the highlighted fields before saving.
        </p>
      ) : null}
      {save.isError ? (
        <p role="alert" className="text-sm text-sev-critical">
          {errorMessage(save.error)}
        </p>
      ) : null}
      {test.isError ? (
        <p role="alert" className="text-sm text-sev-critical">
          {errorMessage(test.error)}
        </p>
      ) : test.data ? (
        <ProviderTestResult result={test.data} />
      ) : null}
      {!canConfigure ? <p className="text-sm text-fg-muted">You need the ai:configure permission for this scope.</p> : null}
      <div className="flex flex-wrap items-center justify-end gap-2 border-t border-line pt-3">
        <Button onClick={onCancel}>Cancel</Button>
        <Button icon={PlugZap} loading={test.isPending || (save.isPending && !saved)} disabled={!canConfigure} onClick={() => (saved && !replaceKey && JSON.stringify(draftFromProvider(saved)) === JSON.stringify({ ...draft, apiKey: "" }) ? test.mutate(saved.id) : persist((p) => test.mutate(p.id)))}>
          {saved ? "Test connection" : "Save & test connection"}
        </Button>
        <Button type="submit" variant="primary" loading={save.isPending} disabled={!canConfigure}>
          {saved ? "Save" : "Add provider"}
        </Button>
      </div>
    </form>
  );
}
