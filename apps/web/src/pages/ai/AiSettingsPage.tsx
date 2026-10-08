import type { AiProviderConfig, AiProviderKind } from "@bloody/contracts";
import { BrainCircuit, Cloud, HardDrive, Pencil, PlugZap, Plus, ShieldCheck, Star, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useAiProviders, useDeleteAiProvider, useTestAiProvider } from "../../api/hooks";
import { ORG_PARAM, useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { DescriptionList } from "../../components/DescriptionList";
import { EmptyState } from "../../components/EmptyState";
import { ErrorState } from "../../components/ErrorState";
import { Select } from "../../components/Form";
import { Dialog } from "../../components/Overlay";
import { PageHeader } from "../../components/PageHeader";
import { CardSkeleton } from "../../components/Skeleton";
import { Tabs } from "../../components/Tabs";
import { TierBadge } from "../../components/TierBadge";
import { AiProviderForm, ProviderTestResult } from "../../features/ai/AiProviderForm";
import { AI_PROVIDER_META, LOCAL_KINDS, TOOL_TIERS, TOOL_TIER_META, effectiveProvider } from "../../lib/aiProviders";
import { formatInteger } from "../../lib/format";

function ProviderCard({ provider, providers, onEdit }: { provider: AiProviderConfig; providers: AiProviderConfig[]; onEdit: () => void }) {
  const session = useSession();
  const test = useTestAiProvider();
  const del = useDeleteAiProvider();
  const [confirm, setConfirm] = useState(false);
  const meta = AI_PROVIDER_META[provider.kind];
  const fallback = provider.fallbackProviderId ? providers.find((p) => p.id === provider.fallbackProviderId) : null;
  const canConfigure = session.can("ai:configure", provider.organizationId);
  return (
    <article className="rounded border border-line bg-surface p-3 shadow-card" data-testid="ai-provider-card" aria-label={provider.name}>
      <header className="flex flex-wrap items-center gap-2">
        {meta.deployment === "local" ? <HardDrive size={15} className="text-fg-muted" aria-hidden /> : <Cloud size={15} className="text-fg-muted" aria-hidden />}
        <h3 className="min-w-0 flex-1 truncate text-md font-semibold text-fg">{provider.name}</h3>
        {provider.isDefault ? (
          <Badge size="xs" tone="info" icon={Star}>
            Default
          </Badge>
        ) : null}
        {provider.enabled ? <Badge size="xs" tone="success">Enabled</Badge> : <Badge size="xs">Disabled</Badge>}
        <TierBadge tier={provider.maxToolTier} />
      </header>
      <DescriptionList
        className="mt-2"
        items={[
          { label: "Type", value: meta.label },
          { label: "Model", value: <span className="font-mono text-sm">{provider.model}</span> },
          { label: "Endpoint", value: provider.endpoint ? <span className="break-all font-mono text-xs">{provider.endpoint}</span> : (meta.defaultEndpoint ?? "Vendor default") },
          { label: "API key", value: provider.hasCredential ? "••• stored" : meta.credential === "none" ? "Not required" : "Not set" },
          { label: "Context / output", value: `${formatInteger(provider.contextWindow)} / ${formatInteger(provider.maxOutputTokens)} tokens` },
          { label: "Temperature", value: provider.temperature.toFixed(2) },
          { label: "Retention", value: provider.retentionDays === 0 ? "Not retained" : `${provider.retentionDays} days` },
          { label: "Scope", value: provider.organizationId ? (session.organizationName(provider.organizationId) ?? "Organization override") : "Tenant default" },
          { label: "Privacy", value: [provider.redactSensitive ? "Redacts secrets/PII" : "No redaction", meta.deployment === "cloud" ? (provider.allowCloudData ? "Tenant data allowed" : "No tenant data") : "Data stays local"].join(" · "), wide: true },
          { label: "Fallback", value: fallback ? `${fallback.name} · ${fallback.model}` : null },
        ]}
      />
      {test.data ? <div className="mt-2"><ProviderTestResult result={test.data} /></div> : null}
      {test.isError ? <p className="mt-2 text-sm text-sev-critical">{errorMessage(test.error)}</p> : null}
      {del.isError ? <p className="mt-2 text-sm text-sev-critical">{errorMessage(del.error)}</p> : null}
      <footer className="mt-3 flex flex-wrap gap-2">
        <Button size="sm" icon={PlugZap} loading={test.isPending} onClick={() => test.mutate(provider.id)} disabled={!canConfigure}>
          Test connection
        </Button>
        {canConfigure ? (
          <>
            <Button size="sm" icon={Pencil} onClick={onEdit}>
              Edit
            </Button>
            <Button size="sm" variant="ghost" icon={Trash2} onClick={() => setConfirm(true)}>
              Delete
            </Button>
          </>
        ) : null}
      </footer>
      {confirm ? (
        <Dialog
          open
          onClose={() => setConfirm(false)}
          size="sm"
          title={`Delete ${provider.name}?`}
          description="Conversations that used it keep their history. Providers falling back to it lose their fallback."
          footer={
            <>
              <Button onClick={() => setConfirm(false)}>Cancel</Button>
              <Button variant="danger" loading={del.isPending} onClick={() => del.mutate(provider.id, { onSuccess: () => setConfirm(false) })}>
                Delete provider
              </Button>
            </>
          }
        />
      ) : null}
    </article>
  );
}

type View = "providers" | "policies";

/**
 * AI settings: local and cloud model providers per tenant with per-organization overrides,
 * connection tests, tool-tier ceilings, privacy and retention. API keys are write-only.
 */
export default function AiSettingsPage() {
  const session = useSession();
  const location = useLocation();
  const navigate = useNavigate();
  const providers = useAiProviders({ enabled: session.canAnywhere("ai:configure") || session.canAnywhere("ai:use") });
  const [scope, setScope] = useState<string>(session.organizationId ?? "");
  const [editing, setEditing] = useState<{ provider: AiProviderConfig | null; kind: AiProviderKind } | null>(null);
  const view: View = location.pathname.endsWith("/policies") ? "policies" : "providers";
  const canConfigure = session.canAnywhere("ai:configure");

  const list = providers.data ?? [];
  const inScope = useMemo(() => list.filter((p) => (scope ? p.organizationId === scope || p.organizationId === null : true)), [list, scope]);
  const effective = effectiveProvider(list, scope || null);
  const local = inScope.filter((p) => LOCAL_KINDS.includes(p.kind));
  const cloud = inScope.filter((p) => !LOCAL_KINDS.includes(p.kind));

  const go = (v: View) => {
    const org = new URLSearchParams(location.search).get(ORG_PARAM);
    const base = location.pathname.startsWith("/ai/") ? "/ai" : "/settings/ai";
    navigate({ pathname: v === "policies" ? (base === "/ai" ? "/ai/policies" : "/settings/ai/policies") : base === "/ai" ? "/ai/providers" : "/settings/ai", search: org ? `?${ORG_PARAM}=${encodeURIComponent(org)}` : "" });
  };

  const section = (title: string, icon: typeof Cloud, items: AiProviderConfig[], hint: string, kind: AiProviderKind) => (
    <section aria-label={title}>
      <div className="mb-2 flex items-center gap-2">
        <h2 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted">
          {(() => {
            const I = icon;
            return <I size={13} aria-hidden />;
          })()}
          {title} ({items.length})
        </h2>
        <span className="text-xs text-fg-subtle">{hint}</span>
        {canConfigure ? (
          <Button size="xs" icon={Plus} className="ml-auto" onClick={() => setEditing({ provider: null, kind })}>
            Add {title.toLowerCase().includes("local") ? "local" : "cloud"} provider
          </Button>
        ) : null}
      </div>
      {items.length === 0 ? (
        <div className="rounded border border-dashed border-line-strong bg-surface p-3 text-sm text-fg-muted">None configured for this scope.</div>
      ) : (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2 2xl:grid-cols-3">
          {items.map((p) => (
            <ProviderCard key={p.id} provider={p} providers={list} onEdit={() => setEditing({ provider: p, kind: p.kind })} />
          ))}
        </div>
      )}
    </section>
  );

  return (
    <div>
      <PageHeader
        title="AI Settings"
        subtitle="Choose the models behind the AI SOC analyst — local (Ollama, vLLM, LM Studio, OpenAI-compatible) or cloud — and what they may do."
        breadcrumbs={[{ label: "Settings", href: "/settings" }, { label: "AI" }]}
        actions={
          canConfigure ? (
            <Button variant="primary" icon={Plus} onClick={() => setEditing({ provider: null, kind: "ollama" })}>
              Add provider
            </Button>
          ) : null
        }
      >
        <Tabs<View> ariaLabel="AI settings sections" idPrefix="ai-settings" value={view} onChange={go} tabs={[{ id: "providers", label: "Models & providers", icon: BrainCircuit }, { id: "policies", label: "Policies", icon: ShieldCheck }]} />
      </PageHeader>

      {!session.canAnywhere("ai:configure") && !session.canAnywhere("ai:use") ? (
        <div className="rounded border border-line bg-surface shadow-card">
          <EmptyState title="You don't have access to AI settings" description="Ask an administrator for the ai:configure permission." />
        </div>
      ) : providers.isPending ? (
        <CardSkeleton rows={6} />
      ) : providers.isError ? (
        <div className="rounded border border-line bg-surface shadow-card">
          <ErrorState error={providers.error} onRetry={() => void providers.refetch()} />
        </div>
      ) : view === "policies" ? (
        <div className="space-y-3">
          <Card title="Tool permission tiers" info="Each provider has a ceiling. Tools above it never run on the model's say-so: they become approval requests for a human.">
            <ol className="space-y-2">
              {TOOL_TIERS.map((t, i) => (
                <li key={t} className="flex items-start gap-3">
                  <span className="mt-0.5 w-5 text-right font-mono text-xs text-fg-subtle">{i + 1}</span>
                  <TierBadge tier={t} size="sm" />
                  <span className="text-sm text-fg-muted">{TOOL_TIER_META[t].description}</span>
                  <span className="ml-auto text-xs text-fg-subtle">{list.filter((p) => p.maxToolTier === t).length} provider(s)</span>
                </li>
              ))}
            </ol>
            <p className="mt-3 text-xs text-fg-muted">Dangerous actions (isolate, block, disable identity, revoke) always require RBAC permission, an approval gate and an audit record — even at the EXECUTE tier.</p>
          </Card>
          <Card title="Privacy & retention by provider" count={list.length} padded={false}>
            {list.length === 0 ? (
              <EmptyState compact title="No providers configured" />
            ) : (
              <ul className="divide-y divide-line">
                {list.map((p) => (
                  <li key={p.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
                    <span className="min-w-0 flex-1 truncate font-medium">{p.name}</span>
                    <Badge size="xs" tone={p.redactSensitive ? "success" : "warning"}>{p.redactSensitive ? "Redaction on" : "No redaction"}</Badge>
                    {AI_PROVIDER_META[p.kind].deployment === "cloud" ? <Badge size="xs" tone={p.allowCloudData ? "warning" : "success"}>{p.allowCloudData ? "Tenant data to cloud" : "No tenant data to cloud"}</Badge> : <Badge size="xs">Local</Badge>}
                    <Badge size="xs" tone="outline">{p.retentionDays === 0 ? "Not retained" : `Retained ${p.retentionDays}d`}</Badge>
                    <TierBadge tier={p.maxToolTier} />
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      ) : (
        <div className="space-y-4">
          <Card title="Per-organization override" info="Tenant defaults apply everywhere; an organization's own default provider overrides them for that organization.">
            <div className="flex flex-wrap items-center gap-3">
              <label className="flex items-center gap-2 text-sm text-fg-muted">
                Scope
                <Select value={scope} onChange={(e) => setScope(e.target.value)} className="h-7 w-64" aria-label="Override scope">
                  <option value="">Tenant default (all organizations)</option>
                  {session.organizations.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.name}
                    </option>
                  ))}
                </Select>
              </label>
              <span className="text-sm">
                Effective model:{" "}
                {effective ? (
                  <span className="font-medium text-fg">
                    {effective.name} · <span className="font-mono">{effective.model}</span>
                    {effective.organizationId ? <Badge size="xs" tone="purple" className="ml-1">org override</Badge> : <Badge size="xs" className="ml-1">tenant default</Badge>}
                  </span>
                ) : (
                  <span className="text-sev-high">none — the AI SOC is unavailable for this scope</span>
                )}
              </span>
            </div>
          </Card>
          {list.length === 0 ? (
            <div className="rounded border border-line bg-surface shadow-card">
              <EmptyState icon={BrainCircuit} title="No AI provider configured" description="Start with a local model (Ollama at http://localhost:11434) to keep data on your infrastructure, or add a cloud provider." action={canConfigure ? <Button size="sm" variant="primary" icon={Plus} onClick={() => setEditing({ provider: null, kind: "ollama" })}>Add Ollama</Button> : undefined} />
            </div>
          ) : (
            <>
              {section("Local models", HardDrive, local, "Self-hosted — data stays on your infrastructure", "ollama")}
              {section("Cloud models", Cloud, cloud, "Vendor APIs — tenant data is sent only when allowed", "openai")}
            </>
          )}
        </div>
      )}

      {editing ? (
        <Dialog open onClose={() => setEditing(null)} size="xl" title={editing.provider ? `Edit ${editing.provider.name}` : "Add AI provider"} description="Credentials are stored in the secret store and never returned by the API.">
          <AiProviderForm provider={editing.provider} providers={list} initialKind={editing.kind} organizationId={scope || null} onSaved={() => setEditing(null)} onCancel={() => setEditing(null)} />
        </Dialog>
      ) : null}
    </div>
  );
}
