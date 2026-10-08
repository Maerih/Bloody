import type { AiProviderConfig } from "@bloody/contracts";
import { clsx } from "clsx";
import { Bot, ClipboardCheck, MessageSquarePlus, MessagesSquare, Search, Settings2, X } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useAiConversation, useAiConversations, useAiProviders, useAsset, useIdentity, useIncident, useInvestigation, useResponseActions } from "../../api/hooks";
import type { AiContextKind } from "../../api/types";
import { ORG_PARAM, useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button, ButtonLink } from "../../components/Button";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { Input, Select } from "../../components/Form";
import { PageHeader } from "../../components/PageHeader";
import { RelativeTime } from "../../components/RelativeTime";
import { SkeletonText } from "../../components/Skeleton";
import { Tabs } from "../../components/Tabs";
import { TierBadge } from "../../components/TierBadge";
import { AiChatPanel, type AiContextRef } from "../../features/ai/AiChatPanel";
import { ApprovalDialog, ResponseActionsTable, actionLabel, isOwnRequest } from "../../features/response/ResponseActionsTable";
import { AI_PROVIDER_META, TOOL_TIERS, TOOL_TIER_META, effectiveProvider } from "../../lib/aiProviders";
import { hrefForEntity } from "../../lib/entityLinks";
import { humanize } from "../../lib/format";

const CONTEXT_KINDS: AiContextKind[] = ["incident", "investigation", "asset", "identity", "indicator", "alert"];

/** Parse `?context=incident:<id>` into a context reference. */
export function parseContextParam(value: string | null): AiContextRef | null {
  if (!value) return null;
  const idx = value.indexOf(":");
  if (idx <= 0) return null;
  const kind = value.slice(0, idx) as AiContextKind;
  const id = value.slice(idx + 1).trim();
  if (!CONTEXT_KINDS.includes(kind) || !id || id.length > 500) return null;
  return { kind, id };
}

/** Human label + organization for the context chip, resolved from the API. */
function useContextInfo(ctx: AiContextRef | null): { label: string; href: string | null; organizationId: string | null; loading: boolean } {
  const incident = useIncident(ctx?.kind === "incident" ? ctx.id : null);
  const investigation = useInvestigation(ctx?.kind === "investigation" ? ctx.id : null);
  const asset = useAsset(ctx?.kind === "asset" ? ctx.id : null);
  const identity = useIdentity(ctx?.kind === "identity" ? ctx.id : null);
  if (!ctx || !ctx.id) return { label: "", href: null, organizationId: null, loading: false };
  switch (ctx.kind) {
    case "incident":
      return { label: incident.data ? `Incident #${incident.data.number} ${incident.data.title}` : `Incident ${ctx.id.slice(0, 8)}`, href: hrefForEntity("incident", ctx.id), organizationId: incident.data?.organizationId ?? null, loading: incident.isLoading };
    case "investigation":
      return { label: investigation.data ? `Investigation: ${investigation.data.title}` : `Investigation ${ctx.id.slice(0, 8)}`, href: hrefForEntity("investigation", ctx.id), organizationId: investigation.data?.organizationId ?? null, loading: investigation.isLoading };
    case "asset":
      return { label: asset.data ? `Asset ${asset.data.hostname ?? asset.data.name}` : `Asset ${ctx.id.slice(0, 8)}`, href: hrefForEntity("asset", ctx.id), organizationId: asset.data?.organizationId ?? null, loading: asset.isLoading };
    case "identity":
      return { label: identity.data ? `Identity ${identity.data.displayName ?? identity.data.principal}` : `Identity ${ctx.id.slice(0, 8)}`, href: hrefForEntity("identity", ctx.id), organizationId: identity.data?.organizationId ?? null, loading: identity.isLoading };
    case "indicator":
      return { label: `IOC ${ctx.id}`, href: `/cti/indicators?q=${encodeURIComponent(ctx.id)}`, organizationId: null, loading: false };
    case "alert":
      return { label: `Alert ${ctx.id.slice(0, 8)}`, href: hrefForEntity("alert", ctx.id), organizationId: null, loading: false };
    default:
      return { label: humanize(ctx.kind), href: null, organizationId: null, loading: false };
  }
}

function PendingAiApprovals() {
  const session = useSession();
  const pending = useResponseActions({ status: ["pending_approval"], limit: 50 }, { refetchIntervalMs: 30_000 });
  const [decision, setDecision] = useState<{ id: string; decision: "approve" | "reject" } | null>(null);
  const items = (pending.data?.items ?? []).filter((a) => a.requestedVia === "ai");
  const record = decision ? items.find((a) => a.id === decision.id) : undefined;
  return (
    <Card title="AI actions awaiting approval" count={pending.data ? items.length : null} padded={false} info="Actions the assistant requested above its permitted tier. Nothing runs until a different human approves.">
      {pending.isPending ? (
        <div className="p-3">
          <SkeletonText lines={3} />
        </div>
      ) : pending.isError ? (
        <p className="p-3 text-sm text-sev-critical">{errorMessage(pending.error)}</p>
      ) : items.length === 0 ? (
        <p className="p-3 text-sm text-fg-muted">Nothing waiting.</p>
      ) : (
        <ul className="divide-y divide-line">
          {items.slice(0, 8).map((a) => {
            const canDecide = session.can("response:approve", a.organizationId) && !isOwnRequest(a, session.principal.id);
            return (
              <li key={a.id} className="space-y-1 px-3 py-2 text-sm">
                <div className="flex items-center gap-2">
                  <TierBadge tier="require_approval" />
                  <span className="min-w-0 flex-1 truncate font-medium">{actionLabel(a.action)}</span>
                </div>
                <p className="truncate text-xs text-fg-muted" title={a.reason}>
                  {a.target.label ?? a.target.id} · {a.reason}
                </p>
                {canDecide ? (
                  <div className="flex gap-1">
                    <Button size="xs" variant="success" onClick={() => setDecision({ id: a.id, decision: "approve" })}>
                      Approve
                    </Button>
                    <Button size="xs" onClick={() => setDecision({ id: a.id, decision: "reject" })}>
                      Reject
                    </Button>
                  </div>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
      {record && decision ? <ApprovalDialog record={record} decision={decision.decision} onClose={() => setDecision(null)} /> : null}
    </Card>
  );
}

type View = "analyst" | "actions";

/**
 * AI SOC analyst workspace: conversations, a thread showing every tool call with its tier and
 * approve / reject for pending actions, a context chip (?context=kind:id) and the model
 * selector. The assistant only ever acts within its provider's tool tier.
 */
export default function AiSocPage() {
  const session = useSession();
  const location = useLocation();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const view: View = location.pathname.startsWith("/ai/actions") ? "actions" : "analyst";
  const conversationId = params.get("c");
  const conversations = useAiConversations({ enabled: session.canAnywhere("ai:use") });
  const conversation = useAiConversation(conversationId);
  const providers = useAiProviders({ enabled: session.canAnywhere("ai:use") });
  const urlContext = parseContextParam(params.get("context"));
  const convContext = conversation.data?.conversation.context && conversation.data.conversation.context.kind !== "none" ? (conversation.data.conversation.context as AiContextRef) : null;
  const context = urlContext ?? convContext;
  const contextInfo = useContextInfo(context);
  const [filter, setFilter] = useState("");
  const [providerId, setProviderId] = useState<string>("");
  const [groundingOrg, setGroundingOrg] = useState<string>(session.organizationId ?? session.organizations[0]?.id ?? "");
  const organizationId = contextInfo.organizationId ?? conversation.data?.conversation.organizationId ?? session.organizationId ?? (groundingOrg || null);

  const usable = useMemo(() => (providers.data ?? []).filter((p) => p.enabled && (p.organizationId === null || p.organizationId === organizationId)), [providers.data, organizationId]);
  const effective = effectiveProvider(providers.data ?? [], organizationId);
  const selectedProvider: AiProviderConfig | null = usable.find((p) => p.id === providerId) ?? effective;

  const setParam = (key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: key !== "c" });
  };

  const list = useMemo(() => {
    const term = filter.trim().toLowerCase();
    return (conversations.data ?? []).filter((c) => !term || (c.title ?? "").toLowerCase().includes(term));
  }, [conversations.data, filter]);

  const go = (v: View) => {
    const org = new URLSearchParams(location.search).get(ORG_PARAM);
    navigate({ pathname: v === "actions" ? "/ai/actions" : "/ai", search: org ? `?${ORG_PARAM}=${encodeURIComponent(org)}` : "" });
  };

  if (!session.canAnywhere("ai:use")) {
    return (
      <div>
        <PageHeader title="AI SOC Analyst" />
        <div className="rounded border border-line bg-surface shadow-card">
          <EmptyState icon={Bot} title="You don't have access to the AI SOC" description="Ask an administrator for the ai:use permission." />
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="AI SOC Analyst"
        subtitle="Investigate, hunt, explain and recommend — grounded in your tenant's data, within the tool tier each model is allowed."
        actions={
          <>
            {session.canAnywhere("ai:configure") ? (
              <ButtonLink size="sm" icon={Settings2} to="/settings/ai">
                AI settings
              </ButtonLink>
            ) : null}
            <Button size="sm" variant="primary" icon={MessageSquarePlus} onClick={() => setParam("c", null)}>
              New conversation
            </Button>
          </>
        }
      >
        <Tabs<View> ariaLabel="AI SOC sections" idPrefix="ai" value={view} onChange={go} tabs={[{ id: "analyst", label: "Analyst", icon: Bot }, { id: "actions", label: "Actions & approvals", icon: ClipboardCheck }]} />
      </PageHeader>

      {view === "actions" ? (
        <AiActionsLog />
      ) : (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-[260px_minmax(0,1fr)] 2xl:grid-cols-[280px_minmax(0,1fr)_300px]">
          <Card title="Conversations" count={conversations.data ? conversations.data.length : null} padded={false} className="lg:max-h-[calc(100vh-200px)]">
            <div className="border-b border-line p-2">
              <label className="relative block">
                <Search size={12} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-fg-subtle" aria-hidden />
                <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter conversations" className="h-7 pl-6 text-sm" aria-label="Filter conversations" />
              </label>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto scrollbar-thin">
              {conversations.isPending ? (
                <div className="p-3">
                  <SkeletonText lines={5} />
                </div>
              ) : conversations.isError ? (
                <p className="p-3 text-sm text-sev-critical">{errorMessage(conversations.error)}</p>
              ) : list.length === 0 ? (
                <EmptyState compact icon={MessagesSquare} title="No conversations yet" description="Ask a question to start one." />
              ) : (
                <ul aria-label="Conversations">
                  {list.map((c) => (
                    <li key={c.id}>
                      <button
                        type="button"
                        onClick={() => setParam("c", c.id)}
                        aria-current={c.id === conversationId ? "true" : undefined}
                        className={clsx("block w-full border-l-2 px-3 py-2 text-left hover:bg-surface-2", c.id === conversationId ? "border-primary bg-primary-soft/50" : "border-transparent")}
                      >
                        <span className="block truncate text-sm font-medium text-fg">{c.title ?? "Untitled conversation"}</span>
                        <span className="flex items-center gap-1.5 text-2xs text-fg-subtle">
                          {c.context && c.context.kind !== "none" ? <Badge size="xs" tone="outline">{c.context.kind}</Badge> : null}
                          {c.model ? <span className="truncate font-mono">{c.model}</span> : null}
                          <RelativeTime value={c.updatedAt} className="ml-auto shrink-0" />
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </Card>

          <section className="flex h-[calc(100vh-200px)] min-h-[520px] flex-col rounded border border-line bg-surface shadow-card" aria-label="Conversation">
            <header className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
              {context ? (
                <span className="inline-flex max-w-full items-center gap-1 rounded-full border border-primary/40 bg-primary-soft py-0.5 pl-2 pr-0.5 text-xs text-primary" data-testid="ai-context-chip">
                  <span className="font-semibold uppercase">{context.kind}</span>
                  {contextInfo.href ? (
                    <Link to={contextInfo.href} className="max-w-[320px] truncate hover:underline">
                      {contextInfo.label}
                    </Link>
                  ) : (
                    <span className="max-w-[320px] truncate">{contextInfo.label}</span>
                  )}
                  {urlContext ? (
                    <button type="button" className="rounded-full p-0.5 hover:bg-primary/10" aria-label="Remove context" onClick={() => setParam("context", null)}>
                      <X size={11} />
                    </button>
                  ) : null}
                </span>
              ) : (
                <span className="text-xs text-fg-subtle">No context — answers draw on the whole {organizationId ? "organization" : "tenant"}.</span>
              )}
              <div className="ml-auto flex flex-wrap items-center gap-2">
                {!session.organizationId && !contextInfo.organizationId && !conversation.data?.conversation.organizationId ? (
                  <Select value={groundingOrg} onChange={(e) => setGroundingOrg(e.target.value)} className="h-7 w-44 text-xs" aria-label="Grounding organization">
                    {session.organizations.map((o) => (
                      <option key={o.id} value={o.id}>
                        {o.name}
                      </option>
                    ))}
                  </Select>
                ) : null}
                <Select value={providerId || selectedProvider?.id || ""} onChange={(e) => setProviderId(e.target.value)} className="h-7 w-56 text-xs" aria-label="Model" disabled={usable.length === 0}>
                  {usable.length === 0 ? <option value="">No model configured</option> : null}
                  {usable.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} · {p.model}
                      {p.id === effective?.id ? " (default)" : ""}
                    </option>
                  ))}
                </Select>
                {selectedProvider ? (
                  <span className="flex items-center gap-1 text-2xs text-fg-subtle" title={`${AI_PROVIDER_META[selectedProvider.kind].label} · max tool tier`}>
                    <TierBadge tier={selectedProvider.maxToolTier} />
                  </span>
                ) : null}
              </div>
            </header>
            {usable.length === 0 && providers.data ? (
              <EmptyState
                icon={Bot}
                title="No AI model is configured for this scope"
                description="Add a local model (Ollama, vLLM, LM Studio) or a cloud provider in AI settings."
                action={session.canAnywhere("ai:configure") ? <ButtonLink size="sm" variant="primary" to="/settings/ai">Configure AI</ButtonLink> : undefined}
              />
            ) : (
              <AiChatPanel
                key={`${conversationId ?? "new"}|${context ? `${context.kind}:${context.id ?? ""}` : "none"}`}
                conversationId={conversationId}
                onConversationChange={(id) => setParam("c", id)}
                context={context}
                organizationId={organizationId}
                providerId={providerId || null}
                className="min-h-0 flex-1"
              />
            )}
          </section>

          <div className="hidden space-y-3 2xl:block">
            <PendingAiApprovals />
            <Card title="Tool tiers" info="What the assistant may do on its own. Higher tiers require a model configured for them; above its ceiling, a human approves.">
              <ul className="space-y-1.5">
                {TOOL_TIERS.map((t) => (
                  <li key={t} className="text-xs">
                    <TierBadge tier={t} /> <span className="text-fg-muted">{TOOL_TIER_META[t].description}</span>
                  </li>
                ))}
              </ul>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}

/** Every response action the AI requested (approval queue + history). */
function AiActionsLog() {
  const actions = useResponseActions({ limit: 200 }, { refetchIntervalMs: 30_000 });
  const rows = actions.data?.items.filter((a) => a.requestedVia === "ai");
  return (
    <div className="space-y-2">
      <p className="text-sm text-fg-muted">Actions the AI analyst requested. Anything above a model's tool tier waits here until a different person approves it; every decision is audited.</p>
      <ResponseActionsTable rows={rows} loading={actions.isPending} error={actions.error} onRetry={() => void actions.refetch()} emptyTitle="The AI analyst has not requested any action" savedViewsKey="ai-actions" exportFileName="bloody-ai-actions" />
    </div>
  );
}
