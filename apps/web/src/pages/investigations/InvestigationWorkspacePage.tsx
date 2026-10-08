import { InvestigationStatus, type ResponseActionKey } from "@bloody/contracts";
import { clsx } from "clsx";
import {
  Activity,
  Archive,
  Bot,
  CheckSquare,
  Fingerprint,
  GitBranch,
  ListTree,
  MessageSquare,
  Network,
  PanelRightClose,
  PanelRightOpen,
  Pencil,
  ShieldAlert,
  Stamp,
  Target,
  Terminal,
  Users,
  Waypoints,
} from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useIncident, useInvestigation, useResponseActions, useUpdateInvestigation } from "../../api/hooks";
import type { InvestigationDetail } from "../../api/types";
import { useSession } from "../../app/session";
import { SeverityBadge, StatusBadge } from "../../components/Badge";
import { Button, ButtonLink } from "../../components/Button";
import { EmptyState } from "../../components/EmptyState";
import { ErrorState } from "../../components/ErrorState";
import { Select, Textarea } from "../../components/Form";
import { PageHeader } from "../../components/PageHeader";
import { ReportMenu } from "../../components/ReportMenu";
import { RelativeTime } from "../../components/RelativeTime";
import { CardSkeleton, SkeletonText } from "../../components/Skeleton";
import { TabPanel, Tabs, type TabDef } from "../../components/Tabs";
import { AiChatPanel } from "../../features/ai/AiChatPanel";
import { AlertsLens } from "../../features/alerts/AlertsLens";
import { EventsLens } from "../../features/events/EventsLens";
import { IntelMatchesTable } from "../../features/intel/IntelTables";
import { CollaboratorsPanel, NotesPanel, TasksPanel } from "../../features/investigations/CollaborationPanels";
import { CustodyPanel, EvidencePanel } from "../../features/investigations/EvidencePanel";
import { EntitiesPanel, IncidentGraphPanel, NoIncidentState } from "../../features/investigations/IncidentContextPanels";
import { TimelinePanel } from "../../features/investigations/TimelinePanel";
import { RequestActionDialog } from "../../features/response/RequestActionDialog";
import { ResponseActionsTable } from "../../features/response/ResponseActionsTable";
import { useActorName } from "../../features/users/useActorName";
import { identityName } from "../../features/identities/identityUtils";
import { hrefForEntity } from "../../lib/entityLinks";
import { humanize } from "../../lib/format";
import { buildScope, hasHostScope, hasIdentityScope, identityEventsQuery, networkQuery, processQuery } from "../../lib/investigationScope";
import { useLocalStorageState, isBoolean } from "../../lib/storage";

type TabId = "timeline" | "evidence" | "alerts" | "entities" | "graph" | "process" | "network" | "identity" | "intel" | "notes" | "tasks" | "collaborators" | "response" | "custody";
const TAB_IDS: TabId[] = ["timeline", "evidence", "alerts", "entities", "graph", "process", "network", "identity", "intel", "notes", "tasks", "collaborators", "response", "custody"];

function HypothesisEditor({ investigation, canWrite }: { investigation: InvestigationDetail; canWrite: boolean }) {
  const update = useUpdateInvestigation(investigation.id);
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(investigation.hypothesis ?? "");
  if (editing) {
    return (
      <form
        className="space-y-1.5"
        onSubmit={(e) => {
          e.preventDefault();
          update.mutate({ hypothesis: text.trim() || null }, { onSuccess: () => setEditing(false) });
        }}
      >
        <Textarea value={text} onChange={(e) => setText(e.target.value)} maxLength={10_000} aria-label="Hypothesis" autoFocus />
        <div className="flex items-center gap-2">
          {update.isError ? <span className="text-sm text-sev-critical">{errorMessage(update.error)}</span> : null}
          <Button size="xs" className="ml-auto" onClick={() => setEditing(false)}>
            Cancel
          </Button>
          <Button size="xs" variant="primary" type="submit" loading={update.isPending}>
            Save hypothesis
          </Button>
        </div>
      </form>
    );
  }
  return (
    <div className="flex items-start gap-2">
      <p className={clsx("min-w-0 flex-1 whitespace-pre-wrap text-sm", investigation.hypothesis ? "text-fg" : "italic text-fg-subtle")}>{investigation.hypothesis ?? "No working hypothesis recorded yet."}</p>
      {canWrite ? (
        <Button size="xs" variant="ghost" icon={Pencil} onClick={() => setEditing(true)} aria-label="Edit hypothesis">
          Edit
        </Button>
      ) : null}
    </div>
  );
}

function StatusControl({ investigation, canWrite }: { investigation: InvestigationDetail; canWrite: boolean }) {
  const update = useUpdateInvestigation(investigation.id);
  if (!canWrite) return <StatusBadge status={investigation.status} />;
  return (
    <span className="inline-flex items-center gap-1.5">
      <Select
        value={investigation.status}
        onChange={(e) => update.mutate({ status: e.target.value as InvestigationDetail["status"] })}
        className="h-7 w-44"
        aria-label="Investigation status"
        disabled={update.isPending}
      >
        {InvestigationStatus.options.map((s) => (
          <option key={s} value={s}>
            {humanize(s)}
          </option>
        ))}
      </Select>
      {update.isError ? <span className="text-xs text-sev-critical">{errorMessage(update.error)}</span> : null}
    </span>
  );
}

/**
 * Investigation workspace: timeline, evidence and chain of custody, the incident's alerts /
 * entities / graph, telemetry panels (process tree, network, identity events) scoped to the
 * incident's entities, intel matches, notes, tasks, collaborators and approval-gated response —
 * with the AI analyst bound to this investigation in a side panel.
 */
export default function InvestigationWorkspacePage() {
  const { id = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const session = useSession();
  const investigation = useInvestigation(id);
  const inv = investigation.data;
  const incident = useIncident(inv?.incidentId ?? null);
  const responses = useResponseActions({ incidentId: inv?.incidentId ?? undefined, organizationId: inv?.organizationId }, { enabled: Boolean(inv?.incidentId) && session.can("incident:read", inv?.organizationId) });
  const { name } = useActorName();
  const [aiOpen, setAiOpen] = useLocalStorageState<boolean>("investigation.aiPanel", true, isBoolean);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [requesting, setRequesting] = useState(false);
  const tab = (TAB_IDS as string[]).includes(params.get("tab") ?? "") ? (params.get("tab") as TabId) : "timeline";
  const setTab = (t: TabId) => {
    const next = new URLSearchParams(params);
    if (t === "timeline") next.delete("tab");
    else next.set("tab", t);
    setParams(next, { replace: true });
  };

  const scope = useMemo(() => {
    if (!inv) return null;
    const inc = incident.data;
    return buildScope({
      detectedAt: inc?.detectedAt ?? null,
      createdAt: inv.createdAt,
      assets: (inc?.assets ?? []).map((a) => ({ id: a.id, hostname: a.hostname })),
      assetIds: inc?.assetIds ?? [],
      identities: (inc?.identities ?? []).map((i) => ({ id: i.id, principal: i.principal })),
      identityIds: inc?.identityIds ?? [],
    });
  }, [inv, incident.data]);

  if (investigation.isPending) {
    return (
      <div className="space-y-3">
        <CardSkeleton rows={2} />
        <CardSkeleton rows={8} />
      </div>
    );
  }
  if (investigation.isError) {
    return (
      <div className="rounded border border-line bg-surface shadow-card">
        {investigation.error.isNotFound ? (
          <EmptyState title="Investigation not found" description="It may belong to an organization you can't access, or the link is wrong." action={<ButtonLink to="/investigations" size="sm">All investigations</ButtonLink>} />
        ) : (
          <ErrorState error={investigation.error} onRetry={() => void investigation.refetch()} />
        )}
      </div>
    );
  }
  const data = investigation.data;
  const canWrite = session.can("investigation:write", data.organizationId);
  const inc = incident.data;
  const linked = Boolean(data.incidentId);
  const openTasks = data.tasks.filter((t) => t.status === "open" || t.status === "in_progress").length;
  const pendingApprovals = (responses.data?.items ?? []).filter((a) => a.status === "pending_approval").length;
  const canAi = session.isModuleEnabled("ai_soc") && session.can("ai:use", data.organizationId);

  const tabs: TabDef<TabId>[] = [
    { id: "timeline", label: "Timeline", icon: Activity, count: data.timeline.length },
    { id: "evidence", label: "Evidence", icon: Archive, count: data.evidence.length },
    { id: "alerts", label: "Alerts", icon: ShieldAlert, count: inc?.alertCount ?? null },
    { id: "entities", label: "Entities", icon: Waypoints, count: inc ? inc.assetIds.length + inc.identityIds.length : null },
    { id: "graph", label: "Graph", icon: Network },
    { id: "process", label: "Process tree", icon: ListTree },
    { id: "network", label: "Network", icon: GitBranch },
    { id: "identity", label: "Identity events", icon: Fingerprint },
    { id: "intel", label: "Threat intel", icon: Target },
    { id: "notes", label: "Notes", icon: MessageSquare, count: data.notes.length },
    { id: "tasks", label: "Tasks", icon: CheckSquare, count: openTasks },
    { id: "collaborators", label: "Collaborators", icon: Users },
    { id: "response", label: "Response", icon: Terminal, count: pendingApprovals || null },
    { id: "custody", label: "Chain of custody", icon: Stamp },
  ];

  const incidentPanel = (render: () => ReactNode, what: string) =>
    !linked ? <NoIncidentState what={what} /> : incident.isPending ? <SkeletonText lines={6} /> : incident.isError ? <ErrorState error={incident.error} compact onRetry={() => void incident.refetch()} /> : render();

  const lensFor = (title: string, query: string | null, preset: "process" | "network" | "auth", has: boolean, extra: Partial<Parameters<typeof EventsLens>[0]> = {}) =>
    incidentPanel(
      () =>
        !has || !query || !scope ? (
          <EmptyState compact title={`No ${preset === "auth" ? "identities" : "hosts"} in scope`} description={`The linked incident involves no ${preset === "auth" ? "identities" : "assets"}, so there is no ${title.toLowerCase()} to show.`} />
        ) : (
          <EventsLens key={query} title={title} query={query} preset={preset} defaultRange={scope.range} engines={preset === "auth" ? ["keycloak", "wazuh"] : preset === "network" ? ["zeek", "suricata"] : ["wazuh", "osquery", "velociraptor"]} organizationId={data.organizationId} hideTitle {...extra} />
        ),
      title.toLowerCase(),
    );

  const targetsForRequest = {
    asset: (inc?.assets ?? []).map((a) => ({ id: a.id, label: a.hostname ?? a.name })),
    identity: (inc?.identities ?? []).map((i) => ({ id: i.id, label: identityName(i) })),
    ...(inc ? { incident: [{ id: inc.id, label: `#${inc.number} ${inc.title}` }] } : {}),
  };
  const requestable: ResponseActionKey[] = inc ? ["isolate_endpoint", "release_endpoint", "kill_process", "quarantine_file", "collect_evidence", "run_yara_scan", "block_ip", "block_domain", "disable_identity", "revoke_sessions", "revoke_token", "notify_analyst"] : [];

  return (
    <div>
      <PageHeader
        title={data.title}
        breadcrumbs={[{ label: "Investigations", href: "/investigations" }, { label: data.title }]}
        subtitle={
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            {inc ? (
              <Link to={hrefForEntity("incident", inc.id)} className="inline-flex items-center gap-1.5 text-primary hover:underline">
                <SeverityBadge severity={inc.severity} size="xs" /> Incident #{inc.number} {inc.title}
              </Link>
            ) : linked ? (
              <span>Linked incident</span>
            ) : (
              <span className="text-fg-subtle">No linked incident</span>
            )}
            <span>Lead: {data.leadId ? name(data.leadId) : "unassigned"}</span>
            <span>{data.organizationName ?? session.organizationName(data.organizationId)}</span>
            <span>
              Opened <RelativeTime value={data.createdAt} />
            </span>
          </span>
        }
        actions={
          <>
            <StatusControl investigation={data} canWrite={canWrite} />
            {inc ? <ReportMenu reports={["incident"]} defaultReport="incident" organizationId={data.organizationId} parameters={{ incidentId: inc.id, investigationId: data.id }} /> : null}
            {canAi ? (
              <Button size="sm" icon={aiOpen ? PanelRightClose : PanelRightOpen} onClick={() => setAiOpen((v) => !v)} aria-pressed={aiOpen}>
                AI assistant
              </Button>
            ) : null}
          </>
        }
      />

      <div className={clsx("grid grid-cols-1 gap-3", aiOpen && canAi && "2xl:grid-cols-[minmax(0,1fr)_400px] xl:grid-cols-[minmax(0,1fr)_360px]")}>
        <div className="min-w-0 space-y-3">
          <section className="rounded border border-line bg-surface px-3 py-2 shadow-card" aria-label="Hypothesis">
            <h2 className="mb-1 text-2xs font-semibold uppercase tracking-wide text-fg-subtle">Hypothesis</h2>
            <HypothesisEditor investigation={data} canWrite={canWrite} />
          </section>
          <div className="rounded border border-line bg-surface shadow-card">
            <div className="px-3 pt-1">
              <Tabs<TabId> ariaLabel="Investigation workspace" idPrefix="inv" value={tab} onChange={setTab} tabs={tabs} />
            </div>
            <TabPanel id={tab} idPrefix="inv" className="p-3">
              {tab === "timeline" ? <TimelinePanel entries={data.timeline} actorName={name} /> : null}
              {tab === "evidence" ? <EvidencePanel investigation={data} /> : null}
              {tab === "custody" ? <CustodyPanel investigation={data} actorName={name} /> : null}
              {tab === "alerts" ? incidentPanel(() => <AlertsLens filters={{ incidentId: data.incidentId!, organizationId: data.organizationId }} engines={["wazuh", "suricata", "zeek"]} emptyTitle="No alerts are correlated into this incident" />, "alerts") : null}
              {tab === "entities" ? incidentPanel(() => <EntitiesPanel incident={inc!} />, "entities") : null}
              {tab === "graph" ? incidentPanel(() => <IncidentGraphPanel incident={inc!} />, "graph") : null}
              {tab === "process" ? lensFor("Process activity", scope ? processQuery(scope) : null, "process", scope ? hasHostScope(scope) : false, { processTree: true, defaultView: "tree" }) : null}
              {tab === "network" ? lensFor("Network connections", scope ? networkQuery(scope) : null, "network", scope ? hasHostScope(scope) : false, { aggregations: [{ title: "Top destinations", field: "network.dstIp", value: (e) => e.network?.dstIp }, { title: "Domains", field: "network.dnsQuery", value: (e) => e.network?.dnsQuery ?? e.network?.httpHost ?? e.network?.tlsSni }] }) : null}
              {tab === "identity" ? lensFor("Identity events", scope ? identityEventsQuery(scope) : null, "auth", scope ? hasIdentityScope(scope) : false, { aggregations: [{ title: "Source IPs", field: "identity.sourceIp", value: (e) => e.identity?.sourceIp }, { title: "Countries", field: "identity.geo.country", value: (e) => e.identity?.geo?.country }] }) : null}
              {tab === "intel" ? (linked ? <IntelMatchesTable filters={{ incidentId: data.incidentId!, organizationId: data.organizationId }} emptyTitle="No threat-intelligence matches for this incident" /> : <NoIncidentState what="threat-intelligence matches" />) : null}
              {tab === "notes" ? <NotesPanel investigation={data} /> : null}
              {tab === "tasks" ? <TasksPanel investigation={data} /> : null}
              {tab === "collaborators" ? <CollaboratorsPanel investigation={data} /> : null}
              {tab === "response"
                ? incidentPanel(
                    () => (
                      <div className="space-y-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="text-sm text-fg-muted">High-risk actions (isolate, block, disable identity, revoke) wait for a second approver. Every request and decision is audited.</p>
                          {session.can("response:request", data.organizationId) ? (
                            <Button size="sm" variant="primary" icon={Terminal} className="ml-auto" onClick={() => setRequesting(true)}>
                              Request action
                            </Button>
                          ) : null}
                        </div>
                        <ResponseActionsTable rows={responses.data?.items} loading={responses.isPending} error={responses.error} onRetry={() => void responses.refetch()} emptyTitle="No response actions for this incident yet" exportFileName={`investigation-${data.id}-actions`} />
                      </div>
                    ),
                    "response actions",
                  )
                : null}
            </TabPanel>
          </div>
        </div>
        {aiOpen && canAi ? (
          <aside className="flex h-[calc(100vh-150px)] min-h-[480px] flex-col rounded border border-line bg-surface shadow-card xl:sticky xl:top-2" aria-label="AI assistant">
            <header className="flex items-center gap-2 border-b border-line px-3 py-2">
              <Bot size={14} className="text-brand" aria-hidden />
              <h2 className="text-base font-medium text-fg">AI assistant</h2>
              <span className="truncate text-2xs text-fg-subtle">bound to this investigation</span>
              <ButtonLink size="xs" variant="ghost" className="ml-auto" to={`/ai?context=${encodeURIComponent(`investigation:${data.id}`)}${conversationId ? `&c=${encodeURIComponent(conversationId)}` : ""}`}>
                Open in AI SOC
              </ButtonLink>
            </header>
            <AiChatPanel conversationId={conversationId} onConversationChange={setConversationId} context={{ kind: "investigation", id: data.id }} organizationId={data.organizationId} compact className="min-h-0 flex-1" />
          </aside>
        ) : null}
      </div>
      {requesting && inc ? (
        <RequestActionDialog open onClose={() => setRequesting(false)} organizationId={data.organizationId} incidentId={inc.id} actions={requestable} targets={targetsForRequest} description={`For investigation “${data.title}” · incident #${inc.number}`} />
      ) : null}
    </div>
  );
}
