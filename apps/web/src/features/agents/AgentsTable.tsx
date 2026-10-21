import type { Agent, ResponseActionKey } from "@bloody/contracts";
import { Lock, LockOpen, Monitor, SquareTerminal } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useAgents, useAntivirusOverview } from "../../api/hooks";
import type { AgentFilters } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge, StatusBadge } from "../../components/Badge";
import { Button, ButtonLink } from "../../components/Button";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { RelativeTime } from "../../components/RelativeTime";
import { hrefForEntity } from "../../lib/entityLinks";
import { humanize } from "../../lib/format";
import { RequestActionDialog } from "../response/RequestActionDialog";
import { ContainmentNote, isInFlight, useContainmentState } from "./ContainmentState";
import { ComputerReportButton } from "../assets/ComputerDossier";

const AGENT_TONE: Record<Agent["status"], "success" | "danger" | "warning" | "purple" | "neutral"> = {
  protected: "success",
  unresponsive: "danger",
  outdated: "warning",
  isolated: "purple",
  pending: "neutral",
};
const AV_TONE: Record<Agent["antivirusStatus"], "success" | "danger" | "warning" | "neutral"> = { protected: "success", unhealthy: "danger", unmanaged: "warning", incompatible: "neutral" };

/** "Isolated · LAN only" / "Isolated · full" when the platform isolated the endpoint. */
export function agentStatusLabel(a: Pick<Agent, "status" | "isolation">): string {
  if (a.status !== "isolated" || !a.isolation) return humanize(a.status);
  return a.isolation.mode === "lan" ? "Isolated · LAN only" : "Isolated · full";
}

export type AgentActionMode = "containment" | "live-response" | "none";

const LIVE_RESPONSE: ResponseActionKey[] = ["collect_evidence", "run_yara_scan", "kill_process", "quarantine_file"];

/**
 * Endpoint & agent fleet. Containment mode offers isolate / release (approval-gated);
 * live-response mode offers collection, YARA, kill process and quarantine.
 */
export function AgentsTable({
  filters = {},
  predicate,
  mode = "containment",
  engines = ["wazuh", "velociraptor", "osquery"],
  emptyTitle = "No agents reporting",
  savedViewsKey,
  antivirusDetail = false,
}: {
  filters?: AgentFilters;
  predicate?: (a: Agent) => boolean;
  mode?: AgentActionMode;
  engines?: string[];
  emptyTitle?: string;
  savedViewsKey?: string;
  /** Managed Antivirus: products found by the SCIAT Agent and what is wrong with them. */
  antivirusDetail?: boolean;
}) {
  const session = useSession();
  const agents = useAgents(filters);
  const [action, setAction] = useState<{ agent: Agent; actions: ResponseActionKey[] } | null>(null);
  const rows = useMemo(() => agents.items?.filter((a) => (predicate ? predicate(a) : true)), [agents.items, predicate]);
  const containment = useContainmentState(mode === "containment");
  const avOverview = useAntivirusOverview(undefined, { enabled: antivirusDetail });
  const avByAgent = useMemo(() => new Map((antivirusDetail ? avOverview.data?.items ?? [] : []).map((i) => [i.agentId, i])), [antivirusDetail, avOverview.data]);
  // Refresh the fleet when a request finishes, so "Isolated" / "Protected" shows without a reload.
  const inFlight = [...containment.values()].filter(isInFlight).map((a) => a.id).sort().join(",");
  const refetchAgents = agents.refetch;
  useEffect(() => {
    void refetchAgents();
  }, [inFlight, refetchAgents]);

  const columns: DataTableColumn<Agent>[] = [
    {
      id: "hostname",
      header: "Endpoint",
      accessor: (a) => a.hostname,
      hideable: false,
      cell: (a) =>
        a.assetId ? (
          <Link to={hrefForEntity("asset", a.assetId)} className="font-medium text-heading hover:underline" onClick={(e) => e.stopPropagation()}>
            {a.hostname}
          </Link>
        ) : (
          <span className="font-medium">{a.hostname}</span>
        ),
    },
    { id: "platform", header: "Platform", accessor: (a) => a.platform, filter: { kind: "select", options: ["windows", "macos", "linux"].map((p) => ({ value: p, label: p })) } },
    { id: "status", header: "Agent status", accessor: (a) => a.status, cell: (a) => {
        const pending = a.assetId ? containment.get(a.assetId) : undefined;
        return (
          <div>
            <Badge size="xs" tone={AGENT_TONE[a.status]}>{agentStatusLabel(a)}</Badge>
            {pending ? <ContainmentNote record={pending} /> : null}
          </div>
        );
      },
      filter: { kind: "select", options: Object.keys(AGENT_TONE).map((s) => ({ value: s, label: humanize(s) })) } },
    { id: "av", header: "Antivirus", accessor: (a) => a.antivirusStatus, cell: (a) => <Badge size="xs" tone={AV_TONE[a.antivirusStatus]}>{humanize(a.antivirusStatus)}</Badge>, filter: { kind: "select", options: Object.keys(AV_TONE).map((s) => ({ value: s, label: humanize(s) })) } },
    ...(antivirusDetail
      ? [
          {
            id: "avDetail",
            header: "Products & issues",
            accessor: (a: Agent) => [...(avByAgent.get(a.id)?.products ?? []), ...(avByAgent.get(a.id)?.issues ?? [])].join("; "),
            cell: (a: Agent) => {
              const d = avByAgent.get(a.id);
              if (!d) return <span className="text-xs text-fg-subtle">{a.engine === "sciat" ? "Waiting for inventory" : "—"}</span>;
              return (
                <div className="text-xs">
                  <div>{d.products.join(", ") || "No antivirus found"}</div>
                  {d.issues.map((i) => (
                    <div key={i} className="text-sev-high">
                      {i}
                    </div>
                  ))}
                </div>
              );
            },
          } satisfies DataTableColumn<Agent>,
        ]
      : []),
    { id: "firewall", header: "Firewall", accessor: (a) => (a.firewallEnabled ? "enabled" : "disabled"), cell: (a) => (a.firewallEnabled ? <span className="text-healthy">Enabled</span> : <span className="text-sev-high">Disabled</span>), filter: { kind: "select", options: [{ value: "enabled", label: "Enabled" }, { value: "disabled", label: "Disabled" }] } },
    { id: "engine", header: "Engine", accessor: (a) => (a.engine === "sciat" ? "SCIAT Agent" : a.engine) },
    { id: "version", header: "Version", accessor: (a) => a.version, cell: (a) => <span className="font-mono text-xs">{a.version}</span> },
    { id: "org", header: "Organization", accessor: (a) => session.organizationName(a.organizationId), defaultHidden: session.organizationId !== null },
    { id: "checkin", header: "Last check-in", accessor: (a) => (a.lastCheckinAt ? new Date(a.lastCheckinAt) : null), cell: (a) => <RelativeTime value={a.lastCheckinAt} /> },
  ];
  if (mode !== "none") {
    columns.push({
      id: "actions",
      header: "Response",
      exportable: false,
      sortable: false,
      cell: (a) => {
        if (!session.can("response:request", a.organizationId)) return <span className="text-xs text-fg-subtle">No permission</span>;
        if (!a.assetId) return <span className="text-xs text-fg-subtle" title="The agent is not linked to an asset yet">Unlinked</span>;
        if (mode === "live-response") {
          return (
            <Button size="xs" icon={SquareTerminal} onClick={(e) => (e.stopPropagation(), setAction({ agent: a, actions: LIVE_RESPONSE }))}>
              Respond
            </Button>
          );
        }
        if (isInFlight(containment.get(a.assetId))) return <span className="text-xs text-fg-subtle">Request in progress</span>;
        return a.status === "isolated" ? (
          <Button size="xs" icon={LockOpen} onClick={(e) => (e.stopPropagation(), setAction({ agent: a, actions: ["release_endpoint"] }))}>
            Release
          </Button>
        ) : (
          <Button size="xs" variant="danger" icon={Lock} onClick={(e) => (e.stopPropagation(), setAction({ agent: a, actions: ["isolate_endpoint"] }))}>
            Isolate
          </Button>
        );
      },
    });
  }

  columns.push({
    id: "report",
    header: "Report",
    exportable: false,
    sortable: false,
    cell: (a) => (a.assetId ? <ComputerReportButton assetId={a.assetId} organizationId={a.organizationId} size="xs" label="Report" /> : null),
  });

  return (
    <>
      <DataTable
        caption="Endpoints and agents"
        columns={columns}
        rows={rows}
        getRowId={(a) => a.id}
        loading={agents.isPending}
        error={agents.error}
        onRetry={() => void agents.refetch()}
        initialState={{ sort: { columnId: "hostname", direction: "asc" } }}
        savedViewsKey={savedViewsKey}
        exportFileName="bloody-agents"
        footer={
          agents.hasNextPage ? (
            <Button size="sm" onClick={() => void agents.fetchNextPage()} loading={agents.isFetchingNextPage}>
              Load more
            </Button>
          ) : null
        }
        emptyState={<ConnectEngineEmptyState compact icon={Monitor} title={emptyTitle} engines={engines} extraAction={<ButtonLink to="/agents/download" size="sm" variant="secondary">Install the SCIAT Agent</ButtonLink>} />}
      />
      {action && action.agent.assetId ? (
        <RequestActionDialog
          open
          onClose={() => setAction(null)}
          organizationId={action.agent.organizationId}
          actions={action.actions}
          defaultAction={action.actions[0]}
          targets={{ asset: [{ id: action.agent.assetId, label: action.agent.hostname }] }}
          description={`${action.agent.hostname} · ${humanize(action.agent.platform)} · ${action.agent.engine}`}
        />
      ) : null}
    </>
  );
}
