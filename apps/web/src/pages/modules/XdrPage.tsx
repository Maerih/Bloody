import { ACTIVE_INCIDENT_STATUSES, Severity, type Incident } from "@bloody/contracts";
import { GitMerge, Layers, Siren, Unlink } from "lucide-react";
import { useMemo } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAlerts, useIncidents } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge, SeverityBadge, StatusBadge } from "../../components/Badge";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { EmptyState } from "../../components/EmptyState";
import { RelativeTime } from "../../components/RelativeTime";
import { RiskScore } from "../../components/RiskScore";
import { StatTile } from "../../components/StatTile";
import { AlertsLens } from "../../features/alerts/AlertsLens";
import { KpiGrid, ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { EventSearchView, type HuntSuggestion } from "../../features/siem/EventSearchView";
import { DOMAIN_LABELS, correlationGroups, type CorrelationGroup } from "../../lib/domains";
import { hrefForEntity } from "../../lib/entityLinks";
import { formatInteger } from "../../lib/format";

/** Hunting hypotheses: query templates over the canonical event schema (product content, not data). */
const HUNTS: HuntSuggestion[] = [
  { name: "Encoded PowerShell", query: "process.name:powershell.exe AND process.commandLine:*-enc*", description: "Base64-encoded commands, common in loaders and C2 stagers (T1059.001)." },
  { name: "Office spawning a shell", query: "process.parent.name:(winword.exe OR excel.exe OR powerpnt.exe OR outlook.exe) AND process.name:(cmd.exe OR powershell.exe OR wscript.exe OR mshta.exe)", description: "Macro or exploit execution from documents (T1204)." },
  { name: "LSASS access", query: "category:process AND process.commandLine:*lsass*", description: "Credential dumping attempts (T1003.001)." },
  { name: "Rare outbound ports", query: "category:network AND network.direction:outbound AND NOT network.dstPort:(80 OR 443 OR 53)", description: "Egress on unusual ports — possible C2 or tunnelling (T1571)." },
  { name: "Failed then successful sign-in", query: "category:authentication AND outcome:failure", description: "Start of a brute-force or spraying sequence; pivot on the principal (T1110)." },
  { name: "New services & scheduled tasks", query: "action:(service-install OR scheduled-task-create)", description: "Persistence via services or tasks (T1543, T1053)." },
  { name: "Cloud API calls from new countries", query: "category:cloud AND identity.geo.country:*", description: "Pivot on countries and principals for anomalous cloud access (T1078.004)." },
];

function CorrelatedIncidents({ compact = false }: { compact?: boolean }) {
  const session = useSession();
  const navigate = useNavigate();
  const incidents = useIncidents({ status: ACTIVE_INCIDENT_STATUSES, limit: 500 });
  const alerts = useAlerts({ limit: 500, sort: "recent" });
  const groups = useMemo(() => new Map(correlationGroups(alerts.data?.items ?? []).map((g) => [g.incidentId, g])), [alerts.data]);
  type Row = Incident & { group: CorrelationGroup | null };
  const rows = useMemo<Row[] | undefined>(() => incidents.data?.items.map((i) => ({ ...i, group: groups.get(i.id) ?? null })), [incidents.data, groups]);
  const multi = (rows ?? []).filter((r) => (r.group?.domains.length ?? 0) > 1).length;
  const columns: DataTableColumn<Row>[] = [
    { id: "severity", header: "Severity", accessor: (r) => Severity.options.indexOf(r.severity), cell: (r) => <SeverityBadge severity={r.severity} size="xs" /> },
    { id: "title", header: "Incident", accessor: (r) => r.title, hideable: false, cell: (r) => <Link to={hrefForEntity("incident", r.id)} className="font-medium text-heading hover:underline" onClick={(e) => e.stopPropagation()}>#{r.number} {r.title}</Link> },
    {
      id: "domains",
      header: "Domains",
      accessor: (r) => r.group?.domains.length ?? 0,
      cell: (r) =>
        r.group ? (
          <span className="flex flex-wrap gap-1" title={`Correlated from: ${r.group.sources.join(", ")}`}>
            {r.group.domains.map((d) => (
              <Badge key={d} size="xs" tone={r.group!.domains.length > 1 ? "purple" : "neutral"}>
                {DOMAIN_LABELS[d]}
              </Badge>
            ))}
          </span>
        ) : (
          <span className="text-fg-subtle">—</span>
        ),
    },
    { id: "alerts", header: "Alerts", accessor: (r) => r.alertCount, align: "right" },
    { id: "sources", header: "Sources", accessor: (r) => r.group?.sources.join(", ") ?? null, cell: (r) => <span className="text-xs text-fg-muted">{r.group?.sources.join(", ") ?? "—"}</span> },
    { id: "attack", header: "ATT&CK", accessor: (r) => (r.group?.techniques ?? r.attack.map((t) => t.id)).join(", "), cell: (r) => <span className="font-mono text-xs">{(r.group?.techniques ?? r.attack.map((t) => t.id)).slice(0, 5).join(", ") || "—"}</span>, defaultHidden: compact },
    { id: "entities", header: "Entities", accessor: (r) => r.assetIds.length + r.identityIds.length, cell: (r) => <span className="text-xs">{r.assetIds.length} asset(s) · {r.identityIds.length} identit{r.identityIds.length === 1 ? "y" : "ies"}</span> },
    { id: "status", header: "Status", accessor: (r) => r.status, cell: (r) => <StatusBadge status={r.status} size="xs" /> },
    { id: "org", header: "Organization", accessor: (r) => session.organizationName(r.organizationId), defaultHidden: session.organizationId !== null },
    { id: "risk", header: "Risk", accessor: (r) => r.riskScore, cell: (r) => <RiskScore score={r.riskScore} size="sm" explanationHref={hrefForEntity("incident", r.id)} />, align: "right" },
    { id: "detected", header: "Detected", accessor: (r) => new Date(r.detectedAt), cell: (r) => <RelativeTime value={r.detectedAt} /> },
  ];
  return (
    <div className="space-y-3">
      <KpiGrid>
        <StatTile label="Active incidents" value={incidents.data?.items.length} loading={incidents.isPending} icon={Siren} href="/incidents" />
        <StatTile label="Cross-domain incidents" value={rows ? multi : null} loading={incidents.isPending || alerts.isPending} icon={Layers} tone={multi > 0 ? "high" : "default"} hint="Alerts from 2+ domains" />
        <StatTile label="Correlated alerts" value={alerts.data ? alerts.data.items.filter((a) => a.incidentId).length : null} loading={alerts.isPending} icon={GitMerge} />
        <StatTile label="Uncorrelated alerts" value={alerts.data ? alerts.data.items.filter((a) => !a.incidentId && (a.status === "new" || a.status === "triaged")).length : null} loading={alerts.isPending} icon={Unlink} hint="Open, not yet in an incident" />
      </KpiGrid>
      <DataTable
        caption="Correlated incidents"
        columns={columns}
        rows={rows}
        getRowId={(r) => r.id}
        loading={incidents.isPending}
        error={incidents.error ?? alerts.error}
        onRetry={() => {
          void incidents.refetch();
          void alerts.refetch();
        }}
        onRowClick={(r) => navigate(hrefForEntity("incident", r.id))}
        initialState={{ sort: { columnId: "domains", direction: "desc" } }}
        savedViewsKey="xdr-correlations"
        exportFileName="bloody-xdr-correlations"
        emptyState={<EmptyState icon={GitMerge} tone="success" title="No active incidents" description="Alerts from endpoint, network, identity and cloud sources are correlated into incidents over the Security Graph." />}
      />
      {incidents.data && incidents.data.nextCursor ? <p className="text-xs text-fg-subtle">Showing the first {formatInteger(incidents.data.items.length)} active incidents.</p> : null}
    </div>
  );
}

/** XDR workspace: cross-domain correlated incidents, uncorrelated alerts, graph and hunting. */
export default function XdrPage() {
  return (
    <ModuleWorkspace
      moduleId="xdr"
      sections={{
        "": () => (
          <div className="space-y-4">
            <CorrelatedIncidents compact />
            <AlertsLens title="Uncorrelated alerts" filters={{ unlinked: true }} predicate={(a) => !a.incidentId} engines={["wazuh", "zeek", "keycloak"]} emptyTitle="Every open alert is correlated into an incident" savedViewsKey="xdr-unlinked" />
          </div>
        ),
        correlations: () => <CorrelatedIncidents />,
        hunting: () => <EventSearchView suggestions={HUNTS} defaultRange="7d" />,
      }}
    />
  );
}
