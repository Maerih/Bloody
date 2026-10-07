import { ACTIVE_INCIDENT_STATUSES, IncidentStatus, Severity, type Incident } from "@bloody/contracts";
import { clsx } from "clsx";
import { ExternalLink, Fingerprint, Server, Siren } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useInfiniteIncidents } from "../../api/hooks";
import { DASHBOARD_PRESETS } from "../../app/dashboardPresets";
import { useSession } from "../../app/session";
import { SeverityBadge, StatusBadge } from "../../components/Badge";
import { Button, ButtonLink } from "../../components/Button";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { EmptyState } from "../../components/EmptyState";
import { Input, Select } from "../../components/Form";
import { Drawer } from "../../components/Overlay";
import { PageHeader } from "../../components/PageHeader";
import { RelativeTime } from "../../components/RelativeTime";
import { ReportMenu } from "../../components/ReportMenu";
import { RiskScore } from "../../components/RiskScore";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import { formatInteger, humanize } from "../../lib/format";
import { SEVERITY_META, SEVERITY_ORDER } from "../../lib/severity";
import { IncidentDetailPanel } from "./IncidentDetailPanel";

const SEVERITY_SET = new Set<string>(Severity.options);
const STATUS_SET = new Set<string>(IncidentStatus.options);

export function parseSeverityParam(value: string | null): Severity[] {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s): s is Severity => SEVERITY_SET.has(s));
}

/** "active" (default) → active statuses; "all" → no filter; else comma list of statuses. */
export function parseStatusParam(value: string | null): { mode: "active" | "all" | "custom"; statuses: IncidentStatus[] } {
  if (value === null || value === "" || value === "active") return { mode: "active", statuses: ACTIVE_INCIDENT_STATUSES };
  if (value === "all") return { mode: "all", statuses: [] };
  const statuses = value.split(",").filter((s): s is IncidentStatus => STATUS_SET.has(s));
  return statuses.length > 0 ? { mode: "custom", statuses } : { mode: "active", statuses: ACTIVE_INCIDENT_STATUSES };
}

/** Incidents list with URL-driven filters, saved views, CSV export and a drill-down drawer. */
export default function IncidentsPage() {
  const session = useSession();
  const [params, setParams] = useSearchParams();
  const severity = parseSeverityParam(params.get("severity"));
  const status = parseStatusParam(params.get("status"));
  const urlQ = params.get("q") ?? "";
  const [q, setQ] = useState(urlQ);
  const debouncedQ = useDebouncedValue(q, 300);
  const selectedId = params.get("incident");

  const setParam = (key: string, value: string | null) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (value === null || value === "") next.delete(key);
        else next.set(key, value);
        return next;
      },
      { replace: key !== "incident" },
    );

  useEffect(() => {
    if (debouncedQ !== urlQ) setParam("q", debouncedQ.trim() || null);
  }, [debouncedQ]);

  const query = useInfiniteIncidents({ severity, status: status.statuses, q: urlQ });
  const rows = useMemo(() => {
    if (!query.data) return undefined;
    const items = query.data.pages.flatMap((p) => p.items);
    // Defensive client-side filtering in case the endpoint ignores a filter.
    return items.filter(
      (i) => (severity.length === 0 || severity.includes(i.severity)) && (status.statuses.length === 0 || status.statuses.includes(i.status)),
    );
  }, [query.data, severity, status.statuses]);

  const showOrg = session.organizationId === null;
  const columns = useMemo<DataTableColumn<Incident>[]>(
    () => [
      { id: "number", header: "#", accessor: (i) => i.number, width: "64px", cell: (i) => <span className="font-mono text-fg-muted">#{i.number}</span> },
      {
        id: "title",
        header: "Incident",
        accessor: (i) => i.title,
        hideable: false,
        cell: (i) => (
          <span className="block min-w-[220px]">
            <span className="block truncate font-medium text-heading">{i.title}</span>
            {i.attack.length > 0 ? (
              <span className="block truncate font-mono text-2xs text-fg-subtle">{i.attack.map((t) => t.id).join(" · ")}</span>
            ) : null}
          </span>
        ),
      },
      {
        id: "severity",
        header: "Severity",
        accessor: (i) => i.severity,
        cell: (i) => <SeverityBadge severity={i.severity} />,
        filter: { kind: "select", options: SEVERITY_ORDER.map((s) => ({ value: s, label: SEVERITY_META[s].label })) },
      },
      {
        id: "status",
        header: "Status",
        accessor: (i) => i.status,
        cell: (i) => <StatusBadge status={i.status} />,
        filter: { kind: "select", options: IncidentStatus.options.map((s) => ({ value: s, label: humanize(s) })) },
      },
      { id: "risk", header: "Risk", accessor: (i) => i.riskScore, align: "center", cell: (i) => <RiskScore score={i.riskScore} size="sm" /> },
      ...(showOrg
        ? [
            {
              id: "org",
              header: "Organization",
              accessor: (i: Incident) => session.organizationName(i.organizationId) ?? i.organizationId,
              filter: { kind: "text" as const },
            },
          ]
        : []),
      { id: "alerts", header: "Alerts", accessor: (i) => i.alertCount, align: "right" },
      {
        id: "entities",
        header: "Entities",
        accessor: (i) => i.assetIds.length + i.identityIds.length,
        cell: (i) => (
          <span className="inline-flex items-center gap-2 text-fg-muted">
            <span className="inline-flex items-center gap-0.5" title="Assets">
              <Server size={12} aria-hidden /> {formatInteger(i.assetIds.length)}
            </span>
            <span className="inline-flex items-center gap-0.5" title="Identities">
              <Fingerprint size={12} aria-hidden /> {formatInteger(i.identityIds.length)}
            </span>
          </span>
        ),
      },
      { id: "detected", header: "Detected", accessor: (i) => new Date(i.detectedAt), cell: (i) => <RelativeTime value={i.detectedAt} className="text-fg-muted" /> },
    ],
    [showOrg, session],
  );

  const preset = DASHBOARD_PRESETS[session.dashboardRole];
  const filtersActive = severity.length > 0 || status.mode !== "active" || urlQ.length > 0;

  return (
    <div>
      <PageHeader
        title="Incidents"
        subtitle="Correlated incidents across endpoint, identity, network, cloud and SaaS."
        actions={<ReportMenu reports={preset.reports.includes("incident") ? preset.reports : ["incident", ...preset.reports]} defaultReport="soc_operations" />}
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div role="group" aria-label="Severity filter" className="flex flex-wrap gap-1">
          {SEVERITY_ORDER.filter((s) => s !== "info").map((s) => {
            const on = severity.includes(s);
            return (
              <button
                key={s}
                type="button"
                aria-pressed={on}
                onClick={() => setParam("severity", (on ? severity.filter((x) => x !== s) : [...severity, s]).join(",") || null)}
                className={clsx(
                  "inline-flex h-7 items-center gap-1.5 rounded border px-2.5 text-sm transition-colors",
                  on ? clsx(SEVERITY_META[s].border, SEVERITY_META[s].softBg, "font-semibold text-fg") : "border-line-strong bg-surface text-fg-muted hover:text-fg",
                )}
              >
                <span className={clsx("h-2 w-2 rounded-full", SEVERITY_META[s].bg)} aria-hidden />
                {SEVERITY_META[s].label}
              </button>
            );
          })}
        </div>
        <Select
          value={status.mode === "custom" ? (status.statuses.length === 1 ? status.statuses[0] : "custom") : status.mode}
          onChange={(e) => setParam("status", e.target.value === "active" ? null : e.target.value)}
          className="h-7 w-44"
          aria-label="Status filter"
        >
          <option value="active">Active (open)</option>
          <option value="all">All statuses</option>
          {status.mode === "custom" && status.statuses.length > 1 ? <option value="custom">{status.statuses.map(humanize).join(", ")}</option> : null}
          {IncidentStatus.options.map((s) => (
            <option key={s} value={s}>
              {humanize(s)}
            </option>
          ))}
        </Select>
        <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, host, user, technique…" className="h-7 w-72" aria-label="Search incidents" />
        {filtersActive ? (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setQ("");
              setParams((prev) => {
                const next = new URLSearchParams();
                const org = prev.get("org");
                if (org) next.set("org", org);
                return next;
              });
            }}
          >
            Reset filters
          </Button>
        ) : null}
      </div>

      <DataTable
        caption="Incidents"
        columns={columns}
        rows={rows}
        getRowId={(i) => i.id}
        loading={query.isPending}
        error={query.error}
        onRetry={() => void query.refetch()}
        onRowClick={(i) => setParam("incident", i.id)}
        selectedRowId={selectedId}
        searchable={false}
        initialState={{ sort: { columnId: "detected", direction: "desc" } }}
        savedViewsKey="incidents"
        exportFileName="bloody-incidents"
        emptyState={
          <EmptyState
            icon={Siren}
            tone={filtersActive ? "neutral" : "success"}
            title={filtersActive ? "No incidents match these filters" : "All caught up, no active incidents!"}
            description={filtersActive ? "Try widening the severity or status filters." : "New incidents appear here as soon as correlation raises them."}
          />
        }
        footer={
          query.hasNextPage ? (
            <Button size="xs" onClick={() => void query.fetchNextPage()} loading={query.isFetchingNextPage}>
              Load more
            </Button>
          ) : null
        }
      />

      <Drawer
        open={Boolean(selectedId)}
        onClose={() => setParam("incident", null)}
        title={selectedId ? (rows?.find((r) => r.id === selectedId)?.title ?? "Incident") : "Incident"}
        subtitle={selectedId ? `#${rows?.find((r) => r.id === selectedId)?.number ?? ""}` : undefined}
        headerActions={selectedId ? <ButtonLink to={`/incidents/${encodeURIComponent(selectedId)}`} size="sm" icon={ExternalLink}>Open page</ButtonLink> : null}
        width="xl"
      >
        {selectedId ? <IncidentDetailPanel incidentId={selectedId} /> : null}
      </Drawer>
    </div>
  );
}
