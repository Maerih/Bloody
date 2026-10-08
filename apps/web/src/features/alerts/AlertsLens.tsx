import type { Alert, Severity } from "@bloody/contracts";
import { CheckCheck, EyeOff, Siren, ThumbsDown } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useAlert, useAlerts, useUpdateAlert } from "../../api/hooks";
import type { AlertFilters } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge, SeverityBadge, StatusBadge } from "../../components/Badge";
import { Button, ButtonLink } from "../../components/Button";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { DescriptionList } from "../../components/DescriptionList";
import { Drawer } from "../../components/Overlay";
import { RelativeTime } from "../../components/RelativeTime";
import { RiskScore } from "../../components/RiskScore";
import { SkeletonText } from "../../components/Skeleton";
import { matchCategory, type AlertCategory } from "../../lib/classify";
import { hrefForEntity } from "../../lib/entityLinks";
import { formatDateTime, humanize } from "../../lib/format";
import { SEVERITY_ORDER } from "../../lib/severity";
import { EventsTable } from "../events/EventsTable";

const STATUS_OPTIONS = ["new", "triaged", "suppressed", "promoted", "false_positive"].map((s) => ({ value: s, label: humanize(s) }));

/** Alert detail with contributing events, pivots and triage (suppress / false positive). */
export function AlertDrawer({ alertId, onClose }: { alertId: string | null; onClose: () => void }) {
  const session = useSession();
  const alert = useAlert(alertId);
  const update = useUpdateAlert();
  if (!alertId) return null;
  const a = alert.data;
  const canTriage = a ? session.can("incident:write", a.organizationId) : false;
  const setStatus = (status: "triaged" | "suppressed" | "false_positive") => a && update.mutate({ id: a.id, status, reason: `Set from ${window.location.pathname}` });
  return (
    <Drawer
      open
      onClose={onClose}
      width="xl"
      title={a?.title ?? "Alert"}
      subtitle={
        a ? (
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={a.severity} size="xs" />
            <StatusBadge status={a.status} size="xs" />
            <span>{a.source}</span>
            <RelativeTime value={a.lastSeenAt} />
          </span>
        ) : null
      }
      footer={
        a && canTriage ? (
          <div className="flex flex-wrap items-center gap-2">
            {update.isError ? (
              <span role="alert" className="mr-auto text-sm text-sev-critical">
                {errorMessage(update.error)}
              </span>
            ) : null}
            <Button size="sm" icon={CheckCheck} onClick={() => setStatus("triaged")} disabled={a.status === "triaged" || a.status === "promoted"} loading={update.isPending && update.variables?.status === "triaged"}>
              Mark triaged
            </Button>
            <Button size="sm" icon={EyeOff} onClick={() => setStatus("suppressed")} disabled={a.status === "suppressed" || a.status === "promoted"} loading={update.isPending && update.variables?.status === "suppressed"}>
              Suppress
            </Button>
            <Button size="sm" icon={ThumbsDown} onClick={() => setStatus("false_positive")} disabled={a.status === "false_positive"} loading={update.isPending && update.variables?.status === "false_positive"}>
              False positive
            </Button>
          </div>
        ) : null
      }
    >
      {alert.isPending ? (
        <div className="p-4">
          <SkeletonText lines={6} />
        </div>
      ) : alert.isError ? (
        <p className="p-4 text-sm text-sev-critical">{errorMessage(alert.error)}</p>
      ) : a ? (
        <div>
          <div className="flex flex-wrap gap-2 border-b border-line px-4 py-3">
            {a.incidentId ? (
              <ButtonLink size="sm" variant="primary" to={hrefForEntity("incident", a.incidentId)} onClick={onClose}>
                Open incident
              </ButtonLink>
            ) : null}
            {a.assetId ? (
              <ButtonLink size="sm" to={hrefForEntity("asset", a.assetId)} onClick={onClose}>
                Open asset
              </ButtonLink>
            ) : null}
            {a.identityId ? (
              <ButtonLink size="sm" to={hrefForEntity("identity", a.identityId)} onClick={onClose}>
                Open identity
              </ButtonLink>
            ) : null}
            {session.isModuleEnabled("ai_soc") && session.can("ai:use", a.organizationId) ? (
              <ButtonLink size="sm" to={`/ai?context=${encodeURIComponent(`alert:${a.id}`)}`} onClick={onClose}>
                Ask AI
              </ButtonLink>
            ) : null}
          </div>
          <div className="space-y-3 px-4 py-3">
            <div className="flex items-center gap-3">
              <RiskScore score={a.riskScore} label="Alert risk" />
              <span className="text-sm text-fg-muted">Confidence {(a.confidence * 100).toFixed(0)}%</span>
            </div>
            <DescriptionList
              items={[
                { label: "Rule", value: a.ruleId },
                { label: "Source", value: a.source },
                { label: "First seen", value: formatDateTime(a.firstSeenAt) },
                { label: "Last seen", value: formatDateTime(a.lastSeenAt) },
                { label: "Organization", value: session.organizationName(a.organizationId) },
                { label: "Events", value: String(a.eventIds.length) },
                { label: "ATT&CK", value: a.attack.length > 0 ? a.attack.map((t) => `${t.id}${t.name ? ` ${t.name}` : ""}`).join(", ") : null, wide: true },
              ]}
            />
          </div>
          {a.events && a.events.length > 0 ? (
            <div className="px-4 pb-4">
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted">Contributing events</h3>
              <EventsTable rows={a.events} exportFileName={`alert-${a.id}-events`} />
            </div>
          ) : null}
        </div>
      ) : null}
    </Drawer>
  );
}

export interface AlertsLensProps {
  title?: string;
  filters?: AlertFilters;
  /** Client-side refinement (technique / category membership). */
  predicate?: (a: Alert) => boolean;
  categories?: AlertCategory[];
  engines: string[];
  emptyTitle?: string;
  description?: ReactNode;
  initialAlertId?: string | null;
  savedViewsKey?: string;
}

/** Alerts lens shared by every module (filters + optional ATT&CK/keyword categorization + drawer). */
export function AlertsLens({ title, filters = {}, predicate, categories, engines, emptyTitle, description, initialAlertId = null, savedViewsKey }: AlertsLensProps) {
  const session = useSession();
  const alerts = useAlerts({ limit: 500, sort: "recent", ...filters });
  const [selected, setSelected] = useState<string | null>(initialAlertId);
  const rows = useMemo(() => (alerts.data?.items ?? []).filter((a) => (predicate ? predicate(a) : true)), [alerts.data, predicate]);

  const columns: DataTableColumn<Alert>[] = [
    { id: "severity", header: "Severity", accessor: (a) => SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(a.severity), cell: (a) => <SeverityBadge severity={a.severity} size="xs" />, filter: { kind: "select", options: SEVERITY_ORDER.map((s) => ({ value: String(SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(s as Severity)), label: humanize(s) })) } },
    { id: "title", header: "Alert", accessor: (a) => a.title, hideable: false, cell: (a) => <span className="font-medium text-heading">{a.title}</span> },
    ...(categories
      ? [
          {
            id: "category",
            header: "Detection",
            accessor: (a: Alert) => matchCategory(a, categories)?.category.label ?? "Other",
            cell: (a: Alert) => {
              const m = matchCategory(a, categories);
              return m ? (
                <Badge size="xs" tone="purple" title={`Why: ${m.reason}`}>
                  {m.category.label}
                </Badge>
              ) : (
                <span className="text-fg-subtle">Other</span>
              );
            },
            filter: { kind: "select" as const, options: [...categories.map((c) => ({ value: c.label, label: c.label })), { value: "Other", label: "Other" }] },
          },
        ]
      : []),
    { id: "source", header: "Source", accessor: (a) => a.source },
    {
      id: "entity",
      header: "Entity",
      accessor: (a) => a.assetId ?? a.identityId ?? null,
      cell: (a) =>
        a.assetId ? (
          <Link to={hrefForEntity("asset", a.assetId)} className="text-primary hover:underline" onClick={(e) => e.stopPropagation()}>
            Asset
          </Link>
        ) : a.identityId ? (
          <Link to={hrefForEntity("identity", a.identityId)} className="text-primary hover:underline" onClick={(e) => e.stopPropagation()}>
            Identity
          </Link>
        ) : (
          <span className="text-fg-subtle">—</span>
        ),
    },
    { id: "attack", header: "ATT&CK", accessor: (a) => a.attack.map((t) => t.id).join(", "), cell: (a) => <span className="font-mono text-xs">{a.attack.map((t) => t.id).join(", ") || "—"}</span> },
    { id: "status", header: "Status", accessor: (a) => a.status, cell: (a) => <StatusBadge status={a.status} size="xs" />, filter: { kind: "select", options: STATUS_OPTIONS } },
    { id: "incident", header: "Incident", accessor: (a) => (a.incidentId ? "linked" : "unlinked"), cell: (a) => (a.incidentId ? <Link to={hrefForEntity("incident", a.incidentId)} className="text-primary hover:underline" onClick={(e) => e.stopPropagation()}>Linked</Link> : <span className="text-fg-subtle">—</span>) },
    { id: "risk", header: "Risk", accessor: (a) => a.riskScore, cell: (a) => <RiskScore score={a.riskScore} size="sm" />, align: "right" },
    { id: "org", header: "Organization", accessor: (a) => session.organizationName(a.organizationId), defaultHidden: session.organizationId !== null },
    { id: "lastSeen", header: "Last seen", accessor: (a) => new Date(a.lastSeenAt), cell: (a) => <RelativeTime value={a.lastSeenAt} /> },
  ];

  return (
    <div className="space-y-2">
      {title ? (
        <div className="flex items-baseline gap-2">
          <h2 className="text-md font-semibold text-fg">{title}</h2>
          {alerts.data ? <span className="text-sm text-fg-muted">{rows.length}</span> : null}
        </div>
      ) : null}
      <DataTable
        caption={title ?? "Alerts"}
        columns={columns}
        rows={alerts.data ? rows : undefined}
        getRowId={(a) => a.id}
        loading={alerts.isPending}
        error={alerts.error}
        onRetry={() => void alerts.refetch()}
        onRowClick={(a) => setSelected(a.id)}
        selectedRowId={selected}
        initialState={{ sort: { columnId: "lastSeen", direction: "desc" } }}
        savedViewsKey={savedViewsKey}
        exportFileName="bloody-alerts"
        emptyState={<ConnectEngineEmptyState compact icon={Siren} title={emptyTitle ?? "No alerts for this view"} description={description} engines={engines} />}
      />
      <AlertDrawer alertId={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
