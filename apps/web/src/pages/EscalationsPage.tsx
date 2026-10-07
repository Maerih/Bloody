import type { Escalation } from "@bloody/contracts";
import { CircleAlert, CircleCheck, ExternalLink } from "lucide-react";
import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { errorMessage } from "../api/client";
import { useAcknowledgeEscalation, useEscalations, useResolveEscalation } from "../api/hooks";
import { useSession } from "../app/session";
import { Badge, SeverityBadge, StatusBadge } from "../components/Badge";
import { Button, ButtonLink } from "../components/Button";
import { DataTable, type DataTableColumn } from "../components/DataTable";
import { DescriptionList } from "../components/DescriptionList";
import { EmptyState } from "../components/EmptyState";
import { Drawer } from "../components/Overlay";
import { PageHeader } from "../components/PageHeader";
import { RelativeTime } from "../components/RelativeTime";
import { ReportMenu } from "../components/ReportMenu";
import { Tabs } from "../components/Tabs";
import { hrefForEntity } from "../lib/entityLinks";
import { formatDateTime } from "../lib/format";
import { SEVERITY_META, SEVERITY_ORDER } from "../lib/severity";

type StatusTab = "open" | "acknowledged" | "resolved" | "all";

export function isOverdue(e: Escalation, now = Date.now()): boolean {
  return e.status !== "resolved" && new Date(e.dueAt).getTime() < now;
}

/** Escalations: items the SOC handed to the customer / an analyst, with SLA due dates. */
export default function EscalationsPage() {
  const session = useSession();
  const [params, setParams] = useSearchParams();
  const tabParam = params.get("status");
  const tab: StatusTab = tabParam === "acknowledged" || tabParam === "resolved" || tabParam === "all" ? tabParam : "open";
  const overdueOnly = params.get("overdue") === "1";
  const selectedId = params.get("id");
  const all = useEscalations({ limit: 500 });
  const acknowledge = useAcknowledgeEscalation();
  const resolve = useResolveEscalation();

  const setParam = (key: string, value: string | null) =>
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (value === null) next.delete(key);
      else next.set(key, value);
      return next;
    });

  const items = all.data?.items;
  const counts = useMemo(() => {
    const list = items ?? [];
    return {
      open: list.filter((e) => e.status === "open").length,
      acknowledged: list.filter((e) => e.status === "acknowledged").length,
      resolved: list.filter((e) => e.status === "resolved").length,
      all: list.length,
    };
  }, [items]);

  const rows = useMemo(() => {
    if (!items) return undefined;
    return items.filter((e) => (tab === "all" || e.status === tab) && (!overdueOnly || isOverdue(e)));
  }, [items, tab, overdueOnly]);

  const selected = items?.find((e) => e.id === selectedId) ?? null;
  const showOrg = session.organizationId === null;

  const actionButtons = (e: Escalation, size: "xs" | "sm" = "xs") => {
    if (!session.can("escalation:write", e.organizationId) || e.status === "resolved") return null;
    return (
      <span className="inline-flex gap-1" onClick={(ev) => ev.stopPropagation()}>
        {e.status === "open" ? (
          <Button size={size} onClick={() => acknowledge.mutate({ id: e.id })} loading={acknowledge.isPending && acknowledge.variables?.id === e.id}>
            Acknowledge
          </Button>
        ) : null}
        <Button size={size} variant="success" onClick={() => resolve.mutate({ id: e.id })} loading={resolve.isPending && resolve.variables?.id === e.id}>
          Resolve
        </Button>
      </span>
    );
  };

  const columns: DataTableColumn<Escalation>[] = [
    { id: "title", header: "Escalation", accessor: (e) => e.title, hideable: false, cell: (e) => <span className="font-medium text-heading">{e.title}</span> },
    {
      id: "severity",
      header: "Severity",
      accessor: (e) => e.severity,
      cell: (e) => <SeverityBadge severity={e.severity} />,
      filter: { kind: "select", options: SEVERITY_ORDER.map((s) => ({ value: s, label: SEVERITY_META[s].label })) },
    },
    { id: "status", header: "Status", accessor: (e) => e.status, cell: (e) => <StatusBadge status={e.status} /> },
    ...(showOrg ? [{ id: "org", header: "Organization", accessor: (e: Escalation) => session.organizationName(e.organizationId) ?? e.organizationId, filter: { kind: "text" as const } }] : []),
    {
      id: "due",
      header: "Due",
      accessor: (e) => new Date(e.dueAt),
      cell: (e) => (
        <span className="inline-flex items-center gap-1.5">
          <RelativeTime value={e.dueAt} className={isOverdue(e) ? "font-semibold text-sev-critical" : "text-fg-muted"} />
          {isOverdue(e) ? <Badge tone="danger" size="xs">Overdue</Badge> : null}
        </span>
      ),
    },
    { id: "created", header: "Raised", accessor: (e) => new Date(e.createdAt), cell: (e) => <RelativeTime value={e.createdAt} className="text-fg-muted" /> },
    { id: "actions", header: "", sortable: false, hideable: false, cell: (e) => actionButtons(e) },
  ];

  const mutationError = acknowledge.error ?? resolve.error;

  return (
    <div>
      <PageHeader
        title="Escalations"
        subtitle="Items that need action from your team or the customer. Overdue items breach the agreed response time."
        actions={<ReportMenu reports={["sla", "customer_monthly", "soc_operations"]} defaultReport="sla" />}
      >
        <div className="flex flex-wrap items-center gap-3">
          <Tabs<StatusTab>
            ariaLabel="Escalation status"
            idPrefix="esc"
            value={tab}
            onChange={(t) => setParam("status", t === "open" ? null : t)}
            tabs={[
              { id: "open", label: "Open", count: items ? counts.open : null },
              { id: "acknowledged", label: "Acknowledged", count: items ? counts.acknowledged : null },
              { id: "resolved", label: "Resolved", count: items ? counts.resolved : null },
              { id: "all", label: "All", count: items ? counts.all : null },
            ]}
          />
          <label className="inline-flex items-center gap-1.5 text-sm text-fg-muted">
            <input type="checkbox" checked={overdueOnly} onChange={(e) => setParam("overdue", e.target.checked ? "1" : null)} />
            Overdue only
          </label>
        </div>
      </PageHeader>
      {mutationError ? (
        <p role="alert" className="mb-2 text-sm text-sev-critical">
          {errorMessage(mutationError)}
        </p>
      ) : null}
      <DataTable
        caption="Escalations"
        columns={columns}
        rows={rows}
        getRowId={(e) => e.id}
        loading={all.isPending}
        error={all.error}
        onRetry={() => void all.refetch()}
        onRowClick={(e) => setParam("id", e.id)}
        selectedRowId={selectedId}
        initialState={{ sort: { columnId: "due", direction: "asc" } }}
        savedViewsKey="escalations"
        exportFileName="bloody-escalations"
        emptyState={
          <EmptyState
            tone="success"
            icon={CircleCheck}
            title={tab === "open" ? "All Escalations Resolved" : "No escalations here"}
            description={tab === "open" ? "Nothing is waiting on your team right now." : undefined}
          />
        }
      />
      <Drawer
        open={Boolean(selected)}
        onClose={() => setParam("id", null)}
        title={selected?.title ?? "Escalation"}
        width="md"
        footer={selected ? <div className="flex justify-end">{actionButtons(selected, "sm")}</div> : undefined}
      >
        {selected ? (
          <div className="space-y-4 p-4">
            <div className="flex flex-wrap gap-2">
              <SeverityBadge severity={selected.severity} />
              <StatusBadge status={selected.status} />
              {isOverdue(selected) ? (
                <Badge tone="danger" icon={CircleAlert}>
                  Overdue
                </Badge>
              ) : null}
            </div>
            <DescriptionList
              items={[
                { label: "Organization", value: session.organizationName(selected.organizationId) },
                { label: "Due", value: formatDateTime(selected.dueAt) },
                { label: "Raised", value: formatDateTime(selected.createdAt) },
                { label: "Resolved", value: selected.resolvedAt ? formatDateTime(selected.resolvedAt) : null },
              ]}
            />
            {selected.incidentId ? (
              <ButtonLink to={hrefForEntity("incident", selected.incidentId)} size="sm" icon={ExternalLink}>
                Open related incident
              </ButtonLink>
            ) : null}
          </div>
        ) : null}
      </Drawer>
    </div>
  );
}
