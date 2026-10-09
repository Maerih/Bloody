import { CheckCircle2, Search, ShieldCheck, ScrollText, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useAuditLog, useVerifyAudit } from "../../api/hooks";
import type { AuditFilters, AuditRecord } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { DescriptionList } from "../../components/DescriptionList";
import { EmptyState } from "../../components/EmptyState";
import { Input, Select } from "../../components/Form";
import { JsonView } from "../../components/JsonView";
import { Drawer } from "../../components/Overlay";
import { PageHeader } from "../../components/PageHeader";
import { RelativeTime } from "../../components/RelativeTime";
import { useActorName } from "../../features/users/useActorName";
import { useDebouncedValue } from "../../hooks/useDebouncedValue";
import { formatDateTime, formatInteger } from "../../lib/format";

const OUTCOME_TONE = { success: "success", denied: "warning", failure: "danger" } as const;
const ACTOR_KINDS = ["user", "service", "system", "anonymous"] as const;
const OUTCOMES = ["success", "denied", "failure"] as const;

/** URL query → audit filters (shareable, e.g. from an incident "who changed this?" pivot). */
export function auditFiltersFromParams(params: URLSearchParams, debouncedText: { action: string; target: string; requestId: string }): AuditFilters {
  const actorKind = ACTOR_KINDS.find((k) => k === params.get("actor"));
  const outcome = OUTCOMES.find((o) => o === params.get("outcome"));
  const from = params.get("from");
  const to = params.get("to");
  const isDate = (v: string | null) => v !== null && /^\d{4}-\d{2}-\d{2}$/.test(v);
  return {
    ...(debouncedText.action.trim() ? { action: debouncedText.action.trim() } : {}),
    ...(debouncedText.target.trim() ? { targetId: debouncedText.target.trim() } : {}),
    ...(debouncedText.requestId.trim() ? { requestId: debouncedText.requestId.trim() } : {}),
    ...(actorKind ? { actorKind } : {}),
    ...(outcome ? { outcome: [outcome] } : {}),
    ...(isDate(from) ? { from: new Date(`${from}T00:00:00Z`).toISOString() } : {}),
    ...(isDate(to) ? { to: new Date(`${to}T23:59:59.999Z`).toISOString() } : {}),
  };
}

function AuditDrawer({ record, onClose }: { record: AuditRecord; onClose: () => void }) {
  const session = useSession();
  const { name } = useActorName();
  return (
    <Drawer open onClose={onClose} width="lg" title={record.action} subtitle={formatDateTime(record.at)}>
      <div className="space-y-4 p-4">
        <DescriptionList
          items={[
            { label: "Outcome", value: <Badge tone={OUTCOME_TONE[record.outcome as keyof typeof OUTCOME_TONE] ?? "neutral"}>{record.outcome}</Badge> },
            { label: "Actor", value: `${record.actor.label ?? (record.actor.id ? name(record.actor.id) : record.actor.kind)} (${record.actor.kind})` },
            { label: "Target", value: record.target ? `${record.target.kind ?? "—"} ${record.target.id ?? ""}` : null },
            { label: "Organization", value: record.organizationId ? session.organizationName(record.organizationId) : "Tenant" },
            { label: "IP address", value: record.ip },
            { label: "Request id", value: record.requestId ? <span className="font-mono text-xs">{record.requestId}</span> : null },
            { label: "User agent", value: record.userAgent, wide: true },
            { label: "Sequence", value: formatInteger(record.seq) },
          ]}
        />
        <section>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-fg-muted">Details</h3>
          <JsonView value={record.details} maxHeight="16rem" />
        </section>
        <section>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-fg-muted">Hash chain</h3>
          <p className="mb-1 text-xs text-fg-muted">Each record hashes the previous one, so any edit or deletion breaks the chain.</p>
          <dl className="space-y-1 font-mono text-2xs">
            <div>
              <dt className="inline text-fg-subtle">prev </dt>
              <dd className="inline break-all">{record.prevHash ?? "genesis"}</dd>
            </div>
            <div>
              <dt className="inline text-fg-subtle">hash </dt>
              <dd className="inline break-all">{record.hash}</dd>
            </div>
          </dl>
        </section>
      </div>
    </Drawer>
  );
}

/** Audit log: every mutating action (actor, target, outcome, IP, request id) with hash-chain verification. */
export default function AuditLogPage() {
  const session = useSession();
  const [params, setParams] = useSearchParams();
  const { name } = useActorName();
  const [action, setAction] = useState(params.get("action") ?? "");
  const [target, setTarget] = useState(params.get("target") ?? "");
  const [requestId, setRequestId] = useState(params.get("requestId") ?? "");
  const debounced = useDebouncedValue(useMemo(() => ({ action, target, requestId }), [action, target, requestId]), 350);
  const filters = useMemo(() => auditFiltersFromParams(params, debounced), [params, debounced]);
  const allowed = session.canAnywhere("audit:read");
  const audit = useAuditLog(filters, { enabled: allowed });
  const verify = useVerifyAudit();
  const [selected, setSelected] = useState<AuditRecord | null>(null);
  const set = (key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };

  const columns: DataTableColumn<AuditRecord>[] = [
    { id: "at", header: "Time", accessor: (r) => new Date(r.at), cell: (r) => <span title={formatDateTime(r.at)}><RelativeTime value={r.at} /></span> },
    { id: "actor", header: "Actor", accessor: (r) => r.actor.label ?? (r.actor.id ? name(r.actor.id) : r.actor.kind), cell: (r) => <span><span className="block">{r.actor.label ?? (r.actor.id ? name(r.actor.id) : r.actor.kind)}</span><span className="block text-2xs text-fg-subtle">{r.actor.kind}</span></span> },
    { id: "action", header: "Action", accessor: (r) => r.action, hideable: false, cell: (r) => <span className="font-mono text-xs">{r.action}</span> },
    { id: "target", header: "Target", accessor: (r) => (r.target ? `${r.target.kind ?? ""} ${r.target.id ?? ""}` : null), cell: (r) => (r.target ? <span className="text-xs"><span className="text-fg-muted">{r.target.kind}</span> <span className="font-mono">{r.target.id?.slice(0, 8)}</span></span> : <span className="text-fg-subtle">—</span>) },
    { id: "outcome", header: "Outcome", accessor: (r) => r.outcome, cell: (r) => <Badge size="xs" tone={OUTCOME_TONE[r.outcome as keyof typeof OUTCOME_TONE] ?? "neutral"}>{r.outcome}</Badge> },
    { id: "org", header: "Organization", accessor: (r) => (r.organizationId ? session.organizationName(r.organizationId) : "Tenant"), defaultHidden: session.organizationId !== null },
    { id: "ip", header: "IP", accessor: (r) => r.ip, cell: (r) => <span className="font-mono text-xs">{r.ip ?? "—"}</span> },
    { id: "request", header: "Request id", accessor: (r) => r.requestId, cell: (r) => <span className="font-mono text-2xs text-fg-subtle">{r.requestId ?? "—"}</span>, defaultHidden: true },
  ];

  if (!allowed) {
    return (
      <div>
        <PageHeader title="Audit Log" />
        <div className="rounded border border-line bg-surface shadow-card">
          <EmptyState icon={ScrollText} title="You don't have access to the audit log" description="The audit log requires the audit:read permission." />
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="Audit Log"
        subtitle="Every mutating action — who, what, which target, from where, with the request id — in a tamper-evident hash chain."
        breadcrumbs={[{ label: "Settings", href: "/settings" }, { label: "Audit Log" }]}
        actions={
          <Button icon={ShieldCheck} loading={verify.isPending} onClick={() => verify.mutate()}>
            Verify integrity
          </Button>
        }
      />
      {verify.data ? (
        <p role="status" className={`mb-3 flex items-center gap-2 rounded border px-3 py-2 text-sm ${verify.data.intact ? "border-healthy/30 bg-healthy-soft text-healthy" : "border-sev-critical/30 bg-sev-critical/5 text-sev-critical"}`}>
          {verify.data.intact ? <CheckCircle2 size={14} aria-hidden /> : <XCircle size={14} aria-hidden />}
          {verify.data.intact
            ? `Hash chain intact across ${formatInteger(verify.data.records)} records (head #${verify.data.headSeq ?? "—"}).`
            : `Hash chain broken at record #${verify.data.firstBrokenSeq ?? "?"} — escalate to your security officer.`}
        </p>
      ) : verify.isError ? (
        <p role="alert" className="mb-3 text-sm text-sev-critical">
          {errorMessage(verify.error)}
        </p>
      ) : null}
      <div className="mb-2 flex flex-wrap items-end gap-2" role="search" aria-label="Filter audit log">
        <label className="relative w-56">
          <Search size={13} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-fg-subtle" aria-hidden />
          <Input value={action} onChange={(e) => setAction(e.target.value)} onBlur={() => set("action", action.trim() || null)} placeholder="Action, e.g. incident.updated" className="pl-7" aria-label="Action" />
        </label>
        <Select value={params.get("actor") ?? ""} onChange={(e) => set("actor", e.target.value || null)} className="w-36" aria-label="Actor kind">
          <option value="">Any actor</option>
          {ACTOR_KINDS.map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </Select>
        <Select value={params.get("outcome") ?? ""} onChange={(e) => set("outcome", e.target.value || null)} className="w-36" aria-label="Outcome">
          <option value="">Any outcome</option>
          {OUTCOMES.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </Select>
        <Input value={target} onChange={(e) => setTarget(e.target.value)} onBlur={() => set("target", target.trim() || null)} placeholder="Target id" className="w-56 font-mono text-xs" aria-label="Target id" />
        <Input value={requestId} onChange={(e) => setRequestId(e.target.value)} onBlur={() => set("requestId", requestId.trim() || null)} placeholder="Request id" className="w-44 font-mono text-xs" aria-label="Request id" />
        <label className="flex flex-col text-2xs text-fg-muted">
          From
          <Input type="date" value={params.get("from") ?? ""} onChange={(e) => set("from", e.target.value || null)} className="h-8 w-36" aria-label="From date" />
        </label>
        <label className="flex flex-col text-2xs text-fg-muted">
          To
          <Input type="date" value={params.get("to") ?? ""} onChange={(e) => set("to", e.target.value || null)} className="h-8 w-36" aria-label="To date" />
        </label>
      </div>
      <DataTable
        caption="Audit log"
        columns={columns}
        rows={audit.items}
        getRowId={(r) => r.id}
        loading={audit.isPending}
        error={audit.error}
        onRetry={() => void audit.refetch()}
        onRowClick={setSelected}
        selectedRowId={selected?.id ?? null}
        searchable={false}
        initialState={{ sort: { columnId: "at", direction: "desc" } }}
        exportFileName="bloody-audit-log"
        footer={
          audit.hasNextPage ? (
            <Button size="sm" onClick={() => void audit.fetchNextPage()} loading={audit.isFetchingNextPage}>
              Load older records
            </Button>
          ) : null
        }
        emptyState={<EmptyState compact icon={ScrollText} title="No audit records match these filters" />}
      />
      {selected ? <AuditDrawer record={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  );
}
