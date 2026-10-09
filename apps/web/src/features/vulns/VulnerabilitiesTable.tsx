import { Severity, type Vulnerability } from "@bloody/contracts";
import { Bug, ClipboardList, Wrench } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useUpdateVulnerability, useVulnerabilities } from "../../api/hooks";
import type { VulnerabilityFilters, VulnerabilityView } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge, SeverityBadge, StatusBadge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { DescriptionList } from "../../components/DescriptionList";
import { Field, Input, Select, Textarea } from "../../components/Form";
import { Dialog, Drawer } from "../../components/Overlay";
import { RiskScore } from "../../components/RiskScore";
import { hrefForEntity } from "../../lib/entityLinks";
import { daysUntil, formatDate, humanize } from "../../lib/format";

export type SlaState = "overdue" | "due_soon" | "on_track" | "none";

export function slaState(v: Pick<Vulnerability, "slaDueAt" | "status">, now: number = Date.now()): SlaState {
  if (!v.slaDueAt || v.status === "resolved" || v.status === "mitigated" || v.status === "accepted") return "none";
  const d = daysUntil(v.slaDueAt, now);
  if (d === null) return "none";
  if (d < 0) return "overdue";
  if (d <= 7) return "due_soon";
  return "on_track";
}

/** Why this vulnerability ranks where it does (plain-language risk-based priority). */
export function priorityReasons(v: VulnerabilityView): string[] {
  const out: string[] = [];
  if (v.knownExploited) out.push("Known exploited (CISA KEV)");
  if (v.epss !== null && v.epss >= 0.1) out.push(`High exploit probability (EPSS ${(v.epss * 100).toFixed(1)}%)`);
  if (v.cvss !== null && v.cvss >= 9) out.push(`Critical CVSS ${v.cvss.toFixed(1)}`);
  else if (v.cvss !== null && v.cvss >= 7) out.push(`High CVSS ${v.cvss.toFixed(1)}`);
  if (!v.patchAvailable) out.push("No patch available yet");
  if (slaState(v) === "overdue") out.push("Remediation SLA overdue");
  return out;
}

const PRIORITY_TONE: Record<string, "danger" | "warning" | "info" | "neutral"> = { P1: "danger", P2: "warning", P3: "info", P4: "neutral" };

const SLA_LABEL: Record<SlaState, string> = { overdue: "Overdue", due_soon: "Due ≤ 7 days", on_track: "On track", none: "—" };

function ExceptionDialog({ vuln, onClose }: { vuln: VulnerabilityView; onClose: () => void }) {
  const update = useUpdateVulnerability();
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const expiresMs = expires ? Date.parse(`${expires}T23:59:59Z`) : NaN;
  const errors = {
    reason: reason.trim().length >= 10 ? null : "Explain the business justification and compensating controls (min. 10 characters)",
    expires: expires && !Number.isNaN(expiresMs) && expiresMs > Date.now() ? (expiresMs - Date.now() > 366 * 86_400_000 ? "Exceptions can last at most one year" : null) : "Choose a future review date",
  };
  return (
    <Dialog
      open
      onClose={onClose}
      title="Request risk exception"
      description={`${vuln.cve ?? vuln.title} — exceptions are time-boxed, audited and reported.`}
      footer={
        <>
          {update.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(update.error)}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            loading={update.isPending}
            onClick={() => {
              setSubmitted(true);
              if (errors.reason || errors.expires) return;
              update.mutate({ id: vuln.id, input: { status: "accepted", reason: reason.trim(), expiresAt: new Date(expiresMs).toISOString() } }, { onSuccess: onClose });
            }}
          >
            Accept risk until {expires || "…"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {vuln.knownExploited ? <p className="rounded border border-sev-critical/30 bg-sev-critical/5 p-2 text-sm">This vulnerability is known to be exploited in the wild. Prefer mitigation over acceptance.</p> : null}
        <Field label="Justification" required error={submitted ? errors.reason : null}>
          {(p) => <Textarea {...p} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} />}
        </Field>
        <Field label="Review / expiry date" required error={submitted ? errors.expires : null}>
          {(p) => <Input {...p} type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />}
        </Field>
      </div>
    </Dialog>
  );
}

function VulnerabilityDrawer({ vuln, onClose }: { vuln: VulnerabilityView; onClose: () => void }) {
  const session = useSession();
  const update = useUpdateVulnerability();
  const [exception, setException] = useState(false);
  const canWrite = session.can("vuln:write", vuln.organizationId);
  const reasons = priorityReasons(vuln);
  return (
    <Drawer open onClose={onClose} width="lg" title={vuln.cve ?? vuln.title} subtitle={vuln.cve ? vuln.title : undefined}>
      <div className="space-y-4 px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={vuln.severity} />
          <StatusBadge status={vuln.status} />
          {vuln.knownExploited ? <Badge tone="danger">KEV</Badge> : null}
          {vuln.patchAvailable ? <Badge tone="success">Patch available</Badge> : <Badge>No patch</Badge>}
        </div>
        <div className="flex items-start gap-3">
          <RiskScore score={vuln.riskScore} factors={vuln.risk?.factors} summary={vuln.risk?.summary} modelVersion={vuln.risk?.modelVersion} size="lg" label="Risk-based priority" explanationHref={vuln.risk ? undefined : hrefForEntity("asset", vuln.assetId)} />
          <div className="text-sm">
            {vuln.priority ? <Badge tone={PRIORITY_TONE[vuln.priority] ?? "neutral"} className="mb-1">Priority {vuln.priority}</Badge> : null}
            <p className="font-medium text-fg">Why it is prioritized</p>
            {reasons.length > 0 ? (
              <ul className="mt-1 list-disc pl-4 text-fg-muted">
                {reasons.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            ) : (
              <p className="text-fg-muted">No aggravating factors beyond the base severity.</p>
            )}
          </div>
        </div>
        <DescriptionList
          items={[
            { label: "CVSS", value: vuln.cvss !== null ? vuln.cvss.toFixed(1) : null },
            { label: "EPSS", value: vuln.epss !== null ? `${(vuln.epss * 100).toFixed(2)}%${vuln.epssPercentile !== null && vuln.epssPercentile !== undefined ? ` (percentile ${Math.round(vuln.epssPercentile * 100)})` : ""}` : null },
            { label: "Asset criticality", value: vuln.assetCriticality ? humanize(vuln.assetCriticality) : null },
            { label: "Exposure", value: vuln.internetFacing === null || vuln.internetFacing === undefined ? null : vuln.internetFacing ? "Internet-facing asset" : "Internal asset" },
            { label: "SLA due", value: vuln.slaDueAt ? `${formatDate(vuln.slaDueAt)} (${SLA_LABEL[slaState(vuln)]})` : null },
            { label: "Asset", value: <Link to={hrefForEntity("asset", vuln.assetId)} className="text-primary hover:underline">{vuln.assetName ?? "Open asset"}</Link> },
            { label: "Organization", value: session.organizationName(vuln.organizationId) },
            { label: "Exception", value: vuln.status === "accepted" ? `${vuln.exceptionReason ?? "Accepted"}${vuln.exceptionExpiresAt ? ` · until ${formatDate(vuln.exceptionExpiresAt)}` : ""}` : null, wide: true },
          ]}
        />
        {vuln.cve ? (
          <a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vuln.cve)}`} target="_blank" rel="noopener noreferrer" className="text-sm text-primary hover:underline">
            NVD entry for {vuln.cve}
          </a>
        ) : null}
        {canWrite ? (
          <div className="space-y-2 border-t border-line pt-3">
            <div className="flex flex-wrap gap-2">
              <Button size="sm" icon={Wrench} disabled={vuln.status === "in_remediation"} loading={update.isPending && update.variables?.input.status === "in_remediation"} onClick={() => update.mutate({ id: vuln.id, input: { status: "in_remediation" } })}>
                Start remediation
              </Button>
              <Button size="sm" disabled={vuln.status === "mitigated"} loading={update.isPending && update.variables?.input.status === "mitigated"} onClick={() => update.mutate({ id: vuln.id, input: { status: "mitigated" } })}>
                Mark mitigated
              </Button>
              <Button size="sm" icon={ClipboardList} disabled={vuln.status === "accepted"} onClick={() => setException(true)}>
                Request exception
              </Button>
            </div>
            {update.isError ? (
              <p role="alert" className="text-sm text-sev-critical">
                {errorMessage(update.error)}
              </p>
            ) : null}
          </div>
        ) : null}
      </div>
      {exception ? <ExceptionDialog vuln={vuln} onClose={() => setException(false)} /> : null}
    </Drawer>
  );
}

/** CVE table with CVSS, EPSS, KEV, SLA and risk-based priority (shared by VM, ESPM, ASM, K8s). */
export function VulnerabilitiesTable({
  filters = {},
  predicate,
  engines = ["greenbone", "nuclei", "trivy"],
  emptyTitle = "No vulnerabilities match this view",
  description,
  savedViewsKey,
  initialId = null,
  extraColumns = [],
  toolbar,
}: {
  filters?: VulnerabilityFilters;
  predicate?: (v: VulnerabilityView) => boolean;
  engines?: string[];
  emptyTitle?: string;
  description?: ReactNode;
  savedViewsKey?: string;
  initialId?: string | null;
  /** Lens-specific columns (exception reason, SLA owner…), inserted before Priority. */
  extraColumns?: DataTableColumn<VulnerabilityView>[];
  toolbar?: ReactNode;
}) {
  const session = useSession();
  const vulns = useVulnerabilities(filters);
  const [selected, setSelected] = useState<string | null>(initialId);
  const rows = useMemo(() => vulns.items?.filter((v) => (predicate ? predicate(v) : true)), [vulns.items, predicate]);
  const sel = rows?.find((v) => v.id === selected) ?? null;

  const columns: DataTableColumn<VulnerabilityView>[] = [
    { id: "cve", header: "CVE", accessor: (v) => v.cve, cell: (v) => <span className="font-mono text-xs font-semibold">{v.cve ?? "—"}</span>, hideable: false },
    { id: "title", header: "Title", accessor: (v) => v.title, cell: (v) => <span className="line-clamp-1 max-w-[320px]" title={v.title}>{v.title}</span> },
    { id: "asset", header: "Asset", accessor: (v) => v.assetName ?? v.assetId, cell: (v) => <Link to={hrefForEntity("asset", v.assetId)} className="text-primary hover:underline" onClick={(e) => e.stopPropagation()}>{v.assetName ?? "Asset"}</Link> },
    { id: "severity", header: "Severity", accessor: (v) => Severity.options.indexOf(v.severity), cell: (v) => <SeverityBadge severity={v.severity} size="xs" /> },
    { id: "cvss", header: "CVSS", accessor: (v) => v.cvss, cell: (v) => (v.cvss !== null ? v.cvss.toFixed(1) : "—"), align: "right" },
    { id: "epss", header: "EPSS", accessor: (v) => v.epss, cell: (v) => (v.epss !== null ? `${(v.epss * 100).toFixed(1)}%` : "—"), align: "right" },
    { id: "kev", header: "KEV", accessor: (v) => (v.knownExploited ? "KEV" : "No"), cell: (v) => (v.knownExploited ? <Badge size="xs" tone="danger">KEV</Badge> : <span className="text-fg-subtle">—</span>), filter: { kind: "select", options: [{ value: "KEV", label: "Known exploited" }, { value: "No", label: "Not in KEV" }] } },
    { id: "status", header: "Status", accessor: (v) => v.status, cell: (v) => <StatusBadge status={v.status} size="xs" />, filter: { kind: "select", options: ["open", "in_remediation", "accepted", "mitigated", "resolved"].map((s) => ({ value: s, label: humanize(s) })) } },
    {
      id: "sla",
      header: "SLA due",
      accessor: (v) => (v.slaDueAt ? new Date(v.slaDueAt) : null),
      cell: (v) => {
        const s = slaState(v);
        const d = v.slaDueAt ? daysUntil(v.slaDueAt) : null;
        return v.slaDueAt ? (
          <span className={s === "overdue" ? "font-semibold text-sev-critical" : s === "due_soon" ? "text-sev-high" : "text-fg-muted"} title={formatDate(v.slaDueAt)}>
            {d !== null && d < 0 ? `${-d}d overdue` : `${d ?? "?"}d`}
          </span>
        ) : (
          <span className="text-fg-subtle">—</span>
        );
      },
    },
    { id: "patch", header: "Patch", accessor: (v) => (v.patchAvailable ? "Available" : "None"), defaultHidden: true },
    { id: "org", header: "Organization", accessor: (v) => session.organizationName(v.organizationId), defaultHidden: session.organizationId !== null },
    ...extraColumns,
    { id: "priority", header: "Priority", accessor: (v) => v.priority ?? null, cell: (v) => (v.priority ? <Badge size="xs" tone={PRIORITY_TONE[v.priority] ?? "neutral"}>{v.priority}</Badge> : <span className="text-fg-subtle">—</span>), filter: { kind: "select", options: ["P1", "P2", "P3", "P4"].map((p) => ({ value: p, label: p })) } },
    { id: "risk", header: "Risk", accessor: (v) => v.riskScore, cell: (v) => <RiskScore score={v.riskScore} factors={v.risk?.factors} summary={v.risk?.summary} size="sm" label="Risk-based priority" />, align: "right" },
  ];

  return (
    <>
      <DataTable
        caption="Vulnerabilities"
        columns={columns}
        rows={rows}
        getRowId={(v) => v.id}
        loading={vulns.isPending}
        error={vulns.error}
        onRetry={() => void vulns.refetch()}
        onRowClick={(v) => setSelected(v.id)}
        selectedRowId={selected}
        initialState={{ sort: { columnId: "risk", direction: "desc" } }}
        savedViewsKey={savedViewsKey}
        exportFileName="bloody-vulnerabilities"
        toolbar={toolbar}
        footer={
          vulns.hasNextPage ? (
            <Button size="sm" onClick={() => void vulns.fetchNextPage()} loading={vulns.isFetchingNextPage}>
              Load more
            </Button>
          ) : null
        }
        emptyState={<ConnectEngineEmptyState compact icon={Bug} title={emptyTitle} description={description} engines={engines} />}
      />
      {sel ? <VulnerabilityDrawer vuln={sel} onClose={() => setSelected(null)} /> : null}
    </>
  );
}
