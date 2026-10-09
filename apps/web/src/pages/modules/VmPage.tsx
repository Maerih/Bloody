import { AlarmClock, Bug, Earth, Flame, PackageCheck, Server, Siren } from "lucide-react";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useVulnerabilitySummary } from "../../api/hooks";
import type { VulnerabilityView } from "../../api/types";
import { Badge } from "../../components/Badge";
import { Card } from "../../components/Card";
import type { DataTableColumn } from "../../components/DataTable";
import { ErrorState } from "../../components/ErrorState";
import { Meter } from "../../components/Meter";
import { RelativeTime } from "../../components/RelativeTime";
import { SkeletonText } from "../../components/Skeleton";
import { StatTile } from "../../components/StatTile";
import { EventsLens } from "../../features/events/EventsLens";
import { IntegrationStatusList } from "../../features/integrations/IntegrationStatusList";
import { KpiGrid, ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { slaState, VulnerabilitiesTable } from "../../features/vulns/VulnerabilitiesTable";
import { daysUntil, formatDate, formatInteger } from "../../lib/format";

const SCANNERS = ["greenbone", "nuclei", "trivy", "grype"];
const OPEN: VulnerabilityView["status"][] = ["open", "in_remediation"];

/** Risk-based posture KPIs (GET /vulnerabilities/summary). */
function PostureKpis() {
  const summary = useVulnerabilitySummary();
  const s = summary.data;
  if (summary.isError) {
    return (
      <div className="mb-4 rounded border border-line bg-surface shadow-card">
        <ErrorState error={summary.error} compact onRetry={() => void summary.refetch()} />
      </div>
    );
  }
  return (
    <KpiGrid>
      <StatTile label="Open vulnerabilities" value={s?.open} loading={summary.isPending} icon={Bug} href="/vm/vulnerabilities" />
      <StatTile label="P1 — fix first" value={s?.byPriority.P1} loading={summary.isPending} icon={Flame} tone={(s?.byPriority.P1 ?? 0) > 0 ? "critical" : "healthy"} href="/vm/vulnerabilities?priority=P1" hint="Risk Engine priority" />
      <StatTile label="Known exploited (KEV)" value={s?.knownExploited} loading={summary.isPending} icon={Siren} tone={(s?.knownExploited ?? 0) > 0 ? "critical" : "healthy"} href="/vm/kev" />
      <StatTile label="KEV on internet-facing" value={s?.knownExploitedOnInternetFacing} loading={summary.isPending} icon={Earth} tone={(s?.knownExploitedOnInternetFacing ?? 0) > 0 ? "critical" : "healthy"} href="/vm/kev?internet=1" />
      <StatTile label="SLA overdue" value={s?.overdueSla} loading={summary.isPending} icon={AlarmClock} tone={(s?.overdueSla ?? 0) > 0 ? "high" : "healthy"} href="/vm/remediation" />
      <StatTile label="Affected assets" value={s?.affectedAssets} loading={summary.isPending} icon={Server} hint={s ? `${formatInteger(s.patchAvailable)} with a patch available` : undefined} />
    </KpiGrid>
  );
}

function PriorityBreakdown() {
  const summary = useVulnerabilitySummary();
  const s = summary.data;
  return (
    <Card title="Risk-based priority" info="Priority combines CVSS, EPSS exploit probability, CISA KEV, asset criticality and internet exposure — not CVSS alone.">
      {summary.isPending ? (
        <SkeletonText lines={4} />
      ) : !s ? null : (
        <div className="space-y-2.5">
          {(["P1", "P2", "P3", "P4"] as const).map((p) => (
            <Meter key={p} label={p} used={s.byPriority[p]} limit={s.open} format={formatInteger} />
          ))}
          <p className="text-xs text-fg-muted">
            KEV / EPSS enrichment {s.lastEnrichedAt ? <>last ran <RelativeTime value={s.lastEnrichedAt} /></> : "has not run yet"}
            {s.enrichmentEnabled === false ? " (disabled in this deployment)" : ""}.
          </p>
        </div>
      )}
    </Card>
  );
}

type SlaView = "overdue" | "due_soon" | "all";

function Remediation() {
  const [view, setView] = useState<SlaView>("overdue");
  const predicate = useMemo(() => (view === "all" ? undefined : (v: VulnerabilityView) => slaState(v) === view), [view]);
  const columns = useMemo<DataTableColumn<VulnerabilityView>[]>(
    () => [
      {
        id: "slaState",
        header: "SLA state",
        accessor: (v) => slaState(v),
        cell: (v) => {
          const s = slaState(v);
          return s === "overdue" ? <Badge size="xs" tone="danger">Overdue</Badge> : s === "due_soon" ? <Badge size="xs" tone="warning">Due ≤ 7 days</Badge> : s === "on_track" ? <Badge size="xs" tone="success">On track</Badge> : <span className="text-fg-subtle">—</span>;
        },
      },
    ],
    [],
  );
  return (
    <div className="space-y-3">
      <div role="group" aria-label="SLA view" className="inline-flex rounded border border-line-strong bg-surface p-0.5">
        {(
          [
            ["overdue", "Overdue"],
            ["due_soon", "Due within 7 days"],
            ["all", "All open by due date"],
          ] as [SlaView, string][]
        ).map(([id, label]) => (
          <button key={id} type="button" aria-pressed={view === id} onClick={() => setView(id)} className={`rounded px-2.5 py-0.5 text-sm ${view === id ? "bg-primary text-white" : "text-fg-muted hover:text-fg"}`}>
            {label}
          </button>
        ))}
      </div>
      <VulnerabilitiesTable
        key={view}
        filters={{ status: OPEN, sort: "sla", ...(view === "overdue" ? { overdue: true } : {}) }}
        predicate={predicate}
        extraColumns={columns}
        emptyTitle={view === "overdue" ? "No remediation SLA is overdue" : view === "due_soon" ? "Nothing is due in the next 7 days" : "No open vulnerabilities"}
        savedViewsKey="vm-remediation"
      />
    </div>
  );
}

function Exceptions() {
  const columns = useMemo<DataTableColumn<VulnerabilityView>[]>(
    () => [
      { id: "exceptionReason", header: "Justification", accessor: (v) => v.exceptionReason ?? null, cell: (v) => <span className="line-clamp-2 max-w-[320px] text-xs text-fg-muted" title={v.exceptionReason ?? undefined}>{v.exceptionReason ?? "—"}</span> },
      {
        id: "exceptionExpires",
        header: "Review by",
        accessor: (v) => (v.exceptionExpiresAt ? new Date(v.exceptionExpiresAt) : null),
        cell: (v) => {
          if (!v.exceptionExpiresAt) return <span className="text-sev-high">No expiry</span>;
          const d = daysUntil(v.exceptionExpiresAt);
          return <span className={d !== null && d < 0 ? "font-semibold text-sev-critical" : d !== null && d <= 14 ? "text-sev-high" : "text-fg-muted"}>{d !== null && d < 0 ? `Expired ${formatDate(v.exceptionExpiresAt)}` : formatDate(v.exceptionExpiresAt)}</span>;
        },
      },
    ],
    [],
  );
  return (
    <div className="space-y-2">
      <p className="text-sm text-fg-muted">Accepted risks with their business justification and review date. Expired exceptions should be re-reviewed or remediated; every acceptance is audited.</p>
      <VulnerabilitiesTable filters={{ status: ["accepted"] }} extraColumns={columns} emptyTitle="No risk-acceptance exceptions" description="Open a vulnerability and choose “Accept risk” to record a time-bound exception." savedViewsKey="vm-exceptions" />
    </div>
  );
}

function Scanners() {
  const summary = useVulnerabilitySummary();
  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_360px]">
      <Card title="Scanner connections" padded={false} info="Network (Greenbone/OpenVAS), template (Nuclei) and image / IaC (Trivy, Grype) scanners run as separate services; findings are normalized and de-duplicated per asset and CVE.">
        <IntegrationStatusList engines={SCANNERS} />
      </Card>
      <Card title="Enrichment" actions={<PackageCheck size={14} className="text-fg-muted" aria-hidden />}>
        <dl className="space-y-2 text-sm">
          <div className="flex justify-between gap-2">
            <dt className="text-fg-muted">CISA KEV & FIRST EPSS</dt>
            <dd className="font-medium">{summary.data ? (summary.data.enrichmentEnabled === false ? "Disabled" : "Enabled") : "…"}</dd>
          </div>
          <div className="flex justify-between gap-2">
            <dt className="text-fg-muted">Last enrichment</dt>
            <dd className="font-medium">{summary.data?.lastEnrichedAt ? <RelativeTime value={summary.data.lastEnrichedAt} /> : "Never"}</dd>
          </div>
        </dl>
        <p className="mt-3 text-xs text-fg-muted">Free, key-less sources only: the CISA Known Exploited Vulnerabilities catalogue and FIRST EPSS scores.</p>
      </Card>
    </div>
  );
}

/** VM workspace: risk-based prioritization (CVSS, EPSS, KEV, criticality), SLA, exceptions, scanners. */
export default function VmPage() {
  const [params] = useSearchParams();
  const priority = (["P1", "P2", "P3", "P4"] as const).find((p) => p === params.get("priority"));
  const q = params.get("q") ?? undefined;
  const asset = params.get("asset") ?? undefined;
  const id = params.get("id");
  return (
    <ModuleWorkspace
      moduleId="vm"
      aliases={{ "/vulnerabilities": "vulnerabilities" }}
      sections={{
        "": () => (
          <div className="space-y-4">
            <PostureKpis />
            <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_340px]">
              <div className="min-w-0">
                <h2 className="mb-2 text-md font-semibold text-fg">Fix first</h2>
                <VulnerabilitiesTable filters={{ status: OPEN, priority: ["P1", "P2"] }} emptyTitle="No P1 or P2 vulnerabilities" savedViewsKey="vm-fix-first" />
              </div>
              <PriorityBreakdown />
            </div>
          </div>
        ),
        vulnerabilities: () => (
          <VulnerabilitiesTable
            filters={{ ...(q ? { q } : {}), ...(asset ? { assetId: asset } : {}), ...(priority ? { priority: [priority], status: OPEN } : {}) }}
            initialId={id}
            emptyTitle={asset ? "No vulnerabilities on this asset" : "No vulnerabilities match this view"}
            savedViewsKey="vm-all"
          />
        ),
        kev: () => (
          <div className="space-y-2">
            <p className="text-sm text-fg-muted">Vulnerabilities in the CISA Known Exploited Vulnerabilities catalogue — attackers use these in the wild, so they outrank CVSS-only severity.</p>
            <VulnerabilitiesTable
              filters={{ knownExploited: true, status: OPEN, ...(params.get("internet") === "1" ? { internetFacing: true } : {}) }}
              emptyTitle="No known-exploited vulnerabilities in this environment"
              savedViewsKey="vm-kev"
            />
          </div>
        ),
        software: () => (
          <EventsLens
            title="Software inventory"
            query="labels.pkg.name:* OR labels.osquery.query:(programs OR deb_packages OR rpm_packages OR apps OR homebrew_packages)"
            engines={["osquery", "trivy", "grype"]}
            defaultRange={{ preset: "30d" }}
            description="Installed packages reported by agents (osquery) and image / SBOM scanners (Trivy, Grype)."
            aggregations={[
              { title: "Packages", field: "labels.pkg.name", value: (e) => e.labels?.["pkg.name"] ?? e.labels?.["osquery.col.name"] ?? null },
              { title: "Package versions", field: "labels.pkg.installed_version", value: (e) => (e.labels?.["pkg.name"] ? `${e.labels["pkg.name"]}@${e.labels["pkg.installed_version"] ?? "?"}` : e.labels?.["osquery.col.version"] ? `${e.labels["osquery.col.name"] ?? "?"}@${e.labels["osquery.col.version"]}` : null) },
              { title: "Hosts & artifacts", field: "asset.hostname", value: (e) => e.asset?.hostname ?? e.labels?.["artifact.name"] ?? null },
            ]}
          />
        ),
        remediation: () => <Remediation />,
        exceptions: () => <Exceptions />,
        scanners: () => <Scanners />,
      }}
    />
  );
}
