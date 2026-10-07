import type { MsspOverview } from "@bloody/contracts";
import { Building2, ChartArea, Monitor, Search, Server, Siren, Users, Zap } from "lucide-react";
import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useMsspOverview } from "../api/hooks";
import { useSession } from "../app/session";
import { Badge } from "../components/Badge";
import { ButtonLink } from "../components/Button";
import { DataTable, type DataTableColumn } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { ErrorState } from "../components/ErrorState";
import { PageHeader } from "../components/PageHeader";
import { ReportMenu } from "../components/ReportMenu";
import { RiskScore } from "../components/RiskScore";
import { StatTile } from "../components/StatTile";
import { formatCurrency, formatInteger, formatPercent } from "../lib/format";

type Customer = MsspOverview["customers"][number];

function AgentHealth({ c }: { c: Customer }) {
  const healthy = Math.max(0, c.agents - c.unhealthyAgents);
  const pct = c.agents > 0 ? (healthy / c.agents) * 100 : 0;
  return (
    <div className="min-w-[110px]">
      <div className="flex justify-between text-xs">
        <span className="tabular-nums text-fg">{formatInteger(c.agents)}</span>
        <span className={c.unhealthyAgents > 0 ? "text-sev-high" : "text-fg-subtle"}>
          {c.agents > 0 ? `${formatPercent(healthy, c.agents)} healthy` : "no agents"}
        </span>
      </div>
      <div className="mt-0.5 h-1 rounded bg-surface-3" aria-hidden>
        <div className={pct >= 95 ? "h-1 rounded bg-healthy" : pct >= 80 ? "h-1 rounded bg-sev-medium" : "h-1 rounded bg-sev-critical"} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

/**
 * MSSP Command Center (/mssp): aggregate posture across every customer organization plus the
 * customer portfolio. Clicking a customer switches the organization scope to it.
 */
export default function MsspPage() {
  const session = useSession();
  const navigate = useNavigate();
  const allowed = session.isMssp && session.canSelectAll;
  const overview = useMsspOverview({ enabled: allowed });

  const columns = useMemo<DataTableColumn<Customer>[]>(
    () => [
      {
        id: "name",
        header: "Customer",
        accessor: (c) => c.name,
        cell: (c) => (
          <span className="flex items-center gap-2">
            <Building2 size={13} aria-hidden className="text-fg-muted" />
            <span className="font-medium text-heading">{c.name}</span>
          </span>
        ),
        hideable: false,
      },
      {
        id: "plan",
        header: "Plan",
        accessor: (c) => c.plan,
        cell: (c) => <Badge tone={c.plan === "trial" ? "info" : "neutral"}>{c.plan}</Badge>,
        filter: { kind: "text" },
      },
      { id: "risk", header: "Risk", accessor: (c) => c.riskScore, cell: (c) => <RiskScore score={c.riskScore} size="sm" explanationHref={`/espm?org=${c.organizationId}`} />, align: "center" },
      {
        id: "incidents",
        header: "Active incidents",
        accessor: (c) => c.activeIncidents,
        align: "right",
        cell: (c) => <span className={c.activeIncidents > 0 ? "font-semibold text-sev-high" : "text-fg-muted"}>{formatInteger(c.activeIncidents)}</span>,
      },
      {
        id: "critical",
        header: "Critical",
        accessor: (c) => c.critical,
        align: "right",
        cell: (c) => <span className={c.critical > 0 ? "font-semibold text-sev-critical" : "text-fg-muted"}>{formatInteger(c.critical)}</span>,
      },
      { id: "agents", header: "Agents health", accessor: (c) => (c.agents > 0 ? (c.agents - c.unhealthyAgents) / c.agents : null), cell: (c) => <AgentHealth c={c} /> },
      {
        id: "sla",
        header: "SLA breaches",
        accessor: (c) => c.slaBreaches,
        align: "right",
        cell: (c) => (c.slaBreaches > 0 ? <Badge tone="danger">{formatInteger(c.slaBreaches)}</Badge> : <span className="text-fg-subtle">0</span>),
      },
      { id: "mrr", header: "MRR", accessor: (c) => c.mrr, align: "right", cell: (c) => <span className="tabular-nums">{formatCurrency(c.mrr)}</span> },
    ],
    [],
  );

  if (!allowed) {
    return (
      <div>
        <PageHeader title="MSSP Command Center" />
        <div className="rounded border border-line bg-surface shadow-card">
          <EmptyState
            icon={Building2}
            title="The MSSP Command Center is available to MSSP accounts with tenant-wide access"
            description="It aggregates posture, incidents, SLA and revenue across every customer organization you manage."
            action={<ButtonLink to="/" size="sm">Back to Command Center</ButtonLink>}
          />
        </div>
      </div>
    );
  }

  const o = overview.data;
  const totalMrr = o?.customers.reduce((s, c) => s + c.mrr, 0) ?? null;
  const tiles = [
    { label: "Organizations", value: o?.organizations, icon: Building2, href: "/organizations" },
    { label: "Assets", value: o?.assets, icon: Server, href: "/assets" },
    { label: "Active Incidents", value: o?.activeIncidents, icon: Siren, tone: "high" as const, href: "/incidents?status=active&org=all" },
    { label: "Critical", value: o?.critical, icon: Zap, tone: "critical" as const, href: "/incidents?severity=critical&status=active&org=all" },
    { label: "Investigations", value: o?.investigations, icon: Search, href: "/investigations?org=all" },
    { label: "Analysts", value: o?.analysts, icon: Users, href: "/users" },
    { label: "Agents", value: o?.agents, icon: Monitor, href: "/agents?org=all" },
    { label: "Events / day", value: o?.eventsPerDay, icon: ChartArea, href: "/siem" },
  ];

  return (
    <div>
      <PageHeader
        title="MSSP Command Center"
        subtitle={`${session.account.name} · portfolio across all customer organizations`}
        actions={<ReportMenu reports={["mssp_portfolio", "sla", "analyst_activity", "customer_monthly", "executive"]} defaultReport="mssp_portfolio" organizationId={null} />}
      />
      {overview.isError ? (
        <div className="rounded border border-line bg-surface shadow-card">
          <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />
        </div>
      ) : (
        <>
          <div className="mb-3 grid grid-cols-2 gap-3 md:grid-cols-4 2xl:grid-cols-8" data-testid="mssp-kpis">
            {tiles.map((t) => (
              <StatTile key={t.label} label={t.label} value={t.value} icon={t.icon} tone={t.tone ?? "default"} href={t.href} loading={overview.isPending} />
            ))}
          </div>
          <h2 className="mb-2 text-md font-semibold text-fg">Customer portfolio</h2>
          <DataTable
            caption="Customer portfolio"
            columns={columns}
            rows={o?.customers}
            getRowId={(c) => c.organizationId}
            loading={overview.isPending}
            error={overview.error}
            onRetry={() => void overview.refetch()}
            onRowClick={(c) => navigate(`/?org=${encodeURIComponent(c.organizationId)}`)}
            initialState={{ sort: { columnId: "risk", direction: "desc" } }}
            savedViewsKey="mssp.portfolio"
            exportFileName="bloody-customer-portfolio"
            searchPlaceholder="Search customers…"
            emptyState={
              <EmptyState
                icon={Building2}
                title="No customer organizations yet"
                description="Create your first customer organization to start onboarding agents and integrations."
                action={<ButtonLink to="/organizations?create=1" variant="primary" size="sm">Create organization</ButtonLink>}
              />
            }
            footer={totalMrr !== null && o && o.customers.length > 0 ? <span>Total MRR {formatCurrency(totalMrr)}</span> : null}
          />
        </>
      )}
    </div>
  );
}
