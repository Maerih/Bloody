import { MODULES, PLANS, type PlanKey } from "@bloody/contracts";
import { CreditCard, Gauge } from "lucide-react";
import { useBillingUsage, useEntitlements } from "../../api/hooks";
import type { BillingUsage } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge, StatusBadge } from "../../components/Badge";
import { ButtonLink } from "../../components/Button";
import { Card } from "../../components/Card";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { EmptyState } from "../../components/EmptyState";
import { ErrorState } from "../../components/ErrorState";
import { Meter } from "../../components/Meter";
import { PageHeader } from "../../components/PageHeader";
import { RelativeTime } from "../../components/RelativeTime";
import { SkeletonText } from "../../components/Skeleton";
import type { EntitlementView } from "../../api/types";
import { formatDate, formatInteger, formatNumber } from "../../lib/format";

export const METER_LABELS: Record<string, { label: string; daily: boolean }> = {
  endpoints: { label: "Protected endpoints", daily: false },
  organizations: { label: "Organizations", daily: false },
  users: { label: "Users", daily: false },
  eventsPerDay: { label: "Events ingested today", daily: true },
  aiRequestsPerDay: { label: "AI requests today", daily: true },
};

export interface MeterRow {
  key: string;
  label: string;
  used: number;
  limit: number | null;
  resetsAt: string | null;
}

/** Normalize GET /billing/usage into display rows (known meters first, then any extra meters). */
export function meterRows(usage: BillingUsage): MeterRow[] {
  const keys = [...Object.keys(METER_LABELS).filter((k) => k in usage.usage), ...Object.keys(usage.usage).filter((k) => !(k in METER_LABELS))];
  return keys.map((key) => {
    const u = usage.usage[key]!;
    return { key, label: METER_LABELS[key]?.label ?? key, used: u.used, limit: u.limit ?? null, resetsAt: u.resetsAt ?? null };
  });
}

/** Billing & usage: plan, contracted limits vs live usage meters, module entitlements. */
export default function BillingPage() {
  const session = useSession();
  const allowed = session.canAnywhere("billing:read");
  const usage = useBillingUsage({ enabled: allowed });
  const entitlements = useEntitlements();
  const plan: PlanKey = usage.data?.limits?.plan ?? usage.data?.plan ?? session.plan;
  const def = PLANS[plan];
  const overrides = usage.data?.limits?.overrides ?? {};

  const entColumns: DataTableColumn<EntitlementView>[] = [
    { id: "module", header: "Module", accessor: (e) => MODULES.find((m) => m.key === e.module)?.name ?? e.module, hideable: false },
    { id: "state", header: "State", accessor: (e) => e.state, cell: (e) => <StatusBadge status={e.state} size="xs" /> },
    { id: "trial", header: "Trial ends", accessor: (e) => (e.trialEndsAt ? new Date(e.trialEndsAt) : null), cell: (e) => (e.trialEndsAt ? formatDate(e.trialEndsAt) : <span className="text-fg-subtle">—</span>) },
  ];

  if (!allowed) {
    return (
      <div>
        <PageHeader title="Billing & Usage" />
        <div className="rounded border border-line bg-surface shadow-card">
          <EmptyState icon={CreditCard} title="You don't have access to billing" description="Billing requires the billing:read permission." />
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="Billing & Usage"
        subtitle="Your plan, its limits and live usage. Daily meters reset at 00:00 UTC; capacity meters count what exists now."
        breadcrumbs={[{ label: "Settings", href: "/settings" }, { label: "Billing & Usage" }]}
        actions={
          <ButtonLink size="sm" to="/trials">
            Trials & modules
          </ButtonLink>
        }
      />
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_340px]">
        <Card title="Usage vs limits" actions={<Gauge size={14} className="text-fg-muted" aria-hidden />} info="Measured by the platform's metering (usage_counters). When a meter reaches its limit, new endpoints/organizations/users are refused and an automation event fires.">
          {usage.isPending ? (
            <SkeletonText lines={5} />
          ) : usage.isError ? (
            <ErrorState error={usage.error} compact onRetry={() => void usage.refetch()} />
          ) : (
            <div className="space-y-3" data-testid="usage-meters">
              {meterRows(usage.data).map((m) => (
                <Meter
                  key={m.key}
                  label={m.label}
                  used={m.used}
                  limit={m.limit}
                  format={(n) => (n >= 100_000 ? formatNumber(n) : formatInteger(n))}
                />
              ))}
              {meterRows(usage.data).some((m) => m.resetsAt) ? (
                <p className="text-xs text-fg-subtle">
                  Daily meters reset <RelativeTime value={meterRows(usage.data).find((m) => m.resetsAt)!.resetsAt!} />.
                </p>
              ) : null}
            </div>
          )}
        </Card>
        <Card title="Plan" actions={<CreditCard size={14} className="text-fg-muted" aria-hidden />}>
          <p className="text-xl font-semibold text-heading">{def.name}</p>
          <p className="mb-3 text-sm text-fg-muted">{session.account.kind === "mssp" ? "MSSP / MDR account" : "Enterprise account"} · data region {session.account.dataRegion}</p>
          <dl className="space-y-1.5 text-sm">
            {(
              [
                ["Endpoints", "endpoints"],
                ["Organizations", "organizations"],
                ["Users", "users"],
                ["Events / day", "eventsPerDay"],
                ["Hot retention (days)", "retentionDays"],
                ["AI requests / day", "aiRequestsPerDay"],
              ] as const
            ).map(([label, key]) => (
              <div key={key} className="flex justify-between gap-2">
                <dt className="text-fg-muted">{label}</dt>
                <dd className="font-medium tabular-nums">
                  {formatNumber(overrides[key] ?? usage.data?.limits?.limits[key] ?? def.limits[key])}
                  {overrides[key] !== undefined ? <Badge size="xs" tone="info" className="ml-1">contracted</Badge> : null}
                </dd>
              </div>
            ))}
          </dl>
          <p className="mt-3 text-xs text-fg-muted">Modules: {def.modules === "all" ? "all modules" : `${def.modules.length} included`}. Need more? Contact your account team.</p>
        </Card>
      </div>
      <div className="mt-3">
        <DataTable
          caption="Module entitlements"
          columns={entColumns}
          rows={entitlements.data ?? session.entitlements}
          getRowId={(e) => e.module}
          loading={entitlements.isPending && session.entitlements.length === 0}
          initialState={{ sort: { columnId: "module", direction: "asc" } }}
          exportFileName="bloody-entitlements"
          emptyState={<EmptyState compact title="No module entitlements" />}
        />
      </div>
    </div>
  );
}
