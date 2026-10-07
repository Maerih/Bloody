import type { ReportSchedule, ReportType } from "@bloody/contracts";
import { BriefcaseBusiness, Building2, CalendarClock, FileText, MailPlus, Send, ShieldHalf, Users, Webhook, type LucideIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { errorMessage } from "../../api/client";
import { useNotificationChannels, useReportSchedules, useReportTypes, useTestNotificationChannel } from "../../api/hooks";
import type { ReportTypeInfo } from "../../api/types";
import { DASHBOARD_PRESETS } from "../../app/dashboardPresets";
import { useSession } from "../../app/session";
import { Badge, StatusBadge } from "../../components/Badge";
import { Button, ButtonLink } from "../../components/Button";
import { Card } from "../../components/Card";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { EmptyState } from "../../components/EmptyState";
import { ErrorState } from "../../components/ErrorState";
import { PageHeader } from "../../components/PageHeader";
import { RelativeTime } from "../../components/RelativeTime";
import { ReportMenu } from "../../components/ReportMenu";
import { CHANNEL_ICONS, ScheduleReportDialog } from "../../components/ScheduleReportDialog";
import { CardSkeleton, SkeletonText } from "../../components/Skeleton";
import { Tabs } from "../../components/Tabs";
import { describeCron, plural } from "../../lib/format";
import { reportLabel } from "../../lib/reports";

type Audience = "all" | "business" | "soc" | "mssp" | "customer";

const AUDIENCES: { id: Audience; label: string; icon: LucideIcon; description: string }[] = [
  { id: "all", label: "All reports", icon: FileText, description: "" },
  { id: "business", label: "Business & executive", icon: BriefcaseBusiness, description: "Board-ready risk, exposure and compliance posture." },
  { id: "soc", label: "SOC", icon: ShieldHalf, description: "Operational detail for analysts, responders and engineers." },
  { id: "mssp", label: "MSSP", icon: Building2, description: "Portfolio, SLA and analyst performance across customers." },
  { id: "customer", label: "Customer", icon: Users, description: "Service reviews you send to each customer organization." },
];

/** Product copy describing what each report contains (not data). */
const REPORT_COPY: Partial<Record<ReportType, string>> = {
  executive: "Risk and exposure trends, incidents by business impact, MTTD/MTTR and top recommendations.",
  soc_operations: "Event → signal → incident funnel, analyst workload, detections fired and response actions.",
  incident: "Full incident narrative: timeline, ATT&CK techniques, affected entities, risk explanation and actions.",
  vulnerability: "Exposure and vulnerability posture prioritized by KEV, EPSS, asset criticality and SLA.",
  threat_intel: "Indicator matches in your environment, active campaigns and actor activity.",
  compliance: "Control coverage and posture evidence across cloud, identity and endpoint.",
  sla: "Acknowledge / response / resolution times against contracted SLAs, with breaches.",
  analyst_activity: "Per-analyst triage, investigation and escalation throughput and quality.",
  customer_monthly: "Monthly service review: incidents handled, escalations, coverage and recommendations.",
  mssp_portfolio: "Customer portfolio risk, incidents, agent health, SLA breaches and MRR.",
};

/**
 * Reports Center (/reports): on-demand generation for every audience (business, SOC, MSSP,
 * customer), recurring schedules and their email / chat delivery channels.
 */
export default function ReportsPage() {
  const session = useSession();
  const [audience, setAudience] = useState<Audience>("all");
  const [scheduleFor, setScheduleFor] = useState<ReportType | null>(null);
  const types = useReportTypes();
  const schedules = useReportSchedules();
  const channels = useNotificationChannels({ enabled: session.canAnywhere("report:read") });
  const testChannel = useTestNotificationChannel();
  const canSchedule = session.can("report:write");
  const msspScope = session.isMssp && session.canSelectAll;

  const visibleTypes = useMemo<ReportTypeInfo[]>(
    () => (types.data ?? []).filter((t) => (t.audience === "mssp" ? msspScope : true)).filter((t) => audience === "all" || t.audience === audience),
    [types.data, audience, msspScope],
  );
  const channelName = useMemo(() => new Map((channels.data ?? []).map((c) => [c.id, c.name])), [channels.data]);
  const preset = DASHBOARD_PRESETS[session.dashboardRole];
  const scheduleReports = (types.data ?? []).filter((t) => (t.audience === "mssp" ? msspScope : true)).map((t) => t.key);

  const columns: DataTableColumn<ReportSchedule>[] = [
    { id: "name", header: "Schedule", accessor: (s) => s.name, hideable: false, cell: (s) => <span className="font-medium text-heading">{s.name}</span> },
    { id: "type", header: "Report", accessor: (s) => reportLabel(s.type) },
    { id: "cron", header: "When", accessor: (s) => describeCron(s.cron) },
    { id: "format", header: "Format", accessor: (s) => s.format.toUpperCase() },
    { id: "period", header: "Period", accessor: (s) => s.periodDays, cell: (s) => `${s.periodDays} days` },
    {
      id: "channels",
      header: "Delivered to",
      accessor: (s) => s.channelIds.map((id) => channelName.get(id) ?? id).join(", "),
      cell: (s) =>
        s.channelIds.length === 0 ? (
          <span className="text-fg-subtle">Archive only</span>
        ) : (
          <span className="truncate">{s.channelIds.map((id) => channelName.get(id) ?? "Unknown channel").join(", ")}</span>
        ),
    },
    { id: "scope", header: "Scope", accessor: (s) => (s.organizationId ? (session.organizationName(s.organizationId) ?? s.organizationId) : "All organizations") },
    { id: "lastRun", header: "Last run", accessor: (s) => (s.lastRunAt ? new Date(s.lastRunAt) : null), cell: (s) => (s.lastRunAt ? <RelativeTime value={s.lastRunAt} /> : <span className="text-fg-subtle">Not run yet</span>) },
    { id: "enabled", header: "State", accessor: (s) => (s.enabled ? "active" : "paused"), cell: (s) => (s.enabled ? <StatusBadge status="active" /> : <Badge>Paused</Badge>) },
  ];

  return (
    <div>
      <PageHeader
        title="Reports"
        subtitle="Executive, SOC, MSSP and customer reporting — on demand or scheduled to email, Slack and Teams."
        actions={
          canSchedule ? (
            <Button variant="primary" icon={MailPlus} onClick={() => setScheduleFor(preset.defaultReport)}>
              New schedule
            </Button>
          ) : null
        }
      >
        <Tabs<Audience>
          ariaLabel="Report audience"
          idPrefix="audience"
          value={audience}
          onChange={setAudience}
          tabs={AUDIENCES.filter((a) => a.id !== "mssp" || msspScope).map((a) => ({ id: a.id, label: a.label, icon: a.icon }))}
        />
      </PageHeader>

      {audience !== "all" ? <p className="-mt-2 mb-3 text-sm text-fg-muted">{AUDIENCES.find((a) => a.id === audience)?.description}</p> : null}

      {types.isPending ? (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
        </div>
      ) : types.isError ? (
        <div className="rounded border border-line bg-surface shadow-card">
          <ErrorState error={types.error} onRetry={() => void types.refetch()} />
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3" data-testid="report-catalog">
          {visibleTypes.map((t) => (
            <Card key={t.key} title={t.label} actions={<Badge tone="outline" size="xs">{t.audience}</Badge>} className="h-full">
              <p className="min-h-[36px] text-sm text-fg-muted">{REPORT_COPY[t.key] ?? "Generated from live platform data for the selected scope."}</p>
              <div className="mt-3 flex flex-wrap gap-2">
                <ReportMenu reports={[t.key]} defaultReport={t.key} label="Generate" />
                {canSchedule ? (
                  <Button size="sm" icon={CalendarClock} onClick={() => setScheduleFor(t.key)}>
                    Schedule
                  </Button>
                ) : null}
              </div>
            </Card>
          ))}
        </div>
      )}

      <div className="mt-5 grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_340px]">
        <div className="min-w-0">
          <h2 className="mb-2 text-md font-semibold text-fg">Scheduled reports</h2>
          <DataTable
            caption="Scheduled reports"
            columns={columns}
            rows={schedules.data}
            getRowId={(s) => s.id}
            loading={schedules.isPending}
            error={schedules.error}
            onRetry={() => void schedules.refetch()}
            initialState={{ sort: { columnId: "name", direction: "asc" } }}
            savedViewsKey="report-schedules"
            exportFileName="bloody-report-schedules"
            emptyState={
              <EmptyState
                icon={CalendarClock}
                title="No scheduled reports"
                description="Send executive summaries, SOC operations and customer service reviews automatically."
                action={canSchedule ? <Button size="sm" variant="primary" icon={MailPlus} onClick={() => setScheduleFor(preset.defaultReport)}>Schedule a report</Button> : undefined}
              />
            }
          />
        </div>
        <Card
          title="Delivery channels"
          count={channels.data ? channels.data.length : null}
          info="Where scheduled reports and automation notifications are delivered."
          actions={<ButtonLink to="/soar/channels" size="xs" icon={Webhook}>Manage</ButtonLink>}
          padded={false}
        >
          {channels.isPending ? (
            <div className="p-3">
              <SkeletonText lines={3} />
            </div>
          ) : channels.isError ? (
            <ErrorState error={channels.error} compact />
          ) : (channels.data ?? []).length === 0 ? (
            <EmptyState compact icon={Webhook} title="No channels yet" description="Add an email distribution list, Slack or Teams channel." action={<ButtonLink to="/soar/channels?create=1" size="sm" variant="primary">Add channel</ButtonLink>} />
          ) : (
            <ul className="divide-y divide-line">
              {channels.data!.map((c) => {
                const Icon = CHANNEL_ICONS[c.kind];
                const testing = testChannel.isPending && testChannel.variables === c.id;
                return (
                  <li key={c.id} className="flex items-center gap-2 px-3 py-2">
                    <Icon size={14} aria-hidden className="text-fg-muted" />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-base">{c.name}</span>
                      <span className="block text-2xs uppercase text-fg-subtle">
                        {c.kind}
                        {c.enabled ? "" : " · disabled"}
                      </span>
                    </span>
                    <Button size="xs" icon={Send} loading={testing} disabled={!c.enabled} onClick={() => testChannel.mutate(c.id)}>
                      Test
                    </Button>
                  </li>
                );
              })}
            </ul>
          )}
          {testChannel.isSuccess ? (
            <p role="status" className="border-t border-line px-3 py-2 text-sm text-healthy">
              {testChannel.data?.message ?? "Test notification sent."}
            </p>
          ) : testChannel.isError ? (
            <p role="alert" className="border-t border-line px-3 py-2 text-sm text-sev-critical">
              {errorMessage(testChannel.error)}
            </p>
          ) : null}
        </Card>
      </div>

      {scheduleFor ? (
        <ScheduleReportDialog
          open
          onClose={() => setScheduleFor(null)}
          reports={scheduleReports.length > 0 ? scheduleReports : [scheduleFor]}
          defaultReport={scheduleFor}
          organizationId={session.organizationId}
        />
      ) : null}
      <p className="mt-4 text-xs text-fg-subtle">
        {plural(schedules.data?.length ?? 0, "schedule")} · Reports are generated from live data for {session.organization ? session.organization.name : "all organizations"} and every generation is audited.
      </p>
    </div>
  );
}
