import type { CommandCenterSummary } from "@bloody/contracts";
import { clsx } from "clsx";
import {
  Activity,
  AudioWaveform,
  BrainCircuit,
  CalendarClock,
  ChartArea,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  CircleMinus,
  Clock,
  Crosshair,
  Lock,
  LockOpen,
  MailPlus,
  Newspaper,
  Route,
  Search,
  ShieldCheck,
  ShieldOff,
  TriangleAlert,
  Workflow,
  type LucideIcon,
} from "lucide-react";
import { Fragment, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useActiveIncidentBreakdown, useReportSchedules } from "../../api/hooks";
import type { WidgetKey } from "../../app/dashboardPresets";
import { RAIL_MODULES } from "../../app/navigation";
import { useSession } from "../../app/session";
import { Badge, SeverityBadge, StatusBadge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { Donut, DonutLegend, type DonutSegment } from "../../components/Donut";
import { EmptyState } from "../../components/EmptyState";
import { ErrorState } from "../../components/ErrorState";
import { RelativeTime } from "../../components/RelativeTime";
import { RiskScore } from "../../components/RiskScore";
import { ScheduleReportDialog } from "../../components/ScheduleReportDialog";
import { SeverityBar } from "../../components/SeverityBar";
import { SkeletonText } from "../../components/Skeleton";
import { describeCron, formatDuration, formatInteger, formatNumber, formatPercent, plural } from "../../lib/format";
import { reportLabel } from "../../lib/reports";
import { CHART_COLORS } from "../../lib/severity";
import { DASHBOARD_PRESETS } from "../../app/dashboardPresets";

export interface WidgetProps {
  summary: CommandCenterSummary;
  windowDays: number;
}

export interface WidgetDefinition {
  /** Width on the 6-column grid: 2 = third, 3 = half, 4 = two thirds, 6 = full. */
  span: 2 | 3 | 4 | 6;
  Component: (props: WidgetProps) => ReactNode;
}

export const SPAN_CLASSES: Record<WidgetDefinition["span"], string> = {
  2: "col-span-6 md:col-span-3 2xl:col-span-2",
  3: "col-span-6 2xl:col-span-3",
  4: "col-span-6 2xl:col-span-4",
  6: "col-span-6",
};

// ─── Shared bits ────────────────────────────────────────────────────────────

function BigLink({ to, children, tone = "default" }: { to: string; children: ReactNode; tone?: "default" | "alert" }) {
  return (
    <Link to={to} className={clsx("group inline-flex items-center gap-1 text-xl font-normal hover:underline", tone === "alert" ? "text-sev-critical" : "text-heading")}>
      {children}
      <ChevronRight size={16} aria-hidden className="transition-transform group-hover:translate-x-0.5" />
    </Link>
  );
}

function Counter({ label, value, tone, href }: { label: string; value: number | null | undefined; tone?: "critical" | "high" | "healthy" | "low"; href?: string }) {
  const color = tone === "critical" ? "text-sev-critical" : tone === "high" ? "text-sev-high" : tone === "healthy" ? "text-healthy" : tone === "low" ? "text-sev-low" : "text-heading";
  const inner = (
    <>
      <div className="text-xs text-fg-muted">{label}</div>
      <div className={clsx("text-xl font-semibold tabular-nums", color)}>{formatNumber(value)}</div>
    </>
  );
  return href ? (
    <Link to={href} className="block rounded px-2 py-0.5 text-center hover:bg-surface-2">
      {inner}
    </Link>
  ) : (
    <div className="px-2 py-0.5 text-center">{inner}</div>
  );
}

function CounterRow({ children }: { children: ReactNode }) {
  return <div className="flex items-stretch justify-center divide-x divide-line">{children}</div>;
}

function MetricRow({ icon: Icon, label, value, tone, href }: { icon: LucideIcon; label: string; value: ReactNode; tone?: string; href?: string }) {
  const content = (
    <>
      <span className="flex min-w-0 items-center gap-2 text-fg-muted">
        <Icon size={13} aria-hidden />
        <span className="truncate">{label}</span>
      </span>
      <span className={clsx("font-semibold tabular-nums", tone ?? "text-fg")}>{value}</span>
    </>
  );
  return href ? (
    <Link to={href} className="flex items-center justify-between gap-3 rounded px-1 py-1 text-base hover:bg-surface-2">
      {content}
    </Link>
  ) : (
    <div className="flex items-center justify-between gap-3 px-1 py-1 text-base">{content}</div>
  );
}

function CardLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link to={to} className="text-sm text-primary hover:underline">
      {children}
    </Link>
  );
}

// ─── Active incidents ───────────────────────────────────────────────────────

export function ActiveIncidentsWidget({ summary }: WidgetProps) {
  const ai = summary.activeIncidents;
  const { breakdown } = useActiveIncidentBreakdown(ai.total > 0);
  const known = ai.total === 0 ? { critical: { endpoint: 0, identity: 0 }, high: { endpoint: 0, identity: 0 }, lowMedium: { endpoint: 0, identity: 0 } } : breakdown?.complete ? breakdown : null;
  const lowMedium = ai.low + ai.medium;
  return (
    <Card
      title="Active Incidents"
      count={ai.total}
      info="Incidents in New, Triage, Investigating or Contained state. Sub-counts show incidents involving endpoints and identities."
      subtitle={!known && ai.total > 0 ? `${formatInteger(ai.byAssetType.endpoint)} involve endpoints · ${formatInteger(ai.byAssetType.identity)} involve identities` : undefined}
      actions={<CardLink to="/incidents?status=active">View all</CardLink>}
    >
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3 lg:gap-6">
        <SeverityBar level="critical" count={ai.critical} endpointCount={known?.critical.endpoint} identityCount={known?.critical.identity} href="/incidents?severity=critical&status=active" />
        <SeverityBar level="high" count={ai.high} endpointCount={known?.high.endpoint} identityCount={known?.high.identity} href="/incidents?severity=high&status=active" />
        <SeverityBar
          level="low_medium"
          label={ai.medium > 0 ? "Low / Medium" : "Low"}
          count={lowMedium}
          endpointCount={known?.lowMedium.endpoint}
          identityCount={known?.lowMedium.identity}
          href="/incidents?severity=medium,low&status=active"
        />
      </div>
    </Card>
  );
}

// ─── SOC pipeline ───────────────────────────────────────────────────────────

const PIPELINE: { key: keyof CommandCenterSummary["socActions"]; label: string; icon: LucideIcon; color: string; href: string }[] = [
  { key: "eventsAnalyzed", label: "Events Analyzed", icon: ChartArea, color: "bg-primary", href: "/siem/search" },
  { key: "signalsGenerated", label: "Signals Populated", icon: AudioWaveform, color: "bg-sev-low", href: "/siem/alerts" },
  { key: "investigations", label: "Investigations", icon: Search, color: "bg-sev-high", href: "/investigations" },
  { key: "incidentsReported", label: "Incidents Reported", icon: Newspaper, color: "bg-sev-critical", href: "/incidents" },
];

export function SocActionsWidget({ summary, windowDays }: WidgetProps) {
  return (
    <Card
      title="Security Operations Center Actions"
      info="How raw telemetry is distilled: events analyzed by detection, signals raised, investigations opened by analysts or AI, and incidents reported."
      actions={<span className="text-sm text-fg-subtle">last {windowDays} days</span>}
      className="h-full"
    >
      <ol className="flex items-start justify-between gap-1 px-1 pt-2">
        {PIPELINE.map((step, i) => {
          const Icon = step.icon;
          return (
            <Fragment key={step.key}>
              {i > 0 ? <li aria-hidden className="mt-[18px] h-px min-w-[16px] flex-1 bg-line-strong" /> : null}
              <li className="flex min-w-[84px] flex-col items-center text-center">
                <Link to={step.href} className="group flex flex-col items-center" aria-label={`${step.label}: ${formatInteger(summary.socActions[step.key])}`}>
                  <span className={clsx("inline-flex h-9 w-9 items-center justify-center rounded-full text-white ring-4 ring-surface transition-transform group-hover:scale-105", step.color)}>
                    <Icon size={17} aria-hidden />
                  </span>
                  <span className="mt-2 text-sm text-fg">{step.label}</span>
                  <span className="mt-2 text-2xl font-bold tabular-nums text-fg" title={formatInteger(summary.socActions[step.key])}>
                    {formatNumber(summary.socActions[step.key])}
                  </span>
                </Link>
              </li>
            </Fragment>
          );
        })}
      </ol>
    </Card>
  );
}

// ─── Escalations ────────────────────────────────────────────────────────────

export function EscalationsWidget({ summary }: WidgetProps) {
  const e = summary.escalations;
  const allResolved = e.open === 0;
  return (
    <Card title="Escalations" info="Items the SOC escalated for customer or analyst action. Overdue = past the agreed response time." className="h-full">
      <div className="flex flex-col items-center gap-2 py-2 text-center">
        <span className={clsx("text-2xl font-black leading-none", allResolved ? "text-healthy" : "text-sev-critical")} aria-hidden>
          !
        </span>
        {allResolved ? (
          <BigLink to="/escalations">All Escalations Resolved</BigLink>
        ) : (
          <BigLink to="/escalations?status=open" tone="alert">
            {plural(e.open, "Open Escalation")}
          </BigLink>
        )}
        <CounterRow>
          <Counter label="Overdue" value={e.overdue} tone={e.overdue > 0 ? "critical" : undefined} href="/escalations?status=open&overdue=1" />
          <Counter label="Resolved" value={e.resolved} href="/escalations?status=resolved" />
        </CounterRow>
      </div>
    </Card>
  );
}

// ─── Antivirus / agents / firewall ──────────────────────────────────────────

export function AntivirusWidget({ summary }: WidgetProps) {
  const av = summary.antivirus;
  const segments: DonutSegment[] = [
    { key: "protected", label: "Protected", value: av.protected, color: CHART_COLORS.healthy, icon: ShieldCheck, href: "/edr/antivirus?status=protected" },
    { key: "unhealthy", label: "Unhealthy", value: av.unhealthy, color: CHART_COLORS.critical, icon: CircleAlert, href: "/edr/antivirus?status=unhealthy" },
    { key: "unmanaged", label: "Unmanaged", value: av.unmanaged, color: CHART_COLORS.low, icon: LockOpen, href: "/edr/antivirus?status=unmanaged" },
    { key: "incompatible", label: "Incompatible", value: av.incompatible, color: CHART_COLORS.info, icon: CircleMinus, href: "/edr/antivirus?status=incompatible" },
  ];
  const total = segments.reduce((s, x) => s + x.value, 0);
  return (
    <Card title="Managed Antivirus" info="Antivirus protection state reported by agents on managed endpoints." className="h-full">
      <DonutBlock segments={segments} total={total} legendTitle="Protection status" emptyText="No endpoints are reporting antivirus status yet." />
    </Card>
  );
}

export function AgentsWidget({ summary }: WidgetProps) {
  const a = summary.agents;
  const segments: DonutSegment[] = [
    { key: "protected", label: "Protected", value: a.protected, color: CHART_COLORS.healthy, icon: ShieldCheck, href: "/agents?status=protected" },
    { key: "unresponsive", label: "Unresponsive", value: a.unresponsive, color: CHART_COLORS.high, icon: TriangleAlert, href: "/agents?status=unresponsive" },
    { key: "outdated", label: "Outdated", value: a.outdated, color: CHART_COLORS.critical, icon: Clock, href: "/agents?status=outdated" },
    { key: "isolated", label: "Isolated", value: a.isolated, color: CHART_COLORS.low, icon: Lock, href: "/agents?status=isolated" },
  ];
  return (
    <Card title="Agents" count={a.total} info="Agent fleet by health. Isolated endpoints are network-contained by a response action." className="h-full">
      <DonutBlock segments={segments} total={a.total} legendTitle="Status" emptyText="No agents installed yet." emptyAction={<CardLink to="/agents/download">Download agent</CardLink>} />
    </Card>
  );
}

function DonutBlock({ segments, total, legendTitle, emptyText, emptyAction }: { segments: DonutSegment[]; total: number; legendTitle: string; emptyText: string; emptyAction?: ReactNode }) {
  return (
    <div className="flex items-center gap-5 px-1">
      <Donut segments={segments} size={104} thickness={22} />
      {total === 0 ? (
        <div className="min-w-0 flex-1 space-y-1 text-sm text-fg-muted">
          <p>{emptyText}</p>
          {emptyAction}
        </div>
      ) : (
        <DonutLegend title={legendTitle} segments={segments} />
      )}
    </div>
  );
}

export function FirewallWidget({ summary }: WidgetProps) {
  const fw = summary.firewall;
  const total = fw.enabled + fw.disabled;
  return (
    <Card title="Host Firewall" info="Host firewall state reported by managed endpoints." className="h-full">
      {total === 0 ? (
        <EmptyState compact icon={ShieldOff} title="No firewall telemetry" description="Endpoints will report host firewall state once agents are installed." />
      ) : (
        <div className="flex flex-col items-center gap-2 py-2 text-center">
          {fw.disabled === 0 ? (
            <>
              <ShieldCheck size={22} className="text-healthy" aria-hidden />
              <BigLink to="/agents?firewall=enabled">All Firewalls Active</BigLink>
              <Counter label="Active Firewall" value={fw.enabled} />
            </>
          ) : (
            <>
              <ShieldOff size={22} className="text-sev-critical" aria-hidden />
              <BigLink to="/agents?firewall=disabled" tone="alert">
                {plural(fw.disabled, "Firewall")} Disabled
              </BigLink>
              <CounterRow>
                <Counter label="Active" value={fw.enabled} tone="healthy" />
                <Counter label="Disabled" value={fw.disabled} tone="critical" href="/agents?firewall=disabled" />
              </CounterRow>
            </>
          )}
        </div>
      )}
    </Card>
  );
}

// ─── Risk & posture rows ────────────────────────────────────────────────────

export function MttrWidget({ summary, windowDays }: WidgetProps) {
  const none = "No incidents in this window to measure";
  return (
    <Card title="Response Times" info={`Mean time to detect (first malicious activity → detection) and mean time to respond (detection → containment), last ${windowDays} days.`} className="h-full">
      <div className="grid grid-cols-2 divide-x divide-line">
        <div className="px-2 text-center">
          <div className="text-sm text-fg-muted">MTTD</div>
          <div className="text-3xl font-bold tabular-nums text-fg">{formatDuration(summary.mttdMinutes)}</div>
          <div className="text-xs text-fg-subtle">{summary.mttdMinutes === null ? none : "mean time to detect"}</div>
        </div>
        <div className="px-2 text-center">
          <div className="text-sm text-fg-muted">MTTR</div>
          <div className="text-3xl font-bold tabular-nums text-fg">{formatDuration(summary.mttrMinutes)}</div>
          <div className="text-xs text-fg-subtle">{summary.mttrMinutes === null ? none : "mean time to respond"}</div>
        </div>
      </div>
    </Card>
  );
}

export function IdentityRiskWidget({ summary }: WidgetProps) {
  const ir = summary.identityRisk;
  return (
    <Card title="Identity Risk" info="Aggregate identity risk from ITDR detections and ISPM posture (privilege, MFA, dormancy, exposure)." actions={<CardLink to="/ispm">Details</CardLink>} className="h-full">
      <div className="flex items-center gap-4">
        <RiskScore score={ir.score} size="lg" label="Identity risk" explanationHref="/ispm" />
        <div className="min-w-0 flex-1">
          <MetricRow icon={TriangleAlert} label="Risky identities" value={formatInteger(ir.riskyIdentities)} tone={ir.riskyIdentities > 0 ? "text-sev-high" : undefined} href="/ispm/identities?risk=high" />
          <MetricRow icon={ShieldOff} label="Privileged without MFA" value={formatInteger(ir.privilegedWithoutMfa)} tone={ir.privilegedWithoutMfa > 0 ? "text-sev-critical" : undefined} href="/ispm/mfa?privileged=1" />
        </div>
      </div>
    </Card>
  );
}

export function ExposureWidget({ summary }: WidgetProps) {
  return (
    <Card title="Exposure Score" info="Unified exposure across external surface, vulnerabilities, identity, cloud and SaaS — weighted by exploitability and asset criticality. Open the drivers for the full factor breakdown." actions={<CardLink to="/espm">Drivers</CardLink>} className="h-full">
      <div className="flex items-center gap-4">
        <RiskScore score={summary.exposureScore} size="lg" label="Exposure score" explanationHref="/espm" />
        <div className="min-w-0 flex-1 space-y-0.5">
          <MetricRow icon={Route} label="Paths to crown jewels" value={formatInteger(summary.attackPaths.toCrownJewels)} tone={summary.attackPaths.toCrownJewels > 0 ? "text-sev-critical" : undefined} href="/espm/attack-paths?target=crown_jewel" />
          <MetricRow icon={CircleAlert} label="Known exploited vulns" value={formatInteger(summary.vulnerabilities.knownExploited)} tone={summary.vulnerabilities.knownExploited > 0 ? "text-sev-high" : undefined} href="/vm/kev" />
        </div>
      </div>
    </Card>
  );
}

export function VulnerabilitiesWidget({ summary }: WidgetProps) {
  const v = summary.vulnerabilities;
  return (
    <Card title="Vulnerability Posture" info="Open vulnerabilities by severity, CISA KEV (known exploited) matches, and items past their remediation SLA." actions={<CardLink to="/vm">Open VM</CardLink>} className="h-full">
      <div className="grid grid-cols-2 gap-2">
        <Counter label="Critical" value={v.critical} tone={v.critical > 0 ? "critical" : undefined} href="/vm/vulnerabilities?severity=critical" />
        <Counter label="High" value={v.high} tone={v.high > 0 ? "high" : undefined} href="/vm/vulnerabilities?severity=high" />
        <Counter label="Known exploited (KEV)" value={v.knownExploited} tone={v.knownExploited > 0 ? "critical" : undefined} href="/vm/kev" />
        <Counter label="Overdue SLA" value={v.overdueSla} tone={v.overdueSla > 0 ? "high" : undefined} href="/vm/remediation?overdue=1" />
      </div>
    </Card>
  );
}

function ScoreBar({ value, invert = false }: { value: number; invert?: boolean }) {
  const pct = Math.max(0, Math.min(100, value));
  const good = invert ? pct <= 30 : pct >= 80;
  const mid = invert ? pct <= 60 : pct >= 50;
  return (
    <div className="h-1.5 w-full rounded bg-surface-3" aria-hidden>
      <div className={clsx("h-1.5 rounded", good ? "bg-healthy" : mid ? "bg-sev-medium" : "bg-sev-critical")} style={{ width: `${pct}%` }} />
    </div>
  );
}

export function CloudPostureWidget({ summary }: WidgetProps) {
  const c = summary.cloudPosture;
  return (
    <Card title="Cloud Posture" info="Cloud security posture score (0–100, higher is better) and failing controls across connected cloud accounts." actions={<CardLink to="/cspm">Open CSPM</CardLink>} className="h-full">
      <div className="space-y-2">
        <div className="flex items-baseline gap-1">
          <span className="text-3xl font-bold tabular-nums text-fg">{formatInteger(c.score)}</span>
          <span className="text-sm text-fg-muted">/ 100</span>
        </div>
        <ScoreBar value={c.score} />
        <MetricRow icon={CircleAlert} label="Failing controls" value={formatInteger(c.failingControls)} tone={c.failingControls > 0 ? "text-sev-high" : undefined} href="/cspm/findings" />
      </div>
    </Card>
  );
}

export function NetworkHealthWidget({ summary }: WidgetProps) {
  const n = summary.networkHealth;
  return (
    <Card title="Network Health" info="Network sensor coverage and hosts exhibiting periodic beaconing (possible command-and-control)." actions={<CardLink to="/ndr">Open NDR</CardLink>} className="h-full">
      {n.sensors === 0 ? (
        <EmptyState compact icon={Activity} title="No network sensors" description="Deploy a network sensor to analyze flows, DNS and TLS." action={<CardLink to="/ndr/sensors">Set up sensors</CardLink>} />
      ) : (
        <div className="space-y-2">
          <div className="flex items-baseline justify-between">
            <span className="text-sm text-fg-muted">Healthy sensors</span>
            <span className="text-lg font-semibold tabular-nums">
              {formatInteger(n.healthy)} <span className="text-sm font-normal text-fg-muted">/ {formatInteger(n.sensors)}</span>
            </span>
          </div>
          <ScoreBar value={(n.healthy / n.sensors) * 100} />
          <MetricRow icon={Activity} label="Beaconing hosts" value={formatInteger(n.beaconingHosts)} tone={n.beaconingHosts > 0 ? "text-sev-high" : undefined} href="/ndr/beaconing" />
        </div>
      )}
    </Card>
  );
}

export function IntelMatchesWidget({ summary, windowDays }: WidgetProps) {
  return (
    <Card title="Threat-Intel Matches" info="Indicators of compromise from your intelligence feeds observed in endpoint, network, identity, cloud or SIEM data." className="h-full">
      <Link to="/cti/matches" className="group flex items-center gap-3 rounded p-1 hover:bg-surface-2">
        <span className={clsx("inline-flex h-10 w-10 items-center justify-center rounded-full", summary.intelMatches > 0 ? "bg-sev-critical/10 text-sev-critical" : "bg-healthy-soft text-healthy")}>
          <Crosshair size={18} aria-hidden />
        </span>
        <span>
          <span className="block text-3xl font-bold tabular-nums text-fg">{formatNumber(summary.intelMatches)}</span>
          <span className="block text-sm text-fg-muted">IOC matches in your environment · last {windowDays} days</span>
        </span>
      </Link>
    </Card>
  );
}

export function AttackPathsWidget({ summary }: WidgetProps) {
  const ap = summary.attackPaths;
  return (
    <Card title="Active Attack Paths" info="Exploitable paths through the Security Graph from an entry point (internet, phished identity…) to a target. Crown-jewel paths reach business-critical assets." actions={<CardLink to="/espm/attack-paths">View paths</CardLink>} className="h-full">
      <CounterRow>
        <Counter label="Total paths" value={ap.total} tone={ap.total > 0 ? "high" : undefined} href="/espm/attack-paths" />
        <Counter label="To crown jewels" value={ap.toCrownJewels} tone={ap.toCrownJewels > 0 ? "critical" : "healthy"} href="/espm/attack-paths?target=crown_jewel" />
      </CounterRow>
    </Card>
  );
}

function modulePath(module: string): string {
  const m = RAIL_MODULES.find((r) => r.module === module || r.id === module);
  return m?.path ?? "/";
}

export function RecommendationsWidget({ summary }: WidgetProps) {
  const recs = summary.recommendations;
  return (
    <Card title="Security Recommendations" count={recs.length} info="Highest-impact remediations ranked by the Risk Engine (attack paths broken, exposure reduced)." className="h-full" padded={recs.length === 0}>
      {recs.length === 0 ? (
        <EmptyState compact tone="success" icon={CircleCheck} title="No open recommendations" />
      ) : (
        <ul className="divide-y divide-line">
          {recs.slice(0, 6).map((r) => (
            <li key={r.id}>
              <Link to={modulePath(r.module)} className="flex items-center gap-2 px-3 py-2 hover:bg-surface-2">
                <SeverityBadge severity={r.impact} size="xs" />
                <span className="min-w-0 flex-1 truncate text-base text-fg">{r.title}</span>
                <Badge size="xs" tone="outline">
                  {RAIL_MODULES.find((m) => m.module === r.module)?.short ?? r.module}
                </Badge>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export function AiActivityWidget({ summary }: WidgetProps) {
  const a = summary.aiActivity;
  return (
    <Card title="AI Analyst Activity" info="AI SOC conversations and the actions it proposed. Actions above the configured tool tier always require human approval." actions={<CardLink to="/ai">Open AI SOC</CardLink>} className="h-full">
      <div className="space-y-0.5">
        <MetricRow icon={BrainCircuit} label="Investigations & conversations" value={formatInteger(a.conversations)} href="/ai/conversations" />
        <MetricRow icon={Workflow} label="Actions proposed" value={formatInteger(a.actionsProposed)} href="/ai/actions" />
        <MetricRow icon={CircleCheck} label="Approved by analysts" value={`${formatInteger(a.actionsApproved)} (${formatPercent(a.actionsApproved, a.actionsProposed)})`} href="/ai/actions?status=approved" />
      </div>
    </Card>
  );
}

export function AutomationWidget({ summary }: WidgetProps) {
  const a = summary.automation;
  return (
    <Card title="Automation Activity" info="SOAR playbook runs and automation rules (including email/Slack/Teams notifications). High-risk steps wait for approval." actions={<CardLink to="/soar">Open SOAR</CardLink>} className="h-full">
      <div className="space-y-0.5">
        <MetricRow icon={Workflow} label="Playbook runs" value={formatInteger(a.runs)} href="/soar/actions" />
        <MetricRow icon={CircleCheck} label="Success rate" value={formatPercent(a.succeeded, a.runs)} tone={a.runs > 0 && a.succeeded < a.runs ? "text-sev-high" : undefined} />
        <MetricRow icon={Clock} label="Pending approval" value={formatInteger(a.pendingApproval)} tone={a.pendingApproval > 0 ? "text-sev-high" : undefined} href="/soar/approvals" />
      </div>
      <div className="mt-2 flex gap-3 border-t border-line pt-2">
        <CardLink to="/soar/automations">Automation rules</CardLink>
        <CardLink to="/soar/channels">Email &amp; chat channels</CardLink>
      </div>
    </Card>
  );
}

export function ReportSchedulesWidget() {
  const session = useSession();
  const preset = DASHBOARD_PRESETS[session.dashboardRole];
  const schedules = useReportSchedules();
  const [open, setOpen] = useState(false);
  const canWrite = session.can("report:write");
  const list = schedules.data ?? [];
  return (
    <Card
      title="Scheduled Reports"
      count={schedules.data ? list.length : null}
      info="Recurring reports generated for this scope and delivered to email, Slack, Teams or webhooks."
      actions={
        canWrite ? (
          <Button size="xs" icon={MailPlus} onClick={() => setOpen(true)}>
            Schedule
          </Button>
        ) : undefined
      }
      className="h-full"
      padded={false}
    >
      {schedules.isLoading ? (
        <div className="p-3">
          <SkeletonText lines={3} />
        </div>
      ) : schedules.isError ? (
        <ErrorState error={schedules.error} compact onRetry={() => void schedules.refetch()} />
      ) : list.length === 0 ? (
        <EmptyState
          compact
          icon={CalendarClock}
          title="No scheduled reports"
          description="Deliver executive, SOC or customer reports by email on a schedule."
          action={canWrite ? <Button size="sm" variant="primary" icon={MailPlus} onClick={() => setOpen(true)}>Schedule a report</Button> : undefined}
        />
      ) : (
        <ul className="divide-y divide-line">
          {list.slice(0, 5).map((s) => (
            <li key={s.id} className="flex items-center gap-2 px-3 py-2">
              <CalendarClock size={14} aria-hidden className="shrink-0 text-fg-muted" />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-base text-fg">{s.name}</span>
                <span className="block truncate text-xs text-fg-subtle">
                  {reportLabel(s.type)} · {describeCron(s.cron)} · {s.format.toUpperCase()} · {plural(s.channelIds.length, "channel")}
                </span>
              </span>
              <span className="text-right text-2xs text-fg-subtle">
                {s.enabled ? <StatusBadge status="active" size="xs" /> : <Badge size="xs">Paused</Badge>}
                <span className="block">{s.lastRunAt ? <RelativeTime value={s.lastRunAt} /> : "Not run yet"}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
      {open ? (
        <ScheduleReportDialog open onClose={() => setOpen(false)} reports={preset.reports} defaultReport={preset.defaultReport} organizationId={session.organizationId} />
      ) : null}
    </Card>
  );
}

export const WIDGETS: Record<WidgetKey, WidgetDefinition> = {
  activeIncidents: { span: 6, Component: ActiveIncidentsWidget },
  socActions: { span: 3, Component: SocActionsWidget },
  escalations: { span: 3, Component: EscalationsWidget },
  antivirus: { span: 2, Component: AntivirusWidget },
  agents: { span: 2, Component: AgentsWidget },
  firewall: { span: 2, Component: FirewallWidget },
  mttr: { span: 2, Component: MttrWidget },
  identityRisk: { span: 2, Component: IdentityRiskWidget },
  exposure: { span: 2, Component: ExposureWidget },
  vulnerabilities: { span: 2, Component: VulnerabilitiesWidget },
  cloudPosture: { span: 2, Component: CloudPostureWidget },
  networkHealth: { span: 2, Component: NetworkHealthWidget },
  intelMatches: { span: 2, Component: IntelMatchesWidget },
  attackPaths: { span: 2, Component: AttackPathsWidget },
  recommendations: { span: 4, Component: RecommendationsWidget },
  aiActivity: { span: 2, Component: AiActivityWidget },
  automation: { span: 2, Component: AutomationWidget },
  reportSchedules: { span: 2, Component: ReportSchedulesWidget },
};
