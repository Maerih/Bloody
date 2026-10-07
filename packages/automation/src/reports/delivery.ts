import { REPORT_TYPES, type ReportSchedule } from "@bloody/contracts";
import type { NotificationFact, NotificationMessage } from "../channels/types.js";
import type { AutomationEventEnvelope, DeliveryOutcome } from "../rules/engine.js";
import { isDue } from "../scheduling/cron.js";
import { safeAudit, type AuditSink } from "../util/audit.js";
import { errorMessage, systemClock, uuidIds, type Clock, type IdGenerator } from "../util/runtime.js";

/** A rendered report file handed back by the API's generator (reporting builders + renderers). */
export interface GeneratedReportFile {
  filename: string;
  contentType: string;
  content: Buffer;
  title: string;
  /** One-paragraph summary for the e-mail body. */
  summary: string;
  /** Headline KPIs shown as facts in the notification. */
  highlights?: NotificationFact[];
  /** Download link in the portal (used when the file is too large to attach and for chat channels). */
  link?: { url: string; label: string };
  organizationName?: string;
}

export type ReportGenerator = (schedule: ReportSchedule, period: { from: Date; to: Date }) => Promise<GeneratedReportFile>;

export interface ReportScheduleStore {
  listEnabled(tenantId?: string): Promise<ReportSchedule[]>;
  /** Atomically set lastRunAt iff it still equals `expectedLastRunAt` (prevents double runs across replicas). */
  claimRun(tenantId: string, id: string, expectedLastRunAt: string | null, ranAt: string): Promise<boolean>;
}

/** Anything that can deliver a message to channel ids with retries + dead-lettering (AutomationRuleEngine). */
export interface MessageDeliverer {
  deliver(message: NotificationMessage, channelIds: readonly string[], scope: { tenantId: string; organizationId: string | null }): Promise<DeliveryOutcome[]>;
}

export interface ScheduledRunResult {
  scheduleId: string;
  tenantId: string;
  name: string;
  status: "delivered" | "partially_delivered" | "failed" | "skipped";
  scheduledFor: string | null;
  period: { from: string; to: string } | null;
  missedRuns: number;
  deliveries: DeliveryOutcome[];
  error?: string;
}

export interface ScheduledReportRunnerDeps {
  schedules: ReportScheduleStore;
  generate: ReportGenerator;
  delivery: MessageDeliverer;
  /** Raise `report.generated` so automation rules can react (optional). */
  onGenerated?: (envelope: AutomationEventEnvelope) => Promise<void>;
  /** IANA zone of a schedule's tenant (default UTC). */
  timeZoneFor?: (schedule: ReportSchedule) => string | undefined;
  clock?: Clock;
  ids?: IdGenerator;
  audit?: AuditSink;
  /** Attach files up to this size (default 10 MB); larger reports are linked instead. */
  maxAttachmentBytes?: number;
}

export function formatPeriodLabel(from: Date, to: Date): string {
  const fmt = (d: Date, withYear: boolean): string =>
    new Intl.DateTimeFormat("en-GB", { timeZone: "UTC", day: "numeric", month: "short", ...(withYear ? { year: "numeric" } : {}) }).format(d);
  const end = new Date(to.getTime() - 1);
  const sameYear = from.getUTCFullYear() === end.getUTCFullYear();
  return `${fmt(from, !sameYear)} – ${fmt(end, true)}`;
}

/**
 * Runs scheduled reports: decides which schedules are due (cron, coalescing missed runs),
 * claims each run atomically, asks the injected generator for the file, and delivers it —
 * attached to e-mails, linked for chat/webhook channels — through the same retry/dead-letter
 * path as automation notifications. Every run is audited.
 */
export class ScheduledReportRunner {
  private readonly deps: ScheduledReportRunnerDeps;
  private readonly clock: Clock;
  private readonly ids: IdGenerator;

  constructor(deps: ScheduledReportRunnerDeps) {
    this.deps = deps;
    this.clock = deps.clock ?? systemClock;
    this.ids = deps.ids ?? uuidIds;
  }

  /** Execute every due schedule (call every minute from the API scheduler). */
  async runDue(opts: { tenantId?: string } = {}): Promise<ScheduledRunResult[]> {
    const now = this.clock.now();
    const schedules = await this.deps.schedules.listEnabled(opts.tenantId);
    const results: ScheduledRunResult[] = [];
    for (const s of schedules) {
      if (!s.enabled) continue;
      const tz = this.deps.timeZoneFor?.(s);
      let check;
      try {
        check = isDue({ cron: s.cron, now, lastRunAt: s.lastRunAt, ...(tz ? { timeZone: tz } : {}) });
      } catch (err) {
        results.push({ scheduleId: s.id, tenantId: s.tenantId, name: s.name, status: "failed", scheduledFor: null, period: null, missedRuns: 0, deliveries: [], error: `invalid schedule: ${errorMessage(err)}` });
        continue;
      }
      if (!check.due || !check.scheduledFor) continue;
      const claimed = await this.deps.schedules.claimRun(s.tenantId, s.id, s.lastRunAt, now.toISOString());
      if (!claimed) {
        results.push({ scheduleId: s.id, tenantId: s.tenantId, name: s.name, status: "skipped", scheduledFor: check.scheduledFor.toISOString(), period: null, missedRuns: check.missedRuns, deliveries: [], error: "claimed by another worker" });
        continue;
      }
      results.push(await this.execute(s, check.scheduledFor, check.missedRuns));
    }
    return results;
  }

  /** "Run now" from the schedule list (period ends now). Does not touch lastRunAt. */
  async runNow(schedule: ReportSchedule): Promise<ScheduledRunResult> {
    return this.execute(schedule, this.clock.now(), 0);
  }

  private async execute(s: ReportSchedule, scheduledFor: Date, missedRuns: number): Promise<ScheduledRunResult> {
    const to = scheduledFor;
    const from = new Date(to.getTime() - s.periodDays * 86_400_000);
    const period = { from: from.toISOString(), to: to.toISOString() };
    const base = { scheduleId: s.id, tenantId: s.tenantId, name: s.name, scheduledFor: scheduledFor.toISOString(), period, missedRuns };
    let file: GeneratedReportFile;
    try {
      file = await this.deps.generate(s, { from, to });
    } catch (err) {
      await this.audit(s, "report.schedule_failed", "failure", { error: errorMessage(err) });
      return { ...base, status: "failed", deliveries: [], error: `generation failed: ${errorMessage(err)}` };
    }
    const typeLabel = REPORT_TYPES.find((t) => t.key === s.type)?.label ?? s.type;
    const periodLabel = formatPeriodLabel(from, to);
    const max = this.deps.maxAttachmentBytes ?? 10 * 1024 * 1024;
    const attach = file.content.length <= max;
    const message: NotificationMessage = {
      id: this.ids(),
      tenantId: s.tenantId,
      organizationId: s.organizationId,
      ...(file.organizationName ? { organizationName: file.organizationName } : {}),
      event: "report.generated",
      severity: "info",
      subject: `${file.title} — ${periodLabel}`,
      text: [
        `Your scheduled ${typeLabel.toLowerCase()} report "${s.name}" for ${periodLabel} is ready.`,
        file.summary,
        attach ? `The ${s.format.toUpperCase()} file is attached.` : `The report is too large to attach (${Math.round(file.content.length / 1024 / 1024)} MB); download it from the portal.`,
      ]
        .filter((p) => p && p.trim().length > 0)
        .join("\n\n"),
      facts: [{ label: "Report", value: typeLabel }, { label: "Period", value: periodLabel }, ...(file.highlights ?? []).slice(0, 8)],
      ...(file.link ? { link: file.link } : {}),
      occurredAt: this.clock.now().toISOString(),
      dedupKey: `report-schedule:${s.id}`,
      data: { report: { scheduleId: s.id, type: s.type, format: s.format, title: file.title, periodLabel, from: period.from, to: period.to, filename: file.filename, sizeBytes: file.content.length } },
      ...(attach ? { attachments: [{ filename: file.filename, contentType: file.contentType, content: file.content }] } : {}),
      audience: s.type === "customer_monthly" ? "customer" : s.type === "executive" || s.type === "compliance" ? "business" : s.type === "mssp_portfolio" || s.type === "sla" || s.type === "analyst_activity" ? "mssp" : "soc",
      origin: { kind: "report_schedule", id: s.id, name: s.name },
    };
    const deliveries = s.channelIds.length > 0 ? await this.deps.delivery.deliver(message, s.channelIds, { tenantId: s.tenantId, organizationId: s.organizationId }) : [];
    const sent = deliveries.filter((d) => d.status === "sent").length;
    const status: ScheduledRunResult["status"] = deliveries.length === 0 || sent === deliveries.length ? "delivered" : sent > 0 ? "partially_delivered" : "failed";
    await this.audit(s, "report.schedule_run", status === "failed" ? "failure" : "success", { scheduledFor: base.scheduledFor, period, sent, total: deliveries.length, missedRuns, bytes: file.content.length });
    if (this.deps.onGenerated) {
      try {
        await this.deps.onGenerated({
          tenantId: s.tenantId,
          organizationId: s.organizationId,
          ...(file.organizationName ? { organizationName: file.organizationName } : {}),
          event: "report.generated",
          occurredAt: message.occurredAt,
          severity: "info",
          subject: { kind: "report_schedule", id: s.id, label: s.name },
          dedupKey: `report:${s.id}:${base.scheduledFor}`,
          ...(file.link ? { link: file.link } : {}),
          data: { report: { ...(message.data?.["report"] as Record<string, unknown>), headline: file.summary } },
        });
      } catch {
        // follow-up automations must never fail the delivery that already happened
      }
    }
    return { ...base, status, deliveries };
  }

  private async audit(s: ReportSchedule, action: string, outcome: "success" | "failure", details: Record<string, unknown>): Promise<void> {
    await safeAudit(this.deps.audit, {
      tenantId: s.tenantId,
      organizationId: s.organizationId,
      actor: { kind: "system", id: "report-scheduler" },
      action,
      target: { kind: "report_schedule", id: s.id },
      outcome,
      at: this.clock.now().toISOString(),
      details,
    });
  }
}
