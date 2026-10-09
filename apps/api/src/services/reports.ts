import { createHash } from "node:crypto";
import { REPORT_TYPES, type ReportFormat, type ReportSchedule, type ReportType } from "@bloody/contracts";
import { ScheduledReportRunner, type GeneratedReportFile, type ReportScheduleStore, type ScheduledRunResult } from "@bloody/automation";
import type { AttackPathService } from "./attack-paths.js";
import type { RiskEngine } from "@bloody/engines";
import { ReportRequestError, ReportScopeError, buildReport, formatValue, renderReport, type BrandingInput, type RenderedReport, type ReportData, type ReportOptions } from "@bloody/reporting";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError } from "../http/errors.js";
import type { PipelineLogger } from "../pipeline/analytics.js";
import type { Row } from "../repo/mappers.js";
import { activeTenants } from "./approvals.js";
import type { DomainEventBus } from "./domain-events.js";
import type { NotificationService } from "./notifications.js";
import { SqlReportDataSource } from "./report-data.js";

/**
 * Reporting: builds a report (`@bloody/reporting` builders over the SQL data source, scoped to
 * the organizations the caller may see), renders it (HTML / PDF / CSV / JSON), records the run in
 * `report_runs` (with the file for later download when it is small enough) and raises
 * `report.generated`. Report schedules are delivered through notification channels by the
 * automation package's ScheduledReportRunner (claimed atomically per run, so replicas never send
 * a schedule twice).
 */

export interface GenerateInput {
  tenantId: string;
  /** Organization of the report (null = every organization in `organizationIds`). */
  organizationId: string | null;
  /** Scope the caller is authorised for (derived from the principal, never from the body). */
  organizationIds: string[] | "all";
  type: ReportType;
  format: ReportFormat;
  period: { days: number } | { from: string; to: string };
  branding?: Partial<BrandingInput> | null | undefined;
  options?: ReportOptions | undefined;
  requestedBy: string | null;
  /** User id to notify in-app when the report is ready. */
  requestedByUserId?: string | null | undefined;
  scheduleId?: string | null | undefined;
}

export interface GeneratedReport {
  runId: string;
  file: RenderedReport;
  report: ReportData;
  stored: boolean;
  sha256: string;
}

export function toSchedule(r: Row): ReportSchedule & { timezone: string; options: Record<string, unknown>; createdBy: string | null; createdAt: string; updatedAt: string } {
  return {
    id: String(r.id),
    tenantId: String(r.tenant_id),
    organizationId: (r.organization_id as string | null) ?? null,
    type: r.type as ReportType,
    name: String(r.name),
    cron: String(r.cron),
    format: r.format as ReportFormat,
    periodDays: Number(r.period_days),
    channelIds: (r.channel_ids as string[]) ?? [],
    enabled: Boolean(r.enabled),
    lastRunAt: (r.last_run_at as string | null) ?? null,
    timezone: String(r.timezone ?? "UTC"),
    options: (r.options as Record<string, unknown>) ?? {},
    createdBy: (r.created_by as string | null) ?? null,
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
  };
}

export function runView(r: Row) {
  return {
    id: String(r.id),
    organizationId: (r.organization_id as string | null) ?? null,
    scheduleId: (r.schedule_id as string | null) ?? null,
    type: String(r.type),
    format: String(r.format),
    status: String(r.status),
    title: (r.title as string | null) ?? null,
    summary: (r.summary as string | null) ?? null,
    periodFrom: String(r.period_from),
    periodTo: String(r.period_to),
    filename: (r.filename as string | null) ?? null,
    contentType: (r.content_type as string | null) ?? null,
    sizeBytes: r.size_bytes === null || r.size_bytes === undefined ? null : Number(r.size_bytes),
    sha256: (r.sha256 as string | null) ?? null,
    downloadable: r.has_content === true,
    delivery: r.delivery ?? null,
    error: (r.error as string | null) ?? null,
    requestedBy: (r.requested_by as string | null) ?? null,
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
  };
}

/** Postgres ReportScheduleStore (claimRun = compare-and-set on last_run_at). */
class PgReportScheduleStore implements ReportScheduleStore {
  readonly timeZones = new Map<string, string>();
  constructor(private readonly db: Database) {}

  async listEnabled(tenantId?: string): Promise<ReportSchedule[]> {
    const tenants = tenantId ? [tenantId] : (await activeTenants(this.db)).map((t) => t.id);
    const out: ReportSchedule[] = [];
    for (const t of tenants) {
      const rows = await this.db.withTenant(t, async (tx) => (await tx.query<Row>("SELECT * FROM report_schedules WHERE enabled ORDER BY created_at")).rows);
      for (const r of rows) {
        const s = toSchedule(r);
        this.timeZones.set(s.id, s.timezone);
        out.push(s);
      }
    }
    return out;
  }

  async claimRun(tenantId: string, id: string, expectedLastRunAt: string | null, ranAt: string): Promise<boolean> {
    return this.db.withTenant(tenantId, async (tx) => {
      const res = await tx.query("UPDATE report_schedules SET last_run_at = $3 WHERE id = $1 AND last_run_at IS NOT DISTINCT FROM $2::timestamptz", [id, expectedLastRunAt, ranAt]);
      return (res.rowCount ?? 0) === 1;
    });
  }
}

export interface ReportServiceDeps {
  db: Database;
  risk: RiskEngine;
  attackPaths: AttackPathService;
  notifications: NotificationService;
  events: DomainEventBus;
  log: PipelineLogger;
  publicUrl: string;
  maxStoredBytes: number;
  now: () => number;
}

export class ReportService {
  readonly dataSource: SqlReportDataSource;
  readonly schedules: PgReportScheduleStore;
  readonly runner: ScheduledReportRunner;

  constructor(private readonly deps: ReportServiceDeps) {
    this.dataSource = new SqlReportDataSource(deps.db, deps.risk, deps.attackPaths);
    this.schedules = new PgReportScheduleStore(deps.db);
    this.runner = new ScheduledReportRunner({
      schedules: this.schedules,
      generate: (schedule, period) => this.generateForSchedule(schedule, period),
      delivery: deps.notifications.engine,
      timeZoneFor: (s) => this.schedules.timeZones.get(s.id),
      clock: { now: () => new Date(deps.now()) },
      audit: deps.notifications.audit,
      maxAttachmentBytes: 10 * 1024 * 1024,
    });
  }

  types() {
    return REPORT_TYPES.map((t) => ({
      ...t,
      formats: ["html", "pdf", "csv", "json"] as ReportFormat[],
      tenantWideOnly: t.key === "mssp_portfolio" || t.key === "analyst_activity",
      supportsIncident: t.key === "incident",
    }));
  }

  /** White-label branding: explicit request > organization > account settings > Bloody default. */
  async branding(tx: Queryable, tenantId: string, organizationId: string | null): Promise<Partial<BrandingInput> | null> {
    const org = organizationId ? (await tx.query<{ b: unknown }>("SELECT settings->'branding' AS b FROM organizations WHERE id = $1", [organizationId])).rows[0]?.b : null;
    const acc = (await tx.query<{ b: unknown }>("SELECT settings->'branding' AS b FROM accounts WHERE id = $1", [tenantId])).rows[0]?.b;
    const pick = (org ?? acc) as Record<string, unknown> | null | undefined;
    if (!pick || typeof pick !== "object") return null;
    const out: Partial<BrandingInput> = {};
    if (typeof pick.name === "string") out.name = pick.name;
    if (typeof pick.primaryColor === "string") out.primaryColor = pick.primaryColor;
    if (typeof pick.logoDataUrl === "string") out.logoDataUrl = pick.logoDataUrl;
    if (typeof pick.footerText === "string") out.footerText = pick.footerText;
    if (typeof pick.poweredBy === "boolean") out.poweredBy = pick.poweredBy;
    return out;
  }

  async generate(input: GenerateInput): Promise<GeneratedReport> {
    const now = this.deps.now();
    const to = "days" in input.period ? new Date(now) : new Date(input.period.to);
    const from = "days" in input.period ? new Date(now - input.period.days * 86_400_000) : new Date(input.period.from);
    if (!(from.getTime() < to.getTime())) throw new HttpError(400, "invalid_period", "The report period must end after it starts");
    if (to.getTime() - from.getTime() > 366 * 86_400_000) throw new HttpError(400, "invalid_period", "Reports cover at most 366 days");
    const { runId, branding } = await this.deps.db.withTenant(input.tenantId, async (tx) => {
      const { rows } = await tx.query<{ id: string }>(
        `INSERT INTO report_runs (tenant_id, organization_id, schedule_id, type, format, status, period_from, period_to, requested_by)
         VALUES ($1, $2, $3, $4, $5, 'running', $6, $7, $8) RETURNING id`,
        [input.tenantId, input.organizationId, input.scheduleId ?? null, input.type, input.format, from.toISOString(), to.toISOString(), input.requestedBy],
      );
      return { runId: rows[0]!.id, branding: input.branding ?? (await this.branding(tx, input.tenantId, input.organizationId)) };
    });
    let report: ReportData;
    let file: RenderedReport;
    try {
      report = await buildReport(
        { type: input.type, tenantId: input.tenantId, organizationIds: input.organizationIds, period: { from, to }, branding, options: input.options ?? {} },
        { dataSource: this.dataSource, clock: { now: () => new Date(this.deps.now()) } },
      );
      file = await renderReport(report, input.format);
    } catch (err) {
      const message = err instanceof Error ? err.message.slice(0, 1000) : "report generation failed";
      await this.deps.db.withTenant(input.tenantId, (tx) => tx.query("UPDATE report_runs SET status = 'failed', error = $2 WHERE id = $1", [runId, message]));
      if (err instanceof ReportRequestError) throw new HttpError(400, "invalid_report_request", err.message);
      if (err instanceof ReportScopeError) {
        this.deps.log.error({ tenantId: input.tenantId, err: err.message }, "report data source returned out-of-scope rows");
        throw new HttpError(500, "report_scope_violation", "The report could not be produced safely");
      }
      throw err;
    }
    const sha256 = createHash("sha256").update(file.content).digest("hex");
    const stored = file.content.length <= this.deps.maxStoredBytes;
    await this.deps.db.withTenant(input.tenantId, (tx) =>
      tx.query(
        `UPDATE report_runs SET status = 'succeeded', filename = $2, content_type = $3, size_bytes = $4, sha256 = $5, title = $6, summary = $7, content = $8 WHERE id = $1`,
        [runId, file.filename, file.contentType, file.content.length, sha256, report.title.slice(0, 500), report.summary.headline.slice(0, 2000), stored ? file.content : null],
      ),
    );
    this.deps.events.publish({
      tenantId: input.tenantId,
      organizationId: input.organizationId,
      event: "report.generated",
      occurredAt: new Date(this.deps.now()).toISOString(),
      severity: "info",
      subject: { kind: "report_run", id: runId, label: report.title },
      dedupKey: `report:${runId}`,
      data: { type: input.type, format: input.format, title: report.title, summary: report.summary.headline, requestedBy: input.requestedByUserId ?? null, scheduleId: input.scheduleId ?? null, period: report.period.label },
    });
    return { runId, file, report, stored, sha256 };
  }

  private async generateForSchedule(schedule: ReportSchedule, period: { from: Date; to: Date }): Promise<GeneratedReportFile> {
    const opts = await this.deps.db.withTenant(schedule.tenantId, async (tx) => (await tx.query<{ options: Record<string, unknown> }>("SELECT options FROM report_schedules WHERE id = $1", [schedule.id])).rows[0]?.options ?? {});
    const res = await this.generate({
      tenantId: schedule.tenantId,
      organizationId: schedule.organizationId,
      organizationIds: schedule.organizationId ? [schedule.organizationId] : "all",
      type: schedule.type,
      format: schedule.format,
      period: { from: period.from.toISOString(), to: period.to.toISOString() },
      options: opts as ReportOptions,
      requestedBy: `schedule:${schedule.id}`,
      scheduleId: schedule.id,
    });
    return {
      filename: res.file.filename,
      contentType: res.file.contentType,
      content: res.file.content,
      title: res.report.title,
      summary: res.report.summary.headline,
      highlights: res.report.summary.kpis.slice(0, 6).map((k) => ({ label: k.label, value: formatValue(k.value, k.unit, k.currency ? { currency: k.currency } : {}) })),
      ...(res.stored ? { link: { url: `${this.deps.publicUrl.replace(/\/+$/, "")}/reports?run=${res.runId}`, label: "Open in Bloody" } } : {}),
      ...(res.report.scope.organizationName ? { organizationName: res.report.scope.organizationName } : {}),
    };
  }

  /** Run every due schedule of a tenant (scheduler tick) and record the delivery outcome. */
  async runDue(tenantId: string): Promise<ScheduledRunResult[]> {
    const results = await this.runner.runDue({ tenantId });
    await this.recordDeliveries(results);
    return results;
  }

  async runNow(schedule: ReportSchedule): Promise<ScheduledRunResult> {
    const result = await this.runner.runNow(schedule);
    await this.recordDeliveries([result]);
    return result;
  }

  private async recordDeliveries(results: ScheduledRunResult[]): Promise<void> {
    for (const r of results) {
      if (r.status === "skipped") continue;
      const sent = r.deliveries.filter((d) => d.status === "sent").length;
      await this.deps.db.withTenant(r.tenantId, async (tx) => {
        await tx.query(
          `UPDATE report_runs SET delivery = $2::jsonb WHERE id = (SELECT id FROM report_runs WHERE schedule_id = $1 ORDER BY created_at DESC LIMIT 1)`,
          [r.scheduleId, JSON.stringify({ status: r.status, deliveries: r.deliveries, scheduledFor: r.scheduledFor, missedRuns: r.missedRuns, error: r.error ?? null })],
        );
        if (sent > 0) {
          await tx.query(
            `INSERT INTO usage_counters (tenant_id, organization_id, metric, period_start, value) VALUES ($1, NULL, 'notifications.sent', (now() AT TIME ZONE 'UTC')::date, $2)
             ON CONFLICT (tenant_id, org_key(organization_id), metric, period_start) DO UPDATE SET value = usage_counters.value + EXCLUDED.value`,
            [r.tenantId, sent],
          );
        }
      });
    }
  }
}
