import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { ReportFormat, ReportType, Uuid } from "@bloody/contracts";
import { describeCron, nextRun, validateCron } from "@bloody/automation";
import { BrandingInput } from "@bloody/reporting";
import { recordAudit } from "../audit/audit.js";
import { actorId, assertRecordAccess, requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { HttpError, badRequest, notFound } from "../http/errors.js";
import { IdParam, Limit } from "../http/params.js";
import type { Row } from "../repo/mappers.js";
import { runView, toSchedule } from "../services/reports.js";
import { loadOne, parse } from "./util.js";

const Options = z
  .object({
    incidentId: Uuid.optional(),
    topN: z.number().int().min(1).max(50).optional(),
    classification: z.string().trim().min(1).max(60).optional(),
    preparedFor: z.string().trim().max(200).optional(),
    preparedBy: z.string().trim().max(200).optional(),
    timeZone: z.string().trim().max(64).optional(),
    currency: z.string().regex(/^[A-Z]{3}$/).optional(),
    locale: z.string().regex(/^[a-z]{2}(-[A-Z]{2})?$/).optional(),
  })
  .strict();

const GenerateBody = z
  .object({
    type: ReportType,
    format: ReportFormat.default("pdf"),
    organizationId: Uuid.optional(),
    periodDays: z.number().int().min(1).max(366).optional(),
    from: z.string().datetime({ offset: true }).optional(),
    to: z.string().datetime({ offset: true }).optional(),
    branding: BrandingInput.partial().optional(),
    incidentId: Uuid.optional(),
    options: Options.optional(),
  })
  .strict()
  .refine((b) => (b.from === undefined) === (b.to === undefined), { message: "from and to must be given together" })
  .refine((b) => !(b.periodDays && b.from), { message: "use either periodDays or from/to" });

const ScheduleBody = z
  .object({
    name: z.string().trim().min(1).max(200),
    type: ReportType,
    organizationId: Uuid.nullable().default(null),
    cron: z.string().trim().min(9).max(120),
    timezone: z.string().trim().min(1).max(64).default("UTC"),
    format: ReportFormat.default("pdf"),
    periodDays: z.number().int().min(1).max(366).default(30),
    channelIds: z.array(Uuid).max(20).default([]),
    enabled: z.boolean().default(true),
    options: Options.default({}),
  })
  .strict();
const SchedulePatch = z
  .object({
    name: z.string().trim().min(1).max(200).optional(),
    cron: z.string().trim().min(9).max(120).optional(),
    timezone: z.string().trim().min(1).max(64).optional(),
    format: ReportFormat.optional(),
    periodDays: z.number().int().min(1).max(366).optional(),
    channelIds: z.array(Uuid).max(20).optional(),
    enabled: z.boolean().optional(),
    options: Options.optional(),
  })
  .strict();

/** Tenant-wide report types expose cross-customer data (revenue, analyst workload). */
const TENANT_WIDE = new Set(["mssp_portfolio", "analyst_activity"]);

function checkTimeZone(tz: string): void {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz });
  } catch {
    throw badRequest(`Unknown time zone "${tz}"`);
  }
}

function checkCron(expr: string, tz: string): { description: string; nextRunAt: string | null } {
  const v = validateCron(expr);
  if (!v.ok) throw new HttpError(400, "invalid_cron", v.error);
  checkTimeZone(tz);
  const next = nextRun(expr, new Date(), { timeZone: tz });
  return { description: describeCron(expr), nextRunAt: next ? next.toISOString() : null };
}

async function checkChannels(tx: Queryable, organizationId: string | null, channelIds: string[]): Promise<void> {
  if (channelIds.length === 0) return;
  const { rows } = await tx.query<{ id: string; organization_id: string | null }>("SELECT id, organization_id FROM notification_channels WHERE id = ANY($1::uuid[])", [channelIds]);
  const found = new Map(rows.map((r) => [r.id, r.organization_id]));
  for (const id of channelIds) {
    if (!found.has(id)) throw new HttpError(400, "invalid_channel", `Channel ${id} does not exist`);
    const org = found.get(id) ?? null;
    if (org !== null && org !== organizationId) throw new HttpError(400, "invalid_channel", `Channel ${id} belongs to another organization`);
  }
}

/**
 * Reporting: report catalog, on-demand generation streamed as a file (HTML / PDF / CSV / JSON),
 * run history with download, and delivery schedules (cron + time zone → notification channels).
 * The organization scope always comes from the caller's grants.
 */
export async function reportRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  /** Resolve the organization scope of a report for this caller. */
  const reportScope = (request: FastifyRequest, type: string, organizationId: string | null | undefined): string[] | "all" => {
    if (TENANT_WIDE.has(type)) {
      // MSSP portfolio / analyst workload: tenant-wide reporting rights only.
      requirePermission(request, "report:read", null);
      if (type === "mssp_portfolio") requirePermission(request, "billing:read", null);
      if (organizationId) return [organizationId];
      return "all";
    }
    if (organizationId) {
      assertRecordAccess(request, "report:read", organizationId, "Organization");
      return [organizationId];
    }
    const orgs = resolveOrgFilter(request, "report:read", undefined);
    return orgs === null ? "all" : orgs;
  };

  app.get("/reports/types", async (request) => {
    requireAuth(request);
    return { items: s.reports.types() };
  });

  app.post("/reports/generate", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(GenerateBody, request.body);
    const scope = reportScope(request, body.type, body.organizationId);
    const incidentId = body.incidentId ?? body.options?.incidentId;
    if (incidentId) {
      if (body.type !== "incident") throw badRequest("incidentId applies to the incident report only");
      const inc = await s.db.withTenant(auth.tenantId, async (tx) => (await tx.query<{ organization_id: string }>("SELECT organization_id FROM incidents WHERE id = $1", [incidentId])).rows[0]);
      if (!inc || (scope !== "all" && !scope.includes(inc.organization_id))) throw notFound("Incident");
    }
    if (body.organizationId) await s.db.withTenant(auth.tenantId, (tx) => loadOne(tx, "organizations", body.organizationId!, "Organization"));
    if (body.options?.timeZone) checkTimeZone(body.options.timeZone);
    const res = await s.reports.generate({
      tenantId: auth.tenantId,
      organizationId: body.organizationId ?? null,
      organizationIds: scope,
      type: body.type,
      format: body.format,
      period: body.from && body.to ? { from: body.from, to: body.to } : { days: body.periodDays ?? 30 },
      branding: body.branding ?? null,
      options: { ...(body.options ?? {}), ...(incidentId ? { incidentId } : {}) },
      requestedBy: actorId(auth),
      requestedByUserId: auth.principal.kind === "user" ? auth.principal.id : null,
    });
    await s.db.withTenant(auth.tenantId, (tx) =>
      recordAudit(tx, request, {
        action: "report.generated",
        organizationId: body.organizationId ?? null,
        targetKind: "report_run",
        targetId: res.runId,
        details: { type: body.type, format: body.format, scope: scope === "all" ? "all" : scope.length, bytes: res.file.content.length, sha256: res.sha256 },
      }),
    );
    return reply
      .status(200)
      .header("content-type", res.file.contentType)
      .header("content-disposition", `attachment; filename="${res.file.filename.replace(/[^A-Za-z0-9._-]/g, "_")}"`)
      .header("content-length", String(res.file.content.length))
      .header("x-report-run-id", res.runId)
      .header("x-report-sha256", res.sha256)
      .send(res.file.content);
  });

  app.get("/reports/runs", async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid.optional(), type: ReportType.optional(), scheduleId: Uuid.optional(), limit: Limit(200, 50) }), request.query);
    const orgs = resolveOrgFilter(request, "report:read", q.organizationId);
    const params: unknown[] = [];
    const where = ["TRUE"];
    // Tenant-wide runs (organization_id NULL) are visible to tenant-wide report readers only.
    if (orgs) where.push(`organization_id = ANY($${params.push(orgs)}::uuid[])`);
    if (q.type) where.push(`type = $${params.push(q.type)}`);
    if (q.scheduleId) where.push(`schedule_id = $${params.push(q.scheduleId)}`);
    params.push(q.limit);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT id, organization_id, schedule_id, type, format, status, title, summary, period_from, period_to, filename, content_type, size_bytes, sha256, delivery, error, requested_by,
                created_at, updated_at, (content IS NOT NULL) AS has_content
         FROM report_runs WHERE ${where.join(" AND ")} ORDER BY created_at DESC LIMIT $${params.length}`,
        params,
      ),
    );
    return { items: rows.map(runView), nextCursor: null };
  });

  const loadRun = async (tenantId: string, request: FastifyRequest, id: string, withContent = false): Promise<Row> => {
    const { rows } = await s.db.withTenant(tenantId, (tx) =>
      tx.query<Row>(`SELECT *${withContent ? "" : ", NULL AS content"}, (content IS NOT NULL) AS has_content FROM report_runs WHERE id = $1`, [id]),
    );
    const r = rows[0];
    if (!r) throw notFound("Report run");
    if (r.organization_id) assertRecordAccess(request, "report:read", String(r.organization_id), "Report run");
    else requirePermission(request, "report:read", null);
    return r;
  };

  app.get("/reports/runs/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return runView(await loadRun(auth.tenantId, request, id));
  });

  app.get("/reports/runs/:id/download", async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const r = await loadRun(auth.tenantId, request, id, true);
    if (!r.content) throw new HttpError(410, "content_unavailable", r.status === "succeeded" ? "The report file was not retained (too large); generate it again" : `The report run ${String(r.status)}`);
    const content = r.content as Buffer;
    return reply
      .header("content-type", String(r.content_type))
      .header("content-disposition", `attachment; filename="${String(r.filename).replace(/[^A-Za-z0-9._-]/g, "_")}"`)
      .header("x-report-sha256", String(r.sha256))
      .send(content);
  });

  // ─── Schedules ────────────────────────────────────────────────────────────
  app.get("/reports/schedules", async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid.optional() }), request.query);
    const orgs = resolveOrgFilter(request, "report:read", q.organizationId);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      orgs ? tx.query<Row>("SELECT * FROM report_schedules WHERE organization_id = ANY($1::uuid[]) ORDER BY name", [orgs]) : tx.query<Row>("SELECT * FROM report_schedules ORDER BY name"),
    );
    return {
      items: rows.map((r) => {
        const sch = toSchedule(r);
        let next: string | null = null;
        try {
          next = sch.enabled ? (nextRun(sch.cron, new Date(s.now()), { timeZone: sch.timezone })?.toISOString() ?? null) : null;
        } catch {
          next = null;
        }
        return { ...sch, description: describeCron(sch.cron), nextRunAt: next };
      }),
      nextCursor: null,
    };
  });

  app.post("/reports/schedules", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(ScheduleBody, request.body);
    if (TENANT_WIDE.has(body.type) && body.organizationId) throw badRequest(`${body.type} reports are tenant-wide`);
    requirePermission(request, "report:write", body.organizationId);
    if (body.type === "mssp_portfolio") requirePermission(request, "billing:read", null);
    const cron = checkCron(body.cron, body.timezone);
    const created = await s.db.withTenant(auth.tenantId, async (tx) => {
      if (body.organizationId) await loadOne(tx, "organizations", body.organizationId, "Organization");
      await checkChannels(tx, body.organizationId, body.channelIds);
      const { rows } = await tx.query<Row>(
        `INSERT INTO report_schedules (tenant_id, organization_id, type, name, cron, timezone, format, period_days, channel_ids, enabled, options, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::uuid[], $10, $11::jsonb, $12) RETURNING *`,
        [auth.tenantId, body.organizationId, body.type, body.name, body.cron, body.timezone, body.format, body.periodDays, body.channelIds, body.enabled, JSON.stringify(body.options), actorId(auth)],
      );
      const sch = toSchedule(rows[0]!);
      await recordAudit(tx, request, { action: "report_schedule.created", organizationId: body.organizationId, targetKind: "report_schedule", targetId: sch.id, details: { type: body.type, cron: body.cron, timezone: body.timezone, channels: body.channelIds.length } });
      return sch;
    });
    return reply.status(201).send({ ...created, ...cron });
  });

  const loadSchedule = async (tenantId: string, request: FastifyRequest, id: string) => {
    const row = await s.db.withTenant(tenantId, (tx) => loadOne(tx, "report_schedules", id, "Report schedule"));
    const sch = toSchedule(row);
    if (sch.organizationId) assertRecordAccess(request, "report:read", sch.organizationId, "Report schedule");
    else requirePermission(request, "report:read", null);
    return sch;
  };

  app.get("/reports/schedules/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const sch = await loadSchedule(auth.tenantId, request, id);
    return { ...sch, description: describeCron(sch.cron) };
  });

  app.patch("/reports/schedules/:id", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(SchedulePatch, request.body);
    if (Object.keys(body).length === 0) throw badRequest("Nothing to update");
    const cur = await loadSchedule(auth.tenantId, request, id);
    requirePermission(request, "report:write", cur.organizationId);
    const next = { ...cur, ...body };
    const cron = checkCron(next.cron, next.timezone);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      if (body.channelIds) await checkChannels(tx, cur.organizationId, body.channelIds);
      const { rows } = await tx.query<Row>(
        `UPDATE report_schedules SET name = $2, cron = $3, timezone = $4, format = $5, period_days = $6, channel_ids = $7::uuid[], enabled = $8, options = $9::jsonb
         WHERE id = $1 RETURNING *`,
        [id, next.name, next.cron, next.timezone, next.format, next.periodDays, next.channelIds, next.enabled, JSON.stringify(next.options)],
      );
      await recordAudit(tx, request, { action: "report_schedule.updated", organizationId: cur.organizationId, targetKind: "report_schedule", targetId: id, details: { fields: Object.keys(body) } });
      return { ...toSchedule(rows[0]!), ...cron };
    });
  });

  app.delete("/reports/schedules/:id", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const cur = await loadSchedule(auth.tenantId, request, id);
    requirePermission(request, "report:write", cur.organizationId);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      await tx.query("DELETE FROM report_schedules WHERE id = $1", [id]);
      await recordAudit(tx, request, { action: "report_schedule.deleted", organizationId: cur.organizationId, targetKind: "report_schedule", targetId: id, details: { name: cur.name, type: cur.type } });
    });
    return reply.status(204).send();
  });

  app.post("/reports/schedules/:id/run", { config: { audit: "report_schedule.run_now" } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const cur = await loadSchedule(auth.tenantId, request, id);
    requirePermission(request, "report:write", cur.organizationId);
    request.auditState.organizationId = cur.organizationId;
    request.auditState.targetKind = "report_schedule";
    const result = await s.reports.runNow(cur);
    request.auditState.details = { status: result.status, deliveries: result.deliveries.length };
    return result;
  });
}
