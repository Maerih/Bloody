import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { EscalationStatus, Severity, Uuid } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { assertRecordAccess, requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { HttpError, badRequest } from "../http/errors.js";
import { IdParam, Limit, csvOf, decodeCursor } from "../http/params.js";
import { toEscalation, type Row } from "../repo/mappers.js";
import { QueryBool, keysetClause, loadOne, orderBy, pageRows, parse, type KeysetSort } from "./util.js";

const ListQuery = z.object({
  organizationId: Uuid.optional(),
  incidentId: Uuid.optional(),
  status: csvOf(EscalationStatus).optional(),
  severity: csvOf(Severity).optional(),
  overdue: QueryBool.optional(),
  limit: Limit(500, 100),
  cursor: z.string().optional(),
});

const CreateBody = z
  .object({
    organizationId: Uuid.optional(),
    incidentId: Uuid.optional(),
    title: z.string().trim().min(3).max(300),
    reason: z.string().trim().max(2000).optional(),
    severity: Severity,
    dueInMinutes: z.number().int().min(1).max(60 * 24 * 30).optional(),
    dueAt: z.string().datetime({ offset: true }).optional(),
  })
  .strict()
  .refine((b) => b.organizationId || b.incidentId, { message: "organizationId or incidentId is required" })
  .refine((b) => !(b.dueAt && b.dueInMinutes), { message: "Use dueAt or dueInMinutes, not both" });

const TransitionBody = z.object({ note: z.string().trim().max(2000).optional() }).strict();

/** Default response SLA by severity when the caller does not set a due time. */
const DEFAULT_DUE_MINUTES: Record<Severity, number> = { critical: 15, high: 60, medium: 240, low: 1440, info: 2880 };

// Unresolved first (soonest due first), then resolved most-recent first — one keyset over a packed key.
const SORT: KeysetSort = {
  expr: "(CASE WHEN e.status = 'resolved' THEN 1 ELSE 0 END)::numeric * 100000000000000 + (CASE WHEN e.status = 'resolved' THEN -1 ELSE 1 END) * floor(extract(epoch FROM coalesce(CASE WHEN e.status = 'resolved' THEN e.resolved_at END, e.due_at)) * 1000)",
  dir: "asc",
  cast: "numeric",
};

/**
 * Escalations: time-boxed asks to a customer / on-call responder (e.g. every critical incident).
 * `overdue` is computed at read time from `dueAt`.
 */
export async function escalationRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/escalations", async (request) => {
    const auth = requireAuth(request);
    const q = parse(ListQuery, request.query);
    const orgs = resolveOrgFilter(request, "escalation:read", q.organizationId);
    const params: unknown[] = [];
    const where: string[] = [];
    const add = (sql: string, v: unknown) => {
      params.push(v);
      where.push(sql.replaceAll("?", `$${params.length}`));
    };
    if (orgs) add("e.organization_id = ANY(?::uuid[])", orgs);
    if (q.incidentId) add("e.incident_id = ?", q.incidentId);
    if (q.status?.length) add("e.status = ANY(?::text[])", q.status);
    if (q.severity?.length) add("e.severity = ANY(?::text[])", q.severity);
    if (q.overdue === true) where.push("(e.status <> 'resolved' AND e.due_at < now())");
    if (q.overdue === false) where.push("NOT (e.status <> 'resolved' AND e.due_at < now())");
    where.push(keysetClause(SORT, "e.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT e.*, o.name AS organization_name, i.number AS incident_number, ${SORT.expr} AS sort_key
         FROM escalations e JOIN organizations o ON o.id = e.organization_id LEFT JOIN incidents i ON i.id = e.incident_id
         WHERE ${where.join(" AND ")} ORDER BY ${orderBy(SORT, "e.id")} LIMIT $${params.length}`,
        params,
      ),
    );
    const now = s.now();
    return pageRows(rows, q.limit, (r) => ({ ...toEscalation(r, now), organizationName: (r.organization_name as string | null) ?? null, incidentNumber: (r.incident_number as number | null) ?? null }));
  });

  app.post("/escalations", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(CreateBody, request.body);
    const created = await s.db.withTenant(auth.tenantId, async (tx) => {
      let organizationId = body.organizationId ?? null;
      if (body.incidentId) {
        const incident = await loadOne(tx, "incidents", body.incidentId, "Incident");
        assertRecordAccess(request, "incident:read", String(incident.organization_id), "Incident");
        if (organizationId && organizationId !== incident.organization_id) throw badRequest("organizationId does not match the incident's organization");
        organizationId = String(incident.organization_id);
      }
      requirePermission(request, "escalation:write", organizationId);
      await loadOne(tx, "organizations", organizationId!, "Organization");
      const dueAt = body.dueAt ?? new Date(s.now() + (body.dueInMinutes ?? DEFAULT_DUE_MINUTES[body.severity]) * 60_000).toISOString();
      if (Date.parse(dueAt) <= s.now()) throw badRequest("dueAt must be in the future");
      const { rows } = await tx.query<Row>(
        `INSERT INTO escalations (tenant_id, organization_id, incident_id, title, reason, severity, status, due_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, 'open', $7, $8) RETURNING *`,
        [auth.tenantId, organizationId, body.incidentId ?? null, body.title, body.reason ?? null, body.severity, dueAt, `${auth.principal.kind}:${auth.principal.id}`],
      );
      const esc = toEscalation(rows[0]!, s.now());
      await recordAudit(tx, request, { action: "escalation.created", organizationId, targetKind: "escalation", targetId: esc.id, details: { incidentId: esc.incidentId, severity: esc.severity, dueAt } });
      return esc;
    });
    return reply.status(201).send(created);
  });

  app.get("/escalations/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const row = await loadOne(tx, "escalations", id, "Escalation");
      assertRecordAccess(request, "escalation:read", String(row.organization_id), "Escalation");
      return toEscalation(row, s.now());
    });
  });

  for (const action of ["acknowledge", "resolve"] as const) {
    app.post(`/escalations/:id/${action}`, { config: { audit: false } }, async (request) => {
      const auth = requireAuth(request);
      const { id } = parse(IdParam, request.params);
      const body = parse(TransitionBody, request.body ?? {});
      return s.db.withTenant(auth.tenantId, async (tx) => {
        const cur = await tx.query<Row>("SELECT * FROM escalations WHERE id = $1 FOR UPDATE", [id]);
        const row = cur.rows[0];
        if (!row) throw new HttpError(404, "not_found", "Escalation not found");
        assertRecordAccess(request, "escalation:read", String(row.organization_id), "Escalation");
        requirePermission(request, "escalation:write", String(row.organization_id));
        if (row.status === "resolved") throw new HttpError(409, "already_resolved", "The escalation is already resolved");
        if (action === "acknowledge" && row.status === "acknowledged") throw new HttpError(409, "already_acknowledged", "The escalation is already acknowledged");
        const actor = `${auth.principal.kind}:${auth.principal.id}`;
        const { rows } =
          action === "acknowledge"
            ? await tx.query<Row>("UPDATE escalations SET status = 'acknowledged', acknowledged_at = now(), acknowledged_by = $2, resolution_note = coalesce($3, resolution_note) WHERE id = $1 RETURNING *", [id, actor, body.note ?? null])
            : await tx.query<Row>(
                "UPDATE escalations SET status = 'resolved', acknowledged_at = coalesce(acknowledged_at, now()), acknowledged_by = coalesce(acknowledged_by, $2), resolved_at = now(), resolved_by = $2, resolution_note = coalesce($3, resolution_note) WHERE id = $1 RETURNING *",
                [id, actor, body.note ?? null],
              );
        const esc = toEscalation(rows[0]!, s.now());
        const late = Date.parse(String(row.due_at)) < s.now();
        await recordAudit(tx, request, { action: `escalation.${action === "acknowledge" ? "acknowledged" : "resolved"}`, organizationId: esc.organizationId, targetKind: "escalation", targetId: id, details: { incidentId: esc.incidentId, late, note: body.note ? "[provided]" : null } });
        return esc;
      });
    });
  }
}
