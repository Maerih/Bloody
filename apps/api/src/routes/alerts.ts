import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { AlertStatus, Severity, Uuid, principalCan } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { assertRecordAccess, requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { badRequest } from "../http/errors.js";
import { IdParam, Limit, csvOf, decodeCursor, likePattern } from "../http/params.js";
import { toAlert, type Row } from "../repo/mappers.js";
import { keysetClause, loadOne, orderBy, pageRows, parse, type KeysetSort } from "./util.js";

const SORTS: Record<string, KeysetSort> = {
  recent: { expr: "a.last_seen_at", dir: "desc", cast: "timestamptz" },
  risk: { expr: "a.risk_score", dir: "desc", cast: "numeric" },
};

const ListQuery = z.object({
  organizationId: Uuid.optional(),
  incidentId: Uuid.optional(),
  assetId: Uuid.optional(),
  identityId: Uuid.optional(),
  severity: csvOf(Severity).optional(),
  status: csvOf(AlertStatus).optional(),
  ruleId: z.string().trim().max(128).optional(),
  unlinked: z.enum(["true", "false"]).optional(),
  q: z.string().trim().max(200).optional(),
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
  sort: z.enum(["recent", "risk"]).default("recent"),
  limit: Limit(500, 50),
  cursor: z.string().optional(),
});

/** Analysts triage alerts; `promoted` is reserved for correlation / incident linkage. */
const PatchBody = z.object({ status: z.enum(["new", "triaged", "suppressed", "false_positive"]), reason: z.string().trim().max(2000).optional() }).strict();

/** Alerts (detections persisted by the analytics pipeline). */
export async function alertRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/alerts", async (request) => {
    const auth = requireAuth(request);
    const q = parse(ListQuery, request.query);
    const orgs = resolveOrgFilter(request, "alert:read", q.organizationId);
    const sort = SORTS[q.sort]!;
    const params: unknown[] = [];
    const where: string[] = [];
    const add = (sql: string, v: unknown) => {
      params.push(v);
      where.push(sql.replace("?", `$${params.length}`));
    };
    if (orgs) add("a.organization_id = ANY(?::uuid[])", orgs);
    if (q.incidentId) add("a.incident_id = ?", q.incidentId);
    if (q.assetId) add("a.asset_id = ?", q.assetId);
    if (q.identityId) add("a.identity_id = ?", q.identityId);
    if (q.severity?.length) add("a.severity = ANY(?::text[])", q.severity);
    if (q.status?.length) add("a.status = ANY(?::text[])", q.status);
    if (q.ruleId) add("a.rule_id = ?", q.ruleId);
    if (q.unlinked === "true") where.push("a.incident_id IS NULL");
    if (q.q) {
      params.push(likePattern(q.q));
      where.push(`(a.title ILIKE $${params.length} OR a.rule_id ILIKE $${params.length})`);
    }
    if (q.from) add("a.last_seen_at >= ?", q.from);
    if (q.to) add("a.first_seen_at < ?", q.to);
    where.push(keysetClause(sort, "a.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT a.*, o.name AS organization_name, ${sort.expr} AS sort_key FROM alerts a JOIN organizations o ON o.id = a.organization_id
         WHERE ${where.join(" AND ")} ORDER BY ${orderBy(sort, "a.id")} LIMIT $${params.length}`,
        params,
      ),
    );
    return pageRows(rows, q.limit, (r) => ({ ...toAlert(r), organizationName: (r.organization_name as string | null) ?? null }));
  });

  app.get("/alerts/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const alert = toAlert(await loadOne(tx, "alerts", id, "Alert"));
      assertRecordAccess(request, "alert:read", alert.organizationId, "Alert");
      let events: unknown[] | null = null;
      if (principalCan(auth.principal, "event:read", alert.organizationId) && alert.eventIds.length > 0) {
        const lo = new Date(Date.parse(alert.firstSeenAt) - 60_000).toISOString();
        const hi = new Date(Date.parse(alert.lastSeenAt) + 60_000).toISOString();
        const { rows } = await tx.query<{ doc: unknown }>(
          "SELECT doc FROM events WHERE id = ANY($1::uuid[]) AND organization_id = $2 AND occurred_at BETWEEN $3 AND $4 ORDER BY occurred_at LIMIT 100",
          [alert.eventIds.slice(0, 100), alert.organizationId, lo, hi],
        );
        events = rows.map((r) => r.doc);
      }
      return { ...alert, events };
    });
  });

  app.patch("/alerts/:id", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(PatchBody, request.body);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const before = toAlert(await loadOne(tx, "alerts", id, "Alert"));
      assertRecordAccess(request, "alert:read", before.organizationId, "Alert");
      requirePermission(request, "incident:write", before.organizationId);
      if (before.status === "promoted" && body.status !== "false_positive") throw badRequest("A promoted alert can only be marked as a false positive");
      const { rows } = await tx.query<Row>("UPDATE alerts SET status = $2 WHERE id = $1 RETURNING *", [id, body.status]);
      await recordAudit(tx, request, { action: "alert.status_changed", organizationId: before.organizationId, targetKind: "alert", targetId: id, details: { from: before.status, to: body.status, reason: body.reason ?? null, ruleId: before.ruleId } });
      return toAlert(rows[0]!);
    });
  });
}
