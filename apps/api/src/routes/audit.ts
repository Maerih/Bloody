import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { Uuid } from "@bloody/contracts";
import { orgScopeFor, requireAuth, requirePermission } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { forbidden } from "../http/errors.js";
import { Limit, csvOf, decodeCursor } from "../http/params.js";
import type { Row } from "../repo/mappers.js";
import { keysetClause, orderBy, pageRows, parse, type KeysetSort } from "./util.js";

const Query = z.object({
  organizationId: Uuid.optional(),
  /** Exact action or a prefix ending in "." / "*", e.g. `incident.` or `auth.*`. */
  action: z.string().trim().max(200).optional(),
  actorId: z.string().trim().max(200).optional(),
  actorKind: z.enum(["user", "service", "system", "anonymous"]).optional(),
  targetKind: z.string().trim().max(100).optional(),
  targetId: z.string().trim().max(200).optional(),
  outcome: csvOf(z.enum(["success", "denied", "failure"])).optional(),
  requestId: z.string().trim().max(128).optional(),
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
  limit: Limit(500, 100),
  cursor: z.string().optional(),
});

const SORT: KeysetSort = { expr: "a.seq", dir: "desc", cast: "numeric" };

function auditView(r: Row) {
  return {
    id: String(r.id),
    seq: Number(r.seq),
    at: String(r.at),
    organizationId: (r.organization_id as string | null) ?? null,
    actor: { kind: String(r.actor_kind), id: (r.actor_id as string | null) ?? null, label: (r.actor_label as string | null) ?? null },
    action: String(r.action),
    target: r.target_kind || r.target_id ? { kind: (r.target_kind as string | null) ?? null, id: (r.target_id as string | null) ?? null } : null,
    outcome: String(r.outcome),
    ip: (r.ip as string | null) ?? null,
    userAgent: (r.user_agent as string | null) ?? null,
    requestId: (r.request_id as string | null) ?? null,
    details: r.details ?? {},
    hash: String(r.hash),
    prevHash: (r.prev_hash as string | null) ?? null,
  };
}

/** Append-only, hash-chained audit trail (read + integrity verification). */
export async function auditRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/audit", async (request) => {
    const auth = requireAuth(request);
    const q = parse(Query, request.query);
    const scope = orgScopeFor(auth, "audit:read");
    if (scope !== "all" && scope.length === 0) throw forbidden("Missing permission audit:read");
    const params: unknown[] = [];
    const where: string[] = [];
    const add = (sql: string, v: unknown) => {
      params.push(v);
      where.push(sql.replaceAll("?", `$${params.length}`));
    };
    if (q.organizationId) {
      if (scope !== "all" && !scope.includes(q.organizationId)) throw forbidden("Missing permission audit:read for this organization");
      add("a.organization_id = ?", q.organizationId);
    } else if (scope !== "all") {
      // Organization-scoped auditors never see tenant-level (MSSP) records.
      add("a.organization_id = ANY(?::uuid[])", scope);
    }
    if (q.action) {
      if (q.action.endsWith("*") || q.action.endsWith(".")) add("a.action LIKE ?", `${q.action.replace(/\*$/, "").replace(/[\\%_]/g, (c) => `\\${c}`)}%`);
      else add("a.action = ?", q.action);
    }
    if (q.actorId) add("a.actor_id = ?", q.actorId);
    if (q.actorKind) add("a.actor_kind = ?", q.actorKind);
    if (q.targetKind) add("a.target_kind = ?", q.targetKind);
    if (q.targetId) add("a.target_id = ?", q.targetId);
    if (q.outcome?.length) add("a.outcome = ANY(?::text[])", q.outcome);
    if (q.requestId) add("a.request_id = ?", q.requestId);
    if (q.from) add("a.at >= ?", q.from);
    if (q.to) add("a.at < ?", q.to);
    where.push(keysetClause(SORT, "a.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(`SELECT a.*, ${SORT.expr} AS sort_key FROM audit_log a WHERE ${where.length ? where.join(" AND ") : "TRUE"} ORDER BY ${orderBy(SORT, "a.id")} LIMIT $${params.length}`, params),
    );
    return pageRows(rows, q.limit, auditView);
  });

  // GET /audit/verify — recompute the tenant's hash chain (tenant-level auditors only).
  app.get("/audit/verify", { config: { rateLimit: { max: 6, timeWindow: "1 minute" } } }, async (request) => {
    const auth = requirePermission(request, "audit:read", null);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<{ broken: number | null; total: number; last_seq: number | null; last_hash: string | null }>(
        `SELECT audit_log_verify($1::uuid) AS broken, (SELECT count(*)::int FROM audit_log) AS total,
                (SELECT max(seq) FROM audit_log) AS last_seq, (SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1) AS last_hash`,
        [auth.tenantId],
      ),
    );
    const r = rows[0]!;
    return { intact: r.broken === null, firstBrokenSeq: r.broken, records: r.total, headSeq: r.last_seq, headHash: r.last_hash, verifiedAt: new Date(s.now()).toISOString() };
  });
}
