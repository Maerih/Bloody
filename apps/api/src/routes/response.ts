import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { ResponseActionKey, ResponseActionStatus, Uuid } from "@bloody/contracts";
import type { ApprovalRequest } from "@bloody/automation";
import { actorFromRequest } from "../audit/audit.js";
import { assertRecordAccess, requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { notFound } from "../http/errors.js";
import { IdParam, Limit, csvOf, decodeCursor } from "../http/params.js";
import type { Row } from "../repo/mappers.js";
import { toResponseAction } from "../services/response.js";
import { keysetClause, orderBy, pageRows, parse, type KeysetSort } from "./util.js";

const RequestBody = z
  .object({
    action: ResponseActionKey,
    organizationId: Uuid.optional(),
    incidentId: Uuid.optional(),
    target: z.object({ kind: z.enum(["asset", "identity", "indicator", "incident"]), id: z.string().trim().min(1).max(2048), label: z.string().max(300).optional() }).strict(),
    parameters: z.record(z.unknown()).default({}),
    reason: z.string().trim().min(3).max(2000),
  })
  .strict();

const ListQuery = z.object({
  organizationId: Uuid.optional(),
  incidentId: Uuid.optional(),
  status: csvOf(ResponseActionStatus).optional(),
  action: csvOf(ResponseActionKey).optional(),
  requestedVia: z.enum(["user", "playbook", "ai"]).optional(),
  limit: Limit(200, 50),
  cursor: z.string().optional(),
});

const Decision = z.object({ comment: z.string().trim().max(2000).optional() }).strict();
const CancelBody = z.object({ reason: z.string().trim().min(3).max(2000) }).strict();
const SORT: KeysetSort = { expr: "r.created_at", dir: "desc", cast: "timestamptz" };

function approvalView(a: ApprovalRequest, canDecide: { allowed: boolean; reason?: string; code?: string }) {
  return {
    id: a.id,
    organizationId: a.organizationId,
    kind: a.kind,
    action: a.action,
    risk: a.risk,
    reason: a.reason,
    gateReasons: a.gateReasons,
    subject: a.subject,
    parameters: a.parameters,
    requestedBy: a.requestedBy,
    status: a.status,
    requiredApprovals: a.requiredApprovals,
    approvals: a.approvals,
    createdAt: a.createdAt,
    expiresAt: a.expiresAt,
    decidedAt: a.decidedAt,
    decidedBy: a.decidedBy,
    decisionComment: a.decisionComment,
    canDecide: canDecide.allowed,
    ...(canDecide.allowed ? {} : { cannotDecideReason: canDecide.reason ?? null, cannotDecideCode: canDecide.code ?? null }),
  };
}

/**
 * Response actions & approvals (SOAR). Requesting needs `response:request` in the organization;
 * deciding needs `response:approve` and a different human than the requester (ApprovalGate).
 */
export async function responseRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  const soar = { module: "soar" as const };

  app.get("/response/catalog", { config: soar }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid.optional() }), request.query);
    const orgs = resolveOrgFilter(request, "incident:read", q.organizationId);
    const items = await s.db.withTenant(auth.tenantId, (tx) => s.responses.catalog(tx, q.organizationId ?? (orgs?.length === 1 ? orgs[0]! : null)));
    return { items, policy: s.approvals.effectivePolicy };
  });

  app.get("/response/actions", { config: soar }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(ListQuery, request.query);
    const orgs = resolveOrgFilter(request, "incident:read", q.organizationId);
    const params: unknown[] = [];
    const where: string[] = [];
    const add = (sql: string, v: unknown) => {
      params.push(v);
      where.push(sql.replaceAll("?", `$${params.length}`));
    };
    if (orgs) add("r.organization_id = ANY(?::uuid[])", orgs);
    if (q.incidentId) add("r.incident_id = ?", q.incidentId);
    if (q.status?.length) add("r.status = ANY(?::text[])", q.status);
    if (q.action?.length) add("r.action = ANY(?::text[])", q.action);
    if (q.requestedVia) add("r.requested_via = ?", q.requestedVia);
    where.push(keysetClause(SORT, "r.id", decodeCursor(q.cursor), params));
    params.push(q.limit + 1);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT r.*, o.name AS organization_name, i.number AS incident_number, ${SORT.expr} AS sort_key
         FROM response_actions r JOIN organizations o ON o.id = r.organization_id LEFT JOIN incidents i ON i.id = r.incident_id
         WHERE ${where.length ? where.join(" AND ") : "TRUE"} ORDER BY ${orderBy(SORT, "r.id")} LIMIT $${params.length}`,
        params,
      ),
    );
    return pageRows(rows, q.limit, toResponseAction);
  });

  app.post("/response/actions", { config: { ...soar, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(RequestBody, request.body);
    let organizationId = body.organizationId ?? null;
    if (body.incidentId) {
      const inc = await s.db.withTenant(auth.tenantId, async (tx) => (await tx.query<{ organization_id: string }>("SELECT organization_id FROM incidents WHERE id = $1", [body.incidentId])).rows[0]);
      if (!inc) throw notFound("Incident");
      assertRecordAccess(request, "incident:read", inc.organization_id, "Incident");
      organizationId ??= inc.organization_id;
    }
    if (!organizationId) throw notFound("Organization");
    requirePermission(request, "response:request", organizationId);
    request.auditState.organizationId = organizationId;
    const view = await s.responses.request(
      {
        tenantId: auth.tenantId,
        organizationId,
        action: body.action,
        incidentId: body.incidentId ?? null,
        target: body.target,
        parameters: body.parameters,
        reason: body.reason,
        requestedBy: { kind: auth.principal.kind === "user" ? "user" : "service", id: auth.principal.id },
        via: "user",
      },
      actorFromRequest(request),
    );
    // response.requested (and the execution outcome) were audited inside the service.
    request.auditState.recorded = true;
    return reply.status(view.status === "pending_approval" ? 202 : 201).send(view);
  });

  app.get("/response/actions/:id", { config: soar }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const view = await s.responses.get(auth.tenantId, id);
    assertRecordAccess(request, "incident:read", view.organizationId, "Response action");
    const approval = view.approvalId ? await s.approvals.get(auth.tenantId, view.approvalId) : null;
    return { ...view, approval: approval ? approvalView(approval, s.approvals.canDecide(auth.principal, approval)) : null };
  });

  for (const decision of ["approve", "reject"] as const) {
    app.post(`/response/actions/:id/${decision}`, { config: { ...soar, audit: `response.${decision}` } }, async (request) => {
      const auth = requireAuth(request);
      const { id } = parse(IdParam, request.params);
      const body = parse(Decision, request.body ?? {});
      const cur = await s.responses.get(auth.tenantId, id);
      assertRecordAccess(request, "incident:read", cur.organizationId, "Response action");
      requirePermission(request, "response:approve", cur.organizationId);
      request.auditState.organizationId = cur.organizationId;
      request.auditState.targetKind = "response_action";
      const view = await s.responses.decide(auth.principal, id, decision, body.comment);
      // The gate wrote the decision audit row; the generic hook still records the HTTP call.
      return view;
    });
  }

  app.post("/response/actions/:id/cancel", { config: { ...soar, audit: "response.cancel" } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(CancelBody, request.body);
    const cur = await s.responses.get(auth.tenantId, id);
    assertRecordAccess(request, "incident:read", cur.organizationId, "Response action");
    if (cur.requestedBy !== auth.principal.id) requirePermission(request, "response:approve", cur.organizationId);
    else requirePermission(request, "response:request", cur.organizationId);
    request.auditState.organizationId = cur.organizationId;
    return s.responses.cancel(auth.principal, id, body.reason);
  });

  // ─── Unified approval queue (response actions, playbook steps, AI tools) ──
  app.get("/response/approvals", { config: soar }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid.optional(), kind: z.enum(["playbook_step", "response_action", "ai_action"]).optional() }), request.query);
    const orgs = resolveOrgFilter(request, "incident:read", q.organizationId);
    const pending = await s.approvals.listPending(auth.tenantId, orgs ? { organizationIds: orgs } : {});
    const items = pending.filter((a) => !q.kind || a.kind === q.kind).map((a) => approvalView(a, s.approvals.canDecide(auth.principal, a)));
    return { items, nextCursor: null, total: items.length };
  });

  for (const decision of ["approve", "reject"] as const) {
    app.post(`/response/approvals/:id/${decision}`, { config: { ...soar, audit: `approval.${decision}` } }, async (request) => {
      const auth = requireAuth(request);
      const { id } = parse(IdParam, request.params);
      const body = parse(Decision, request.body ?? {});
      const cur = await s.approvals.get(auth.tenantId, id);
      if (!cur) throw notFound("Approval request");
      assertRecordAccess(request, "incident:read", cur.organizationId, "Approval request");
      requirePermission(request, "response:approve", cur.organizationId);
      request.auditState.organizationId = cur.organizationId;
      request.auditState.targetKind = "approval";
      const decided = await s.responses.decideApproval(auth.principal, id, decision, body.comment);
      return approvalView(decided, s.approvals.canDecide(auth.principal, decided));
    });
  }

}
