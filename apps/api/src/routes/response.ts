import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { EMERGENCY_ACTIONS, EMERGENCY_REASON_MIN, IsolationMode, ResponseActionKey, ResponseActionStatus, Uuid, actionRisk, principalCan } from "@bloody/contracts";
import type { ApprovalRequest } from "@bloody/automation";
import { actorFromRequest } from "../audit/audit.js";
import { actorId, assertRecordAccess, requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { badRequest, forbidden, notFound } from "../http/errors.js";
import { IdParam, Limit, csvOf, decodeCursor } from "../http/params.js";
import type { Row } from "../repo/mappers.js";
import { SELF_APPROVAL_REASON_MIN, toResponseAction } from "../services/response.js";
import { keysetClause, orderBy, pageRows, parse, type KeysetSort } from "./util.js";
import { requireRecentMfa } from "../auth/step-up.js";

const RequestBody = z
  .object({
    action: ResponseActionKey,
    organizationId: Uuid.optional(),
    incidentId: Uuid.optional(),
    target: z.object({ kind: z.enum(["asset", "identity", "indicator", "incident"]), id: z.string().trim().min(1).max(2048), label: z.string().max(300).optional() }).strict(),
    parameters: z.record(z.unknown()).default({}),
    reason: z.string().trim().min(3).max(2000),
    emergency: z.boolean().optional(),
  })
  .strict();

const ReviewBody = z.object({ comment: z.string().trim().min(3).max(2000) }).strict();

const ListQuery = z.object({
  organizationId: Uuid.optional(),
  incidentId: Uuid.optional(),
  status: csvOf(ResponseActionStatus).optional(),
  action: csvOf(ResponseActionKey).optional(),
  requestedVia: z.enum(["user", "playbook", "ai"]).optional(),
  /** Break-glass actions: all, or those still awaiting their after-the-fact review. */
  emergency: z.enum(["all", "pending_review"]).optional(),
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
    if (q.emergency === "all") where.push("r.emergency");
    if (q.emergency === "pending_review") where.push("r.review_status = 'pending'");
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
    if (body.action === "isolate_endpoint" && body.parameters.mode !== undefined && !IsolationMode.safeParse(body.parameters.mode).success) {
      throw badRequest('parameters.mode must be "lan" (block the local network, keep internet) or "full"');
    }
    let organizationId = body.organizationId ?? null;
    if (body.incidentId) {
      const inc = await s.db.withTenant(auth.tenantId, async (tx) => (await tx.query<{ organization_id: string }>("SELECT organization_id FROM incidents WHERE id = $1", [body.incidentId])).rows[0]);
      if (!inc) throw notFound("Incident");
      assertRecordAccess(request, "incident:read", inc.organization_id, "Incident");
      organizationId ??= inc.organization_id;
    }
    if (!organizationId) throw notFound("Organization");
    requirePermission(request, "response:request", organizationId);
    if (body.emergency) {
      // Break-glass: a person with response:emergency, an eligible action, a real justification.
      if (auth.principal.kind !== "user") throw forbidden("Emergency actions can only be requested by a signed-in person", "emergency_not_allowed");
      if (!EMERGENCY_ACTIONS.includes(body.action)) throw badRequest(`${body.action} cannot be executed as an emergency action (allowed: ${EMERGENCY_ACTIONS.join(", ")})`);
      requirePermission(request, "response:emergency", organizationId);
      await requireRecentMfa(request, s);
      if (body.reason.length < EMERGENCY_REASON_MIN) throw badRequest(`An emergency action needs a written reason of at least ${EMERGENCY_REASON_MIN} characters`);
    }
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
        emergency: body.emergency === true,
        // Without response:execute a medium- or high-risk action never runs straight away: it waits
        // for an approver (low-risk bookkeeping such as creating a case still runs).
        forceApproval: actionRisk(body.action) !== "low" && !principalCan(auth.principal, "response:execute", organizationId),
      },
      actorFromRequest(request),
    );
    // response.requested (and the execution outcome) were audited inside the service.
    request.auditState.recorded = true;
    return reply.status(view.status === "pending_approval" ? 202 : 201).send(view);
  });

  // After-the-fact review of a break-glass action (a different person with response:approve).
  app.post("/response/actions/:id/review", { config: { ...soar, audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(ReviewBody, request.body);
    const cur = await s.responses.get(auth.tenantId, id);
    assertRecordAccess(request, "incident:read", cur.organizationId, "Response action");
    requirePermission(request, "response:approve", cur.organizationId);
    request.auditState.recorded = true;
    return s.responses.review(auth.principal, id, body.comment, actorFromRequest(request));
  });

  app.get("/response/actions/:id", { config: soar }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const view = await s.responses.get(auth.tenantId, id);
    assertRecordAccess(request, "incident:read", view.organizationId, "Response action");
    const approval = view.approvalId ? await s.approvals.get(auth.tenantId, view.approvalId) : null;
    return { ...view, approval: approval ? approvalView(approval, s.approvals.canDecide(auth.principal, approval)) : null };
  });

  // Whether anyone besides the caller can approve this organization's actions (UI: offer the
  // sole-approver path instead of a dead "requested by you").
  app.get("/response/approvers", { config: soar }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid }), request.query);
    requirePermission(request, "response:request", q.organizationId);
    const others = await s.responses.otherApprovers(auth.tenantId, q.organizationId, auth.principal.id);
    return { others, selfApprovalAllowed: others === 0 && auth.principal.kind === "user", minJustification: SELF_APPROVAL_REASON_MIN };
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
      // Four eyes for automation too: whoever wrote the running playbook version cannot approve
      // its steps (a scheduled or event-triggered run has no human requester to compare with).
      const executionId = (cur.subject as { executionId?: string } | undefined)?.executionId;
      if (decision === "approve" && cur.kind === "playbook_step" && executionId) {
        const author = await s.db.withTenant(auth.tenantId, async (tx) =>
          (
            await tx.query<{ created_by: string | null }>(
              "SELECT v.created_by FROM playbook_runs r JOIN playbook_versions v ON v.playbook_id = r.playbook_id AND v.version = r.playbook_version WHERE r.id = $1",
              [executionId],
            )
          ).rows[0]?.created_by,
        );
        if (author === actorId(auth)) throw forbidden("You wrote this version of the playbook, so another person must approve its steps", "self_approval");
      }
      await requireRecentMfa(request, s);
      const decided = await s.responses.decideApproval(auth.principal, id, decision, body.comment);
      return approvalView(decided, s.approvals.canDecide(auth.principal, decided));
    });
  }

}
