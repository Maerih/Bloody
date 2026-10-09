import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { PlaybookCondition, PlaybookStep, PlaybookTrigger, Uuid } from "@bloody/contracts";
import { AutomationError, resolveEffectivePlaybooks, validatePlaybook, type ExecutionStatus, type PlaybookExecution } from "@bloody/automation";
import { recordAudit } from "../audit/audit.js";
import { actorId, assertRecordAccess, requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { HttpError, badRequest, notFound } from "../http/errors.js";
import { IdParam, Limit } from "../http/params.js";
import type { Row } from "../repo/mappers.js";
import { loadEventContext } from "../services/event-context.js";
import { isTerminal, playbookView, runSummary, toPlaybook } from "../services/soar.js";
import { loadOne, parse } from "./util.js";

const DraftFields = {
  name: z.string().trim().min(1).max(120),
  description: z.string().max(4000).nullable().optional(),
  enabled: z.boolean().optional(),
  trigger: PlaybookTrigger,
  conditions: z.array(PlaybookCondition).max(50).optional(),
  steps: z.array(PlaybookStep).min(1).max(50),
};
const CreateBody = z.object({ ...DraftFields, organizationId: Uuid.nullable().default(null), comment: z.string().max(500).optional() }).strict();
const PatchBody = z
  .object({
    name: DraftFields.name.optional(),
    description: DraftFields.description,
    enabled: z.boolean().optional(),
    trigger: PlaybookTrigger.optional(),
    conditions: z.array(PlaybookCondition).max(50).optional(),
    steps: z.array(PlaybookStep).min(1).max(50).optional(),
    expectedVersion: z.number().int().min(1).optional(),
    comment: z.string().max(500).optional(),
  })
  .strict();
const RunBody = z
  .object({
    organizationId: Uuid.optional(),
    subjectRef: z.object({ kind: z.enum(["incident", "alert", "escalation"]), id: Uuid }).strict().optional(),
    subject: z.record(z.unknown()).optional(),
    idempotencyKey: z.string().trim().min(8).max(200).optional(),
  })
  .strict();
const RunsQuery = z.object({
  organizationId: Uuid.optional(),
  playbookId: Uuid.optional(),
  status: z.enum(["running", "waiting_approval", "succeeded", "partially_succeeded", "failed", "rejected", "cancelled"]).optional(),
  limit: Limit(200, 50),
});

function automationHttpError(err: unknown): unknown {
  if (!(err instanceof AutomationError)) return err;
  if (err.code === "forbidden") return new HttpError(403, "forbidden", err.message);
  if (err.code === "not_found") return new HttpError(404, "not_found", err.message);
  if (err.code === "concurrent_modification" || err.code === "conflict") return new HttpError(409, err.code, err.message);
  return new HttpError(400, err.code, err.message, err.details);
}

/** Playbook writes: playbook:write in the playbook's scope (tenant-wide for global MSSP playbooks). */
function requireWrite(request: FastifyRequest, organizationId: string | null) {
  return requirePermission(request, "playbook:write", organizationId);
}

/**
 * SOAR playbooks: global MSSP playbooks (organizationId = null) with per-organization overrides
 * by name, immutable version history, manual runs and run history. Triggered runs come from
 * domain events (incident.created, alert.created, indicator.matched, escalation.overdue…) and
 * from the scheduler for `schedule` triggers.
 */
export async function playbookRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  const soar = { module: "soar" as const };

  app.get("/playbooks", { config: soar }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid.optional(), effective: z.enum(["true", "false"]).optional() }), request.query);
    const orgs = resolveOrgFilter(request, "playbook:read", q.organizationId);
    const rows = await s.db.withTenant(auth.tenantId, async (tx) =>
      orgs
        ? (await tx.query<Row>("SELECT * FROM playbooks WHERE organization_id IS NULL OR organization_id = ANY($1::uuid[]) ORDER BY name, organization_id NULLS FIRST", [orgs])).rows
        : (await tx.query<Row>("SELECT * FROM playbooks ORDER BY name, organization_id NULLS FIRST")).rows,
    );
    if (q.organizationId && q.effective !== "false") {
      const effective = resolveEffectivePlaybooks(rows.map(toPlaybook), auth.tenantId, q.organizationId);
      const byId = new Map(rows.map((r) => [String(r.id), r]));
      return {
        items: effective.map((e) => ({ ...playbookView(byId.get(e.playbook.id)!), source: e.source, overrides: e.overrides })),
        nextCursor: null,
      };
    }
    return { items: rows.map((r) => ({ ...playbookView(r), source: r.organization_id ? "organization" : "global" })), nextCursor: null };
  });

  app.post("/playbooks/validate", { config: { ...soar, audit: false } }, async (request) => {
    requireAuth(request);
    request.auditState.recorded = true;
    const v = validatePlaybook(request.body ?? {});
    return { ok: v.ok, issues: v.issues, warnings: v.warnings };
  });

  app.post("/playbooks", { config: { ...soar, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(CreateBody, request.body);
    requireWrite(request, body.organizationId);
    const { comment, ...draft } = body;
    const res = await s.db.withTenant(auth.tenantId, async (tx) => {
      if (draft.organizationId) await loadOne(tx, "organizations", draft.organizationId, "Organization");
      const created = await s.playbooks.create(tx, auth.tenantId, draft, actorId(auth), comment);
      await recordAudit(tx, request, {
        action: "playbook.created",
        organizationId: draft.organizationId,
        targetKind: "playbook",
        targetId: created.playbook.id,
        details: { name: draft.name, trigger: draft.trigger.on, steps: draft.steps.map((x) => x.action), global: draft.organizationId === null },
      });
      return created;
    });
    return reply.status(201).send({ ...res.playbook, warnings: res.warnings });
  });

  const loadPlaybook = async (tenantId: string, request: FastifyRequest, id: string) => {
    const row = await s.db.withTenant(tenantId, (tx) => loadOne(tx, "playbooks", id, "Playbook"));
    const orgId = (row.organization_id as string | null) ?? null;
    if (orgId) assertRecordAccess(request, "playbook:read", orgId, "Playbook");
    else resolveOrgFilter(request, "playbook:read", undefined);
    return row;
  };

  app.get("/playbooks/:id", { config: soar }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const row = await loadPlaybook(auth.tenantId, request, id);
    const overrides = row.organization_id
      ? []
      : (await s.db.withTenant(auth.tenantId, (tx) => tx.query<Row>("SELECT id, organization_id, enabled, version FROM playbooks WHERE organization_id IS NOT NULL AND lower(name) = lower($1)", [row.name]))).rows.map((r) => ({
          id: String(r.id),
          organizationId: String(r.organization_id),
          enabled: Boolean(r.enabled),
          version: Number(r.version),
        }));
    return { ...playbookView(row), overriddenBy: overrides };
  });

  app.patch("/playbooks/:id", { config: { ...soar, audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(PatchBody, request.body);
    const row = await loadPlaybook(auth.tenantId, request, id);
    const cur = toPlaybook(row);
    requireWrite(request, cur.organizationId);
    const { expectedVersion, comment, ...patch } = body;
    if (Object.keys(patch).length === 0) throw badRequest("Nothing to update");
    const res = await s.db.withTenant(auth.tenantId, async (tx) => {
      const out = await s.playbooks.update(
        tx,
        id,
        { organizationId: cur.organizationId, name: patch.name ?? cur.name, description: patch.description !== undefined ? patch.description : cur.description, enabled: patch.enabled ?? cur.enabled, trigger: patch.trigger ?? cur.trigger, conditions: patch.conditions ?? cur.conditions, steps: patch.steps ?? cur.steps },
        actorId(auth),
        { expectedVersion, comment },
      );
      await recordAudit(tx, request, { action: "playbook.updated", organizationId: cur.organizationId, targetKind: "playbook", targetId: id, details: { changed: out.changed, version: out.playbook.version, changes: out.changes.map((c) => c.summary) } });
      return out;
    });
    return { ...res.playbook, changed: res.changed, changes: res.changes, warnings: res.warnings };
  });

  for (const op of ["enable", "disable"] as const) {
    app.post(`/playbooks/:id/${op}`, { config: { ...soar, audit: false } }, async (request) => {
      const auth = requireAuth(request);
      const { id } = parse(IdParam, request.params);
      const row = await loadPlaybook(auth.tenantId, request, id);
      const orgId = (row.organization_id as string | null) ?? null;
      requireWrite(request, orgId);
      return s.db.withTenant(auth.tenantId, async (tx) => {
        const out = await s.playbooks.setEnabled(tx, id, op === "enable", actorId(auth));
        await recordAudit(tx, request, { action: `playbook.${op}d`, organizationId: orgId, targetKind: "playbook", targetId: id, details: { changed: out.changed, version: out.playbook.version } });
        return out.playbook;
      });
    });
  }

  app.delete("/playbooks/:id", { config: { ...soar, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const row = await loadPlaybook(auth.tenantId, request, id);
    const orgId = (row.organization_id as string | null) ?? null;
    requireWrite(request, orgId);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const active = await tx.query("SELECT 1 FROM playbook_runs WHERE playbook_id = $1 AND status IN ('running', 'waiting_approval') LIMIT 1", [id]);
      if ((active.rowCount ?? 0) > 0) throw new HttpError(409, "playbook_active", "The playbook has running or approval-pending executions; cancel them or disable the playbook first");
      await tx.query("DELETE FROM playbooks WHERE id = $1", [id]);
      await recordAudit(tx, request, { action: "playbook.deleted", organizationId: orgId, targetKind: "playbook", targetId: id, details: { name: row.name, version: row.version } });
    });
    return reply.status(204).send();
  });

  app.get("/playbooks/:id/versions", { config: soar }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    await loadPlaybook(auth.tenantId, request, id);
    return { items: await s.db.withTenant(auth.tenantId, (tx) => s.playbooks.versions(tx, id)), nextCursor: null };
  });

  app.post("/playbooks/:id/rollback", { config: { ...soar, audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const { version } = parse(z.object({ version: z.number().int().min(1) }).strict(), request.body);
    const row = await loadPlaybook(auth.tenantId, request, id);
    const orgId = (row.organization_id as string | null) ?? null;
    requireWrite(request, orgId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const out = await s.playbooks.rollback(tx, id, version, actorId(auth));
      await recordAudit(tx, request, { action: "playbook.rolled_back", organizationId: orgId, targetKind: "playbook", targetId: id, details: { toVersion: version, newVersion: out.playbook.version, changed: out.changed } });
      return { ...out.playbook, changed: out.changed, changes: out.changes };
    });
  });

  app.post("/playbooks/:id/run", { config: { ...soar, audit: "playbook.run" } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(RunBody, request.body ?? {});
    const row = await loadPlaybook(auth.tenantId, request, id);
    const organizationId = (row.organization_id as string | null) ?? body.organizationId ?? null;
    if (!organizationId) throw badRequest("organizationId is required to run a global playbook");
    if (row.organization_id && body.organizationId && body.organizationId !== row.organization_id) throw badRequest("The playbook belongs to another organization");
    requirePermission(request, "response:request", organizationId);
    request.auditState.organizationId = organizationId;
    request.auditState.targetKind = "playbook";
    let subject = body.subject ?? {};
    if (body.subjectRef) {
      const ctx = await loadEventContext(s.db, { tenantId: auth.tenantId, organizationId, event: "incident.updated", occurredAt: new Date(s.now()).toISOString(), subject: body.subjectRef, data: {} }, s.now());
      const entity = ctx.data[body.subjectRef.kind];
      if (!entity) throw notFound(body.subjectRef.kind);
      const ownerOrg = await s.db.withTenant(auth.tenantId, async (tx) =>
        (await tx.query<{ organization_id: string }>(`SELECT organization_id FROM ${body.subjectRef!.kind}s WHERE id = $1`, [body.subjectRef!.id])).rows[0]?.organization_id,
      );
      if (ownerOrg !== organizationId) throw badRequest("The subject belongs to another organization");
      subject = { ...subject, ...ctx.data };
    }
    try {
      const match = await s.playbookEngine.runManual({
        principal: auth.principal,
        organizationId,
        playbookId: id,
        subject,
        ...(body.subjectRef ? { subjectRef: body.subjectRef } : {}),
        ...(body.idempotencyKey ? { idempotencyKey: body.idempotencyKey } : {}),
      });
      request.auditState.details = { matched: match.matched, executionId: match.execution?.id ?? null, status: match.execution?.status ?? null };
      return reply.status(match.execution && !match.deduplicated ? 201 : 200).send({ ...match, execution: match.execution ? runSummary(match.execution) : null });
    } catch (err) {
      throw automationHttpError(err);
    }
  });

  // ─── Run history ──────────────────────────────────────────────────────────
  app.get("/playbooks/runs", { config: soar }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(RunsQuery, request.query);
    const orgs = resolveOrgFilter(request, "playbook:read", q.organizationId);
    const params: unknown[] = [];
    const where = ["execution IS NOT NULL"];
    if (orgs) where.push(`organization_id = ANY($${params.push(orgs)}::uuid[])`);
    if (q.playbookId) where.push(`playbook_id = $${params.push(q.playbookId)}`);
    if (q.status) where.push(`status = $${params.push(q.status)}`);
    params.push(q.limit);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) => tx.query<{ execution: PlaybookExecution }>(`SELECT execution FROM playbook_runs WHERE ${where.join(" AND ")} ORDER BY started_at DESC LIMIT $${params.length}`, params));
    return { items: rows.map((r) => runSummary(r.execution)), nextCursor: null };
  });

  app.get("/playbooks/runs/:id", { config: soar }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const exec = await s.playbookEngine.getExecution(auth.tenantId, id);
    if (!exec) throw notFound("Playbook run");
    assertRecordAccess(request, "playbook:read", exec.organizationId, "Playbook run");
    const actions = await s.db.withTenant(auth.tenantId, (tx) => tx.query<Row>("SELECT id, action, status, playbook_step_id, approval_id, result, error FROM response_actions WHERE playbook_run_id = $1 ORDER BY created_at", [id]));
    return { ...exec, terminal: isTerminal(exec.status as ExecutionStatus), responseActions: actions.rows };
  });

  app.post("/playbooks/runs/:id/cancel", { config: { ...soar, audit: "playbook.cancel" } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const { reason } = parse(z.object({ reason: z.string().trim().min(3).max(2000) }).strict(), request.body);
    const exec = await s.playbookEngine.getExecution(auth.tenantId, id);
    if (!exec) throw notFound("Playbook run");
    assertRecordAccess(request, "playbook:read", exec.organizationId, "Playbook run");
    requirePermission(request, "response:request", exec.organizationId);
    request.auditState.organizationId = exec.organizationId;
    try {
      const out = await s.playbookEngine.cancel(auth.tenantId, id, { kind: auth.principal.kind === "user" ? "user" : "service", id: auth.principal.id }, reason);
      return runSummary(out);
    } catch (err) {
      throw automationHttpError(err);
    }
  });
}
