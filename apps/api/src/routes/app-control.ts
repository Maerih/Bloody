import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { AppControlMode, AppControlRuleInput, Uuid } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { actorId, requireAuth, requirePermission } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { notFound } from "../http/errors.js";
import { IdParam } from "../http/params.js";
import { parse } from "./util.js";

const OrgQuery = z.object({ organizationId: Uuid });
const InventoryQuery = OrgQuery.extend({ q: z.string().trim().max(200).optional(), limit: z.coerce.number().int().min(1).max(1000).default(200) });
const EventsQuery = OrgQuery.extend({ limit: z.coerce.number().int().min(1).max(1000).default(200) });
const espm = { module: "espm" as const };

async function assertOrganization(tx: Queryable, organizationId: string): Promise<void> {
  // RLS hides other accounts' organizations, so this also stops cross-tenant ids.
  const { rowCount } = await tx.query("SELECT 1 FROM organizations WHERE id = $1", [organizationId]);
  if (!rowCount) throw notFound("Organization");
}

/** App Control (ESPM): per-organization mode, allow / block rules, programs seen and blocked runs. */
export async function appControlRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  const ac = s.appControl;

  app.get("/app-control/overview", { config: espm }, async (request: FastifyRequest) => {
    const auth = requireAuth(request);
    const { organizationId } = parse(OrgQuery, request.query);
    requirePermission(request, "asset:read", organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, organizationId);
      return { organizationId, ...(await ac.mode(tx, organizationId)), rules: await ac.rules(tx, organizationId), stats: await ac.stats(tx, organizationId) };
    });
  });

  app.put("/app-control/settings/:id", { config: { ...espm, audit: false } }, async (request) => {
    const { id } = parse(IdParam, request.params);
    const auth = requirePermission(request, "asset:write", id);
    const { mode } = parse(z.object({ mode: AppControlMode }).strict(), request.body);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, id);
      const before = (await ac.mode(tx, id)).mode;
      await ac.setMode(tx, auth.tenantId, id, mode, actorId(auth));
      await recordAudit(tx, request, { action: "app_control.mode_changed", organizationId: id, targetKind: "organization", targetId: id, details: { from: before, to: mode } });
      return ac.mode(tx, id);
    });
  });

  app.post("/app-control/rules", { config: { ...espm, audit: false } }, async (request, reply) => {
    const body = parse(AppControlRuleInput, request.body);
    // Account-wide rules need the permission for the whole account.
    const auth = requirePermission(request, "asset:write", body.organizationId);
    const rule = await s.db.withTenant(auth.tenantId, async (tx) => {
      if (body.organizationId) await assertOrganization(tx, body.organizationId);
      const r = await ac.addRule(tx, auth.tenantId, body, actorId(auth));
      await recordAudit(tx, request, { action: "app_control.rule_added", organizationId: r.organizationId, targetKind: "app_control_rule", targetId: r.id, details: { action: r.action, kind: r.kind, value: r.value, platform: r.platform } });
      return r;
    });
    return reply.status(201).send(rule);
  });

  app.delete("/app-control/rules/:id", { config: { ...espm, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const rule = await ac.getRule(tx, id);
      if (!rule) throw notFound("Rule");
      requirePermission(request, "asset:write", rule.organizationId);
      await ac.deleteRule(tx, id);
      await recordAudit(tx, request, { action: "app_control.rule_removed", organizationId: rule.organizationId, targetKind: "app_control_rule", targetId: id, details: { action: rule.action, kind: rule.kind, value: rule.value } });
    });
    return reply.status(204).send();
  });

  app.get("/app-control/inventory", { config: espm }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(InventoryQuery, request.query);
    requirePermission(request, "asset:read", q.organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => ({ items: await ac.inventory(tx, q.organizationId, q.q, q.limit) }));
  });

  app.get("/app-control/events", { config: espm }, async (request) => {
    const auth = requireAuth(request);
    const q = parse(EventsQuery, request.query);
    requirePermission(request, "asset:read", q.organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => ({ items: await ac.events(tx, q.organizationId, q.limit) }));
  });
}
