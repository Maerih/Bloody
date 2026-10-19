import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { Uuid } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { actorId, requireAuth, requirePermission, requirePerson } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { notFound } from "../http/errors.js";
import { IdParam } from "../http/params.js";
import { parse } from "./util.js";

const espm = { module: "espm" as const };
const ToolKeys = z.array(z.string().regex(/^[a-z0-9_]{2,40}$/)).max(50);

async function assertOrganization(tx: Queryable, organizationId: string): Promise<void> {
  const { rowCount } = await tx.query("SELECT 1 FROM organizations WHERE id = $1", [organizationId]);
  if (!rowCount) throw notFound("Organization");
}

/** RMM Guard: remote-access / RMM tools found on endpoints, approvals and one-click blocking. */
export async function rmmGuardRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/rmm-guard/overview", { config: espm }, async (request) => {
    const auth = requireAuth(request);
    const { organizationId } = parse(z.object({ organizationId: Uuid }), request.query);
    requirePermission(request, "asset:read", organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, organizationId);
      const agents = (await tx.query<{ n: number }>("SELECT count(*)::int AS n FROM agent_inventory WHERE organization_id = $1", [organizationId])).rows[0]?.n ?? 0;
      return {
        organizationId,
        catalog: s.rmmGuard.catalog(),
        approved: await s.rmmGuard.approved(tx, organizationId),
        findings: await s.rmmGuard.findings(tx, organizationId),
        endpointsWithInventory: agents,
        appControl: (await s.appControl.mode(tx, organizationId)).mode,
      };
    });
  });

  app.put("/rmm-guard/settings/:id", { config: { ...espm, audit: false } }, async (request) => {
    requirePerson(request);
    const { id } = parse(IdParam, request.params);
    const auth = requirePermission(request, "asset:write", id);
    const { approved } = parse(z.object({ approved: ToolKeys }).strict(), request.body);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, id);
      const before = await s.rmmGuard.approved(tx, id);
      const saved = await s.rmmGuard.setApproved(tx, auth.tenantId, id, approved, actorId(auth));
      await recordAudit(tx, request, { action: "rmm_guard.approved_changed", organizationId: id, targetKind: "organization", targetId: id, details: { before, after: saved } });
      return { approved: saved };
    });
  });

  app.post("/rmm-guard/block", { config: { ...espm, audit: false } }, async (request) => {
    requirePerson(request);
    const body = parse(z.object({ organizationId: Uuid, tools: ToolKeys.min(1) }).strict(), request.body);
    const auth = requirePermission(request, "asset:write", body.organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, body.organizationId);
      const r = await s.rmmGuard.block(tx, auth.tenantId, body.organizationId, body.tools, actorId(auth));
      await recordAudit(tx, request, { action: "rmm_guard.blocked", organizationId: body.organizationId, targetKind: "organization", targetId: body.organizationId, details: { tools: body.tools, ...r } });
      return { ...r, appControl: (await s.appControl.mode(tx, body.organizationId)).mode };
    });
  });
}
