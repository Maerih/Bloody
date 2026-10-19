import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { Uuid, hardeningCatalog, hardeningCheck } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { actorId, requireAuth, requirePermission, requirePerson } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { HttpError, notFound } from "../http/errors.js";
import { parse } from "./util.js";

const espm = { module: "espm" as const };
const ExceptionParams = z.object({ id: Uuid, key: z.string().regex(/^[a-z0-9_]{1,40}$/) });
const ExceptionBody = z.object({ reason: z.string().trim().min(10).max(1000) }).strict();

async function assertOrganization(tx: Queryable, organizationId: string): Promise<void> {
  const { rowCount } = await tx.query("SELECT 1 FROM organizations WHERE id = $1", [organizationId]);
  if (!rowCount) throw notFound("Organization");
}

/** Attack Reduction: endpoint hardening graded from SCIAT Agent facts, with accepted exceptions. */
export async function attackReductionRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/attack-reduction/overview", { config: espm }, async (request) => {
    const auth = requireAuth(request);
    const { organizationId } = parse(z.object({ organizationId: Uuid }), request.query);
    requirePermission(request, "asset:read", organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, organizationId);
      return { organizationId, catalog: hardeningCatalog(), ...(await s.attackReduction.overview(tx, organizationId)) };
    });
  });

  // Accept a gap for the whole organization (it stays visible but leaves the score), with a reason.
  app.put("/attack-reduction/exceptions/:id/:key", { config: { ...espm, audit: false } }, async (request) => {
    requirePerson(request);
    const { id, key } = parse(ExceptionParams, request.params);
    const auth = requirePermission(request, "asset:write", id);
    const { reason } = parse(ExceptionBody, request.body);
    if (!hardeningCheck(key)) throw new HttpError(400, "unknown_check", `Unknown check ${key}`);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, id);
      await s.attackReduction.setException(tx, auth.tenantId, id, key, reason, actorId(auth));
      await recordAudit(tx, request, { action: "attack_reduction.exception_set", organizationId: id, targetKind: "hardening_check", targetId: key, details: { reason } });
      return { key, reason };
    });
  });

  app.delete("/attack-reduction/exceptions/:id/:key", { config: { ...espm, audit: false } }, async (request) => {
    requirePerson(request);
    const { id, key } = parse(ExceptionParams, request.params);
    const auth = requirePermission(request, "asset:write", id);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, id);
      if (!(await s.attackReduction.removeException(tx, id, key))) throw notFound("Exception");
      await recordAudit(tx, request, { action: "attack_reduction.exception_removed", organizationId: id, targetKind: "hardening_check", targetId: key });
      return { removed: true };
    });
  });
}
