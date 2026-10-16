import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { FootholdVerdictInput, Uuid } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { actorId, requireAuth, requirePermission } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { notFound } from "../http/errors.js";
import { parse } from "./util.js";

const edr = { module: "edr" as const };

async function assertOrganization(tx: Queryable, organizationId: string): Promise<void> {
  const { rowCount } = await tx.query("SELECT 1 FROM organizations WHERE id = $1", [organizationId]);
  if (!rowCount) throw notFound("Organization");
}

/** Persistent Footholds: autostart entries on endpoints, new since baseline, analyst verdicts. */
export async function footholdRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/footholds/overview", { config: edr }, async (request) => {
    const auth = requireAuth(request);
    const { organizationId } = parse(z.object({ organizationId: Uuid }), request.query);
    requirePermission(request, "asset:read", organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, organizationId);
      return { organizationId, ...(await s.footholds.overview(tx, organizationId)) };
    });
  });

  app.put("/footholds/verdicts", { config: { ...edr, audit: false } }, async (request) => {
    const body = parse(FootholdVerdictInput, request.body);
    const auth = requirePermission(request, "asset:write", body.organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, body.organizationId);
      const changed = await s.footholds.setVerdict(tx, auth.tenantId, body, actorId(auth));
      await recordAudit(tx, request, {
        action: "footholds.verdict_changed",
        organizationId: body.organizationId,
        targetKind: "organization",
        targetId: body.organizationId,
        details: { verdict: body.verdict, fingerprints: body.fingerprints, note: body.note ?? null },
      });
      return { changed };
    });
  });
}
