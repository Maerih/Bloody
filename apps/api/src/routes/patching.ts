import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { Uuid } from "@bloody/contracts";
import { requireAuth, requirePermission } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { notFound } from "../http/errors.js";
import { parse } from "./util.js";

/** Patch Compliance: OS updates outstanding per computer, OS support status, SLA grade. */
export async function patchingRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/patching/overview", { config: { module: "vuln" as const } }, async (request) => {
    const auth = requireAuth(request);
    const { organizationId } = parse(z.object({ organizationId: Uuid }), request.query);
    requirePermission(request, "asset:read", organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const { rowCount } = await tx.query("SELECT 1 FROM organizations WHERE id = $1", [organizationId]);
      if (!rowCount) throw notFound("Organization");
      return { organizationId, ...(await s.patching.overview(tx, organizationId)) };
    });
  });
}
