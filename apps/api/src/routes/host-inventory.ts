import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { Uuid } from "@bloody/contracts";
import { assertRecordAccess, requireAuth, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { IdParam } from "../http/params.js";
import { toAsset } from "../repo/mappers.js";
import { loadOne, parse } from "./util.js";

/** What the SCIAT Agent sees on a host, and antivirus health across the fleet. */
export async function hostInventoryRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/assets/:id/inventory", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const asset = toAsset(await loadOne(tx, "assets", id, "Asset"));
      assertRecordAccess(request, "asset:read", asset.organizationId, "Asset");
      return { inventory: await s.hostInventory.forAsset(tx, id) };
    });
  });

  app.get("/agents/antivirus", async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid.optional() }), request.query);
    const orgs = resolveOrgFilter(request, "asset:read", q.organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => ({ items: await s.hostInventory.antivirusOverview(tx, orgs) }));
  });
}
