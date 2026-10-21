import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { Uuid, principalCan } from "@bloody/contracts";
import { assertRecordAccess, requireAuth, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { IdParam } from "../http/params.js";
import { toAsset } from "../repo/mappers.js";
import { EndpointDossierService, dossierFor } from "../services/endpoint-dossier.js";
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

  // Everything about one computer beyond its inventory, with a timeline of what happened to it.
  app.get("/assets/:id/dossier", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const { days } = parse(z.object({ days: z.coerce.number().int().min(1).max(366).default(90) }), request.query);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const asset = toAsset(await loadOne(tx, "assets", id, "Asset"));
      assertRecordAccess(request, "asset:read", asset.organizationId, "Asset");
      const dossier = await new EndpointDossierService(s.now).build(tx, id, { since: new Date(s.now() - days * 86_400_000).toISOString() });
      return dossierFor(dossier!, (p) => principalCan(auth.principal, p, asset.organizationId));
    });
  });

  app.get("/agents/antivirus", async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid.optional() }), request.query);
    const orgs = resolveOrgFilter(request, "asset:read", q.organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => ({ items: await s.hostInventory.antivirusOverview(tx, orgs) }));
  });
}
