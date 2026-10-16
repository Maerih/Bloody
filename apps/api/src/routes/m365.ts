import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { M365_CHECKS } from "@bloody/adapters";
import { M365_GRAPH_PERMISSIONS, M365ConnectionInput, Uuid } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { actorId, requireAuth, requirePermission } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { notFound } from "../http/errors.js";
import { IdParam } from "../http/params.js";
import type { Row } from "../repo/mappers.js";
import { parse } from "./util.js";

const itdr = { module: "itdr" as const };

async function assertOrganization(tx: Queryable, organizationId: string): Promise<void> {
  const { rowCount } = await tx.query("SELECT 1 FROM organizations WHERE id = $1", [organizationId]);
  if (!rowCount) throw notFound("Organization");
}

/** Microsoft 365 hardening: connect a tenant (read-only Graph app), assess it, read results. */
export async function m365Routes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/m365/overview", { config: itdr }, async (request) => {
    const auth = requireAuth(request);
    const { organizationId } = parse(z.object({ organizationId: Uuid }), request.query);
    requirePermission(request, "identity:read", organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, organizationId);
      return {
        organizationId,
        connection: await s.m365.connection(tx, organizationId),
        assessment: await s.m365.latest(tx, organizationId),
        history: await s.m365.history(tx, organizationId),
        permissions: M365_GRAPH_PERMISSIONS,
        checks: M365_CHECKS.length,
      };
    });
  });

  app.post("/m365/connections", { config: { ...itdr, audit: false } }, async (request, reply) => {
    const body = parse(M365ConnectionInput, request.body);
    const auth = requirePermission(request, "integration:write", body.organizationId);
    const connection = await s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, body.organizationId);
      const c = await s.m365.connect(tx, auth.tenantId, body, actorId(auth));
      await recordAudit(tx, request, { action: "m365.connected", organizationId: body.organizationId, targetKind: "m365_connection", targetId: c.id, details: { directoryTenantId: c.directoryTenantId, clientId: c.clientId } });
      return c;
    });
    // First assessment right away; a wrong secret or missing consent is reported, not fatal.
    try {
      const assessment = await s.m365.assess(auth.tenantId, connection.id);
      const fresh = await s.db.withTenant(auth.tenantId, (tx) => s.m365.connection(tx, body.organizationId));
      return reply.status(201).send({ connection: fresh, assessment, error: null });
    } catch (err) {
      const fresh = await s.db.withTenant(auth.tenantId, (tx) => s.m365.connection(tx, body.organizationId));
      return reply.status(201).send({ connection: fresh, assessment: null, error: err instanceof Error ? err.message : String(err) });
    }
  });

  app.post("/m365/connections/:id/assess", { config: { ...itdr, audit: "m365.assessed", rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const org = await s.db.withTenant(auth.tenantId, async (tx) => (await tx.query<Row>("SELECT organization_id FROM m365_connections WHERE id = $1", [id])).rows[0]?.organization_id as string | undefined);
    if (!org) throw notFound("Microsoft 365 connection");
    requirePermission(request, "identity:read", org);
    return s.m365.assess(auth.tenantId, id);
  });

  app.delete("/m365/connections/:id", { config: { ...itdr, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const org = (await tx.query<Row>("SELECT organization_id FROM m365_connections WHERE id = $1", [id])).rows[0]?.organization_id as string | undefined;
      if (!org) throw notFound("Microsoft 365 connection");
      requirePermission(request, "integration:write", org);
      const c = await s.m365.disconnect(tx, id);
      await recordAudit(tx, request, { action: "m365.disconnected", organizationId: org, targetKind: "m365_connection", targetId: id, details: { directoryTenantId: c.directoryTenantId } });
    });
    return reply.status(204).send();
  });
}
