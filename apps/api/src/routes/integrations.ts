import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { Uuid } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { actorId, assertRecordAccess, requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { HttpError, badRequest } from "../http/errors.js";
import { IdParam } from "../http/params.js";
import type { Row } from "../repo/mappers.js";
import { INTEGRATION_KINDS, capabilitiesOf, toIntegrationView, validateEndpoint, validateIntegrationConfig } from "../services/integrations.js";
import { loadOne, parse } from "./util.js";

const Kind = z.string().refine((k) => INTEGRATION_KINDS.includes(k), { message: `kind must be one of ${INTEGRATION_KINDS.join(", ")}` });

const CreateBody = z
  .object({
    kind: Kind,
    name: z.string().trim().min(1).max(200),
    organizationId: Uuid.nullable().default(null),
    endpoint: z.string().trim().url().max(2048).nullable().optional(),
    config: z.record(z.unknown()).default({}),
    /** Write-only API key / password / token; stored in the secret store, never returned. */
    credential: z.string().min(1).max(16_384).optional(),
    enabled: z.boolean().default(true),
  })
  .strict();

const PatchBody = z
  .object({
    name: z.string().trim().min(1).max(200).optional(),
    endpoint: z.string().trim().url().max(2048).nullable().optional(),
    config: z.record(z.unknown()).optional(),
    credential: z.string().min(1).max(16_384).nullable().optional(),
    enabled: z.boolean().optional(),
  })
  .strict();

/** integration:write in the integration's scope (tenant-wide integrations need a tenant-wide grant). */
function requireWrite(request: FastifyRequest, organizationId: string | null) {
  return requirePermission(request, "integration:write", organizationId);
}

/**
 * Engine integrations (Wazuh, Velociraptor, MISP, OpenCTI, SOCFortress CoPilot, block relays,
 * file-drop / stream sources). Credentials are write-only (secret store); health probes and pull
 * synchronisation reach engines only through their network APIs behind the SSRF guard.
 */
export async function integrationRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/integrations/catalog", async (request) => {
    requireAuth(request);
    return s.integrations.catalog();
  });

  app.get("/integrations", async (request) => {
    const auth = requireAuth(request);
    const q = parse(z.object({ organizationId: Uuid.optional(), kind: z.string().max(64).optional() }), request.query);
    const orgs = resolveOrgFilter(request, "integration:read", q.organizationId);
    const params: unknown[] = [];
    const where = ["TRUE"];
    if (orgs) where.push(`(organization_id IS NULL OR organization_id = ANY($${params.push(orgs)}::uuid[]))`);
    if (q.kind) where.push(`kind = $${params.push(q.kind)}`);
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) => tx.query<Row>(`SELECT * FROM integrations WHERE ${where.join(" AND ")} ORDER BY name`, params));
    return { items: rows.map(toIntegrationView), nextCursor: null };
  });

  app.post("/integrations", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const body = parse(CreateBody, request.body);
    requireWrite(request, body.organizationId);
    const config = validateIntegrationConfig(body.kind, body.config);
    validateEndpoint(body.kind, body.endpoint ?? null, config);
    const created = await s.db.withTenant(auth.tenantId, async (tx) => {
      if (body.organizationId) await loadOne(tx, "organizations", body.organizationId, "Organization");
      const credentialRef = body.credential
        ? (await s.secretStore.put(tx, auth.tenantId, { value: body.credential, name: `${body.kind} integration ${body.name}`, purpose: `integration.${body.kind}`, organizationId: body.organizationId, createdBy: actorId(auth) })).ref
        : null;
      const { rows } = await tx.query<Row>(
        `INSERT INTO integrations (tenant_id, organization_id, kind, name, endpoint, config, credential_ref, enabled, status)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9) RETURNING *`,
        [auth.tenantId, body.organizationId, body.kind, body.name, body.endpoint ?? null, JSON.stringify(config), credentialRef, body.enabled, body.enabled ? "pending" : "disabled"],
      );
      const view = toIntegrationView(rows[0]!);
      await recordAudit(tx, request, { action: "integration.created", organizationId: body.organizationId, targetKind: "integration", targetId: view.id, details: { kind: body.kind, name: body.name, endpoint: body.endpoint ?? null, hasCredential: view.hasCredential } });
      return view;
    });
    return reply.status(201).send(created);
  });

  const load = async (tenantId: string, request: FastifyRequest, id: string): Promise<Row> => {
    const row = await s.db.withTenant(tenantId, (tx) => loadOne(tx, "integrations", id, "Integration"));
    const orgId = (row.organization_id as string | null) ?? null;
    if (orgId) assertRecordAccess(request, "integration:read", orgId, "Integration");
    else resolveOrgFilter(request, "integration:read", undefined);
    return row;
  };

  app.get("/integrations/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    return toIntegrationView(await load(auth.tenantId, request, id));
  });

  app.patch("/integrations/:id", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(PatchBody, request.body);
    if (Object.keys(body).length === 0) throw badRequest("Nothing to update");
    const cur = await load(auth.tenantId, request, id);
    const orgId = (cur.organization_id as string | null) ?? null;
    requireWrite(request, orgId);
    const kind = String(cur.kind);
    const config = body.config ? validateIntegrationConfig(kind, body.config) : ((cur.config as Record<string, unknown>) ?? {});
    const endpoint = body.endpoint !== undefined ? body.endpoint : ((cur.endpoint as string | null) ?? null);
    validateEndpoint(kind, endpoint, config);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      let ref = (cur.credential_ref as string | null) ?? null;
      let released: string | null = null;
      if (typeof body.credential === "string") {
        if (ref) await s.secretStore.replace(tx, auth.tenantId, ref, body.credential);
        else ref = (await s.secretStore.put(tx, auth.tenantId, { value: body.credential, name: `${kind} integration ${body.name ?? String(cur.name)}`, purpose: `integration.${kind}`, organizationId: orgId, createdBy: actorId(auth) })).ref;
      } else if (body.credential === null && ref) {
        released = ref;
        ref = null;
      }
      const enabled = body.enabled ?? Boolean(cur.enabled);
      const { rows } = await tx.query<Row>(
        `UPDATE integrations SET name = $2, endpoint = $3, config = $4::jsonb, credential_ref = $5, enabled = $6,
                status = CASE WHEN NOT $6 THEN 'disabled' WHEN status = 'disabled' THEN 'pending' ELSE status END
         WHERE id = $1 RETURNING *`,
        [id, body.name ?? cur.name, endpoint, JSON.stringify(config), ref, enabled],
      );
      if (released) await s.secretStore.delete(tx, released);
      const fields = Object.keys(body).map((k) => (k === "credential" ? (body.credential === null ? "credential(removed)" : "credential(replaced)") : k));
      await recordAudit(tx, request, { action: "integration.updated", organizationId: orgId, targetKind: "integration", targetId: id, details: { fields } });
      return toIntegrationView(rows[0]!);
    });
  });

  app.delete("/integrations/:id", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const cur = await load(auth.tenantId, request, id);
    const orgId = (cur.organization_id as string | null) ?? null;
    requireWrite(request, orgId);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      await tx.query("DELETE FROM integrations WHERE id = $1", [id]);
      if (cur.credential_ref) await s.secretStore.delete(tx, String(cur.credential_ref));
      await recordAudit(tx, request, { action: "integration.deleted", organizationId: orgId, targetKind: "integration", targetId: id, details: { kind: cur.kind, name: cur.name } });
    });
    return reply.status(204).send();
  });

  app.post("/integrations/:id/health", { config: { audit: "integration.health_checked" } }, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const cur = await load(auth.tenantId, request, id);
    requireWrite(request, (cur.organization_id as string | null) ?? null);
    request.auditState.organizationId = (cur.organization_id as string | null) ?? null;
    request.auditState.targetKind = "integration";
    const result = await s.integrations.health(auth.tenantId, cur);
    request.auditState.details = { ok: result.ok, status: result.status };
    return { integrationId: id, kind: cur.kind, capabilities: capabilitiesOf(String(cur.kind)), health: result };
  });

  // GET alias for dashboards (reads the last stored probe without contacting the engine).
  app.get("/integrations/:id/health", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const cur = await load(auth.tenantId, request, id);
    return { integrationId: id, kind: cur.kind, status: cur.status, health: cur.health ?? {}, lastSyncAt: cur.last_sync_at ?? null, lastEventAt: cur.last_event_at ?? null, lastError: cur.last_error ?? null };
  });

  app.post("/integrations/:id/sync", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const cur = await load(auth.tenantId, request, id);
    const orgId = (cur.organization_id as string | null) ?? null;
    requireWrite(request, orgId);
    // CoPilot sync can create organizations and invite portal users: needs tenant-level org:write.
    if (String(cur.kind) === "copilot" && orgId === null) requirePermission(request, "org:write", null);
    const outcome = await s.integrations.sync(auth.tenantId, cur, actorId(auth));
    if (outcome.status === "failed") {
      // The failure is recorded on the integration; surface it as a gateway error.
      await s.db.withTenant(auth.tenantId, (tx) =>
        recordAudit(tx, request, { action: "integration.sync", organizationId: orgId, targetKind: "integration", targetId: id, outcome: "failure", details: { kind: cur.kind, error: outcome.error ?? null } }),
      );
      throw new HttpError(502, "sync_failed", outcome.message, outcome.error);
    }
    if (String(cur.kind) !== "copilot") {
      await s.db.withTenant(auth.tenantId, (tx) => recordAudit(tx, request, { action: "integration.sync", organizationId: orgId, targetKind: "integration", targetId: id, details: { kind: cur.kind, intel: outcome.intel ?? null } }));
    } else {
      // persistCoPilotPlan wrote the integration.sync audit row inside the sync transaction.
      request.auditState.recorded = true;
    }
    return reply.status(200).send(outcome);
  });
}
