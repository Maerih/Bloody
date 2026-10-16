import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { EXPOSURE_PORTS, Uuid } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { actorId, requireAuth, requirePermission } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { HttpError, notFound } from "../http/errors.js";
import { IdParam } from "../http/params.js";
import { parse } from "./util.js";

const espm = { module: "espm" as const };
const MAX_AUTHORIZATION_DAYS = 366;

const AuthorizeBody = z
  .object({
    /** Contract, statement of work or written approval that allows testing these addresses. */
    reference: z.string().trim().min(3).max(500),
    expiresAt: z.string().datetime(),
    /** The person recording it confirms the organization owns, or may have tested, these addresses. */
    attest: z.literal(true),
  })
  .strict();
const AddTargetBody = z.object({ organizationId: Uuid, ip: z.string().ip(), note: z.string().trim().max(200).optional() }).strict();
const DecideBody = z.object({ status: z.enum(["confirmed", "ignored"]) }).strict();

async function assertOrganization(tx: Queryable, organizationId: string): Promise<void> {
  const { rowCount } = await tx.query("SELECT 1 FROM organizations WHERE id = $1", [organizationId]);
  if (!rowCount) throw notFound("Organization");
}

/** External Exposure: public addresses, the authorization to test them, scans and exposed services. */
export async function exposureRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/exposure/overview", { config: espm }, async (request) => {
    const auth = requireAuth(request);
    const { organizationId } = parse(z.object({ organizationId: Uuid }), request.query);
    requirePermission(request, "asset:read", organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, organizationId);
      return {
        organizationId,
        authorization: await s.exposure.authorization(tx, organizationId),
        targets: await s.exposure.targets(tx, organizationId),
        findings: await s.exposure.findings(tx, organizationId),
        scans: await s.exposure.scans(tx, organizationId),
        portsChecked: EXPOSURE_PORTS.map(({ port, service, severity }) => ({ port, service, severity })),
      };
    });
  });

  app.put("/exposure/authorization/:id", { config: { ...espm, audit: false } }, async (request) => {
    const { id } = parse(IdParam, request.params);
    const auth = requirePermission(request, "asset:write", id);
    const body = parse(AuthorizeBody, request.body);
    const expires = Date.parse(body.expiresAt);
    if (expires <= s.now()) throw new HttpError(400, "invalid_expiry", "The authorization must end in the future");
    if (expires > s.now() + MAX_AUTHORIZATION_DAYS * 86_400_000) throw new HttpError(400, "invalid_expiry", "Authorizations last at most one year — renew them when the contract renews");
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, id);
      const saved = await s.exposure.authorize(tx, auth.tenantId, id, { reference: body.reference, expiresAt: new Date(expires).toISOString() }, actorId(auth));
      await recordAudit(tx, request, { action: "exposure.authorized", organizationId: id, targetKind: "organization", targetId: id, details: { reference: saved.reference, expiresAt: saved.expiresAt, attested: true } });
      return saved;
    });
  });

  app.delete("/exposure/authorization/:id", { config: { ...espm, audit: false } }, async (request) => {
    const { id } = parse(IdParam, request.params);
    const auth = requirePermission(request, "asset:write", id);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, id);
      if (!(await s.exposure.revoke(tx, id))) throw notFound("Authorization");
      await recordAudit(tx, request, { action: "exposure.authorization_revoked", organizationId: id, targetKind: "organization", targetId: id });
      return { revoked: true };
    });
  });

  app.post("/exposure/targets", { config: { ...espm, audit: false } }, async (request, reply) => {
    const body = parse(AddTargetBody, request.body);
    const auth = requirePermission(request, "asset:write", body.organizationId);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, body.organizationId);
      await s.exposure.addTarget(tx, auth.tenantId, body.organizationId, body.ip, body.note ?? null, actorId(auth));
      await recordAudit(tx, request, { action: "exposure.address_added", organizationId: body.organizationId, targetKind: "address", targetId: body.ip, details: { note: body.note ?? null } });
    });
    return reply.code(201).send({ ok: true });
  });

  app.patch("/exposure/targets/:id", { config: { ...espm, audit: false } }, async (request) => {
    const { id } = parse(IdParam, request.params);
    const { status } = parse(DecideBody, request.body);
    const auth = requireAuth(request);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const target = await s.exposure.getTarget(tx, id);
      requirePermission(request, "asset:write", target.organizationId);
      await s.exposure.decide(tx, id, status, actorId(auth));
      await recordAudit(tx, request, { action: status === "confirmed" ? "exposure.address_confirmed" : "exposure.address_ignored", organizationId: target.organizationId, targetKind: "address", targetId: target.ip });
      return { ok: true };
    });
  });

  app.delete("/exposure/targets/:id", { config: { ...espm, audit: false } }, async (request) => {
    const { id } = parse(IdParam, request.params);
    const auth = requireAuth(request);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const target = await s.exposure.getTarget(tx, id);
      requirePermission(request, "asset:write", target.organizationId);
      await s.exposure.removeTarget(tx, id);
      await recordAudit(tx, request, { action: "exposure.address_removed", organizationId: target.organizationId, targetKind: "address", targetId: target.ip });
      return { ok: true };
    });
  });

  app.post("/exposure/scans", { config: { ...espm, audit: false } }, async (request, reply) => {
    const { organizationId } = parse(z.object({ organizationId: Uuid }).strict(), request.body);
    const auth = requirePermission(request, "asset:write", organizationId);
    await s.db.withTenant(auth.tenantId, (tx) => assertOrganization(tx, organizationId));
    const { scan } = await s.exposure.startScan(auth.tenantId, organizationId, "manual", actorId(auth));
    await s.db.withTenant(auth.tenantId, (tx) =>
      recordAudit(tx, request, { action: "exposure.scan_started", organizationId, targetKind: "organization", targetId: organizationId, details: { scanId: scan.id, addresses: scan.addresses } }),
    );
    return reply.code(202).send(scan);
  });
}
