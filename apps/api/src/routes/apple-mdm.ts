import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { AppleEnrollmentInput, AppleMdmPolicyInput, ApplePushCertificateInput, Uuid } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { actorId, requireAuth, requirePermission, requirePerson } from "../auth/rbac.js";
import { requireRecentMfa } from "../auth/step-up.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { notFound } from "../http/errors.js";
import { IdParam } from "../http/params.js";
import { parse } from "./util.js";

const mdm = { module: "mdm" as const };
const PLIST_TYPE = "application/x-apple-aspen-mdm";
const TokenParam = z.object({ token: z.string().regex(/^[0-9a-f]{32}_[0-9a-f]{36}$/) });

async function assertOrganization(tx: Queryable, organizationId: string): Promise<void> {
  const { rowCount } = await tx.query("SELECT 1 FROM organizations WHERE id = $1", [organizationId]);
  if (!rowCount) throw notFound("Organization");
}

/**
 * Apple (iOS / iPadOS) device management. Admin side: APNs push certificate, baseline policy,
 * enrollment profiles. Device side (public): the enrollment profile download and the MDM check-in
 * and command endpoints the iPhone/iPad talk to. Lock / erase are response actions (approval-gated).
 */
export async function appleMdmRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  // The iPhone/iPad posts raw plist bodies; keep them as a string for the service to parse.
  app.addContentTypeParser([PLIST_TYPE, "application/xml", "text/xml"], { parseAs: "string" }, (_req, body, done) => done(null, body));

  // ---- Admin: APNs push certificate ----------------------------------------------------------
  app.get("/mobile/apple/certificate", { config: mdm }, async (request) => {
    const auth = requirePermission(request, "integration:read", null);
    return s.db.withTenant(auth.tenantId, (tx) => s.appleMdm.settings(tx));
  });

  app.put("/mobile/apple/certificate", { config: { ...mdm, audit: false } }, async (request) => {
    const auth = requirePermission(request, "integration:write", null);
    requirePerson(request);
    await requireRecentMfa(request, s);
    const body = parse(ApplePushCertificateInput, request.body);
    const view = await s.appleMdm.saveCertificate(auth.tenantId, body.certificatePem, body.privateKeyPem, actorId(auth));
    await s.db.withTenant(auth.tenantId, (tx) => recordAudit(tx, request, { action: "mobile.apple_certificate_uploaded", targetKind: "account", targetId: auth.tenantId, details: { topic: view.topic, expiresAt: view.expiresAt } }));
    return view;
  });

  app.delete("/mobile/apple/certificate", { config: { ...mdm, audit: false } }, async (request) => {
    const auth = requirePermission(request, "integration:write", null);
    requirePerson(request);
    await requireRecentMfa(request, s);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await s.appleMdm.removeCertificate(tx);
      await recordAudit(tx, request, { action: "mobile.apple_certificate_removed", targetKind: "account", targetId: auth.tenantId });
      return s.appleMdm.settings(tx);
    });
  });

  // ---- Admin: organization -------------------------------------------------------------------
  app.get("/mobile/apple/overview", { config: mdm }, async (request) => {
    const auth = requireAuth(request);
    const { organizationId } = parse(z.object({ organizationId: Uuid }), request.query);
    requirePermission(request, "asset:read", organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, organizationId);
      return s.appleMdm.overview(tx, organizationId);
    });
  });

  app.put("/mobile/apple/policy", { config: { ...mdm, audit: false } }, async (request) => {
    const body = parse(AppleMdmPolicyInput, request.body);
    const auth = requirePermission(request, "asset:write", body.organizationId);
    await s.db.withTenant(auth.tenantId, (tx) => assertOrganization(tx, body.organizationId));
    const settings = await s.appleMdm.savePolicy(auth.tenantId, body.organizationId, body.settings);
    await s.db.withTenant(auth.tenantId, (tx) => recordAudit(tx, request, { action: "mobile.apple_policy_changed", organizationId: body.organizationId, targetKind: "organization", targetId: body.organizationId, details: { settings } }));
    return settings;
  });

  app.post("/mobile/apple/enrollments", { config: { ...mdm, audit: false } }, async (request, reply) => {
    const body = parse(AppleEnrollmentInput, request.body);
    const auth = requirePermission(request, "asset:write", body.organizationId);
    await s.db.withTenant(auth.tenantId, (tx) => assertOrganization(tx, body.organizationId));
    const enrollment = await s.appleMdm.createEnrollment(auth.tenantId, body, actorId(auth));
    await s.db.withTenant(auth.tenantId, (tx) =>
      recordAudit(tx, request, { action: "mobile.apple_enrollment_created", organizationId: body.organizationId, targetKind: "apple_enrollment", targetId: enrollment.id, details: { ownership: body.ownership, validDays: body.validDays, assignee: body.assignee ?? null } }),
    );
    return reply.status(201).send(enrollment);
  });

  app.delete("/mobile/apple/enrollments/:id", { config: { ...mdm, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const org = await s.db.withTenant(auth.tenantId, async (tx) => (await tx.query<{ organization_id: string }>("SELECT organization_id FROM apple_enrollments WHERE id = $1 AND revoked_at IS NULL", [id])).rows[0]?.organization_id);
    if (!org) throw notFound("Enrollment profile");
    requirePermission(request, "asset:write", org);
    await s.appleMdm.revokeEnrollment(auth.tenantId, id);
    await s.db.withTenant(auth.tenantId, (tx) => recordAudit(tx, request, { action: "mobile.apple_enrollment_revoked", organizationId: org, targetKind: "apple_enrollment", targetId: id }));
    return reply.status(204).send();
  });

  app.post("/mobile/apple/sync", { config: { ...mdm, audit: false, rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (request) => {
    const { organizationId } = parse(z.object({ organizationId: Uuid }), request.body);
    const auth = requirePermission(request, "asset:read", organizationId);
    await s.db.withTenant(auth.tenantId, (tx) => assertOrganization(tx, organizationId));
    return s.appleMdm.sync(auth.tenantId, organizationId);
  });

  // ---- Device-facing (public MDM protocol) ---------------------------------------------------
  const deviceLimit = { max: 240, timeWindow: "1 minute" };

  app.get("/mdm/apple/enroll/:token", { config: { public: true, audit: false, rateLimit: deviceLimit } }, async (request, reply) => {
    const { token } = parse(TokenParam, request.params);
    const profile = await s.appleMdm.enrollmentProfile(token);
    if (!profile) return reply.status(404).type("text/plain").send("This enrollment link has expired or was revoked.");
    return reply.type("application/x-apple-aspen-config").header("content-disposition", 'attachment; filename="sciat-enroll.mobileconfig"').send(profile.xml);
  });

  for (const path of ["/mdm/apple/checkin/:token", "/mdm/apple/connect/:token"] as const) {
    const checkin = path.includes("checkin");
    app.put(path, { config: { public: true, audit: false, rateLimit: deviceLimit } }, async (request, reply) => {
      const { token } = parse(TokenParam, request.params);
      const body = typeof request.body === "string" ? request.body : "";
      const res = checkin ? await s.appleMdm.handleCheckin(token, body) : await s.appleMdm.handleConnect(token, body);
      reply.status(res.status);
      if (res.body) return reply.type(PLIST_TYPE).send(res.body);
      return reply.send();
    });
  }
}
