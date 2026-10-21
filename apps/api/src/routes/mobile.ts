import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { AndroidEnterpriseLinkInput, AndroidEnterpriseSignupInput, AndroidPolicyInput, AndroidServiceAccountInput, MobileEnrollmentTokenInput, Uuid } from "@bloody/contracts";
import { SYSTEM_ACTOR, recordAudit, writeAudit } from "../audit/audit.js";
import { actorId, requireAuth, requirePermission, requirePerson } from "../auth/rbac.js";
import { requireRecentMfa } from "../auth/step-up.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { HttpError, notFound } from "../http/errors.js";
import { IdParam } from "../http/params.js";
import { parse } from "./util.js";

const mdm = { module: "mdm" as const };

async function assertOrganization(tx: Queryable, organizationId: string): Promise<void> {
  const { rowCount } = await tx.query("SELECT 1 FROM organizations WHERE id = $1", [organizationId]);
  if (!rowCount) throw notFound("Organization");
}

/**
 * Mobile Device Management (Android Enterprise). Account: the Google Cloud service account.
 * Organization: its Android Enterprise, SCIAT baseline policy, enrollment QR codes and phones.
 * Lock / wipe are response actions (lock_device / wipe_device) so they go through approval.
 */
export async function mobileRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  // ---- Account: Google service account --------------------------------------------------------
  app.get("/mobile/android/account", { config: mdm }, async (request) => {
    const auth = requirePermission(request, "integration:read", null);
    return s.db.withTenant(auth.tenantId, (tx) => s.android.settings(tx));
  });

  app.put("/mobile/android/account", { config: { ...mdm, audit: false } }, async (request) => {
    const auth = requirePermission(request, "integration:write", null);
    requirePerson(request);
    await requireRecentMfa(request, s);
    const { serviceAccountJson } = parse(AndroidServiceAccountInput, request.body);
    const view = await s.android.saveServiceAccount(auth.tenantId, serviceAccountJson, actorId(auth));
    await s.db.withTenant(auth.tenantId, (tx) =>
      recordAudit(tx, request, { action: "mobile.google_account_connected", targetKind: "account", targetId: auth.tenantId, details: { projectId: view.projectId, clientEmail: view.clientEmail } }),
    );
    return view;
  });

  app.delete("/mobile/android/account", { config: { ...mdm, audit: false } }, async (request) => {
    const auth = requirePermission(request, "integration:write", null);
    requirePerson(request);
    await requireRecentMfa(request, s);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await s.android.removeServiceAccount(tx);
      await recordAudit(tx, request, { action: "mobile.google_account_removed", targetKind: "account", targetId: auth.tenantId });
      return s.android.settings(tx);
    });
  });

  // ---- Organization ---------------------------------------------------------------------------
  app.get("/mobile/overview", { config: mdm }, async (request) => {
    const auth = requireAuth(request);
    const { organizationId } = parse(z.object({ organizationId: Uuid }), request.query);
    requirePermission(request, "asset:read", organizationId);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      await assertOrganization(tx, organizationId);
      return s.android.overview(tx, organizationId);
    });
  });

  app.post("/mobile/android/enterprise/signup", { config: { ...mdm, audit: false } }, async (request) => {
    const body = parse(AndroidEnterpriseSignupInput, request.body);
    const auth = requirePermission(request, "asset:write", body.organizationId);
    requirePerson(request);
    await s.db.withTenant(auth.tenantId, (tx) => assertOrganization(tx, body.organizationId));
    const res = await s.android.startSignup(auth.tenantId, body.organizationId, actorId(auth), body.adminEmail);
    await s.db.withTenant(auth.tenantId, (tx) => recordAudit(tx, request, { action: "mobile.enterprise_signup_started", organizationId: body.organizationId, targetKind: "organization", targetId: body.organizationId }));
    return res;
  });

  /** Google's browser redirect after the customer signs up (no session needed; the state is single-use). */
  app.get("/mobile/android/signup-callback", { config: { public: true, audit: false, rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (request, reply) => {
    const q = parse(z.object({ state: z.string().min(40).max(200), enterpriseToken: z.string().min(1).max(4096).optional() }), request.query);
    const base = s.config.http.publicUrl.replace(/\/+$/, "");
    if (!q.enterpriseToken) return reply.redirect(`${base}/mdm?android=cancelled`);
    try {
      const { tenantId, organizationId } = await s.android.completeSignup(q.state, q.enterpriseToken);
      await s.db.withTenant(tenantId, (tx) =>
        writeAudit(tx, SYSTEM_ACTOR(tenantId, "google-signup"), { action: "mobile.enterprise_created", organizationId, targetKind: "organization", targetId: organizationId }),
      );
      return reply.redirect(`${base}/mdm?organizationId=${organizationId}&android=connected`);
    } catch (err) {
      const code = err instanceof HttpError ? err.code : "android_signup_failed";
      return reply.redirect(`${base}/mdm?android=error&reason=${encodeURIComponent(code)}`);
    }
  });

  app.post("/mobile/android/enterprise/link", { config: { ...mdm, audit: false } }, async (request) => {
    const body = parse(AndroidEnterpriseLinkInput, request.body);
    const auth = requirePermission(request, "asset:write", body.organizationId);
    requirePerson(request);
    await s.db.withTenant(auth.tenantId, (tx) => assertOrganization(tx, body.organizationId));
    const e = await s.android.link(auth.tenantId, body.organizationId, body.enterpriseName, actorId(auth));
    await s.db.withTenant(auth.tenantId, (tx) =>
      recordAudit(tx, request, { action: "mobile.enterprise_linked", organizationId: body.organizationId, targetKind: "organization", targetId: body.organizationId, details: { enterpriseName: e.enterpriseName } }),
    );
    return e;
  });

  app.delete("/mobile/android/enterprise", { config: { ...mdm, audit: false } }, async (request, reply) => {
    const { organizationId } = parse(z.object({ organizationId: Uuid }), request.query);
    const auth = requirePermission(request, "asset:write", organizationId);
    requirePerson(request);
    await requireRecentMfa(request, s);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const e = await s.android.unlink(tx, organizationId);
      await recordAudit(tx, request, { action: "mobile.enterprise_unlinked", organizationId, targetKind: "organization", targetId: organizationId, details: { enterpriseName: e.enterpriseName } });
    });
    return reply.status(204).send();
  });

  app.put("/mobile/android/policy", { config: { ...mdm, audit: false } }, async (request) => {
    const body = parse(AndroidPolicyInput, request.body);
    const auth = requirePermission(request, "asset:write", body.organizationId);
    const e = await s.android.savePolicy(auth.tenantId, body.organizationId, body.settings);
    await s.db.withTenant(auth.tenantId, (tx) =>
      recordAudit(tx, request, { action: "mobile.policy_changed", organizationId: body.organizationId, targetKind: "organization", targetId: body.organizationId, details: { settings: body.settings } }),
    );
    return e;
  });

  app.post("/mobile/android/enrollment-tokens", { config: { ...mdm, audit: false } }, async (request, reply) => {
    const body = parse(MobileEnrollmentTokenInput, request.body);
    const auth = requirePermission(request, "asset:write", body.organizationId);
    const token = await s.android.createToken(auth.tenantId, body, actorId(auth));
    await s.db.withTenant(auth.tenantId, (tx) =>
      recordAudit(tx, request, {
        action: "mobile.enrollment_code_created",
        organizationId: body.organizationId,
        targetKind: "mobile_enrollment_token",
        targetId: token.id,
        details: { ownership: body.ownership, validDays: body.validDays, assignee: body.assignee ?? null },
      }),
    );
    return reply.status(201).send(token);
  });

  app.delete("/mobile/android/enrollment-tokens/:id", { config: { ...mdm, audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const org = await s.db.withTenant(auth.tenantId, async (tx) => (await tx.query<{ organization_id: string }>("SELECT organization_id FROM mobile_enrollment_tokens WHERE id = $1 AND revoked_at IS NULL", [id])).rows[0]?.organization_id);
    if (!org) throw notFound("Enrollment code");
    requirePermission(request, "asset:write", org);
    await s.android.revokeToken(auth.tenantId, id);
    await s.db.withTenant(auth.tenantId, (tx) => recordAudit(tx, request, { action: "mobile.enrollment_code_revoked", organizationId: org, targetKind: "mobile_enrollment_token", targetId: id }));
    return reply.status(204).send();
  });

  app.post("/mobile/android/sync", { config: { ...mdm, audit: false, rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (request) => {
    const { organizationId } = parse(z.object({ organizationId: Uuid }), request.body);
    const auth = requirePermission(request, "asset:read", organizationId);
    await s.db.withTenant(auth.tenantId, (tx) => assertOrganization(tx, organizationId));
    return s.android.sync(auth.tenantId, organizationId);
  });
}
