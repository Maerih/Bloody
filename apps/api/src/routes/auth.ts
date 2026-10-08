import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { principalOrgScope } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { safeReturnTo } from "../auth/oidc.js";
import { requireAuth } from "../auth/rbac.js";
import { CSRF_COOKIE, CSRF_HEADER, OIDC_STATE_COOKIE, SESSION_COOKIE } from "../auth/types.js";
import type { AppServices } from "../context.js";
import { HttpError, badRequest, forbidden, notFound, unauthorized } from "../http/errors.js";
import { IdParam } from "../http/params.js";
import { toAccount, toOrganization, type Row } from "../repo/mappers.js";
import { hashPassword, passwordPolicyErrors, verifyPassword, PASSWORD_MAX_LENGTH } from "../security/passwords.js";
import { computeEntitlements } from "../services/entitlements.js";
import { clearSessionCookies, clientInfo, parse, setSessionCookies } from "./util.js";

const LoginBody = z.object({
  email: z.string().trim().min(3).max(320),
  password: z.string().min(1).max(PASSWORD_MAX_LENGTH),
  totp: z
    .string()
    .trim()
    .regex(/^\d{6}$/, "must be a 6-digit code")
    .optional(),
});
const CodeBody = z.object({ code: z.string().trim().regex(/^\d{6}$/, "must be a 6-digit code") });
const PasswordChangeBody = z.object({ currentPassword: z.string().min(1).max(PASSWORD_MAX_LENGTH), newPassword: z.string().min(1).max(PASSWORD_MAX_LENGTH) });
const OidcStartQuery = z.object({ returnTo: z.string().max(2000).optional() });
const OidcCallbackQuery = z.object({
  code: z.string().min(1).max(4096).optional(),
  state: z.string().min(1).max(512).optional(),
  error: z.string().max(200).optional(),
});

/**
 * Authentication: password (+ TOTP) login, rotating cookie sessions with short-lived bearer
 * JWTs, CSRF double-submit, MFA enrollment / step-up, session management and OIDC SSO.
 */
export async function authRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  const loginLimit = {
    max: s.config.auth.loginRateLimitPerMinute,
    timeWindow: "1 minute",
    keyGenerator: (req: { ip: string }) => `login:${req.ip}`,
  };

  // POST /auth/login → { token, expiresAt, principal, csrfToken } | { mfaRequired: true }
  app.post("/auth/login", { config: { public: true, audit: false, rateLimit: loginLimit } }, async (request, reply) => {
    const body = parse(LoginBody, request.body);
    const result = await s.auth.login({ email: body.email, password: body.password, totp: body.totp }, clientInfo(request));
    if (result.kind === "mfa_required") return { mfaRequired: true };
    const csrfToken = setSessionCookies(s, reply, result.session);
    return {
      token: result.accessToken,
      tokenType: "Bearer",
      expiresAt: result.accessTokenExpiresAt,
      sessionExpiresAt: result.session.expiresAt,
      principal: result.principal,
      csrfToken,
    };
  });

  // POST /auth/refresh — rotate the session secret (cookie) and mint a new access token.
  app.post("/auth/refresh", { config: { public: true, audit: false, rateLimit: loginLimit } }, async (request, reply) => {
    const cookie = request.cookies[SESSION_COOKIE];
    if (!cookie) throw unauthorized("No session", "invalid_session");
    const sessionId = s.auth.sessionIdFromCookie(cookie);
    const header = request.headers[CSRF_HEADER];
    if (!sessionId || !s.auth.verifyCsrf(sessionId, request.cookies[CSRF_COOKIE], typeof header === "string" ? header : undefined)) {
      throw forbidden("Missing or invalid CSRF token", "csrf");
    }
    const r = await s.auth.refresh(cookie, clientInfo(request));
    const csrfToken = setSessionCookies(s, reply, r.session);
    return { token: r.accessToken, tokenType: "Bearer", expiresAt: r.accessTokenExpiresAt, sessionExpiresAt: r.session.expiresAt, principal: r.principal, csrfToken };
  });

  // POST /auth/logout — revoke the current session (if any) and clear cookies. Always 204.
  app.post("/auth/logout", { config: { public: true, audit: false } }, async (request, reply) => {
    const auth = request.auth;
    if (auth?.sessionId) {
      await s.db.withTenant(auth.tenantId, async (tx) => {
        await s.auth.revokeSession(tx, auth.sessionId!, "logout");
        await recordAudit(tx, request, { action: "auth.logout", targetKind: "session", targetId: auth.sessionId });
      });
    }
    clearSessionCookies(s, reply);
    return reply.status(204).send();
  });

  // GET /auth/me → { principal, account, organizations, entitlements, plan, user, session }
  app.get("/auth/me", async (request) => {
    const auth = requireAuth(request);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const account = await tx.query<Row>("SELECT * FROM accounts WHERE id = $1", [auth.tenantId]);
      if (!account.rows[0]) throw unauthorized("Account is no longer available", "account_unavailable");
      let scope = principalOrgScope(auth.principal);
      if (auth.boundOrganizationId) scope = scope === "all" || scope.includes(auth.boundOrganizationId) ? [auth.boundOrganizationId] : [];
      const orgs =
        scope === "all"
          ? await tx.query<Row>("SELECT * FROM organizations ORDER BY lower(name), id")
          : await tx.query<Row>("SELECT * FROM organizations WHERE id = ANY($1::uuid[]) ORDER BY lower(name), id", [scope]);
      const { plan, entitlements } = await computeEntitlements(tx, auth.tenantId, s.now());
      let user: Record<string, unknown> | null = null;
      let session: Record<string, unknown> | null = null;
      if (auth.principal.kind === "user") {
        const u = await tx.query<Row>("SELECT id, email, display_name, title, organization_id, mfa_enabled, last_login_at FROM users WHERE id = $1", [auth.principal.id]);
        const r = u.rows[0];
        if (r) {
          user = { id: r.id, email: r.email, displayName: r.display_name, title: r.title, organizationId: r.organization_id, mfaEnabled: r.mfa_enabled, lastLoginAt: r.last_login_at };
        }
        if (auth.sessionId) {
          const sr = await tx.query<Row>("SELECT id, auth_method, mfa_verified, created_at, expires_at, idle_expires_at FROM sessions WHERE id = $1", [auth.sessionId]);
          const x = sr.rows[0];
          if (x) session = { id: x.id, method: x.auth_method, mfaVerified: x.mfa_verified, createdAt: x.created_at, expiresAt: x.expires_at, idleExpiresAt: x.idle_expires_at };
        }
      }
      return {
        principal: auth.principal,
        account: { ...toAccount(account.rows[0]), plan: account.rows[0].plan, status: account.rows[0].status, trialEndsAt: account.rows[0].trial_ends_at ?? null },
        organizations: orgs.rows.map(toOrganization),
        entitlements,
        plan,
        authMethod: auth.method,
        boundOrganizationId: auth.boundOrganizationId,
        user,
        session,
        accountTeam: null,
      };
    });
  });

  // ─── Sessions ────────────────────────────────────────────────────────────

  app.get("/auth/sessions", async (request) => {
    const auth = requireAuth(request);
    if (auth.principal.kind !== "user") throw forbidden("Only user principals have sessions");
    const { rows } = await s.db.withTenant(auth.tenantId, (tx) =>
      tx.query<Row>(
        `SELECT id, auth_method, mfa_verified, ip, user_agent, created_at, last_seen_at, expires_at, idle_expires_at FROM sessions
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now() AND idle_expires_at > now() ORDER BY last_seen_at DESC LIMIT 100`,
        [auth.principal.id],
      ),
    );
    return {
      items: rows.map((r) => ({
        id: r.id,
        current: r.id === auth.sessionId,
        method: r.auth_method,
        mfaVerified: r.mfa_verified,
        ip: r.ip,
        userAgent: r.user_agent,
        createdAt: r.created_at,
        lastSeenAt: r.last_seen_at,
        expiresAt: r.expires_at,
      })),
      nextCursor: null,
    };
  });

  app.delete("/auth/sessions/:id", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      const res = await tx.query("UPDATE sessions SET revoked_at = now(), revoked_reason = 'user_revoked' WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL", [id, auth.principal.id]);
      if ((res.rowCount ?? 0) === 0) throw notFound("Session");
      await recordAudit(tx, request, { action: "auth.session_revoked", targetKind: "session", targetId: id });
    });
    if (id === auth.sessionId) clearSessionCookies(s, reply);
    return reply.status(204).send();
  });

  // POST /auth/password — change own password (revokes every other session).
  app.post("/auth/password", { config: { audit: false, rateLimit: loginLimit } }, async (request, reply) => {
    const auth = requireAuth(request);
    if (auth.principal.kind !== "user") throw forbidden("Only user principals have passwords");
    const body = parse(PasswordChangeBody, request.body);
    const errors = passwordPolicyErrors(body.newPassword, auth.principal.email);
    if (errors.length > 0) throw new HttpError(400, "weak_password", "The new password does not meet the password policy", errors);
    const current = await s.db.withTenant(auth.tenantId, (tx) => tx.query<{ password_hash: string }>("SELECT password_hash FROM user_credentials WHERE user_id = $1", [auth.principal.id]));
    const hash = current.rows[0]?.password_hash;
    if (!hash || !(await verifyPassword(hash, body.currentPassword))) {
      await s.db.withTenant(auth.tenantId, (tx) => recordAudit(tx, request, { action: "auth.password_changed", targetKind: "user", targetId: auth.principal.id, outcome: "denied", details: { reason: "bad_current_password" } }));
      throw unauthorized("Current password is incorrect", "invalid_credentials");
    }
    const next = await hashPassword(body.newPassword);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      await tx.query("UPDATE user_credentials SET password_hash = $2, password_changed_at = now() WHERE user_id = $1", [auth.principal.id, next]);
      await tx.query("UPDATE sessions SET revoked_at = now(), revoked_reason = 'password_changed' WHERE user_id = $1 AND revoked_at IS NULL AND id IS DISTINCT FROM $2", [auth.principal.id, auth.sessionId]);
      await recordAudit(tx, request, { action: "auth.password_changed", targetKind: "user", targetId: auth.principal.id });
    });
    return reply.status(204).send();
  });

  // ─── TOTP MFA ────────────────────────────────────────────────────────────

  app.post("/auth/mfa/totp/enroll", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    if (auth.principal.kind !== "user") throw forbidden("Only user principals can enroll MFA");
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const out = await s.auth.beginTotpEnrollment(tx, auth);
      await recordAudit(tx, request, { action: "auth.mfa_enrollment_started", targetKind: "user", targetId: auth.principal.id });
      return out;
    });
  });

  app.post("/auth/mfa/totp/confirm", { config: { audit: false, rateLimit: loginLimit } }, async (request) => {
    const auth = requireAuth(request);
    const { code } = parse(CodeBody, request.body);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      await s.auth.confirmTotpEnrollment(tx, auth, code);
      if (auth.sessionId) await tx.query("UPDATE sessions SET mfa_verified = true WHERE id = $1", [auth.sessionId]);
      await recordAudit(tx, request, { action: "auth.mfa_enabled", targetKind: "user", targetId: auth.principal.id });
    });
    return { mfaEnabled: true };
  });

  app.post("/auth/mfa/totp/disable", { config: { audit: false, rateLimit: loginLimit } }, async (request) => {
    const auth = requireAuth(request);
    const { code } = parse(CodeBody, request.body);
    await s.db.withTenant(auth.tenantId, async (tx) => {
      await s.auth.disableTotp(tx, auth, code);
      await recordAudit(tx, request, { action: "auth.mfa_disabled", targetKind: "user", targetId: auth.principal.id });
    });
    return { mfaEnabled: false };
  });

  // POST /auth/mfa/verify — step-up: mark the current session as MFA-verified.
  app.post("/auth/mfa/verify", { config: { audit: false, rateLimit: loginLimit } }, async (request) => {
    const auth = requireAuth(request);
    if (!auth.sessionId) throw badRequest("Step-up verification needs a user session");
    const { code } = parse(CodeBody, request.body);
    const ok = await s.db.withTenant(auth.tenantId, async (tx) => {
      const valid = await s.auth.consumeTotp(tx, auth.tenantId, auth.principal.id, code);
      if (valid) await tx.query("UPDATE sessions SET mfa_verified = true WHERE id = $1", [auth.sessionId]);
      await recordAudit(tx, request, { action: "auth.mfa_step_up", targetKind: "session", targetId: auth.sessionId, outcome: valid ? "success" : "failure" });
      return valid;
    });
    if (!ok) throw new HttpError(400, "invalid_mfa_code", "Invalid verification code");
    return { mfaVerified: true };
  });

  // ─── OIDC SSO (Keycloak / Entra ID / Okta) ───────────────────────────────

  app.get("/auth/oidc/config", { config: { public: true } }, async () => ({ enabled: s.oidc !== null, provider: s.oidc?.id ?? null }));

  app.get("/auth/oidc/start", { config: { public: true, rateLimit: loginLimit } }, async (request, reply) => {
    if (!s.oidc) throw new HttpError(501, "sso_not_configured", "Single sign-on is not configured for this deployment");
    const q = parse(OidcStartQuery, request.query);
    const { url, stateCookie } = await s.oidc.start({ returnTo: safeReturnTo(q.returnTo ?? "/") });
    void reply.setCookie(OIDC_STATE_COOKIE, stateCookie, { httpOnly: true, secure: s.config.http.cookieSecure, sameSite: "lax", path: "/api/v1/auth/oidc", maxAge: 600 });
    return { url, authorizationUrl: url, provider: s.oidc.id };
  });

  app.get("/auth/oidc/callback", { config: { public: true, rateLimit: loginLimit } }, async (request, reply) => {
    const base = s.config.http.publicUrl.replace(/\/+$/, "");
    void reply.clearCookie(OIDC_STATE_COOKIE, { path: "/api/v1/auth/oidc", secure: s.config.http.cookieSecure, sameSite: "lax", httpOnly: true });
    if (!s.oidc) return reply.redirect(`${base}/login?sso_error=sso_not_configured`);
    const q = parse(OidcCallbackQuery, request.query);
    try {
      if (q.error || !q.code || !q.state) throw new HttpError(400, "sso_denied", "The identity provider did not complete the sign-in");
      const identity = await s.oidc.callback({ code: q.code, state: q.state, stateCookie: request.cookies[OIDC_STATE_COOKIE] });
      const login = await s.auth.loginWithOidc(identity, clientInfo(request));
      setSessionCookies(s, reply, login.session);
      return reply.redirect(`${base}${safeReturnTo(identity.returnTo)}`);
    } catch (err) {
      const code = err instanceof HttpError ? err.code : "sso_failed";
      request.log.warn({ code, err: err instanceof Error ? err.message : String(err) }, "OIDC sign-in failed");
      return reply.redirect(`${base}/login?sso_error=${encodeURIComponent(code)}`);
    }
  });
}
