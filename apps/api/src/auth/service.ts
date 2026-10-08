import { RoleKey, type Principal, type RoleBinding } from "@bloody/contracts";
import type { AppConfig } from "../config.js";
import { SYSTEM_ACTOR, writeAudit, type AuditActor } from "../audit/audit.js";
import type { Database, Queryable } from "../db/pool.js";
import { isUuid } from "../db/pool.js";
import { HttpError, conflict, unauthorized } from "../http/errors.js";
import { hmacSha256, randomAlnum, randomToken, safeEqual, sha256Hex, type SecretBox } from "../security/crypto.js";
import { hashPassword, needsRehash, verifyAgainstDummy, verifyPassword } from "../security/passwords.js";
import { signAccessToken, TokenError, verifyAccessToken, type TokenSettings } from "../security/tokens.js";
import { generateTotpSecret, otpauthUri, verifyTotp } from "../security/totp.js";
import type { AuthContext } from "./types.js";

export interface UserRow {
  id: string;
  tenant_id: string;
  organization_id: string | null;
  email: string;
  display_name: string | null;
  status: "active" | "invited" | "disabled";
  mfa_enabled: boolean;
  failed_login_count: number;
  locked_until: string | null;
  oidc_subject: string | null;
}

export interface IssuedSession {
  sessionId: string;
  cookieValue: string;
  expiresAt: string;
}

export interface LoginSuccess {
  kind: "success";
  tenantId: string;
  principal: Principal;
  session: IssuedSession;
  accessToken: string;
  accessTokenExpiresAt: string;
}

export type LoginResult = LoginSuccess | { kind: "mfa_required" };

export interface ClientInfo {
  ip: string | null;
  userAgent: string | null;
  requestId: string | null;
}

const API_KEY_RE = /^bk_([a-z0-9]{12})_([A-Za-z0-9_-]{32,128})$/;
const INVALID_CREDENTIALS = "Invalid credentials or the account is temporarily locked";

/** Effective role bindings of a user: direct bindings plus those of every team they belong to. */
export async function loadUserBindings(tx: Queryable, userId: string): Promise<RoleBinding[]> {
  const { rows } = await tx.query<{ role: string; organization_id: string | null }>(
    `SELECT DISTINCT role, organization_id FROM role_bindings
     WHERE (principal_kind = 'user' AND principal_id = $1)
        OR (principal_kind = 'team' AND principal_id IN (SELECT team_id FROM team_members WHERE user_id = $1))
     ORDER BY role, organization_id NULLS FIRST`,
    [userId],
  );
  return rows.flatMap((r) => {
    const role = RoleKey.safeParse(r.role);
    return role.success ? [{ role: role.data, organizationId: r.organization_id }] : [];
  });
}

export async function loadApiKeyBindings(tx: Queryable, apiKeyId: string): Promise<RoleBinding[]> {
  const { rows } = await tx.query<{ role: string; organization_id: string | null }>(
    "SELECT role, organization_id FROM role_bindings WHERE principal_kind = 'api_key' AND principal_id = $1 ORDER BY role",
    [apiKeyId],
  );
  return rows.flatMap((r) => {
    const role = RoleKey.safeParse(r.role);
    return role.success ? [{ role: role.data, organizationId: r.organization_id }] : [];
  });
}

export class AuthService {
  readonly tokenSettings: TokenSettings;

  constructor(
    private readonly db: Database,
    private readonly config: AppConfig,
    private readonly secrets: SecretBox,
    private readonly now: () => number = () => Date.now(),
  ) {
    this.tokenSettings = { secret: config.auth.jwtSecret, issuer: config.auth.jwtIssuer, audience: config.auth.jwtAudience, ttlSeconds: config.auth.accessTokenTtlSeconds };
  }

  // ─── Pre-auth directory ──────────────────────────────────────────────────

  async lookupEmail(email: string): Promise<{ tenantId: string; userId: string } | null> {
    return this.lookup("user_email", email.trim().toLowerCase());
  }

  private async lookup(kind: "user_email" | "api_key", value: string): Promise<{ tenantId: string; userId: string } | null> {
    const rows = await this.db.withoutTenant(async (tx) =>
      (await tx.query<{ tenant_id: string; subject_id: string }>("SELECT tenant_id, subject_id FROM auth_lookup WHERE lookup_hash = auth_lookup_digest($1, $2) AND kind = $1", [kind, value])).rows,
    );
    const row = rows[0];
    return row ? { tenantId: row.tenant_id, userId: row.subject_id } : null;
  }

  // ─── Password login ──────────────────────────────────────────────────────

  async login(input: { email: string; password: string; totp?: string | undefined }, client: ClientInfo): Promise<LoginResult> {
    const email = input.email.trim().toLowerCase();
    const found = await this.lookupEmail(email);
    if (!found) {
      await verifyAgainstDummy(input.password);
      throw unauthorized(INVALID_CREDENTIALS, "invalid_credentials");
    }
    const { tenantId, userId } = found;
    const actor: AuditActor = { tenantId, actorKind: "anonymous", actorId: null, actorLabel: email, ip: client.ip, userAgent: client.userAgent, requestId: client.requestId };

    const user = await this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<UserRow & { password_hash: string | null }>(
        `SELECT u.*, c.password_hash FROM users u LEFT JOIN user_credentials c ON c.user_id = u.id WHERE u.id = $1`,
        [userId],
      );
      return rows[0] ?? null;
    });
    if (!user) {
      await verifyAgainstDummy(input.password);
      throw unauthorized(INVALID_CREDENTIALS, "invalid_credentials");
    }
    const lockedUntil = user.locked_until ? Date.parse(user.locked_until) : 0;
    if (lockedUntil > this.now()) {
      await verifyAgainstDummy(input.password);
      await this.db.withTenant(tenantId, (tx) => writeAudit(tx, actor, { action: "auth.login", targetKind: "user", targetId: userId, outcome: "denied", details: { reason: "locked" } }));
      throw unauthorized(INVALID_CREDENTIALS, "invalid_credentials");
    }
    const passwordOk = user.password_hash ? await verifyPassword(user.password_hash, input.password) : (await verifyAgainstDummy(input.password), false);
    if (!passwordOk || user.status !== "active") {
      await this.registerFailure(tenantId, userId, actor, passwordOk ? `status:${user.status}` : "bad_password");
      throw unauthorized(INVALID_CREDENTIALS, "invalid_credentials");
    }

    let mfaVerified = false;
    if (user.mfa_enabled) {
      if (!input.totp) return { kind: "mfa_required" };
      const ok = await this.db.withTenant(tenantId, (tx) => this.consumeTotp(tx, tenantId, userId, input.totp!));
      if (!ok) {
        await this.registerFailure(tenantId, userId, actor, "bad_totp");
        throw unauthorized("Invalid verification code", "invalid_mfa_code");
      }
      mfaVerified = true;
    }

    const rehash = user.password_hash && needsRehash(user.password_hash) ? await hashPassword(input.password) : null;
    return this.db.withTenant(tenantId, async (tx) => {
      await tx.query("UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = now() WHERE id = $1", [userId]);
      if (rehash) await tx.query("UPDATE user_credentials SET password_hash = $2, password_changed_at = password_changed_at WHERE user_id = $1", [userId, rehash]);
      const session = await this.createSession(tx, { tenantId, userId, organizationId: user.organization_id, method: "password", mfaVerified, client });
      const principal = await this.principalFor(tx, user, session.sessionId);
      await writeAudit(tx, { ...actor, actorKind: "user", actorId: userId }, { action: "auth.login", targetKind: "session", targetId: session.sessionId, details: { method: "password", mfa: mfaVerified } });
      const access = await signAccessToken({ sub: userId, tid: tenantId, sid: session.sessionId, kind: "user" }, this.tokenSettings, this.now());
      return { kind: "success" as const, tenantId, principal, session, accessToken: access.token, accessTokenExpiresAt: access.expiresAt };
    });
  }

  private async registerFailure(tenantId: string, userId: string, actor: AuditActor, reason: string): Promise<void> {
    const max = this.config.auth.loginMaxFailures;
    const lockMinutes = this.config.auth.loginLockoutMinutes;
    await this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<{ failed_login_count: number; locked_until: string | null }>(
        `UPDATE users SET failed_login_count = failed_login_count + 1,
                          locked_until = CASE WHEN failed_login_count + 1 >= $2 THEN now() + make_interval(mins => $3) ELSE locked_until END
         WHERE id = $1 RETURNING failed_login_count, locked_until`,
        [userId, max, lockMinutes],
      );
      const locked = (rows[0]?.failed_login_count ?? 0) >= max;
      await writeAudit(tx, actor, { action: locked ? "auth.account_locked" : "auth.login", targetKind: "user", targetId: userId, outcome: "failure", details: { reason, failures: rows[0]?.failed_login_count ?? null } });
      if (locked) await tx.query("UPDATE users SET failed_login_count = 0 WHERE id = $1", [userId]);
    });
  }

  // ─── Sessions ────────────────────────────────────────────────────────────

  async createSession(
    tx: Queryable,
    input: { tenantId: string; userId: string; organizationId: string | null; method: "password" | "oidc"; mfaVerified: boolean; client: ClientInfo },
  ): Promise<IssuedSession> {
    const secret = randomToken(32);
    const now = this.now();
    const expiresAt = new Date(now + this.config.auth.sessionTtlHours * 3600_000).toISOString();
    const idleAt = new Date(Math.min(now + this.config.auth.sessionIdleMinutes * 60_000, Date.parse(expiresAt))).toISOString();
    const { rows } = await tx.query<{ id: string }>(
      `INSERT INTO sessions (tenant_id, organization_id, user_id, secret_hash, auth_method, mfa_verified, ip, user_agent, idle_expires_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
      [input.tenantId, input.organizationId, input.userId, sha256Hex(secret), input.method, input.mfaVerified, input.client.ip, input.client.userAgent?.slice(0, 500) ?? null, idleAt, expiresAt],
    );
    const sessionId = rows[0]!.id;
    return { sessionId, cookieValue: `${input.tenantId}.${sessionId}.${secret}`, expiresAt };
  }

  /** Session id carried by a well-formed session cookie (no validation of the secret). */
  sessionIdFromCookie(value: string): string | null {
    return this.parseSessionCookie(value)?.sessionId ?? null;
  }

  private parseSessionCookie(value: string): { tenantId: string; sessionId: string; secret: string } | null {
    const parts = value.split(".");
    if (parts.length !== 3) return null;
    const [tenantId, sessionId, secret] = parts as [string, string, string];
    if (!isUuid(tenantId) || !isUuid(sessionId) || secret.length < 32 || secret.length > 128) return null;
    return { tenantId, sessionId, secret };
  }

  /** Validate the opaque session cookie (constant-time secret check, idle + absolute expiry). */
  async authenticateSessionCookie(value: string): Promise<AuthContext | null> {
    const parsed = this.parseSessionCookie(value);
    if (!parsed) return null;
    return this.db.withTenant(parsed.tenantId, async (tx) => {
      const session = await this.activeSession(tx, parsed.sessionId);
      if (!session || !safeEqual(session.secret_hash, sha256Hex(parsed.secret))) return null;
      const user = await this.activeUser(tx, session.user_id);
      if (!user) return null;
      await this.touchSession(tx, session);
      const principal = await this.principalFor(tx, user, session.id);
      return { principal, method: "session" as const, tenantId: parsed.tenantId, boundOrganizationId: null, sessionId: session.id, csrfProtected: true };
    });
  }

  async authenticateBearer(token: string): Promise<AuthContext> {
    let claims;
    try {
      claims = await verifyAccessToken(token, this.tokenSettings);
    } catch (err) {
      throw unauthorized(err instanceof TokenError && err.code === "expired" ? "Access token expired" : "Invalid access token", err instanceof TokenError && err.code === "expired" ? "token_expired" : "invalid_token");
    }
    const ctx = await this.db.withTenant(claims.tid, async (tx) => {
      const session = await this.activeSession(tx, claims.sid);
      if (!session || session.user_id !== claims.sub) return null;
      const user = await this.activeUser(tx, claims.sub);
      if (!user) return null;
      const principal = await this.principalFor(tx, user, session.id);
      return { principal, method: "bearer" as const, tenantId: claims.tid, boundOrganizationId: null, sessionId: session.id, csrfProtected: false };
    });
    if (!ctx) throw unauthorized("Session is no longer valid", "session_revoked");
    return ctx;
  }

  async refresh(cookieValue: string, client: ClientInfo): Promise<{ session: IssuedSession; accessToken: string; accessTokenExpiresAt: string; principal: Principal; tenantId: string }> {
    const parsed = this.parseSessionCookie(cookieValue);
    if (!parsed) throw unauthorized("No valid session", "invalid_session");
    return this.db.withTenant(parsed.tenantId, async (tx) => {
      const session = await this.activeSession(tx, parsed.sessionId, true);
      if (!session) throw unauthorized("No valid session", "invalid_session");
      if (!safeEqual(session.secret_hash, sha256Hex(parsed.secret))) {
        // A stale secret for a live session means the cookie was copied: revoke the session.
        await tx.query("UPDATE sessions SET revoked_at = now(), revoked_reason = 'refresh_secret_reuse' WHERE id = $1", [session.id]);
        await writeAudit(tx, { ...SYSTEM_ACTOR(parsed.tenantId, "auth"), ip: client.ip, userAgent: client.userAgent, requestId: client.requestId }, { action: "auth.session_revoked", targetKind: "session", targetId: session.id, outcome: "denied", details: { reason: "refresh_secret_reuse" } });
        throw unauthorized("No valid session", "invalid_session");
      }
      const user = await this.activeUser(tx, session.user_id);
      if (!user) throw unauthorized("No valid session", "invalid_session");
      const secret = randomToken(32);
      const now = this.now();
      const idleAt = new Date(Math.min(now + this.config.auth.sessionIdleMinutes * 60_000, Date.parse(session.expires_at))).toISOString();
      await tx.query("UPDATE sessions SET secret_hash = $2, last_seen_at = now(), idle_expires_at = $3 WHERE id = $1", [session.id, sha256Hex(secret), idleAt]);
      const principal = await this.principalFor(tx, user, session.id);
      const access = await signAccessToken({ sub: user.id, tid: parsed.tenantId, sid: session.id, kind: "user" }, this.tokenSettings, now);
      return {
        session: { sessionId: session.id, cookieValue: `${parsed.tenantId}.${session.id}.${secret}`, expiresAt: session.expires_at },
        accessToken: access.token,
        accessTokenExpiresAt: access.expiresAt,
        principal,
        tenantId: parsed.tenantId,
      };
    });
  }

  async revokeSession(tx: Queryable, sessionId: string, reason: string): Promise<void> {
    await tx.query("UPDATE sessions SET revoked_at = now(), revoked_reason = $2 WHERE id = $1 AND revoked_at IS NULL", [sessionId, reason]);
  }

  private async activeSession(tx: Queryable, sessionId: string, forUpdate = false) {
    const { rows } = await tx.query<{ id: string; user_id: string; secret_hash: string; last_seen_at: string; expires_at: string; idle_expires_at: string }>(
      `SELECT id, user_id, secret_hash, last_seen_at, expires_at, idle_expires_at FROM sessions
       WHERE id = $1 AND revoked_at IS NULL AND expires_at > now() AND idle_expires_at > now()${forUpdate ? " FOR UPDATE" : ""}`,
      [sessionId],
    );
    return rows[0] ?? null;
  }

  private async touchSession(tx: Queryable, session: { id: string; last_seen_at: string; expires_at: string }): Promise<void> {
    const now = this.now();
    if (now - Date.parse(session.last_seen_at) < 60_000) return;
    const idleAt = new Date(Math.min(now + this.config.auth.sessionIdleMinutes * 60_000, Date.parse(session.expires_at))).toISOString();
    await tx.query("UPDATE sessions SET last_seen_at = now(), idle_expires_at = $2 WHERE id = $1", [session.id, idleAt]);
  }

  private async activeUser(tx: Queryable, userId: string): Promise<UserRow | null> {
    const { rows } = await tx.query<UserRow>("SELECT * FROM users WHERE id = $1 AND status = 'active'", [userId]);
    return rows[0] ?? null;
  }

  async principalFor(tx: Queryable, user: Pick<UserRow, "id" | "tenant_id" | "email" | "display_name">, sessionId?: string): Promise<Principal> {
    return {
      kind: "user",
      id: user.id,
      tenantId: user.tenant_id,
      email: user.email,
      ...(user.display_name ? { displayName: user.display_name } : {}),
      bindings: await loadUserBindings(tx, user.id),
      ...(sessionId ? { sessionId } : {}),
    };
  }

  // ─── CSRF (signed double-submit, bound to the session) ───────────────────

  csrfTokenFor(sessionId: string): string {
    const nonce = randomToken(18);
    return `${nonce}.${hmacSha256(this.config.auth.jwtSecret, `csrf:${sessionId}:${nonce}`)}`;
  }

  verifyCsrf(sessionId: string, cookieToken: string | undefined, headerToken: string | undefined): boolean {
    if (!cookieToken || !headerToken || !safeEqual(cookieToken, headerToken)) return false;
    const idx = headerToken.indexOf(".");
    if (idx <= 0) return false;
    const nonce = headerToken.slice(0, idx);
    return safeEqual(headerToken.slice(idx + 1), hmacSha256(this.config.auth.jwtSecret, `csrf:${sessionId}:${nonce}`));
  }

  // ─── API keys ────────────────────────────────────────────────────────────

  static generateApiKey(): { prefix: string; key: string; hash: string } {
    const prefix = randomAlnum(12);
    const key = `bk_${prefix}_${randomToken(32)}`;
    return { prefix, key, hash: sha256Hex(key) };
  }

  static looksLikeApiKey(value: string): boolean {
    return value.startsWith("bk_");
  }

  async authenticateApiKey(key: string, ip: string | null): Promise<AuthContext> {
    const m = API_KEY_RE.exec(key);
    if (!m) throw unauthorized("Invalid API key", "invalid_api_key");
    const found = await this.lookup("api_key", m[1]!);
    if (!found) {
      sha256Hex(key);
      throw unauthorized("Invalid API key", "invalid_api_key");
    }
    const ctx = await this.db.withTenant(found.tenantId, async (tx) => {
      const { rows } = await tx.query<{ id: string; name: string; organization_id: string | null; key_hash: string; last_used_at: string | null }>(
        "SELECT id, name, organization_id, key_hash, last_used_at FROM api_keys WHERE id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())",
        [found.userId],
      );
      const row = rows[0];
      if (!row || !safeEqual(row.key_hash, sha256Hex(key))) return null;
      if (!row.last_used_at || this.now() - Date.parse(row.last_used_at) > 60_000) {
        await tx.query("UPDATE api_keys SET last_used_at = now(), last_used_ip = $2 WHERE id = $1", [row.id, ip]);
      }
      const bindings = await loadApiKeyBindings(tx, row.id);
      const principal: Principal = { kind: "service", id: row.id, tenantId: found.tenantId, displayName: row.name, bindings };
      return { principal, method: "api_key" as const, tenantId: found.tenantId, boundOrganizationId: row.organization_id, sessionId: null, csrfProtected: false };
    });
    if (!ctx) throw unauthorized("Invalid API key", "invalid_api_key");
    return ctx;
  }

  // ─── TOTP MFA ────────────────────────────────────────────────────────────

  private totpContext(tenantId: string, userId: string): string {
    return `${tenantId}:mfa_totp:${userId}`;
  }

  async beginTotpEnrollment(tx: Queryable, auth: AuthContext): Promise<{ secret: string; otpauthUri: string }> {
    const userId = auth.principal.id;
    const existing = await tx.query<{ confirmed_at: string | null }>("SELECT confirmed_at FROM mfa_totp WHERE user_id = $1", [userId]);
    if (existing.rows[0]?.confirmed_at) throw conflict("TOTP is already enabled; disable it before enrolling a new authenticator");
    const secret = generateTotpSecret();
    const enc = this.secrets.encrypt(secret, this.totpContext(auth.tenantId, userId));
    await tx.query(
      `INSERT INTO mfa_totp (user_id, tenant_id, secret_enc, confirmed_at, last_used_step) VALUES ($1, $2, $3, NULL, 0)
       ON CONFLICT (user_id) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, confirmed_at = NULL, last_used_step = 0`,
      [userId, auth.tenantId, enc],
    );
    return { secret, otpauthUri: otpauthUri({ secret, account: auth.principal.email ?? userId, issuer: "Bloody" }) };
  }

  async confirmTotpEnrollment(tx: Queryable, auth: AuthContext, code: string): Promise<void> {
    const { rows } = await tx.query<{ secret_enc: string; last_used_step: number }>("SELECT secret_enc, last_used_step FROM mfa_totp WHERE user_id = $1 AND confirmed_at IS NULL FOR UPDATE", [auth.principal.id]);
    const row = rows[0];
    if (!row) throw new HttpError(409, "no_pending_enrollment", "Start TOTP enrollment first");
    const step = verifyTotp(this.secrets.decrypt(row.secret_enc, this.totpContext(auth.tenantId, auth.principal.id)), code, this.now(), { lastUsedStep: row.last_used_step });
    if (step === null) throw new HttpError(400, "invalid_mfa_code", "Invalid verification code");
    await tx.query("UPDATE mfa_totp SET confirmed_at = now(), last_used_step = $2 WHERE user_id = $1", [auth.principal.id, step]);
    await tx.query("UPDATE users SET mfa_enabled = true WHERE id = $1", [auth.principal.id]);
  }

  /** Verify (and consume) a login/step-up TOTP code. */
  async consumeTotp(tx: Queryable, tenantId: string, userId: string, code: string): Promise<boolean> {
    const { rows } = await tx.query<{ secret_enc: string; last_used_step: number }>("SELECT secret_enc, last_used_step FROM mfa_totp WHERE user_id = $1 AND confirmed_at IS NOT NULL FOR UPDATE", [userId]);
    const row = rows[0];
    if (!row) return false;
    const step = verifyTotp(this.secrets.decrypt(row.secret_enc, this.totpContext(tenantId, userId)), code, this.now(), { lastUsedStep: row.last_used_step });
    if (step === null) return false;
    await tx.query("UPDATE mfa_totp SET last_used_step = $2 WHERE user_id = $1", [userId, step]);
    return true;
  }

  async disableTotp(tx: Queryable, auth: AuthContext, code: string): Promise<void> {
    if (!(await this.consumeTotp(tx, auth.tenantId, auth.principal.id, code))) throw new HttpError(400, "invalid_mfa_code", "Invalid verification code");
    await tx.query("DELETE FROM mfa_totp WHERE user_id = $1", [auth.principal.id]);
    await tx.query("UPDATE users SET mfa_enabled = false WHERE id = $1", [auth.principal.id]);
  }

  // ─── OIDC ────────────────────────────────────────────────────────────────

  /** Sign in a pre-provisioned user after a verified OIDC callback (no just-in-time provisioning). */
  async loginWithOidc(identity: { email: string; subject: string; issuer: string }, client: ClientInfo): Promise<LoginSuccess> {
    const found = await this.lookupEmail(identity.email);
    if (!found) throw new HttpError(403, "sso_user_not_provisioned", "No Bloody account is provisioned for this identity");
    return this.db.withTenant(found.tenantId, async (tx) => {
      const user = await this.activeUser(tx, found.userId);
      if (!user) throw new HttpError(403, "sso_user_not_provisioned", "No active Bloody account is provisioned for this identity");
      const subject = `${identity.issuer}|${identity.subject}`;
      if (user.oidc_subject && user.oidc_subject !== subject) throw new HttpError(403, "sso_subject_mismatch", "This account is linked to a different SSO identity");
      if (!user.oidc_subject) await tx.query("UPDATE users SET oidc_subject = $2 WHERE id = $1", [user.id, subject]);
      await tx.query("UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = now() WHERE id = $1", [user.id]);
      const session = await this.createSession(tx, { tenantId: found.tenantId, userId: user.id, organizationId: user.organization_id, method: "oidc", mfaVerified: true, client });
      const principal = await this.principalFor(tx, user, session.sessionId);
      await writeAudit(tx, { tenantId: found.tenantId, actorKind: "user", actorId: user.id, actorLabel: user.email, ip: client.ip, userAgent: client.userAgent, requestId: client.requestId }, { action: "auth.login", targetKind: "session", targetId: session.sessionId, details: { method: "oidc", issuer: identity.issuer } });
      const access = await signAccessToken({ sub: user.id, tid: found.tenantId, sid: session.sessionId, kind: "user" }, this.tokenSettings, this.now());
      return { kind: "success" as const, tenantId: found.tenantId, principal, session, accessToken: access.token, accessTokenExpiresAt: access.expiresAt };
    });
  }
}
