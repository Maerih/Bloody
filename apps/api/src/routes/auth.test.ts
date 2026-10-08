import { createHash } from "node:crypto";
import { SignJWT, exportJWK, generateKeyPair, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { OidcProvider, type FetchLike } from "../auth/oidc.js";
import { CSRF_COOKIE, SESSION_COOKIE } from "../auth/types.js";
import { totp } from "../security/totp.js";
import { TEST_PASSWORD, api, call, createApiKey, createTenant, createTestApp, createUser, login, testConfig, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 2 });
});
afterAll(async () => {
  await t?.close();
});

describe("password login and sessions", () => {
  it("issues a bearer JWT plus httpOnly session and CSRF cookies", async () => {
    const res = await call(t.app, "POST", "/auth/login", { body: { email: tenant.admin.email.toUpperCase(), password: TEST_PASSWORD } });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ tokenType: "Bearer", principal: { kind: "user", id: tenant.admin.id, tenantId: tenant.tenantId } });
    expect(res.body.token.split(".")).toHaveLength(3);
    expect(Date.parse(res.body.expiresAt) - Date.now()).toBeLessThanOrEqual(15 * 60_000 + 5_000);
    const session = res.cookies.find((c) => c.name === SESSION_COOKIE)!;
    const csrf = res.cookies.find((c) => c.name === CSRF_COOKIE)!;
    expect(session).toMatchObject({ httpOnly: true, secure: true, sameSite: "Lax", path: "/" });
    expect(csrf.httpOnly).toBeFalsy();
    expect(csrf.value).toBe(res.body.csrfToken);

    const me = await api(t.app, { token: res.body.token }).get("/auth/me");
    expect(me.status).toBe(200);
    expect(me.body.principal.bindings).toEqual([{ role: "mssp_admin", organizationId: null }]);
    expect(me.body.account).toMatchObject({ id: tenant.tenantId, kind: "mssp", plan: "mssp" });
    expect(me.body.organizations.map((o: { id: string }) => o.id).sort()).toEqual([...tenant.orgIds].sort());
    expect(me.body.entitlements.length).toBeGreaterThan(10);
    expect(me.body.plan).toBe("mssp");
  });

  it("answers unknown users and wrong passwords identically", async () => {
    const wrong = await call(t.app, "POST", "/auth/login", { body: { email: tenant.admin.email, password: "nope-nope-nope" } });
    const unknown = await call(t.app, "POST", "/auth/login", { body: { email: "nobody@example.test", password: "nope-nope-nope" } });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body.error.code).toBe("invalid_credentials");
    expect(unknown.body.error).toMatchObject({ code: wrong.body.error.code, message: wrong.body.error.message });
  });

  it("locks the account after repeated failures and audits it", async () => {
    const user = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: null }] });
    for (let i = 0; i < t.config.auth.loginMaxFailures; i++) {
      expect((await call(t.app, "POST", "/auth/login", { body: { email: user.email, password: "Wrong-password-1" } })).status).toBe(401);
    }
    const locked = await call(t.app, "POST", "/auth/login", { body: { email: user.email, password: TEST_PASSWORD } });
    expect(locked.status).toBe(401);
    const { rows } = await t.privileged.query("SELECT action, outcome FROM audit_log WHERE tenant_id = $1 AND target_id = $2 ORDER BY seq", [tenant.tenantId, user.id]);
    expect(rows.map((r) => r.action)).toContain("auth.account_locked");
    expect(rows.at(-1)).toMatchObject({ action: "auth.login", outcome: "denied" });
    const lockedUntil = await t.privileged.query<{ locked_until: string }>("SELECT locked_until FROM users WHERE id = $1", [user.id]);
    expect(Date.parse(lockedUntil.rows[0]!.locked_until)).toBeGreaterThan(Date.now());
  });

  it("validates input with a uniform 400 envelope", async () => {
    const res = await call(t.app, "POST", "/auth/login", { body: { email: 42 } });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("validation_error");
    expect(res.body.error.requestId).toBe(res.headers["x-request-id"]);
    expect(res.body.error.details.map((d: { path: string }) => d.path)).toEqual(expect.arrayContaining(["email", "password"]));
  });

  it("rejects unauthenticated and forged credentials", async () => {
    const anon = await call(t.app, "GET", "/incidents");
    expect(anon.status).toBe(401);
    expect(anon.body.error.code).toBe("unauthorized");
    const forged = await api(t.app, { token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl" }).get("/auth/me");
    expect(forged.status).toBe(401);
    expect(forged.body.error.code).toBe("invalid_token");
    const basic = await call(t.app, "GET", "/auth/me", { headers: { authorization: "Basic YWRtaW46YWRtaW4=" } });
    expect(basic.status).toBe(401);
  });

  it("logout revokes the session behind the JWT", async () => {
    const s = await login(t.app, tenant.admin.email);
    const client = api(t.app, { token: s.token });
    expect((await client.get("/auth/me")).status).toBe(200);
    expect((await client.post("/auth/logout")).status).toBe(204);
    const after = await client.get("/auth/me");
    expect(after.status).toBe(401);
    expect(after.body.error.code).toBe("session_revoked");
  });

  it("refresh rotates the session secret and treats reuse of the old one as theft", async () => {
    const s = await login(t.app, tenant.admin.email);
    const refreshed = await call(t.app, "POST", "/auth/refresh", { auth: { session: s } });
    expect(refreshed.status).toBe(200);
    const next = refreshed.cookies.find((c) => c.name === SESSION_COOKIE)!.value;
    expect(next).not.toBe(s.sessionCookie);
    expect(next.split(".")[1]).toBe(s.sessionCookie.split(".")[1]);
    const rotated = { ...s, sessionCookie: next, csrfCookie: refreshed.body.csrfToken, csrfToken: refreshed.body.csrfToken };
    expect((await call(t.app, "GET", "/auth/me", { auth: { session: rotated } })).status).toBe(200);

    const replay = await call(t.app, "POST", "/auth/refresh", { auth: { session: s } });
    expect(replay.status).toBe(401);
    // The whole session is now revoked — including the rotated cookie and its JWT.
    expect((await call(t.app, "GET", "/auth/me", { auth: { session: rotated } })).status).toBe(401);
    expect((await api(t.app, { token: refreshed.body.token }).get("/auth/me")).status).toBe(401);
  });

  it("enforces the login rate limit", async () => {
    const limited = await createTestApp({ env: { LOGIN_RATE_LIMIT_PER_MINUTE: "3" } });
    try {
      const statuses: number[] = [];
      for (let i = 0; i < 4; i++) statuses.push((await call(limited.app, "POST", "/auth/login", { body: { email: "rate@example.test", password: "x" } })).status);
      expect(statuses).toEqual([401, 401, 401, 429]);
    } finally {
      await limited.close();
    }
  });
});

describe("CSRF protection for cookie sessions", () => {
  it("requires the double-submit token on unsafe cookie-authenticated requests", async () => {
    const s = await login(t.app, tenant.admin.email);
    const body = { name: "SOC pod (csrf test)" };
    const read = await call(t.app, "GET", "/auth/me", { auth: { session: s } });
    expect(read.status).toBe(200);

    const missing = await call(t.app, "POST", "/teams", { auth: { session: s, csrf: false }, body });
    expect(missing.status).toBe(403);
    expect(missing.body.error.code).toBe("csrf");

    const wrong = await call(t.app, "POST", "/teams", { auth: { session: s, csrf: "forged.token" }, body });
    expect(wrong.status).toBe(403);

    const otherSession = await login(t.app, tenant.admin.email);
    const crossSession = await call(t.app, "POST", "/teams", { auth: { session: { ...s, csrfCookie: otherSession.csrfToken }, csrf: otherSession.csrfToken }, body });
    expect(crossSession.status).toBe(403);

    const foreignOrigin = await call(t.app, "POST", "/teams", { auth: { session: s, origin: "https://evil.example" }, body });
    expect(foreignOrigin.status).toBe(403);
    expect(foreignOrigin.body.error.code).toBe("csrf_origin");

    const ok = await call(t.app, "POST", "/teams", { auth: { session: s, origin: "http://localhost:5173" }, body });
    expect(ok.status).toBe(201);

    // Bearer tokens are not ambient credentials: no CSRF token needed.
    const bearer = await api(t.app, { token: s.token }).post("/teams", { name: "SOC pod (bearer)" });
    expect(bearer.status).toBe(201);

    const denied = await t.privileged.query("SELECT details FROM audit_log WHERE tenant_id = $1 AND outcome = 'denied' AND action = 'post /api/v1/teams' ORDER BY seq", [tenant.tenantId]);
    expect(denied.rows.map((r) => r.details.reason)).toEqual(expect.arrayContaining(["csrf", "csrf_origin"]));
  });
});

describe("TOTP multi-factor authentication", () => {
  it("enrolls, requires the second factor at login and rejects replayed codes", async () => {
    const user = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t2", organizationId: null }] });
    const s = await login(t.app, user.email);
    const client = api(t.app, { token: s.token });
    const enroll = await client.post("/auth/mfa/totp/enroll");
    expect(enroll.status).toBe(200);
    // Key URI format: label "issuer:account" with the colon URL-encoded.
    expect(enroll.body.otpauthUri).toMatch(/^otpauth:\/\/totp\/Bloody%3A.+\?secret=[A-Z2-7]+&issuer=Bloody/);
    const secret: string = enroll.body.secret;
    const stored = await t.privileged.query<{ secret_enc: string }>("SELECT secret_enc FROM mfa_totp WHERE user_id = $1", [user.id]);
    expect(stored.rows[0]!.secret_enc).toMatch(/^v1\./);
    expect(stored.rows[0]!.secret_enc).not.toContain(secret);

    expect((await client.post("/auth/mfa/totp/confirm", { code: "000000" })).status).toBe(400);
    const confirm = await client.post("/auth/mfa/totp/confirm", { code: totp(secret, Date.now()) });
    expect(confirm.status).toBe(200);
    expect(confirm.body).toEqual({ mfaEnabled: true });

    const challenge = await call(t.app, "POST", "/auth/login", { body: { email: user.email, password: TEST_PASSWORD } });
    expect(challenge.status).toBe(200);
    expect(challenge.body).toEqual({ mfaRequired: true });
    expect(challenge.cookies.find((c) => c.name === SESSION_COOKIE)).toBeUndefined();

    const bad = await call(t.app, "POST", "/auth/login", { body: { email: user.email, password: TEST_PASSWORD, totp: "123456" } });
    expect(bad.status).toBe(401);
    expect(bad.body.error.code).toBe("invalid_mfa_code");

    const code = totp(secret, Date.now() + 30_000); // the next step (the current one was used to confirm)
    const ok = await call(t.app, "POST", "/auth/login", { body: { email: user.email, password: TEST_PASSWORD, totp: code } });
    expect(ok.status).toBe(200);
    const sessionRow = await t.privileged.query<{ mfa_verified: boolean }>("SELECT mfa_verified FROM sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1", [user.id]);
    expect(sessionRow.rows[0]!.mfa_verified).toBe(true);

    const replay = await call(t.app, "POST", "/auth/login", { body: { email: user.email, password: TEST_PASSWORD, totp: code } });
    expect(replay.status).toBe(401);
  });
});

describe("API keys", () => {
  it("authenticates org-bound service keys, stores only a digest and honours revocation", async () => {
    const admin = await login(t.app, tenant.admin.email);
    const [org1, org2] = tenant.orgIds as [string, string];
    const created = await createApiKey(t.app, admin.token, { organizationId: org1, roles: ["api_service"] });
    expect(created.key).toMatch(/^bk_[a-z0-9]{12}_[A-Za-z0-9_-]{43}$/);
    const row = await t.privileged.query<{ key_hash: string; prefix: string }>("SELECT key_hash, prefix FROM api_keys WHERE id = $1", [created.id]);
    expect(row.rows[0]!.key_hash).toBe(createHash("sha256").update(created.key).digest("hex"));
    expect(created.key.startsWith(`bk_${row.rows[0]!.prefix}_`)).toBe(true);

    const listed = await api(t.app, { token: admin.token }).get("/api-keys");
    expect(JSON.stringify(listed.body)).not.toContain(created.key);
    expect(listed.body.items.find((k: { id: string }) => k.id === created.id)).toMatchObject({ organizationId: org1, active: true, roles: [{ role: "api_service", organizationId: org1 }] });

    const key = api(t.app, { apiKey: created.key });
    expect((await key.get(`/assets?organizationId=${org1}`)).status).toBe(200);
    expect((await call(t.app, "GET", "/assets", { headers: { "x-api-key": created.key } })).status).toBe(200);
    expect((await key.get(`/assets?organizationId=${org2}`)).status).toBe(403);
    expect((await key.get("/incidents")).status).toBe(403);
    expect((await key.post("/organizations", { name: "x", slug: "xx" })).status).toBe(403);
    const me = await key.get("/auth/me");
    expect(me.body).toMatchObject({ authMethod: "api_key", boundOrganizationId: org1, principal: { kind: "service" } });

    const tampered = created.key.slice(0, -2) + (created.key.endsWith("AA") ? "BB" : "AA");
    expect((await api(t.app, { apiKey: tampered }).get("/assets")).status).toBe(401);
    expect((await api(t.app, { apiKey: "bk_short_x" }).get("/assets")).body.error.code).toBe("invalid_api_key");

    expect((await api(t.app, { token: admin.token }).delete(`/api-keys/${created.id}`)).status).toBe(204);
    expect((await key.get("/assets")).status).toBe(401);
  });

  it("never lets a key carry more privilege than its creator", async () => {
    const [org1] = tenant.orgIds as [string];
    const orgAdmin = await createUser(t, tenant.tenantId, { organizationId: org1, roles: [{ role: "org_admin", organizationId: org1 }] });
    const s = await login(t.app, orgAdmin.email);
    const client = api(t.app, { token: s.token });
    const escalate = await client.post("/api-keys", { name: "too strong", organizationId: org1, roles: ["mssp_admin"] });
    expect(escalate.status).toBe(403);
    expect(escalate.body.error.code).toBe("role_escalation");
    expect((await client.post("/api-keys", { name: "tenant wide", organizationId: null, roles: ["api_service"] })).status).toBe(403);
    expect((await client.post("/api-keys", { name: "ingest", organizationId: org1, roles: ["api_service"] })).status).toBe(201);
  });
});

describe("HTTP hardening", () => {
  it("sets security headers, request ids and a strict CORS allow-list", async () => {
    const res = await call(t.app, "GET", "/healthz", { headers: { "x-request-id": "trace-0123456789" } });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: "ok", service: "bloody-api" });
    expect(res.headers["x-request-id"]).toBe("trace-0123456789");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(String(res.headers["content-security-policy"])).toContain("default-src 'none'");
    expect(res.headers["cache-control"]).toBe("no-store");

    const allowed = await t.app.inject({ method: "OPTIONS", url: "/api/v1/auth/me", headers: { origin: "http://localhost:5173", "access-control-request-method": "GET" } });
    expect(allowed.headers["access-control-allow-origin"]).toBe("http://localhost:5173");
    expect(allowed.headers["access-control-allow-credentials"]).toBe("true");
    const blocked = await t.app.inject({ method: "OPTIONS", url: "/api/v1/auth/me", headers: { origin: "https://evil.example", "access-control-request-method": "GET" } });
    expect(blocked.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("serves readiness and Prometheus metrics", async () => {
    const ready = await call(t.app, "GET", "/readyz");
    expect(ready.status).toBe(200);
    expect(ready.body.checks.database.ok).toBe(true);
    expect(ready.body.checks.migrations.ok).toBe(true);
    const metrics = await call(t.app, "GET", "/metrics");
    expect(metrics.status).toBe(200);
    expect(metrics.text).toContain("bloody_http_request_duration_seconds_bucket");
    expect(metrics.text).toContain("bloody_pipeline_queue_lag_seconds");
    expect(metrics.text).toContain("bloody_ingest_events_total");
  });

  it("protects /metrics with a bearer token when configured", async () => {
    const guarded = await createTestApp({ env: { METRICS_TOKEN: "metrics-token-0123456789" } });
    try {
      expect((await call(guarded.app, "GET", "/metrics")).status).toBe(401);
      expect((await call(guarded.app, "GET", "/metrics", { headers: { authorization: "Bearer metrics-token-0123456789" } })).status).toBe(200);
    } finally {
      await guarded.close();
    }
  });
});

describe("OIDC single sign-on", () => {
  it("is disabled unless configured", async () => {
    expect((await call(t.app, "GET", "/auth/oidc/config")).body).toEqual({ enabled: false, provider: null });
    const start = await call(t.app, "GET", "/auth/oidc/start");
    expect(start.status).toBe(501);
    expect(start.body.error.code).toBe("sso_not_configured");
  });

  it("runs the authorization-code + PKCE flow against a discovered provider", async () => {
    const issuer = "https://idp.example.test/realms/bloody";
    const { publicKey, privateKey } = await generateKeyPair("RS256");
    const jwk: JWK = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
    const codes = new Map<string, { nonce: string; challenge: string; email: string }>();
    const json = (body: unknown, status = 200) => ({ ok: status < 400, status, json: async () => body });
    const fetchImpl: FetchLike = async (url, init) => {
      if (url === `${issuer}/.well-known/openid-configuration`) {
        return json({ issuer, authorization_endpoint: `${issuer}/auth`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/certs`, code_challenge_methods_supported: ["S256"] });
      }
      if (url === `${issuer}/certs`) return json({ keys: [jwk] });
      if (url === `${issuer}/token` && init?.method === "POST") {
        const form = new URLSearchParams(init.body ?? "");
        const grant = codes.get(form.get("code") ?? "");
        const verifier = form.get("code_verifier") ?? "";
        if (!grant || createHash("sha256").update(verifier).digest("base64url") !== grant.challenge) return json({ error: "invalid_grant" }, 400);
        const idToken = await new SignJWT({ email: grant.email, email_verified: true, nonce: grant.nonce, name: "SSO User" })
          .setProtectedHeader({ alg: "RS256", kid: "k1" })
          .setIssuer(issuer)
          .setAudience("bloody-web")
          .setSubject("idp-subject-42")
          .setIssuedAt()
          .setExpirationTime("5m")
          .sign(privateKey);
        return json({ id_token: idToken, token_type: "Bearer" });
      }
      return json({ error: "not_found" }, 404);
    };
    const config = testConfig();
    const oidc = new OidcProvider(
      { issuerUrl: issuer, clientId: "bloody-web", clientSecret: "client-secret", redirectUri: "http://localhost:5173/api/v1/auth/oidc/callback", scopes: "openid email profile", providerName: "keycloak" },
      { secret: config.auth.jwtSecret, issuer: config.auth.jwtIssuer },
      fetchImpl,
    );
    const sso = await createTestApp({ deps: { oidc } });
    try {
      const user = await createUser(sso, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: null }], withPassword: false });
      // invited users activate via SSO only when an admin activates them; make it active.
      await sso.privileged.query("UPDATE users SET status = 'active' WHERE id = $1", [user.id]);

      const flow = async (email: string, tamperState = false) => {
        const start = await call(sso.app, "GET", "/auth/oidc/start?returnTo=/incidents");
        expect(start.status).toBe(200);
        const url = new URL(start.body.url);
        expect(url.origin + url.pathname).toBe(`${issuer}/auth`);
        expect(url.searchParams.get("code_challenge_method")).toBe("S256");
        const stateCookie = start.cookies.find((c) => c.name === "bloody_oidc")!;
        expect(stateCookie).toMatchObject({ httpOnly: true, path: "/api/v1/auth/oidc" });
        const code = `code-${Math.random().toString(36).slice(2)}`;
        codes.set(code, { nonce: url.searchParams.get("nonce")!, challenge: url.searchParams.get("code_challenge")!, email });
        const state = tamperState ? "tampered-state" : url.searchParams.get("state")!;
        return call(sso.app, "GET", `/auth/oidc/callback?code=${code}&state=${encodeURIComponent(state)}`, { headers: { cookie: `bloody_oidc=${stateCookie.value}` } });
      };

      const ok = await flow(user.email);
      expect(ok.status).toBe(302);
      expect(ok.headers.location).toBe(`${sso.config.http.publicUrl}/incidents`);
      const cookie = ok.cookies.find((c) => c.name === SESSION_COOKIE)!;
      const me = await call(sso.app, "GET", "/auth/me", { headers: { cookie: `${SESSION_COOKIE}=${cookie.value}` } });
      expect(me.status).toBe(200);
      expect(me.body.principal.email).toBe(user.email);
      expect(me.body.session.method).toBe("oidc");
      const linked = await sso.privileged.query<{ oidc_subject: string }>("SELECT oidc_subject FROM users WHERE id = $1", [user.id]);
      expect(linked.rows[0]!.oidc_subject).toBe(`${issuer}|idp-subject-42`);

      const unknown = await flow("stranger@example.test");
      expect(unknown.status).toBe(302);
      expect(unknown.headers.location).toContain("sso_error=sso_user_not_provisioned");

      const forged = await flow(user.email, true);
      expect(forged.headers.location).toContain("sso_error=sso_state_mismatch");
    } finally {
      await sso.close();
    }
  });
});
