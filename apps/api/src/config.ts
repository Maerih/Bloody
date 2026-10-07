import { z } from "zod";

/**
 * Control-plane configuration. Every value is read from the environment once, validated with
 * zod and frozen. Secrets have development defaults ONLY outside production; in production a
 * missing/weak secret is a startup error.
 *
 * Variable names follow the task contract (`JWT_SECRET`, `ENCRYPTION_KEY`, …). The deployment
 * manifests use a `BLOODY_` prefix for the same settings; both spellings are accepted (the
 * un-prefixed one wins when both are set).
 */

const DEV_JWT_SECRET = "bloody-dev-only-jwt-secret-do-not-use-in-production-0123456789";
/** 32 zero-entropy bytes, base64 — development only. */
const DEV_ENCRYPTION_KEY = Buffer.from("bloody-dev-only-encryption-key!!", "utf8").toString("base64");

const bool = z
  .union([z.boolean(), z.string()])
  .transform((v) => (typeof v === "boolean" ? v : ["1", "true", "yes", "on"].includes(v.trim().toLowerCase())));

const csv = z
  .string()
  .transform((v) =>
    v
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
  );

const RawEnv = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  HOST: z.string().default("0.0.0.0"),
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),

  /** Privileged connection: migrations, dev seed, test fixtures. Never used by request handlers. */
  DATABASE_URL: z.string().url().default("postgres://postgres:postgres@localhost:5432/bloody"),
  /** Runtime connection as the non-superuser, RLS-enforced role `bloody_app`. */
  DATABASE_APP_URL: z.string().url().optional(),
  BLOODY_APP_DB_PASSWORD: z.string().min(1).default("bloody_app"),
  DATABASE_POOL_MAX: z.coerce.number().int().min(1).max(500).default(20),
  DATABASE_STATEMENT_TIMEOUT_MS: z.coerce.number().int().min(100).max(600_000).default(30_000),

  JWT_SECRET: z.string().optional(),
  JWT_ISSUER: z.string().default("bloody-api"),
  JWT_AUDIENCE: z.string().default("bloody"),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
  SESSION_TTL_HOURS: z.coerce.number().int().min(1).max(24 * 30).default(12),
  SESSION_IDLE_MINUTES: z.coerce.number().int().min(5).max(24 * 60).default(120),

  ENCRYPTION_KEY: z.string().optional(),
  ENCRYPTION_KEY_VERSION: z.coerce.number().int().min(1).max(65535).default(1),
  /** Retired keys kept for decryption only: "1:<base64>,2:<base64>". */
  ENCRYPTION_PREVIOUS_KEYS: z.string().default(""),

  CORS_ORIGINS: csv.optional(),
  PUBLIC_URL: z.string().url().optional(),
  COOKIE_SECURE: bool.optional(),
  TRUST_PROXY: bool.default(false),

  LOGIN_MAX_FAILURES: z.coerce.number().int().min(1).max(100).default(5),
  LOGIN_LOCKOUT_MINUTES: z.coerce.number().int().min(1).max(24 * 60).default(15),
  LOGIN_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(1).max(10_000).default(20),
  RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(10).max(1_000_000).default(1200),

  INGEST_MAX_BATCH: z.coerce.number().int().min(1).max(50_000).default(5000),
  INGEST_BODY_LIMIT_BYTES: z.coerce.number().int().min(1024).max(512 * 1024 * 1024).default(32 * 1024 * 1024),
  BODY_LIMIT_BYTES: z.coerce.number().int().min(1024).max(64 * 1024 * 1024).default(2 * 1024 * 1024),
  /** Events older than this are rejected at ingest (beyond any plan's retention). */
  INGEST_MAX_EVENT_AGE_DAYS: z.coerce.number().int().min(1).max(3650).default(400),

  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(587),
  SMTP_SECURE: bool.default(false),
  SMTP_USER: z.string().optional(),
  SMTP_PASSWORD: z.string().optional(),
  SMTP_FROM: z.string().default("notifications@bloody.local"),
  SMTP_FROM_NAME: z.string().default("Bloody Security Operations"),

  OIDC_ISSUER_URL: z.string().url().optional(),
  OIDC_CLIENT_ID: z.string().optional(),
  OIDC_CLIENT_SECRET: z.string().optional(),
  OIDC_REDIRECT_URI: z.string().url().optional(),
  OIDC_SCOPES: z.string().default("openid email profile"),
  OIDC_PROVIDER_NAME: z.string().default("sso"),

  /** When set, GET /metrics requires `Authorization: Bearer <token>`. */
  METRICS_TOKEN: z.string().min(16).optional(),
  /** Run the in-process analytics pipeline consumer (disable on API-only replicas fed by Kafka). */
  PIPELINE_ENABLED: bool.default(true),
});

export interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  user: string | undefined;
  password: string | undefined;
  from: string;
  fromName: string;
}

export interface OidcConfig {
  issuerUrl: string;
  clientId: string;
  clientSecret: string | undefined;
  redirectUri: string;
  scopes: string;
  providerName: string;
}

export interface AppConfig {
  env: "development" | "test" | "production";
  host: string;
  port: number;
  logLevel: "fatal" | "error" | "warn" | "info" | "debug" | "trace" | "silent";
  database: {
    privilegedUrl: string;
    appUrl: string;
    appPassword: string;
    poolMax: number;
    statementTimeoutMs: number;
  };
  auth: {
    jwtSecret: Uint8Array;
    jwtIssuer: string;
    jwtAudience: string;
    accessTokenTtlSeconds: number;
    sessionTtlHours: number;
    sessionIdleMinutes: number;
    loginMaxFailures: number;
    loginLockoutMinutes: number;
    loginRateLimitPerMinute: number;
  };
  encryption: { activeVersion: number; keys: Map<number, Buffer> };
  http: {
    corsOrigins: string[];
    publicUrl: string;
    cookieSecure: boolean;
    trustProxy: boolean;
    rateLimitPerMinute: number;
    bodyLimitBytes: number;
  };
  ingest: { maxBatch: number; bodyLimitBytes: number; maxEventAgeDays: number; pipelineEnabled: boolean };
  metricsToken: string | null;
  smtp: SmtpConfig | null;
  oidc: OidcConfig | null;
  /** Human-readable warnings produced while loading (dev defaults in use, …). */
  warnings: string[];
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

/** Apply `BLOODY_<NAME>` aliases for the variables the deployment manifests prefix. */
function withAliases(env: NodeJS.ProcessEnv): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = { ...env };
  const aliases = [
    "JWT_SECRET",
    "ENCRYPTION_KEY",
    "ENCRYPTION_KEY_VERSION",
    "ENCRYPTION_PREVIOUS_KEYS",
    "CORS_ORIGINS",
    "PUBLIC_URL",
    "COOKIE_SECURE",
    "TRUST_PROXY",
    "METRICS_TOKEN",
  ];
  for (const name of aliases) {
    if ((out[name] === undefined || out[name] === "") && env[`BLOODY_${name}`]) out[name] = env[`BLOODY_${name}`];
  }
  // Blank strings mean "unset" for optional values (docker-compose `${X:-}`).
  for (const [k, v] of Object.entries(out)) if (v === "") delete out[k];
  return out;
}

function decodeKey(b64: string, label: string): Buffer {
  const key = Buffer.from(b64.trim(), "base64");
  if (key.length !== 32) throw new ConfigError(`${label} must be 32 bytes encoded as base64 (got ${key.length} bytes)`);
  return key;
}

function deriveAppUrl(privilegedUrl: string, password: string): string {
  const u = new URL(privilegedUrl);
  u.username = "bloody_app";
  u.password = password;
  return u.toString();
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = RawEnv.safeParse(withAliases(env));
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
    throw new ConfigError(`Invalid configuration: ${issues}`);
  }
  const e = parsed.data;
  const production = e.NODE_ENV === "production";
  const warnings: string[] = [];

  let jwtSecret = e.JWT_SECRET;
  if (!jwtSecret) {
    if (production) throw new ConfigError("JWT_SECRET is required in production");
    jwtSecret = DEV_JWT_SECRET;
    warnings.push("JWT_SECRET not set — using the insecure development default");
  }
  if (jwtSecret.length < 32) {
    if (production) throw new ConfigError("JWT_SECRET must be at least 32 characters");
    warnings.push("JWT_SECRET is shorter than 32 characters");
  }

  let encryptionKey = e.ENCRYPTION_KEY;
  if (!encryptionKey) {
    if (production) throw new ConfigError("ENCRYPTION_KEY (32-byte base64) is required in production");
    encryptionKey = DEV_ENCRYPTION_KEY;
    warnings.push("ENCRYPTION_KEY not set — using the insecure development key for the secret store");
  }
  const keys = new Map<number, Buffer>();
  keys.set(e.ENCRYPTION_KEY_VERSION, decodeKey(encryptionKey, "ENCRYPTION_KEY"));
  for (const entry of e.ENCRYPTION_PREVIOUS_KEYS.split(",").map((s) => s.trim()).filter(Boolean)) {
    const idx = entry.indexOf(":");
    const version = Number(entry.slice(0, idx));
    if (idx <= 0 || !Number.isInteger(version) || version < 1) throw new ConfigError(`ENCRYPTION_PREVIOUS_KEYS entry must be "<version>:<base64>"`);
    if (keys.has(version)) throw new ConfigError(`Encryption key version ${version} is defined twice`);
    keys.set(version, decodeKey(entry.slice(idx + 1), `ENCRYPTION_PREVIOUS_KEYS[${version}]`));
  }

  const publicUrl = e.PUBLIC_URL ?? "http://localhost:5173";
  const corsOrigins = e.CORS_ORIGINS ?? (production ? [new URL(publicUrl).origin] : ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8080"]);
  if (corsOrigins.includes("*")) throw new ConfigError("CORS_ORIGINS must be an explicit allow-list ('*' is not permitted with credentials)");

  const appUrl = e.DATABASE_APP_URL ?? deriveAppUrl(e.DATABASE_URL, e.BLOODY_APP_DB_PASSWORD);
  if (production && e.DATABASE_APP_URL === undefined) warnings.push("DATABASE_APP_URL not set — derived from DATABASE_URL with role bloody_app");

  const smtp: SmtpConfig | null = e.SMTP_HOST
    ? { host: e.SMTP_HOST, port: e.SMTP_PORT, secure: e.SMTP_SECURE, user: e.SMTP_USER, password: e.SMTP_PASSWORD, from: e.SMTP_FROM, fromName: e.SMTP_FROM_NAME }
    : null;

  let oidc: OidcConfig | null = null;
  if (e.OIDC_ISSUER_URL && e.OIDC_CLIENT_ID) {
    const issuer = new URL(e.OIDC_ISSUER_URL);
    if (production && issuer.protocol !== "https:") throw new ConfigError("OIDC_ISSUER_URL must use https in production");
    oidc = {
      issuerUrl: e.OIDC_ISSUER_URL.replace(/\/+$/, ""),
      clientId: e.OIDC_CLIENT_ID,
      clientSecret: e.OIDC_CLIENT_SECRET,
      redirectUri: e.OIDC_REDIRECT_URI ?? `${publicUrl.replace(/\/+$/, "")}/api/v1/auth/oidc/callback`,
      scopes: e.OIDC_SCOPES.includes("openid") ? e.OIDC_SCOPES : `openid ${e.OIDC_SCOPES}`,
      providerName: e.OIDC_PROVIDER_NAME,
    };
  }

  return Object.freeze({
    env: e.NODE_ENV,
    host: e.HOST,
    port: e.PORT,
    logLevel: e.LOG_LEVEL,
    database: {
      privilegedUrl: e.DATABASE_URL,
      appUrl,
      appPassword: e.BLOODY_APP_DB_PASSWORD,
      poolMax: e.DATABASE_POOL_MAX,
      statementTimeoutMs: e.DATABASE_STATEMENT_TIMEOUT_MS,
    },
    auth: {
      jwtSecret: new TextEncoder().encode(jwtSecret),
      jwtIssuer: e.JWT_ISSUER,
      jwtAudience: e.JWT_AUDIENCE,
      accessTokenTtlSeconds: e.ACCESS_TOKEN_TTL_SECONDS,
      sessionTtlHours: e.SESSION_TTL_HOURS,
      sessionIdleMinutes: e.SESSION_IDLE_MINUTES,
      loginMaxFailures: e.LOGIN_MAX_FAILURES,
      loginLockoutMinutes: e.LOGIN_LOCKOUT_MINUTES,
      loginRateLimitPerMinute: e.LOGIN_RATE_LIMIT_PER_MINUTE,
    },
    encryption: { activeVersion: e.ENCRYPTION_KEY_VERSION, keys },
    http: {
      corsOrigins,
      publicUrl,
      // Secure by default; only an explicit COOKIE_SECURE=false (plain-http dev proxies) disables it.
      cookieSecure: e.COOKIE_SECURE ?? true,
      trustProxy: e.TRUST_PROXY,
      rateLimitPerMinute: e.RATE_LIMIT_PER_MINUTE,
      bodyLimitBytes: e.BODY_LIMIT_BYTES,
    },
    ingest: { maxBatch: e.INGEST_MAX_BATCH, bodyLimitBytes: e.INGEST_BODY_LIMIT_BYTES, maxEventAgeDays: e.INGEST_MAX_EVENT_AGE_DAYS, pipelineEnabled: e.PIPELINE_ENABLED },
    metricsToken: e.METRICS_TOKEN ?? null,
    smtp,
    oidc,
    warnings,
  });
}
