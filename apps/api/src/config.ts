import { DEFAULT_PRICE_BOOK, PriceBook } from "@bloody/contracts";
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
  /**
   * SCIAT Agent endpoints, per source IP. A whole office reaches the platform through one public
   * address, so this must fit the largest site (each agent: ~1 check-in a minute plus inventory).
   */
  AGENT_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(60).max(1_000_000).default(3000),
  /** Agent enrolment per source IP (mass deployment through an RMM / GPO). */
  AGENT_ENROLL_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(10).max(1_000_000).default(600),
  /** Valkey/Redis for state shared across API replicas (rate limits). Unset = in-process only. */
  VALKEY_URL: z.string().url().optional(),
  /** Data-fabric transport: memory (single process) or kafka (KAFKA_BROKERS). */
  BLOODY_EVENT_BUS: z.enum(["memory", "kafka"]).default("memory"),
  KAFKA_BROKERS: z.string().max(2000).optional(),
  KAFKA_CONSUMER_GROUP: z.string().min(1).max(200).default("bloody-pipeline"),
  /** Billing (operator side). Price book JSON overrides DEFAULT_PRICE_BOOK (cents). */
  BLOODY_PRICE_BOOK: z.string().max(10_000).optional(),
  /** Wire-transfer instructions shown on invoices (use \n for new lines). Enables bank transfer. */
  BLOODY_BILLING_BANK_DETAILS: z.string().max(2000).optional(),
  /** Account team shown on the billing page: "Name <email>". */
  BLOODY_BILLING_CONTACT: z.string().max(300).optional(),
  /** Demo sandbox account (UUID, see `pnpm admin sandbox-setup`); unset disables the sandbox. */
  BLOODY_DEMO_ACCOUNT: z.guid().optional(),
  /** Directory holding the SCIAT Agent installers (infra/agent); found automatically when unset. */
  BLOODY_AGENT_FILES_DIR: z.string().min(1).optional(),
  /** Native SCIAT Agent binaries with SHA256SUMS and VERSION (image: <files dir>/bin; dev: dist/agent/<version>). */
  BLOODY_AGENT_BINARIES_DIR: z.string().min(1).optional(),
  BLOODY_INVOICE_DUE_DAYS: z.coerce.number().int().min(0).max(90).default(14),
  STRIPE_SECRET_KEY: z.string().max(300).optional(),
  STRIPE_WEBHOOK_SECRET: z.string().max(300).optional(),
  PADDLE_API_KEY: z.string().max(300).optional(),
  PADDLE_WEBHOOK_SECRET: z.string().max(300).optional(),
  PADDLE_SANDBOX: bool.default(false),
  NOWPAYMENTS_API_KEY: z.string().max(300).optional(),
  NOWPAYMENTS_IPN_SECRET: z.string().max(300).optional(),
  NOWPAYMENTS_SANDBOX: bool.default(false),
  BTCPAY_URL: z.string().url().optional(),
  BTCPAY_STORE_ID: z.string().max(200).optional(),
  BTCPAY_API_KEY: z.string().max(300).optional(),
  BTCPAY_WEBHOOK_SECRET: z.string().max(300).optional(),
  /** Event search engine: postgres (default) or opensearch (OPENSEARCH_URL; Postgres stays the system of record). */
  BLOODY_EVENT_SEARCH: z.enum(["postgres", "opensearch"]).default("postgres"),
  OPENSEARCH_URL: z.string().url().optional(),
  OPENSEARCH_USERNAME: z.string().max(200).optional(),
  OPENSEARCH_PASSWORD: z.string().max(1000).optional(),
  OPENSEARCH_INDEX_PREFIX: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,60}$/).default("bloody-events"),
  /** OpenTelemetry: OTLP/HTTP endpoint of the collector (traces). Unset = tracing off. */
  OTEL_EXPORTER_OTLP_ENDPOINT: z.string().url().optional(),
  OTEL_SERVICE_NAME: z.string().min(1).max(100).default("bloody-api"),
  OTEL_RESOURCE_ATTRIBUTES: z.string().max(2000).optional(),

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
  SMTP_FROM_NAME: z.string().default("SCIAT AFRICA Security Operations"),

  OIDC_ISSUER_URL: z.string().url().optional(),
  OIDC_CLIENT_ID: z.string().optional(),
  OIDC_CLIENT_SECRET: z.string().optional(),
  OIDC_REDIRECT_URI: z.string().url().optional(),
  OIDC_SCOPES: z.string().default("openid email profile"),
  OIDC_PROVIDER_NAME: z.string().default("sso"),
  /** Accept identity tokens without email_verified (IdPs such as Microsoft Entra omit the claim). */
  OIDC_TRUST_UNVERIFIED_EMAIL: bool.default(false),

  /** When set, GET /metrics requires `Authorization: Bearer <token>`. */
  METRICS_TOKEN: z.string().min(16).optional(),
  /** Run the in-process analytics pipeline consumer (disable on API-only replicas fed by Kafka). */
  PIPELINE_ENABLED: bool.default(true),

  /** Background scheduler (report schedules, scheduled playbooks, approval expiry, overdue sweeps). */
  SCHEDULER_ENABLED: bool.optional(),
  SCHEDULER_INTERVAL_SECONDS: z.coerce.number().int().min(5).max(3600).default(60),

  /**
   * KEV / EPSS vulnerability enrichment from public feeds (CISA, FIRST). Off by default: it makes
   * outbound requests, restricted to ENRICHMENT_ALLOWED_HOSTS (SSRF guard, https only).
   */
  FEATURE_VULN_ENRICHMENT: bool.default(false),
  ENRICHMENT_ALLOWED_HOSTS: csv.prefault("www.cisa.gov,api.first.org,epss.cyentia.com"),
  KEV_FEED_URL: z.string().url().default("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
  EPSS_API_URL: z.string().url().default("https://api.first.org/data/v1/epss"),

  /** Generated report files kept for later download up to this size (larger ones are not stored). */
  REPORT_MAX_STORED_BYTES: z.coerce.number().int().min(0).max(64 * 1024 * 1024).default(10 * 1024 * 1024),
  /** Platform default for AI endpoints on private networks (tenants can also opt in via settings). */
  AI_ALLOW_PRIVATE_ENDPOINTS: bool.default(false),
  /** Engine connectors (Wazuh, MISP, CoPilot…) on private networks: on-prem relays are the norm. */
  INTEGRATIONS_ALLOW_PRIVATE_NETWORKS: bool.default(true),
});

export interface FeatureConfig {
  vulnEnrichment: boolean;
}

export interface EnrichmentConfig {
  allowedHosts: string[];
  kevFeedUrl: string;
  epssApiUrl: string;
}

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
  /** Link accounts by e-mail even when the token does not assert email_verified: true. */
  trustUnverifiedEmail: boolean;
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
    agentRateLimitPerMinute: number;
    agentEnrollRateLimitPerMinute: number;
    bodyLimitBytes: number;
    /** redis:// or rediss:// URL of Valkey; rate limits are shared across replicas when set. */
    valkeyUrl: string | null;
  };
  telemetry: { otlpEndpoint: string | null; serviceName: string; resourceAttributes: string | undefined };
  bus: { kind: "memory" | "kafka"; brokers: string[]; consumerGroup: string };
  agent: { filesDir: string | undefined; binariesDir: string | undefined };
  sandbox: { accountId: string | null };
  billing: {
    priceBook: PriceBook;
    bankDetails: string | null;
    contact: { name: string; email: string } | null;
    invoiceDueDays: number;
    stripe: { secretKey: string; webhookSecret: string } | null;
    paddle: { apiKey: string; webhookSecret: string; sandbox: boolean } | null;
    nowpayments: { apiKey: string; ipnSecret: string; sandbox: boolean } | null;
    btcpay: { url: string; storeId: string; apiKey: string; webhookSecret: string } | null;
  };
  search: { engine: "postgres" | "opensearch"; opensearch: { url: string; username: string | undefined; password: string | undefined; indexPrefix: string } | null };
  ingest: { maxBatch: number; bodyLimitBytes: number; maxEventAgeDays: number; pipelineEnabled: boolean };
  scheduler: { enabled: boolean; intervalSeconds: number };
  features: FeatureConfig;
  enrichment: EnrichmentConfig;
  reports: { maxStoredBytes: number };
  ai: { allowPrivateEndpoints: boolean };
  integrations: { allowPrivateNetworks: boolean };
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
    "SCHEDULER_ENABLED",
    "SCHEDULER_INTERVAL_SECONDS",
    "AI_ALLOW_PRIVATE_ENDPOINTS",
    "OIDC_CLIENT_SECRET",
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
  if (e.BLOODY_EVENT_BUS === "kafka" && !(e.KAFKA_BROKERS ?? "").trim()) throw new ConfigError("BLOODY_EVENT_BUS=kafka requires KAFKA_BROKERS (host:port,host:port)");
  let priceBook: PriceBook = DEFAULT_PRICE_BOOK;
  if (e.BLOODY_PRICE_BOOK) {
    try {
      priceBook = PriceBook.parse(JSON.parse(e.BLOODY_PRICE_BOOK));
    } catch (err) {
      throw new ConfigError(`BLOODY_PRICE_BOOK is not a valid price book: ${err instanceof Error ? err.message.slice(0, 300) : "invalid JSON"}`);
    }
  }
  if (e.BLOODY_EVENT_SEARCH === "opensearch" && !e.OPENSEARCH_URL) throw new ConfigError("BLOODY_EVENT_SEARCH=opensearch requires OPENSEARCH_URL");
  const production = e.NODE_ENV === "production";
  const warnings: string[] = [];

  if (production && !e.METRICS_TOKEN) warnings.push("METRICS_TOKEN not set — GET /api/v1/metrics is disabled until it is");
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

  // Enrichment feeds are fetched server-side: https only, and only from the allow-listed hosts.
  const enrichmentHosts = e.ENRICHMENT_ALLOWED_HOSTS.map((h) => h.toLowerCase());
  for (const [label, raw] of [["KEV_FEED_URL", e.KEV_FEED_URL], ["EPSS_API_URL", e.EPSS_API_URL]] as const) {
    const u = new URL(raw);
    if (u.protocol !== "https:") throw new ConfigError(`${label} must use https`);
    if (!enrichmentHosts.includes(u.hostname.toLowerCase())) throw new ConfigError(`${label} host ${u.hostname} is not in ENRICHMENT_ALLOWED_HOSTS`);
  }

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
      trustUnverifiedEmail: e.OIDC_TRUST_UNVERIFIED_EMAIL,
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
      agentRateLimitPerMinute: e.AGENT_RATE_LIMIT_PER_MINUTE,
      agentEnrollRateLimitPerMinute: e.AGENT_ENROLL_RATE_LIMIT_PER_MINUTE,
      valkeyUrl: e.VALKEY_URL ?? null,
      bodyLimitBytes: e.BODY_LIMIT_BYTES,
    },
    ingest: { maxBatch: e.INGEST_MAX_BATCH, bodyLimitBytes: e.INGEST_BODY_LIMIT_BYTES, maxEventAgeDays: e.INGEST_MAX_EVENT_AGE_DAYS, pipelineEnabled: e.PIPELINE_ENABLED },
    scheduler: { enabled: e.SCHEDULER_ENABLED ?? e.NODE_ENV !== "test", intervalSeconds: e.SCHEDULER_INTERVAL_SECONDS },
    features: { vulnEnrichment: e.FEATURE_VULN_ENRICHMENT },
    enrichment: { allowedHosts: e.ENRICHMENT_ALLOWED_HOSTS.map((h) => h.toLowerCase()), kevFeedUrl: e.KEV_FEED_URL, epssApiUrl: e.EPSS_API_URL },
    reports: { maxStoredBytes: e.REPORT_MAX_STORED_BYTES },
    agent: { filesDir: e.BLOODY_AGENT_FILES_DIR, binariesDir: e.BLOODY_AGENT_BINARIES_DIR },
    sandbox: { accountId: e.BLOODY_DEMO_ACCOUNT ?? null },
    billing: {
      priceBook,
      bankDetails: e.BLOODY_BILLING_BANK_DETAILS ? e.BLOODY_BILLING_BANK_DETAILS.replace(/\\n/g, "\n") : null,
      contact: (() => {
        const m = /^\s*(.*?)\s*<([^>]+)>\s*$/.exec(e.BLOODY_BILLING_CONTACT ?? "");
        return m ? { name: m[1] || m[2]!, email: m[2]! } : null;
      })(),
      invoiceDueDays: e.BLOODY_INVOICE_DUE_DAYS,
      stripe: e.STRIPE_SECRET_KEY && e.STRIPE_WEBHOOK_SECRET ? { secretKey: e.STRIPE_SECRET_KEY, webhookSecret: e.STRIPE_WEBHOOK_SECRET } : null,
      paddle: e.PADDLE_API_KEY && e.PADDLE_WEBHOOK_SECRET ? { apiKey: e.PADDLE_API_KEY, webhookSecret: e.PADDLE_WEBHOOK_SECRET, sandbox: e.PADDLE_SANDBOX } : null,
      nowpayments: e.NOWPAYMENTS_API_KEY && e.NOWPAYMENTS_IPN_SECRET ? { apiKey: e.NOWPAYMENTS_API_KEY, ipnSecret: e.NOWPAYMENTS_IPN_SECRET, sandbox: e.NOWPAYMENTS_SANDBOX } : null,
      btcpay:
        e.BTCPAY_URL && e.BTCPAY_STORE_ID && e.BTCPAY_API_KEY && e.BTCPAY_WEBHOOK_SECRET
          ? { url: e.BTCPAY_URL, storeId: e.BTCPAY_STORE_ID, apiKey: e.BTCPAY_API_KEY, webhookSecret: e.BTCPAY_WEBHOOK_SECRET }
          : null,
    },
    search: {
      engine: e.BLOODY_EVENT_SEARCH,
      opensearch: e.OPENSEARCH_URL ? { url: e.OPENSEARCH_URL, username: e.OPENSEARCH_USERNAME, password: e.OPENSEARCH_PASSWORD, indexPrefix: e.OPENSEARCH_INDEX_PREFIX } : null,
    },
    bus: { kind: e.BLOODY_EVENT_BUS, brokers: (e.KAFKA_BROKERS ?? "").split(",").map((b) => b.trim()).filter(Boolean), consumerGroup: e.KAFKA_CONSUMER_GROUP },
    telemetry: { otlpEndpoint: e.OTEL_EXPORTER_OTLP_ENDPOINT ?? null, serviceName: e.OTEL_SERVICE_NAME, resourceAttributes: e.OTEL_RESOURCE_ATTRIBUTES },
    ai: { allowPrivateEndpoints: e.AI_ALLOW_PRIVATE_ENDPOINTS },
    integrations: { allowPrivateNetworks: e.INTEGRATIONS_ALLOW_PRIVATE_NETWORKS },
    metricsToken: e.METRICS_TOKEN ?? null,
    smtp,
    oidc,
    warnings,
  });
}
