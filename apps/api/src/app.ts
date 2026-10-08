import { randomUUID } from "node:crypto";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { createDefaultRegistry, type AdapterRegistry } from "@bloody/adapters";
import { API_VERSION } from "@bloody/contracts";
import { AttackPathEngine, RiskEngine } from "@bloody/engines";
import Fastify, { type FastifyInstance, type FastifyRequest, type FastifyServerOptions } from "fastify";
import { actorFromRequest, writeAudit, type AuditOutcome } from "./audit/audit.js";
import { OidcProvider, type ExternalAuthProvider } from "./auth/oidc.js";
import { AuthService } from "./auth/service.js";
import { CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE, type AuditState } from "./auth/types.js";
import type { AppConfig } from "./config.js";
import type { AppServices } from "./context.js";
import type { Database } from "./db/pool.js";
import { HttpError, forbidden, registerErrorHandling, unauthorized } from "./http/errors.js";
import { Metrics } from "./metrics.js";
import { AnalyticsPipeline, type AutomationSink } from "./pipeline/analytics.js";
import { InMemoryEventBus, type EventBus } from "./pipeline/event-bus.js";
import { IngestService } from "./pipeline/ingest.js";
import { registerRoutes } from "./routes/index.js";
import { SecretBox } from "./security/crypto.js";
import { AttackPathService } from "./services/attack-paths.js";
import { InventoryService } from "./services/inventory.js";
import { SecretStore } from "./services/secret-store.js";

export interface AppDeps {
  config: AppConfig;
  db: Database;
  bus?: EventBus;
  metrics?: Metrics;
  adapters?: AdapterRegistry;
  oidc?: ExternalAuthProvider | null;
  automation?: AutomationSink;
  now?: () => number;
  /** Fastify logger option (default: config.logLevel, silent in tests). */
  logger?: FastifyServerOptions["logger"];
  /** Start the in-process analytics consumer (default: config.ingest.pipelineEnabled). */
  startPipeline?: boolean;
}

export interface BuiltApp {
  app: FastifyInstance;
  services: AppServices;
}

const REQUEST_ID_RE = /^[A-Za-z0-9._:-]{8,128}$/;
const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * Composition root. Everything with I/O is injected so tests build isolated apps against the
 * test database (and a fresh in-process event bus) without touching globals.
 */
export async function buildApp(deps: AppDeps): Promise<BuiltApp> {
  const { config, db } = deps;
  const now = deps.now ?? (() => Date.now());
  const metrics = deps.metrics ?? new Metrics({ defaultMetrics: config.env !== "test" });
  const bus = deps.bus ?? new InMemoryEventBus();
  const secrets = new SecretBox(config.encryption.keys, config.encryption.activeVersion);
  const risk = new RiskEngine({ clock: { now } });
  const attackPathEngine = new AttackPathEngine({ riskEngine: risk, clock: { now } });
  const inventory = new InventoryService(risk, now);
  const auth = new AuthService(db, config, secrets, now);
  const oidc = deps.oidc !== undefined ? deps.oidc : config.oidc ? new OidcProvider(config.oidc, auth.tokenSettings) : null;

  const app = Fastify({
    logger: deps.logger ?? (config.env === "test" ? false : { level: config.logLevel, redact: ["req.headers.authorization", "req.headers.cookie", 'res.headers["set-cookie"]'] }),
    trustProxy: config.http.trustProxy,
    bodyLimit: config.http.bodyLimitBytes,
    genReqId: (req) => {
      const incoming = req.headers["x-request-id"];
      return typeof incoming === "string" && REQUEST_ID_RE.test(incoming) ? incoming : randomUUID();
    },
    routerOptions: { ignoreTrailingSlash: true },
  });

  const log = app.log;
  const pipeline = new AnalyticsPipeline({ db, bus, metrics, inventory, risk, log, automation: deps.automation, now });
  const services: AppServices = {
    config,
    db,
    bus,
    metrics,
    auth,
    secrets,
    secretStore: new SecretStore(secrets, db),
    risk,
    attackPathEngine,
    attackPaths: new AttackPathService(db, attackPathEngine, 60_000, now),
    inventory,
    ingest: new IngestService(db, bus, metrics, config.ingest, now),
    pipeline,
    adapters: deps.adapters ?? createDefaultRegistry(),
    oidc,
    now,
  };

  app.decorateRequest("auth", null);
  app.decorateRequest("auditState", null as unknown as AuditState);

  registerErrorHandling(app);

  await app.register(cookie);
  await app.register(helmet, {
    // JSON API: nothing may be framed or executed from responses.
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'none'"], formAction: ["'none'"] } },
    crossOriginResourcePolicy: { policy: "same-site" },
    hsts: config.env === "production" ? { maxAge: 31_536_000, includeSubDomains: true } : false,
  });
  const allowed = new Set(config.http.corsOrigins);
  await app.register(cors, {
    origin: (origin, cb) => cb(null, origin === undefined || allowed.has(origin)),
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["authorization", "content-type", CSRF_HEADER, "x-request-id", "x-api-key"],
    exposedHeaders: ["x-request-id", "content-disposition", "retry-after"],
    maxAge: 600,
  });
  await app.register(rateLimit, {
    global: true,
    max: config.http.rateLimitPerMinute,
    timeWindow: "1 minute",
    keyGenerator: (req) => req.ip,
    errorResponseBuilder: (_req, ctx) => new HttpError(429, "rate_limited", `Too many requests — retry in ${Math.ceil(ctx.ttl / 1000)} s`, undefined, { "retry-after": String(Math.ceil(ctx.ttl / 1000)) }),
  });

  // Raw engine payloads (adapter ingest) arrive as NDJSON / plain text as well as JSON.
  app.addContentTypeParser(["application/x-ndjson", "text/plain"], { parseAs: "string" }, (_req, body, done) => done(null, body));

  app.addHook("onRequest", async (request, reply) => {
    request.auditState = { recorded: false };
    void reply.header("x-request-id", request.id);
    void reply.header("cache-control", "no-store");
  });

  // Authentication (before body parsing) + CSRF for cookie sessions.
  app.addHook("onRequest", async (request, reply) => {
    const routeConfig = request.routeOptions.config as { public?: boolean } | undefined;
    const isPublic = request.routeOptions.url === undefined || routeConfig?.public === true;
    try {
      request.auth = await authenticate(services, request);
    } catch (err) {
      if (isPublic) request.auth = null;
      else throw err;
    }
    if (!request.auth) {
      if (isPublic) return;
      throw unauthorized();
    }
    if (request.auth.csrfProtected && UNSAFE_METHODS.has(request.method)) {
      const origin = request.headers.origin;
      const originOk = typeof origin !== "string" || allowed.has(origin);
      const header = request.headers[CSRF_HEADER];
      const tokenOk = originOk && auth.verifyCsrf(request.auth.sessionId!, request.cookies[CSRF_COOKIE], typeof header === "string" ? header : undefined);
      if (!tokenOk) {
        // Public endpoints (login, refresh, logout) simply ignore a cookie session that is not
        // backed by a valid CSRF token; everything else rejects the forged request.
        if (isPublic) {
          request.auth = null;
          return;
        }
        request.auditState.details = { reason: originOk ? "csrf" : "csrf_origin" };
        if (!originOk) throw forbidden("Cross-origin request rejected", "csrf_origin");
        throw forbidden("Missing or invalid CSRF token", "csrf");
      }
    }
    void reply;
  });

  // Generic audit for every mutation not already audited by a committed handler transaction.
  // Routes marked `audit: false` write their own (richer) record on success; any attempt that
  // fails before or inside the handler — RBAC/CSRF denials, validation, rolled-back work — is
  // still recorded here with its outcome.
  app.addHook("onSend", async (request, reply, payload) => {
    if (!UNSAFE_METHODS.has(request.method) || request.auditState?.recorded) return payload;
    const routeConfig = request.routeOptions.config as { audit?: string | false } | undefined;
    const status = reply.statusCode;
    if (routeConfig?.audit === false && status < 400) return payload;
    const tenantId = request.auth?.tenantId ?? request.auditState?.tenantId;
    if (!tenantId) return payload;
    const outcome: AuditOutcome = status < 400 ? "success" : status === 401 || status === 403 ? "denied" : "failure";
    const action = typeof routeConfig?.audit === "string" ? routeConfig.audit : `${request.method.toLowerCase()} ${request.routeOptions.url ?? request.url.split("?")[0]}`;
    try {
      await db.withTenant(tenantId, (tx) =>
        writeAudit(tx, actorFromRequest(request, tenantId), {
          action,
          organizationId: request.auditState.organizationId ?? null,
          targetKind: request.auditState.targetKind ?? null,
          targetId: request.auditState.targetId ?? ((request.params as Record<string, string> | undefined)?.id ?? null),
          outcome,
          details: { status, ...(request.auditState.details ?? {}) },
        }),
      );
      request.auditState.recorded = true;
    } catch (err) {
      request.log.error({ err }, "failed to write audit record");
    }
    return payload;
  });

  app.addHook("onResponse", async (request, reply) => {
    metrics.httpDuration.observe({ method: request.method, route: request.routeOptions.url ?? "unmatched", status_code: String(reply.statusCode) }, reply.elapsedTime / 1000);
  });

  await app.register(async (api) => registerRoutes(api, services), { prefix: `/api/${API_VERSION}` });

  const shouldStart = deps.startPipeline ?? config.ingest.pipelineEnabled;
  if (shouldStart) pipeline.start();
  app.addHook("onClose", async () => {
    pipeline.stop();
    await bus.drain();
  });

  return { app, services };
}

async function authenticate(services: AppServices, request: FastifyRequest) {
  const header = request.headers.authorization;
  const apiKeyHeader = request.headers["x-api-key"];
  if (typeof apiKeyHeader === "string" && apiKeyHeader.length > 0) return services.auth.authenticateApiKey(apiKeyHeader.trim(), request.ip);
  if (typeof header === "string" && header.length > 0) {
    const m = /^Bearer\s+(\S+)$/i.exec(header.trim());
    if (!m) throw unauthorized("Unsupported authorization scheme", "invalid_authorization");
    const token = m[1]!;
    if (AuthService.looksLikeApiKey(token)) return services.auth.authenticateApiKey(token, request.ip);
    return services.auth.authenticateBearer(token);
  }
  const sessionCookie = request.cookies[SESSION_COOKIE];
  if (sessionCookie) return services.auth.authenticateSessionCookie(sessionCookie);
  return null;
}
