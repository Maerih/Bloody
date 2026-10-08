import type { FastifyInstance } from "fastify";
import type { AppServices } from "../context.js";
import { unauthorized } from "../http/errors.js";
import { safeEqual } from "../security/crypto.js";

const STARTED_AT = Date.now();
const VERSION = process.env.BLOODY_VERSION ?? process.env.npm_package_version ?? "0.1.0";

/**
 * Liveness (`/healthz`: the process serves requests), readiness (`/readyz`: database reachable
 * through the runtime role, schema current, pipeline not dead-lettering) and Prometheus metrics.
 */
export async function healthRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/healthz", { config: { public: true, rateLimit: false } }, async () => ({
    status: "ok",
    service: "bloody-api",
    version: VERSION,
    uptimeSeconds: Math.round((Date.now() - STARTED_AT) / 1000),
  }));

  app.get("/readyz", { config: { public: true, rateLimit: false } }, async (_request, reply) => {
    const checks: Record<string, { ok: boolean; detail?: string; latencyMs?: number }> = {};
    const t0 = Date.now();
    try {
      await s.db.ping();
      checks.database = { ok: true, latencyMs: Date.now() - t0 };
    } catch (err) {
      checks.database = { ok: false, detail: err instanceof Error ? err.message.split("\n")[0] : "unreachable" };
    }
    if (checks.database.ok) {
      try {
        const { rows } = await s.db.withoutTenant((tx) => tx.query<{ n: number }>("SELECT count(*)::int AS n FROM schema_migrations"));
        checks.migrations = { ok: (rows[0]?.n ?? 0) > 0, detail: `${rows[0]?.n ?? 0} applied` };
      } catch {
        checks.migrations = { ok: false, detail: "schema_migrations not readable" };
      }
    }
    const bus = s.bus.stats();
    checks.pipeline = { ok: bus.oldestAgeMs < 15 * 60_000, detail: `depth=${bus.depth} lagMs=${bus.oldestAgeMs} deadLetters=${bus.deadLetters}` };
    const ready = Object.values(checks).every((c) => c.ok);
    void reply.status(ready ? 200 : 503);
    return { status: ready ? "ready" : "not_ready", checks };
  });

  app.get("/metrics", { config: { public: true, rateLimit: false } }, async (request, reply) => {
    if (s.config.metricsToken) {
      const header = request.headers.authorization ?? "";
      const token = /^Bearer\s+(.+)$/i.exec(header)?.[1]?.trim() ?? "";
      if (!safeEqual(token, s.config.metricsToken)) throw unauthorized("Metrics token required", "metrics_unauthorized");
    }
    const bus = s.bus.stats();
    s.metrics.queueDepth.set(bus.depth);
    s.metrics.queueLag.set(bus.oldestAgeMs / 1000);
    void reply.header("content-type", s.metrics.registry.contentType);
    return s.metrics.registry.metrics();
  });
}
