import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { MODULES, ModuleKey, PLANS, principalCan, Uuid } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { requireAuth, requirePermission, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { forbidden } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";
import { TRIAL_DAYS, TRIAL_GRACE_DAYS } from "../services/commercial.js";
import { computeEntitlements, loadAccountPlan } from "../services/entitlements.js";
import { parse } from "./util.js";

/** Trials change what the whole account can use: billing:write or settings:write, tenant-wide. */
function requireTrialManager(request: FastifyRequest): void {
  const auth = requireAuth(request);
  if (auth.boundOrganizationId !== null) throw forbidden("Organization-bound API keys cannot manage the account's trials");
  if (!principalCan(auth.principal, "billing:write", null) && !principalCan(auth.principal, "settings:write", null)) {
    request.auditState.details = { deniedPermission: "billing:write|settings:write" };
    throw forbidden("Missing permission billing:write or settings:write (tenant-wide)");
  }
}

/**
 * Commercial surface: module entitlements (plan + per-module trials, the basis of the 402
 * ENTITLEMENT_REQUIRED guard), 14-day trials and plan usage vs limits (quota meters).
 */
export async function commercialRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/entitlements", async (request) => {
    const auth = requireAuth(request);
    const { plan, entitlements, account } = await s.db.withTenant(auth.tenantId, async (tx) => ({ ...(await computeEntitlements(tx, auth.tenantId, s.now())), account: await loadAccountPlan(tx, auth.tenantId) }));
    const meta = new Map<string, (typeof MODULES)[number]>(MODULES.map((m) => [m.key, m]));
    return {
      plan,
      planName: PLANS[plan].name,
      accountTrialEndsAt: account.trialEndsAt,
      trialDays: TRIAL_DAYS,
      graceDays: TRIAL_GRACE_DAYS,
      items: entitlements.map((e) => ({
        ...e,
        name: meta.get(e.module)?.name ?? e.module,
        short: meta.get(e.module)?.short ?? e.module,
        group: meta.get(e.module)?.group ?? null,
        entitled: e.state === "active" || e.state === "trial",
        trialAvailable: e.state === "available",
      })),
    };
  });

  app.post("/entitlements/:module/trial", { config: { audit: false } }, async (request, reply) => {
    const auth = requireAuth(request);
    const { module } = parse(z.object({ module: ModuleKey }), request.params);
    requireTrialManager(request);
    const started = await s.db.withTenant(auth.tenantId, async (tx) => {
      const e = await s.entitlements.startTrial(tx, auth.tenantId, module);
      await recordAudit(tx, request, { action: "entitlement.trial_started", targetKind: "module", targetId: module, details: { trialEndsAt: e.trialEndsAt, uninstallAt: e.uninstallAt } });
      return e;
    });
    s.entitlements.invalidate(auth.tenantId);
    return reply.status(201).send(started);
  });

  app.get("/billing/usage", async (request) => {
    const auth = requireAuth(request);
    requirePermission(request, "billing:read", null);
    const q = parse(z.object({ days: z.coerce.number().int().min(1).max(90).default(30) }), request.query);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const { limits, usage } = await s.quota.usage(tx, auth.tenantId);
      const { rows } = await tx.query<Row>(
        `SELECT o.id, o.name, o.plan, o.mrr,
                (SELECT count(*) FROM agents a WHERE a.organization_id = o.id) AS endpoints,
                (SELECT count(*) FROM users u WHERE u.organization_id = o.id AND u.status <> 'disabled') AS users,
                (SELECT coalesce(sum(value), 0) FROM usage_counters c WHERE c.organization_id = o.id AND c.metric = 'events_ingested' AND c.period_start > (now() AT TIME ZONE 'UTC')::date - $1::int) AS events,
                (SELECT coalesce(sum(value), 0) FROM usage_counters c WHERE c.organization_id = o.id AND c.metric = 'ai.calls' AND c.period_start > (now() AT TIME ZONE 'UTC')::date - $1::int) AS ai_calls,
                (SELECT coalesce(sum(value), 0) FROM usage_counters c WHERE c.organization_id = o.id AND c.metric IN ('ai.tokens.input', 'ai.tokens.output') AND c.period_start > (now() AT TIME ZONE 'UTC')::date - $1::int) AS ai_tokens
         FROM organizations o WHERE o.status <> 'offboarded' ORDER BY lower(o.name)`,
        [q.days],
      );
      const daily = await tx.query<Row>(
        `SELECT period_start::text AS day, metric, sum(value) AS value FROM usage_counters
         WHERE metric IN ('events_ingested', 'ai_requests', 'ai.calls', 'notifications.sent') AND period_start > (now() AT TIME ZONE 'UTC')::date - $1::int
         GROUP BY 1, 2 ORDER BY 1`,
        [q.days],
      );
      return {
        plan: limits.plan,
        planName: PLANS[limits.plan].name,
        limits: limits.limits,
        overrides: limits.overrides,
        usage,
        exceeded: Object.entries(usage).filter(([, u]) => u.used > u.limit).map(([m]) => m),
        organizations: rows.map((r) => ({
          organizationId: String(r.id),
          name: String(r.name),
          plan: (r.plan as string | null) ?? null,
          mrr: Number(r.mrr ?? 0),
          endpoints: Number(r.endpoints),
          users: Number(r.users),
          eventsLastDays: Number(r.events),
          aiCallsLastDays: Number(r.ai_calls),
          aiTokensLastDays: Number(r.ai_tokens),
        })),
        daily: daily.rows.map((r) => ({ day: String(r.day), metric: String(r.metric), value: Number(r.value) })),
        windowDays: q.days,
        generatedAt: new Date(s.now()).toISOString(),
      };
    });
  });

  // Entitlement check for a single module (UI gating without listing everything).
  app.get("/entitlements/:module", async (request) => {
    const auth = requireAuth(request);
    const { module } = parse(z.object({ module: ModuleKey }), request.params);
    const q = parse(z.object({ organizationId: Uuid.optional() }), request.query);
    if (q.organizationId) resolveOrgFilter(request, "org:read", q.organizationId);
    const e = await s.entitlements.state(auth.tenantId, module);
    return { ...e, entitled: e.state === "active" || e.state === "trial", trialAvailable: e.state === "available" };
  });
}
