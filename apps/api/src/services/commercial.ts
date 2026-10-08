import { MODULES, PLANS, type ModuleKey, type PlanDefinition, type PlanKey } from "@bloody/contracts";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError } from "../http/errors.js";
import type { DomainEventBus } from "./domain-events.js";
import { computeEntitlements, loadAccountPlan, type EntitlementView } from "./entitlements.js";

/**
 * Commercial controls: module entitlements (plan + trials) and plan quotas (endpoints,
 * organizations, users, events per day, AI requests per day), metered in `usage_counters`.
 */

export const TRIAL_DAYS = 14;
/** Data of an ended trial is kept this long before the module is uninstalled. */
export const TRIAL_GRACE_DAYS = 14;
const ENTITLED_STATES = new Set(["active", "trial"]);

export function moduleName(module: ModuleKey): string {
  return MODULES.find((m) => m.key === module)?.name ?? module;
}

export class EntitlementService {
  private readonly cache = new Map<string, { at: number; value: { plan: PlanKey; entitlements: EntitlementView[] } }>();

  constructor(
    private readonly db: Database,
    private readonly now: () => number,
    private readonly ttlMs = 15_000,
  ) {}

  async forTenant(tenantId: string): Promise<{ plan: PlanKey; entitlements: EntitlementView[] }> {
    const hit = this.cache.get(tenantId);
    if (hit && this.now() - hit.at < this.ttlMs) return hit.value;
    const value = await this.db.withTenant(tenantId, (tx) => computeEntitlements(tx, tenantId, this.now()));
    this.cache.set(tenantId, { at: this.now(), value });
    if (this.cache.size > 10_000) this.cache.clear();
    return value;
  }

  invalidate(tenantId: string): void {
    this.cache.delete(tenantId);
  }

  async state(tenantId: string, module: ModuleKey): Promise<EntitlementView> {
    const { entitlements } = await this.forTenant(tenantId);
    return entitlements.find((e) => e.module === module) ?? { module, state: "locked", trialEndsAt: null, uninstallAt: null, basis: "lock" };
  }

  async isEntitled(tenantId: string, module: ModuleKey): Promise<boolean> {
    return ENTITLED_STATES.has((await this.state(tenantId, module)).state);
  }

  /** Entitlement guard: 402 ENTITLEMENT_REQUIRED unless the module is active or in an active trial. */
  async require(tenantId: string, module: ModuleKey): Promise<void> {
    const e = await this.state(tenantId, module);
    if (ENTITLED_STATES.has(e.state)) return;
    const why =
      e.state === "trial_ended"
        ? `The ${moduleName(module)} trial has ended`
        : e.state === "locked"
          ? `${moduleName(module)} is locked for this account`
          : `${moduleName(module)} is not included in the current plan`;
    throw new HttpError(402, "ENTITLEMENT_REQUIRED", `${why} — upgrade the plan or start a trial`, {
      module,
      state: e.state,
      trialEndsAt: e.trialEndsAt,
      trialAvailable: e.state === "available",
    });
  }

  /** Start a 14-day module trial (tenant-wide). One trial per module per account. */
  async startTrial(tx: Queryable, tenantId: string, module: ModuleKey): Promise<EntitlementView> {
    const { entitlements } = await computeEntitlements(tx, tenantId, this.now());
    const cur = entitlements.find((e) => e.module === module);
    if (!cur) throw new HttpError(404, "not_found", "Unknown module");
    if (cur.state === "active") throw new HttpError(409, "already_entitled", `${moduleName(module)} is already included in the plan`);
    if (cur.state === "trial") throw new HttpError(409, "trial_active", `A ${moduleName(module)} trial is already running`, { trialEndsAt: cur.trialEndsAt });
    if (cur.state === "locked") throw new HttpError(403, "module_locked", `${moduleName(module)} is locked for this account; contact sales`);
    if (cur.basis === "trial") throw new HttpError(409, "trial_already_used", `The ${moduleName(module)} trial was already used; upgrade the plan to continue`, { trialEndsAt: cur.trialEndsAt });
    if (cur.state === "trial_ended" && cur.basis === "plan") throw new HttpError(409, "trial_already_used", "The account trial has ended; upgrade the plan to continue");
    const endsAt = new Date(this.now() + TRIAL_DAYS * 86_400_000).toISOString();
    const uninstallAt = new Date(this.now() + (TRIAL_DAYS + TRIAL_GRACE_DAYS) * 86_400_000).toISOString();
    const { rows } = await tx.query<{ module: string }>(
      `INSERT INTO entitlements (tenant_id, organization_id, module, state, trial_ends_at, uninstall_at)
       VALUES ($1, NULL, $2, 'trial', $3, $4)
       ON CONFLICT (tenant_id, org_key(organization_id), module) DO NOTHING RETURNING module`,
      [tenantId, module, endsAt, uninstallAt],
    );
    if (!rows[0]) throw new HttpError(409, "trial_already_used", `The ${moduleName(module)} trial was already used`);
    this.invalidate(tenantId);
    return { module, state: "trial", trialEndsAt: endsAt, uninstallAt, basis: "trial" };
  }
}

// ─── Quotas ──────────────────────────────────────────────────────────────────

export type CapacityMeter = "endpoints" | "organizations" | "users";
export type DailyMeter = "eventsPerDay" | "aiRequestsPerDay";
export type QuotaMeter = CapacityMeter | DailyMeter;
export const QUOTA_METERS: readonly QuotaMeter[] = ["endpoints", "organizations", "users", "eventsPerDay", "aiRequestsPerDay"];

const METER_KEY: Record<QuotaMeter, string> = {
  endpoints: "endpoints",
  organizations: "organizations",
  users: "users",
  eventsPerDay: "events_per_day",
  aiRequestsPerDay: "ai_requests_per_day",
};

export interface MeterUsage {
  used: number;
  limit: number;
  remaining: number;
  /** 0..100 (may exceed 100 when a limit was lowered below current usage). */
  percent: number;
  /** Daily meters reset at 00:00 UTC. */
  resetsAt: string | null;
}

export interface TenantLimits {
  plan: PlanKey;
  limits: PlanDefinition["limits"];
  /** Contracted per-account overrides (accounts.settings.limits). */
  overrides: Partial<PlanDefinition["limits"]>;
}

function utcDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

function nextUtcMidnight(ms: number): string {
  const d = new Date(`${utcDay(ms)}T00:00:00.000Z`);
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString();
}

export class QuotaService {
  constructor(
    private readonly db: Database,
    private readonly events: DomainEventBus,
    private readonly now: () => number,
  ) {}

  async limits(tx: Queryable, tenantId: string): Promise<TenantLimits> {
    const plan = (await loadAccountPlan(tx, tenantId)).plan;
    const { rows } = await tx.query<{ limits: Record<string, unknown> | null }>("SELECT settings->'limits' AS limits FROM accounts WHERE id = $1", [tenantId]);
    const overrides: Partial<PlanDefinition["limits"]> = {};
    const raw = rows[0]?.limits ?? {};
    for (const k of Object.keys(PLANS[plan].limits) as Array<keyof PlanDefinition["limits"]>) {
      const v = raw[k];
      if (typeof v === "number" && Number.isFinite(v) && v >= 0) overrides[k] = Math.floor(v);
    }
    return { plan, limits: { ...PLANS[plan].limits, ...overrides }, overrides };
  }

  private async capacityUsed(tx: Queryable, meter: CapacityMeter): Promise<number> {
    const sql =
      meter === "endpoints"
        ? "SELECT count(*)::int AS n FROM agents"
        : meter === "organizations"
          ? "SELECT count(*)::int AS n FROM organizations WHERE status <> 'offboarded'"
          : "SELECT count(*)::int AS n FROM users WHERE status <> 'disabled'";
    return (await tx.query<{ n: number }>(sql)).rows[0]?.n ?? 0;
  }

  private async dailyUsed(tx: Queryable, meter: DailyMeter): Promise<number> {
    const metric = meter === "eventsPerDay" ? "events_ingested" : "ai_requests";
    const orgFilter = meter === "eventsPerDay" ? "" : "AND organization_id IS NULL";
    const { rows } = await tx.query<{ n: string | null }>(`SELECT sum(value)::text AS n FROM usage_counters WHERE metric = $1 AND period_start = $2::date ${orgFilter}`, [metric, utcDay(this.now())]);
    return Number(rows[0]?.n ?? 0);
  }

  /** Usage of every meter against the plan (GET /billing/usage). */
  async usage(tx: Queryable, tenantId: string): Promise<{ limits: TenantLimits; usage: Record<QuotaMeter, MeterUsage> }> {
    const limits = await this.limits(tx, tenantId);
    const usage = {} as Record<QuotaMeter, MeterUsage>;
    for (const meter of QUOTA_METERS) {
      const used = meter === "eventsPerDay" || meter === "aiRequestsPerDay" ? await this.dailyUsed(tx, meter) : await this.capacityUsed(tx, meter);
      const limit = limits.limits[meter];
      usage[meter] = {
        used,
        limit,
        remaining: Math.max(0, limit - used),
        percent: limit > 0 ? Math.round((used / limit) * 1000) / 10 : used > 0 ? 100 : 0,
        resetsAt: meter === "eventsPerDay" || meter === "aiRequestsPerDay" ? nextUtcMidnight(this.now()) : null,
      };
    }
    return { limits, usage };
  }

  /** Capacity check before creating endpoints / organizations / users (402 quota_exceeded). */
  async assertCapacity(tx: Queryable, tenantId: string, meter: CapacityMeter, adding = 1): Promise<void> {
    const { limits } = await this.limits(tx, tenantId);
    const limit = limits[meter];
    const used = await this.capacityUsed(tx, meter);
    if (used + adding <= limit) return;
    this.notifyExceeded(tenantId, meter, used, limit);
    throw new HttpError(402, "quota_exceeded", `The plan allows ${limit} ${meter}; ${used} are in use`, { meter, used, limit });
  }

  /** Daily ingest budget (events/day). Rejects the whole batch with 429 when it would exceed it. */
  async assertIngest(tenantId: string, incoming: number): Promise<void> {
    const { used, limit } = await this.db.withTenant(tenantId, async (tx) => ({ used: await this.dailyUsed(tx, "eventsPerDay"), limit: (await this.limits(tx, tenantId)).limits.eventsPerDay }));
    if (used + incoming <= limit) return;
    this.notifyExceeded(tenantId, "eventsPerDay", used, limit);
    const resetsAt = nextUtcMidnight(this.now());
    throw new HttpError(429, "quota_exceeded", `Daily event quota of ${limit} reached (${used} ingested today); resets at ${resetsAt}`, { meter: "eventsPerDay", used, limit, resetsAt }, {
      "retry-after": String(Math.max(1, Math.ceil((Date.parse(resetsAt) - this.now()) / 1000))),
    });
  }

  /**
   * Atomically consume daily AI request units (tenant counter). Over the limit the units are
   * given back and the request is refused.
   */
  async consumeAi(tenantId: string, units: number): Promise<{ allowed: boolean; used: number; limit: number; resetsAt: string }> {
    const resetsAt = nextUtcMidnight(this.now());
    return this.db.withTenant(tenantId, async (tx) => {
      const { limits } = await this.limits(tx, tenantId);
      const day = utcDay(this.now());
      const { rows } = await tx.query<{ value: number }>(
        `INSERT INTO usage_counters (tenant_id, organization_id, metric, period_start, value) VALUES ($1, NULL, 'ai_requests', $2::date, $3)
         ON CONFLICT (tenant_id, org_key(organization_id), metric, period_start) DO UPDATE SET value = usage_counters.value + EXCLUDED.value
         RETURNING value`,
        [tenantId, day, units],
      );
      const used = Number(rows[0]!.value);
      if (used <= limits.aiRequestsPerDay) return { allowed: true, used, limit: limits.aiRequestsPerDay, resetsAt };
      await tx.query("UPDATE usage_counters SET value = greatest(0, value - $3) WHERE metric = 'ai_requests' AND organization_id IS NULL AND period_start = $2::date AND tenant_id = $1", [tenantId, day, units]);
      this.notifyExceeded(tenantId, "aiRequestsPerDay", used - units, limits.aiRequestsPerDay);
      return { allowed: false, used: used - units, limit: limits.aiRequestsPerDay, resetsAt };
    });
  }

  /** Increment a free-form usage meter (per organization, per UTC day). */
  async meter(tx: Queryable, tenantId: string, organizationId: string | null, metric: string, by: number): Promise<void> {
    if (!/^[a-z0-9_.]{2,64}$/.test(metric) || by <= 0) return;
    await tx.query(
      `INSERT INTO usage_counters (tenant_id, organization_id, metric, period_start, value) VALUES ($1, $2, $3, $4::date, $5)
       ON CONFLICT (tenant_id, org_key(organization_id), metric, period_start) DO UPDATE SET value = usage_counters.value + EXCLUDED.value`,
      [tenantId, organizationId, metric, utcDay(this.now()), Math.floor(by)],
    );
  }

  /** usage.quota_exceeded, at most once per meter and UTC day. Runs detached from the caller's transaction. */
  private notifyExceeded(tenantId: string, meter: QuotaMeter, used: number, limit: number): void {
    const day = utcDay(this.now());
    void this.db
      .withTenant(tenantId, async (tx) => {
        const { rows } = await tx.query(
          `INSERT INTO usage_counters (tenant_id, organization_id, metric, period_start, value) VALUES ($1, NULL, $2, $3::date, 1)
           ON CONFLICT (tenant_id, org_key(organization_id), metric, period_start) DO NOTHING RETURNING metric`,
          [tenantId, `quota_notice.${METER_KEY[meter]}`, day],
        );
        return rows.length > 0;
      })
      .then((first) => {
        if (!first) return;
        this.events.publish({
          tenantId,
          organizationId: null,
          event: "usage.quota_exceeded",
          occurredAt: new Date(this.now()).toISOString(),
          severity: "high",
          subject: { kind: "quota", id: meter, label: meter },
          dedupKey: `quota:${meter}:${day}`,
          data: { meter, used, limit, day },
        });
      })
      .catch(() => undefined);
  }
}
