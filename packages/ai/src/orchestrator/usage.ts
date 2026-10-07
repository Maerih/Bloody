import { PLANS, type AiProviderKind, type PlanKey } from "@bloody/contracts";
import type { DataEgress } from "../safety/egress.js";
import { systemClock, type Clock } from "../util/ids.js";

/**
 * AI usage metering (billing + per-tenant reporting) and plan quota enforcement
 * (`PLANS[plan].limits.aiRequestsPerDay`). Every model call is metered, including fallbacks.
 */

export type AiUsagePurpose = "chat" | "report_narrative" | "notification_draft" | "health_check";

export interface AiUsageRecord {
  id: string;
  at: string;
  tenantId: string;
  organizationId: string | null;
  principalId: string | null;
  conversationId: string | null;
  providerId: string | null;
  providerKind: AiProviderKind;
  model: string;
  egress: DataEgress;
  purpose: AiUsagePurpose;
  inputTokens: number;
  outputTokens: number;
  estimated: boolean;
  latencyMs: number;
  fallbackUsed: boolean;
}

export interface AiUsageMeter {
  record(record: AiUsageRecord): Promise<void>;
}

export class InMemoryUsageMeter implements AiUsageMeter {
  readonly records: AiUsageRecord[] = [];
  async record(record: AiUsageRecord): Promise<void> {
    this.records.push({ ...record });
  }
  forTenant(tenantId: string): AiUsageRecord[] {
    return this.records.filter((r) => r.tenantId === tenantId);
  }
}

export interface QuotaDecision {
  allowed: boolean;
  limit: number | null;
  used: number;
  remaining: number | null;
  resetsAt: string | null;
}

export interface AiQuotaGuard {
  consume(input: { tenantId: string; organizationId: string | null; units: number }): Promise<QuotaDecision>;
}

/** Atomic counter store (Valkey INCRBY + EXPIRE in production). */
export interface QuotaCounterStore {
  increment(key: string, by: number, ttlSeconds: number): Promise<number>;
}

export class InMemoryQuotaCounterStore implements QuotaCounterStore {
  private readonly counters = new Map<string, { value: number; expiresAt: number }>();
  constructor(private readonly clock: Clock = systemClock) {}
  async increment(key: string, by: number, ttlSeconds: number): Promise<number> {
    const now = this.clock.now().getTime();
    const cur = this.counters.get(key);
    const entry = cur && cur.expiresAt > now ? cur : { value: 0, expiresAt: now + ttlSeconds * 1000 };
    entry.value += by;
    this.counters.set(key, entry);
    return entry.value;
  }
}

/** Daily AI request quota per tenant derived from its subscription plan. */
export class PlanQuotaGuard implements AiQuotaGuard {
  private readonly clock: Clock;
  constructor(
    private readonly deps: { planFor: (tenantId: string) => Promise<PlanKey>; counters: QuotaCounterStore; clock?: Clock; overrideLimit?: (tenantId: string) => Promise<number | null> },
  ) {
    this.clock = deps.clock ?? systemClock;
  }

  async consume(input: { tenantId: string; organizationId: string | null; units: number }): Promise<QuotaDecision> {
    const now = this.clock.now();
    const day = now.toISOString().slice(0, 10);
    const reset = new Date(`${day}T00:00:00.000Z`);
    reset.setUTCDate(reset.getUTCDate() + 1);
    const limit = (await this.deps.overrideLimit?.(input.tenantId)) ?? PLANS[await this.deps.planFor(input.tenantId)].limits.aiRequestsPerDay;
    const key = `ai:requests:t/${input.tenantId}:${day}`;
    const ttl = Math.ceil((reset.getTime() - now.getTime()) / 1000) + 60;
    const used = await this.deps.counters.increment(key, input.units, ttl);
    if (used > limit) {
      const after = await this.deps.counters.increment(key, -input.units, ttl);
      return { allowed: false, limit, used: after, remaining: Math.max(0, limit - after), resetsAt: reset.toISOString() };
    }
    return { allowed: true, limit, used, remaining: limit - used, resetsAt: reset.toISOString() };
  }
}
