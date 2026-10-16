import {
  HARDENING_CHECKS,
  evaluateHardening,
  hardeningCheck,
  hardeningScore,
  type AttackReductionCheckSummary,
  type AttackReductionEndpoint,
  type HardeningContext,
} from "@bloody/contracts";
import type { Queryable } from "../db/pool.js";
import type { Row } from "../repo/mappers.js";

const arr = <T>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);
const iso = (v: unknown) => new Date(String(v)).toISOString();

export interface InventorySnapshot {
  hardening: Record<string, unknown>;
  users: Array<{ name: string; admin: boolean; enabled: boolean }>;
  firewall: { enabled: boolean } | null;
}

export function contextOf(s: InventorySnapshot): HardeningContext {
  return { facts: s.hardening ?? {}, users: s.users ?? [], firewall: s.firewall ?? null };
}

/** Attack Reduction: hardening of each endpoint, graded from the facts its SCIAT Agent reports. */
export class AttackReductionService {
  async exceptions(tx: Queryable, organizationId: string): Promise<Map<string, { reason: string; createdBy: string | null; createdAt: string }>> {
    const { rows } = await tx.query<Row>("SELECT check_key, reason, created_by, created_at FROM attack_reduction_exceptions WHERE organization_id = $1", [organizationId]);
    return new Map(rows.map((r) => [String(r.check_key), { reason: String(r.reason), createdBy: (r.created_by as string | null) ?? null, createdAt: iso(r.created_at) }]));
  }

  async setException(tx: Queryable, tenantId: string, organizationId: string, key: string, reason: string, actor: string): Promise<void> {
    await tx.query(
      `INSERT INTO attack_reduction_exceptions (organization_id, tenant_id, check_key, reason, created_by) VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (organization_id, check_key) DO UPDATE SET reason = EXCLUDED.reason, created_by = EXCLUDED.created_by, created_at = now()`,
      [organizationId, tenantId, key, reason, actor],
    );
  }

  async removeException(tx: Queryable, organizationId: string, key: string): Promise<boolean> {
    return ((await tx.query("DELETE FROM attack_reduction_exceptions WHERE organization_id = $1 AND check_key = $2", [organizationId, key])).rowCount ?? 0) > 0;
  }

  async endpoints(tx: Queryable, organizationId: string, accepted: ReadonlySet<string>): Promise<AttackReductionEndpoint[]> {
    const { rows } = await tx.query<Row>(
      `SELECT a.id, a.asset_id, a.hostname, a.platform, i.collected_at, i.hardening, i.users, i.firewall
         FROM agent_inventory i JOIN agents a ON a.id = i.agent_id
        WHERE i.organization_id = $1 ORDER BY a.hostname`,
      [organizationId],
    );
    return rows.map((r) => {
      const results = evaluateHardening(String(r.platform), contextOf({ hardening: (r.hardening as Record<string, unknown>) ?? {}, users: arr(r.users), firewall: (r.firewall as { enabled: boolean } | null) ?? null }));
      return { agentId: String(r.id), assetId: r.asset_id ? String(r.asset_id) : null, hostname: String(r.hostname), platform: String(r.platform), collectedAt: iso(r.collected_at), score: hardeningScore(results, accepted), results };
    });
  }

  async overview(tx: Queryable, organizationId: string) {
    const exceptions = await this.exceptions(tx, organizationId);
    const accepted = new Set(exceptions.keys());
    const endpoints = await this.endpoints(tx, organizationId, accepted);
    const summary = new Map<string, AttackReductionCheckSummary>();
    for (const e of endpoints) {
      for (const r of e.results) {
        const s = summary.get(r.key) ?? { key: r.key, failing: 0, passing: 0, unknown: 0, exception: exceptions.get(r.key) ?? null };
        if (r.status === "fail") s.failing++;
        else if (r.status === "pass") s.passing++;
        else if (r.status === "unknown") s.unknown++;
        summary.set(r.key, s);
      }
    }
    const scored = endpoints.filter((e) => e.score !== null);
    return {
      score: scored.length ? Math.round(scored.reduce((n, e) => n + e.score!, 0) / scored.length) : null,
      checks: HARDENING_CHECKS.filter((c) => summary.has(c.key)).map((c) => summary.get(c.key)!),
      endpoints,
    };
  }

  /** Checks that passed in the previous report and fail now (accepted gaps excluded). */
  async regressions(tx: Queryable, organizationId: string, platform: string, before: InventorySnapshot | null, after: InventorySnapshot): Promise<Array<{ key: string; title: string; detail: string | null }>> {
    if (!before) return [];
    const accepted = await this.exceptions(tx, organizationId);
    const was = new Map(evaluateHardening(platform, contextOf(before)).map((r) => [r.key, r.status]));
    return evaluateHardening(platform, contextOf(after))
      .filter((r) => r.status === "fail" && was.get(r.key) === "pass" && !accepted.has(r.key))
      .map((r) => ({ key: r.key, title: hardeningCheck(r.key)!.title, detail: r.detail }));
  }
}
