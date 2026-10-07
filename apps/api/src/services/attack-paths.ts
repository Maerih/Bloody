import { isCrownJewel, type AttackPathAnalysis, type AttackPathEngine } from "@bloody/engines";
import type { Database } from "../db/pool.js";
import { graphFor } from "./inventory.js";

/**
 * Attack-path analysis per organization: loads the org's attack surface from the Security
 * Graph and runs the proprietary attack-path engine. Results are cached briefly per
 * (tenant, organization) because dashboards ask often and the graph changes in batches.
 */
export class AttackPathService {
  private readonly cache = new Map<string, { at: number; value: AttackPathAnalysis }>();

  constructor(
    private readonly db: Database,
    private readonly engine: AttackPathEngine,
    private readonly ttlMs = 60_000,
    private readonly now: () => number = () => Date.now(),
  ) {}

  async analyze(tenantId: string, organizationId: string): Promise<AttackPathAnalysis> {
    const key = `${tenantId}|${organizationId}`;
    const hit = this.cache.get(key);
    if (hit && this.now() - hit.at < this.ttlMs) return hit.value;
    const surface = await this.db.withTenant(tenantId, (tx) => graphFor(tx, tenantId).loadAttackSurface(organizationId, { maxNodes: 5000 }));
    const value = this.engine.analyze(surface, { maxPaths: 200 }, { tenantId, organizationId });
    this.cache.set(key, { at: this.now(), value });
    if (this.cache.size > 5000) {
      const oldest = [...this.cache.entries()].sort((a, b) => a[1].at - b[1].at).slice(0, 1000);
      for (const [k] of oldest) this.cache.delete(k);
    }
    return value;
  }

  async counts(tenantId: string, organizationIds: string[]): Promise<{ total: number; toCrownJewels: number; byOrganization: Map<string, { total: number; toCrownJewels: number }> }> {
    let total = 0;
    let toCrownJewels = 0;
    const byOrganization = new Map<string, { total: number; toCrownJewels: number }>();
    for (const org of organizationIds) {
      const a = await this.analyze(tenantId, org);
      const crown = a.paths.filter((p) => isCrownJewel(p.target)).length;
      total += a.paths.length;
      toCrownJewels += crown;
      byOrganization.set(org, { total: a.paths.length, toCrownJewels: crown });
    }
    return { total, toCrownJewels, byOrganization };
  }

  invalidate(tenantId: string): void {
    for (const k of this.cache.keys()) if (k.startsWith(`${tenantId}|`)) this.cache.delete(k);
  }
}
