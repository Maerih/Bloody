import type { Database } from "../db/pool.js";
import type { SqlReportDataSource } from "./report-data.js";

/**
 * Records each organization's endpoint posture once a day (UTC), so reports can show trends and
 * describe past periods as they were. Organizations without a SCIAT Agent are skipped.
 */
export class PostureSnapshotService {
  constructor(private readonly deps: { db: Database; dataSource: SqlReportDataSource; now: () => number }) {}

  async snapshotDue(tenantId: string): Promise<number> {
    const now = this.deps.now();
    const day = new Date(now).toISOString().slice(0, 10);
    const orgs = await this.deps.db.withTenant(tenantId, async (tx) =>
      (
        await tx.query<{ id: string }>(
          `SELECT o.id FROM organizations o
            WHERE o.status IN ('active', 'onboarding')
              AND EXISTS (SELECT 1 FROM agents a WHERE a.organization_id = o.id AND a.engine = 'sciat' AND a.agent_token_hash IS NOT NULL)
              AND NOT EXISTS (SELECT 1 FROM endpoint_posture_snapshots s WHERE s.organization_id = o.id AND s.day = $1::date)`,
          [day],
        )
      ).rows.map((r) => r.id),
    );
    let recorded = 0;
    for (const organizationId of orgs) {
      const [fact] = await this.deps.dataSource.livePosture({ tenantId, organizationIds: [organizationId], from: new Date(now - 86_400_000), to: new Date(now) });
      if (!fact) continue;
      const { organizationId: _o, asOf: _a, ...stored } = fact;
      const { rowCount } = await this.deps.db.withTenant(tenantId, (tx) =>
        tx.query("INSERT INTO endpoint_posture_snapshots (organization_id, day, tenant_id, fact) VALUES ($1, $2::date, $3, $4::jsonb) ON CONFLICT DO NOTHING", [organizationId, day, tenantId, JSON.stringify(stored)]),
      );
      recorded += rowCount ?? 0;
    }
    return recorded;
  }
}
