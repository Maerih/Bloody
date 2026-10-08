import type { ApprovalRequest, ApprovalStore } from "@bloody/automation";
import type { Database } from "../db/pool.js";

/**
 * Postgres store for the automation ApprovalGate (`approval_requests`). The full request is kept
 * as JSON; status / version / expiry are mirrored into columns for the queue, the sweeper and the
 * optimistic-concurrency check (two approvers can never both flip the same version).
 */
export class PgApprovalStore implements ApprovalStore {
  constructor(
    private readonly db: Database,
    /** Tenants with work (directory) — for the cross-tenant expiry sweep. */
    private readonly tenants: () => Promise<string[]>,
  ) {}

  async insert(r: ApprovalRequest): Promise<void> {
    await this.db.withTenant(r.tenantId, (tx) =>
      tx.query(
        `INSERT INTO approval_requests (id, tenant_id, organization_id, kind, action, risk, status, requested_by, record, version, expires_at, decided_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12)`,
        [r.id, r.tenantId, r.organizationId, r.kind, r.action, r.risk, r.status, `${r.requestedBy.kind}:${r.requestedBy.id}`, JSON.stringify(r), r.version, r.expiresAt, r.decidedAt],
      ),
    );
  }

  async get(tenantId: string, id: string): Promise<ApprovalRequest | null> {
    if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
    return this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<{ record: ApprovalRequest }>("SELECT record FROM approval_requests WHERE id = $1", [id]);
      return rows[0]?.record ?? null;
    });
  }

  async compareAndSet(next: ApprovalRequest, expectedVersion: number): Promise<boolean> {
    return this.db.withTenant(next.tenantId, async (tx) => {
      const res = await tx.query(
        "UPDATE approval_requests SET record = $2::jsonb, status = $3, version = $4, decided_at = $5, expires_at = $6 WHERE id = $1 AND version = $7",
        [next.id, JSON.stringify(next), next.status, next.version, next.decidedAt, next.expiresAt, expectedVersion],
      );
      return (res.rowCount ?? 0) === 1;
    });
  }

  async listPending(tenantId: string, filter: { organizationId?: string; organizationIds?: readonly string[] } = {}): Promise<ApprovalRequest[]> {
    return this.db.withTenant(tenantId, async (tx) => {
      const params: unknown[] = [];
      const where = ["status = 'pending'"];
      if (filter.organizationId) where.push(`organization_id = $${params.push(filter.organizationId)}`);
      if (filter.organizationIds) where.push(`organization_id = ANY($${params.push([...filter.organizationIds])}::uuid[])`);
      const { rows } = await tx.query<{ record: ApprovalRequest }>(`SELECT record FROM approval_requests WHERE ${where.join(" AND ")} ORDER BY created_at LIMIT 1000`, params);
      return rows.map((r) => r.record);
    });
  }

  async listExpired(now: Date, tenantId?: string): Promise<ApprovalRequest[]> {
    const tenants = tenantId ? [tenantId] : await this.tenants();
    const out: ApprovalRequest[] = [];
    for (const t of tenants) {
      const rows = await this.db.withTenant(t, async (tx) => (await tx.query<{ record: ApprovalRequest }>("SELECT record FROM approval_requests WHERE status = 'pending' AND expires_at <= $1 LIMIT 500", [now.toISOString()])).rows);
      out.push(...rows.map((r) => r.record));
    }
    return out;
  }
}

/** Tenant ids from the RLS-free account directory (platform jobs only). */
export async function activeTenants(db: Database): Promise<Array<{ id: string; plan: string; trialEndsAt: string | null }>> {
  const { rows } = await db.app.query<{ account_id: string; plan: string; trial_ends_at: string | null }>("SELECT account_id, plan, trial_ends_at FROM account_directory WHERE status = 'active' ORDER BY account_id");
  return rows.map((r) => ({ id: r.account_id, plan: r.plan, trialEndsAt: r.trial_ends_at }));
}
