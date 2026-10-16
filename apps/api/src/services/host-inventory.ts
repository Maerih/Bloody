import { antivirusIssues, antivirusStatusOf, type AntivirusStatus, type HostInventory, type HostInventoryReport } from "@bloody/contracts";
import type { Queryable } from "../db/pool.js";
import type { Row } from "../repo/mappers.js";

const arr = <T>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);

/** Host inventory snapshots from SCIAT Agents (tenant transaction; RLS applies). */
export class HostInventoryService {
  constructor(private readonly now: () => number) {}

  /**
   * Store the agent's snapshot and derive the agent's antivirus and firewall state from it.
   * Returns the antivirus status before and after, so callers can notify on a change.
   */
  async record(tx: Queryable, agentId: string, report: HostInventoryReport): Promise<{ before: string; after: AntivirusStatus; hostname: string; organizationId: string; issues: string[] }> {
    const { rows } = await tx.query<Row>("SELECT tenant_id, organization_id, asset_id, hostname, antivirus_status FROM agents WHERE id = $1 FOR UPDATE", [agentId]);
    const agent = rows[0]!;
    const at = new Date(this.now()).toISOString();
    await tx.query(
      `INSERT INTO agent_inventory (agent_id, tenant_id, organization_id, asset_id, collected_at, software, services, users, processes, ports, antivirus, firewall, hardening, patches)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, $11::jsonb, $12::jsonb, $13::jsonb, $14::jsonb)
       ON CONFLICT (agent_id) DO UPDATE SET organization_id = EXCLUDED.organization_id, asset_id = EXCLUDED.asset_id, collected_at = EXCLUDED.collected_at,
         software = EXCLUDED.software, services = EXCLUDED.services, users = EXCLUDED.users, processes = EXCLUDED.processes,
         ports = EXCLUDED.ports, antivirus = EXCLUDED.antivirus, firewall = EXCLUDED.firewall, hardening = EXCLUDED.hardening,
         patches = coalesce(EXCLUDED.patches, agent_inventory.patches)`,
      [
        agentId,
        agent.tenant_id,
        agent.organization_id,
        agent.asset_id,
        at,
        JSON.stringify(report.software),
        JSON.stringify(report.services),
        JSON.stringify(report.users),
        JSON.stringify(report.processes),
        JSON.stringify(report.ports),
        JSON.stringify(report.antivirus),
        report.firewall ? JSON.stringify(report.firewall) : null,
        JSON.stringify(report.hardening),
        report.patches ? JSON.stringify(report.patches) : null,
      ],
    );
    const after = antivirusStatusOf(report.antivirus);
    await tx.query("UPDATE agents SET antivirus_status = $2, firewall_enabled = coalesce($3, firewall_enabled) WHERE id = $1", [agentId, after, report.firewall?.enabled ?? null]);
    return { before: String(agent.antivirus_status), after, hostname: String(agent.hostname), organizationId: String(agent.organization_id), issues: antivirusIssues(report.antivirus) };
  }

  /** The most recent snapshot of any agent on the asset. */
  async forAsset(tx: Queryable, assetId: string): Promise<HostInventory | null> {
    const { rows } = await tx.query<Row>(
      `SELECT i.*, a.hostname, a.platform FROM agent_inventory i JOIN agents a ON a.id = i.agent_id
        WHERE a.asset_id = $1 ORDER BY i.collected_at DESC LIMIT 1`,
      [assetId],
    );
    const r = rows[0];
    if (!r) return null;
    const antivirus = arr<HostInventory["antivirus"][number]>(r.antivirus);
    return {
      agentId: String(r.agent_id),
      hostname: String(r.hostname),
      platform: String(r.platform),
      collectedAt: new Date(String(r.collected_at)).toISOString(),
      software: arr(r.software),
      services: arr(r.services),
      users: arr(r.users),
      processes: arr(r.processes),
      ports: arr(r.ports),
      antivirus,
      firewall: (r.firewall as HostInventory["firewall"]) ?? null,
      hardening: (r.hardening as HostInventory["hardening"]) ?? {},
      antivirusStatus: antivirusStatusOf(antivirus),
      antivirusIssues: antivirusIssues(antivirus),
    };
  }

  /** Antivirus issues per agent (Managed Antivirus view). */
  async antivirusOverview(tx: Queryable, orgs: string[] | null): Promise<Array<{ agentId: string; products: string[]; issues: string[]; collectedAt: string }>> {
    const { rows } = await tx.query<Row>(
      `SELECT agent_id, antivirus, collected_at FROM agent_inventory ${orgs ? "WHERE organization_id = ANY($1::uuid[])" : ""}`,
      orgs ? [orgs] : [],
    );
    return rows.map((r) => {
      const av = arr<HostInventory["antivirus"][number]>(r.antivirus);
      return { agentId: String(r.agent_id), products: av.map((p) => p.name), issues: antivirusIssues(av), collectedAt: new Date(String(r.collected_at)).toISOString() };
    });
  }
}
