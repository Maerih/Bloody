import { AppControlRuleInput, RMM_TOOLS, detectRmmTools, rmmToolByKey, type RmmFinding } from "@bloody/contracts";
import type { Queryable } from "../db/pool.js";
import { HttpError } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";
import type { AppControlService } from "./app-control.js";

const arr = <T>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);
type Inventory = { software: Array<{ name: string; version?: string | null }>; processes: Array<{ name: string; path?: string | null }> };

/** RMM Guard: approved remote-access tools per organization, findings from host inventory, blocking. */
export class RmmGuardService {
  constructor(private readonly appControl: AppControlService) {}

  async approved(tx: Queryable, organizationId: string): Promise<string[]> {
    const { rows } = await tx.query<Row>("SELECT approved FROM rmm_guard_settings WHERE organization_id = $1", [organizationId]);
    return arr<string>(rows[0]?.approved);
  }

  async setApproved(tx: Queryable, tenantId: string, organizationId: string, keys: string[], actor: string): Promise<string[]> {
    const valid = [...new Set(keys)].filter((k) => rmmToolByKey(k));
    await tx.query(
      `INSERT INTO rmm_guard_settings (organization_id, tenant_id, approved, updated_by, updated_at) VALUES ($1, $2, $3, $4, now())
       ON CONFLICT (organization_id) DO UPDATE SET approved = EXCLUDED.approved, updated_by = EXCLUDED.updated_by, updated_at = now()`,
      [organizationId, tenantId, valid, actor],
    );
    return valid;
  }

  /** Every tool seen on the organization's endpoints (from the latest host inventory of each agent). */
  async findings(tx: Queryable, organizationId: string): Promise<RmmFinding[]> {
    const approved = new Set(await this.approved(tx, organizationId));
    const { rows } = await tx.query<Row>(
      "SELECT i.agent_id, a.hostname, i.collected_at, i.software, i.processes FROM agent_inventory i JOIN agents a ON a.id = i.agent_id WHERE i.organization_id = $1",
      [organizationId],
    );
    const byTool = new Map<string, RmmFinding>();
    for (const r of rows) {
      for (const [key, evidence] of detectRmmTools({ software: arr(r.software), processes: arr(r.processes) })) {
        const tool = rmmToolByKey(key)!;
        const f = byTool.get(key) ?? { tool: { key, name: tool.name, vendor: tool.vendor }, approved: approved.has(key), endpoints: [] };
        f.endpoints.push({ agentId: String(r.agent_id), hostname: String(r.hostname), evidence, seenAt: new Date(String(r.collected_at)).toISOString() });
        byTool.set(key, f);
      }
    }
    return [...byTool.values()].sort((a, b) => Number(a.approved) - Number(b.approved) || b.endpoints.length - a.endpoints.length);
  }

  /** Unapproved tools that appear on a host now but did not in its previous inventory. */
  async newlyUnapproved(tx: Queryable, organizationId: string, before: Inventory | null, after: Inventory): Promise<Array<{ key: string; name: string; evidence: string[] }>> {
    const approved = new Set(await this.approved(tx, organizationId));
    const old = before ? detectRmmTools(before) : new Map();
    const out: Array<{ key: string; name: string; evidence: string[] }> = [];
    for (const [key, evidence] of detectRmmTools(after)) {
      if (approved.has(key) || old.has(key)) continue;
      out.push({ key, name: rmmToolByKey(key)!.name, evidence: evidence.map((e) => `${e.kind}: ${e.value}`) });
    }
    return out;
  }

  /** Block tools through App Control: one block rule per executable pattern (duplicates skipped). */
  async block(tx: Queryable, tenantId: string, organizationId: string, keys: string[], actor: string): Promise<{ created: number; skipped: number }> {
    const approved = new Set(await this.approved(tx, organizationId));
    let created = 0;
    let skipped = 0;
    for (const key of keys) {
      const tool = rmmToolByKey(key);
      if (!tool) throw new HttpError(400, "unknown_tool", `Unknown tool ${key}`);
      if (approved.has(key)) throw new HttpError(409, "tool_approved", `${tool.name} is approved for this organization — remove the approval first`);
      for (const pattern of tool.processes) {
        const input = AppControlRuleInput.safeParse({ organizationId, action: "block", kind: "name", value: pattern, platform: pattern.endsWith(".exe") ? "windows" : "any", note: `RMM Guard: ${tool.name}` });
        if (!input.success) {
          skipped++;
          continue;
        }
        try {
          await tx.query("SAVEPOINT rmm_rule");
          await this.appControl.addRule(tx, tenantId, input.data, actor);
          await tx.query("RELEASE SAVEPOINT rmm_rule");
          created++;
        } catch (err) {
          await tx.query("ROLLBACK TO SAVEPOINT rmm_rule");
          if (err instanceof HttpError && err.code === "duplicate_rule") skipped++;
          else throw err;
        }
      }
    }
    return { created, skipped };
  }

  catalog() {
    return RMM_TOOLS.map(({ key, name, vendor }) => ({ key, name, vendor }));
  }
}
