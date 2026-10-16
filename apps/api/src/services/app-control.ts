import { createHash } from "node:crypto";
import { decideProgram, type AppControlEvent, type AppControlMode, type AppControlPolicy, type AppControlRule, type AppControlRuleInput, type AppInventoryItem } from "@bloody/contracts";
import type { Queryable } from "../db/pool.js";
import { HttpError } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";

const iso = (v: unknown) => (v ? new Date(String(v)).toISOString() : null);

export function toRule(r: Row): AppControlRule {
  return {
    id: String(r.id),
    organizationId: (r.organization_id as string | null) ?? null,
    action: r.action as AppControlRule["action"],
    kind: r.kind as AppControlRule["kind"],
    value: String(r.value),
    platform: r.platform as AppControlRule["platform"],
    note: (r.note as string | null) ?? null,
    createdBy: (r.created_by as string | null) ?? null,
    createdAt: iso(r.created_at)!,
  };
}

/** Windows paths carry a drive letter or backslashes; everything else is treated as Unix. */
const platformOfPath = (path: string): "windows" | "linux" => (/^[a-z]:\\|\\/i.test(path) ? "windows" : "linux");

export interface ReportedProgram {
  name: string;
  path: string;
  sha256?: string | undefined;
  publisher?: string | undefined;
}

export interface ReportedRun {
  name: string;
  path?: string | undefined;
  sha256?: string | undefined;
  publisher?: string | undefined;
  ruleId?: string | undefined;
  verdict: "blocked" | "audited";
  occurredAt: string;
}

/**
 * App Control (ESPM): policy per organization, rules (organization or whole account), programs
 * reported by SCIAT Agents and the runs they blocked or audited. All calls run inside the
 * caller's tenant transaction (RLS).
 */
export class AppControlService {
  constructor(private readonly now: () => number) {}

  async mode(tx: Queryable, organizationId: string): Promise<{ mode: AppControlMode; updatedAt: string | null; updatedBy: string | null }> {
    const { rows } = await tx.query<Row>("SELECT mode, updated_at, updated_by FROM app_control_settings WHERE organization_id = $1", [organizationId]);
    return { mode: (rows[0]?.mode as AppControlMode | undefined) ?? "off", updatedAt: iso(rows[0]?.updated_at), updatedBy: (rows[0]?.updated_by as string | null) ?? null };
  }

  async setMode(tx: Queryable, tenantId: string, organizationId: string, mode: AppControlMode, actor: string): Promise<void> {
    await tx.query(
      `INSERT INTO app_control_settings (organization_id, tenant_id, mode, updated_by, updated_at) VALUES ($1, $2, $3, $4, now())
       ON CONFLICT (organization_id) DO UPDATE SET mode = EXCLUDED.mode, updated_by = EXCLUDED.updated_by, updated_at = now()`,
      [organizationId, tenantId, mode, actor],
    );
  }

  /** Rules of the organization plus the account-wide ones. */
  async rules(tx: Queryable, organizationId: string): Promise<AppControlRule[]> {
    const { rows } = await tx.query<Row>("SELECT * FROM app_control_rules WHERE organization_id = $1 OR organization_id IS NULL ORDER BY action, created_at", [organizationId]);
    return rows.map(toRule);
  }

  async addRule(tx: Queryable, tenantId: string, input: AppControlRuleInput & { platform: AppControlRule["platform"] }, actor: string): Promise<AppControlRule> {
    const value = input.kind === "sha256" ? input.value.toLowerCase() : input.value;
    const { rows } = await tx.query<Row>(
      `INSERT INTO app_control_rules (tenant_id, organization_id, action, kind, value, platform, note, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING RETURNING *`,
      [tenantId, input.organizationId, input.action, input.kind, value, input.platform, input.note ?? null, actor],
    );
    if (!rows[0]) throw new HttpError(409, "duplicate_rule", "The same rule already exists");
    return toRule(rows[0]);
  }

  async getRule(tx: Queryable, id: string): Promise<AppControlRule | null> {
    const { rows } = await tx.query<Row>("SELECT * FROM app_control_rules WHERE id = $1", [id]);
    return rows[0] ? toRule(rows[0]) : null;
  }

  async deleteRule(tx: Queryable, id: string): Promise<void> {
    await tx.query("DELETE FROM app_control_rules WHERE id = $1", [id]);
  }

  /** The effective policy an agent of this organization applies; the etag changes with it. */
  async policy(tx: Queryable, organizationId: string): Promise<AppControlPolicy> {
    const { mode } = await this.mode(tx, organizationId);
    const rules = mode === "off" ? [] : (await this.rules(tx, organizationId)).map(({ id, action, kind, value, platform }) => ({ id, action, kind, value, platform }));
    const etag = createHash("sha256").update(JSON.stringify({ mode, rules })).digest("hex").slice(0, 16);
    return { etag, mode, rules };
  }

  /** Programs running on an endpoint (replaces nothing: first / last seen per path). */
  async recordInventory(tx: Queryable, tenantId: string, organizationId: string, agentId: string, apps: ReportedProgram[]): Promise<number> {
    if (apps.length === 0) return 0;
    const seen = new Date(this.now()).toISOString();
    await tx.query(
      `INSERT INTO app_inventory (tenant_id, organization_id, agent_id, name, path, sha256, publisher, first_seen_at, last_seen_at)
       SELECT $1, $2, $3, a.name, a.path, a.sha256, a.publisher, $4, $4
         FROM jsonb_to_recordset($5::jsonb) AS a(name text, path text, sha256 text, publisher text)
       ON CONFLICT (agent_id, path) DO UPDATE SET name = EXCLUDED.name, sha256 = coalesce(EXCLUDED.sha256, app_inventory.sha256),
         publisher = coalesce(EXCLUDED.publisher, app_inventory.publisher), organization_id = EXCLUDED.organization_id, last_seen_at = EXCLUDED.last_seen_at`,
      [tenantId, organizationId, agentId, seen, JSON.stringify(apps.map((a) => ({ name: a.name, path: a.path, sha256: a.sha256?.toLowerCase() ?? null, publisher: a.publisher ?? null })))],
    );
    return apps.length;
  }

  /** Programs across the organization, with what the current policy would do to each. */
  async inventory(tx: Queryable, organizationId: string, q: string | undefined, limit: number): Promise<AppInventoryItem[]> {
    const params: unknown[] = [organizationId, limit];
    let filter = "";
    if (q) {
      params.push(`%${q.toLowerCase().replace(/[\\%_]/g, (c) => `\\${c}`)}%`);
      filter = "AND (lower(name) LIKE $3 OR lower(path) LIKE $3 OR lower(coalesce(publisher, '')) LIKE $3 OR sha256 LIKE $3)";
    }
    const { rows } = await tx.query<Row>(
      `SELECT name, path, max(sha256) AS sha256, max(publisher) AS publisher, count(DISTINCT agent_id)::int AS endpoints, max(last_seen_at) AS last_seen_at
         FROM app_inventory WHERE organization_id = $1 ${filter}
        GROUP BY name, path ORDER BY count(DISTINCT agent_id) DESC, lower(name) LIMIT $2`,
      params,
    );
    const { mode } = await this.mode(tx, organizationId);
    // Show the verdict as if enforcing, so admins see what a rule does before switching modes.
    const policy = { mode: mode === "audit" ? ("audit" as const) : ("enforce" as const), rules: await this.rules(tx, organizationId) };
    return rows.map((r) => {
      const item = { name: String(r.name), path: String(r.path), sha256: (r.sha256 as string | null) ?? null, publisher: (r.publisher as string | null) ?? null };
      return { ...item, endpoints: Number(r.endpoints), lastSeenAt: iso(r.last_seen_at)!, verdict: decideProgram(policy, platformOfPath(item.path), item).verdict };
    });
  }

  async recordEvents(tx: Queryable, tenantId: string, organizationId: string, agentId: string, hostname: string, runs: ReportedRun[]): Promise<number> {
    if (runs.length === 0) return 0;
    const { rowCount } = await tx.query(
      `INSERT INTO app_control_events (tenant_id, organization_id, agent_id, hostname, name, path, sha256, publisher, rule_id, verdict, occurred_at)
       SELECT $1, $2, $3, $4, e.name, e.path, e.sha256, e.publisher, r.id, e.verdict, e.occurred_at
         FROM jsonb_to_recordset($5::jsonb) AS e(name text, path text, sha256 text, publisher text, rule_id uuid, verdict text, occurred_at timestamptz)
         LEFT JOIN app_control_rules r ON r.id = e.rule_id`,
      [tenantId, organizationId, agentId, hostname, JSON.stringify(runs.map((e) => ({ name: e.name, path: e.path ?? null, sha256: e.sha256?.toLowerCase() ?? null, publisher: e.publisher ?? null, rule_id: e.ruleId ?? null, verdict: e.verdict, occurred_at: e.occurredAt })))],
    );
    return rowCount ?? 0;
  }

  async events(tx: Queryable, organizationId: string, limit: number): Promise<AppControlEvent[]> {
    const { rows } = await tx.query<Row>("SELECT * FROM app_control_events WHERE organization_id = $1 ORDER BY occurred_at DESC LIMIT $2", [organizationId, limit]);
    return rows.map((r) => ({
      id: String(r.id),
      organizationId: String(r.organization_id),
      agentId: String(r.agent_id),
      hostname: String(r.hostname),
      name: String(r.name),
      path: (r.path as string | null) ?? null,
      sha256: (r.sha256 as string | null) ?? null,
      publisher: (r.publisher as string | null) ?? null,
      ruleId: (r.rule_id as string | null) ?? null,
      verdict: r.verdict as "blocked" | "audited",
      occurredAt: iso(r.occurred_at)!,
    }));
  }

  async stats(tx: Queryable, organizationId: string): Promise<{ agents: number; blocked24h: number; audited24h: number; programs: number }> {
    const since = new Date(this.now() - 86_400_000).toISOString();
    const { rows } = await tx.query<Row>(
      `SELECT (SELECT count(*)::int FROM agents WHERE organization_id = $1 AND engine = 'sciat' AND agent_token_hash IS NOT NULL) AS agents,
              (SELECT count(*)::int FROM app_control_events WHERE organization_id = $1 AND verdict = 'blocked' AND occurred_at >= $2) AS blocked,
              (SELECT count(*)::int FROM app_control_events WHERE organization_id = $1 AND verdict = 'audited' AND occurred_at >= $2) AS audited,
              (SELECT count(DISTINCT path)::int FROM app_inventory WHERE organization_id = $1) AS programs`,
      [organizationId, since],
    );
    const r = rows[0] ?? {};
    return { agents: Number(r.agents ?? 0), blocked24h: Number(r.blocked ?? 0), audited24h: Number(r.audited ?? 0), programs: Number(r.programs ?? 0) };
  }
}
