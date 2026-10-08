import type { FastifyInstance } from "fastify";
import { inOrder } from "../db/pool.js";
import type { MsspOverview } from "@bloody/contracts";
import { isCrownJewel } from "@bloody/engines";
import { requireAuth, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import type { Row } from "../repo/mappers.js";
import { attackPathCandidates, exposureInputsFor, loadPosture } from "../services/posture.js";

const ANALYST_ROLES = ["soc_analyst_t1", "soc_analyst_t2", "threat_hunter", "incident_responder"];
const n = (v: unknown): number => (v === null || v === undefined ? 0 : Number(v));

type MsspCustomer = MsspOverview["customers"][number];

export interface MsspCustomerView extends MsspCustomer {
  riskSeverity: string;
  riskSummary: string;
  investigations: number;
  overdueEscalations: number;
  assets: number;
}

/**
 * GET /mssp/overview — portfolio view across every customer organization in the caller's scope.
 * Customer risk is the Risk Engine's explainable exposure score of each organization.
 */
export async function msspRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/mssp/overview", async (request): Promise<MsspOverview & { customers: MsspCustomerView[]; generatedAt: string }> => {
    const auth = requireAuth(request);
    const orgs = resolveOrgFilter(request, "org:read", undefined);
    const data = await s.db.withTenant(auth.tenantId, async (tx) => {
      const account = await tx.query<{ plan: string }>("SELECT plan FROM accounts WHERE id = $1", [auth.tenantId]);
      const posture = await loadPosture(tx, orgs);
      const ids = [...posture.keys()];
      const [orgRows, incidents, investigations, escalations, analysts, events] = await inOrder([
        () => tx.query<Row>("SELECT id, name, plan, mrr FROM organizations WHERE id = ANY($1::uuid[]) ORDER BY lower(name)", [ids]),
        () => tx.query<Row>(
          `SELECT organization_id, count(*) AS active, count(*) FILTER (WHERE severity = 'critical') AS critical FROM incidents
           WHERE organization_id = ANY($1::uuid[]) AND status IN ('new', 'triage', 'investigating', 'contained') AND merged_into IS NULL GROUP BY organization_id`,
          [ids],
        ),
        () => tx.query<Row>("SELECT organization_id, count(*) AS n FROM investigations WHERE organization_id = ANY($1::uuid[]) AND status <> 'closed' GROUP BY organization_id", [ids]),
        () => tx.query<Row>(
          `SELECT organization_id,
                  count(*) FILTER (WHERE status <> 'resolved' AND due_at < now()) AS overdue,
                  count(*) FILTER (WHERE status = 'resolved' AND resolved_at > due_at AND resolved_at > now() - interval '30 days') AS late_resolved
           FROM escalations WHERE organization_id = ANY($1::uuid[]) GROUP BY organization_id`,
          [ids],
        ),
        () => // Analysts: users holding an analyst role tenant-wide or for an organization in scope.
        tx.query<{ n: number }>(
          `SELECT count(DISTINCT u.id)::int AS n FROM users u
           WHERE u.status = 'active' AND EXISTS (
             SELECT 1 FROM role_bindings rb
             WHERE rb.role = ANY($2::text[]) AND (rb.organization_id IS NULL OR rb.organization_id = ANY($1::uuid[]))
               AND ((rb.principal_kind = 'user' AND rb.principal_id = u.id)
                 OR (rb.principal_kind = 'team' AND rb.principal_id IN (SELECT team_id FROM team_members WHERE user_id = u.id))))`,
          [ids, ANALYST_ROLES],
        ),
        () => // Events per day: mean of the daily ingest meter over the last 7 days that have data.
        tx.query<{ avg: number | null }>(
          `SELECT avg(day_total) AS avg FROM (
             SELECT period_start, sum(value) AS day_total FROM usage_counters
             WHERE metric = 'events_ingested' AND organization_id = ANY($1::uuid[]) AND period_start > (now() AT TIME ZONE 'UTC')::date - 7
             GROUP BY period_start) d`,
          [ids],
        ),
      ]);
      return { plan: account.rows[0]?.plan ?? "trial", posture, orgRows: orgRows.rows, incidents: incidents.rows, investigations: investigations.rows, escalations: escalations.rows, analysts: analysts.rows[0]?.n ?? 0, eventsPerDay: events.rows[0]?.avg ?? 0 };
    });

    const byOrg = <T extends Row>(rows: T[]) => new Map(rows.map((r) => [String(r.organization_id), r]));
    const inc = byOrg(data.incidents);
    const inv = byOrg(data.investigations);
    const esc = byOrg(data.escalations);
    const candidates = new Set(attackPathCandidates(data.posture));
    const customers: MsspCustomerView[] = [];
    for (const o of data.orgRows) {
      const id = String(o.id);
      const p = data.posture.get(id)!;
      let paths: { total: number; toCrownJewels: number } | null = null;
      if (candidates.has(id)) {
        const a = await s.attackPaths.analyze(auth.tenantId, id);
        paths = { total: a.paths.length, toCrownJewels: a.paths.filter((x) => isCrownJewel(x.target)).length };
      }
      const exposure = s.risk.exposureScore(exposureInputsFor(p, paths, String(o.name)));
      customers.push({
        organizationId: id,
        name: String(o.name),
        plan: String(o.plan ?? data.plan),
        riskScore: exposure.score,
        riskSeverity: exposure.severity,
        riskSummary: exposure.summary,
        activeIncidents: n(inc.get(id)?.active),
        critical: n(inc.get(id)?.critical),
        investigations: n(inv.get(id)?.n),
        agents: p.agents.total,
        unhealthyAgents: p.agents.unresponsive + p.agents.outdated,
        overdueEscalations: n(esc.get(id)?.overdue),
        slaBreaches: n(esc.get(id)?.overdue) + n(esc.get(id)?.late_resolved),
        assets: p.assets.total,
        mrr: n(o.mrr),
      });
    }
    customers.sort((a, b) => b.critical - a.critical || b.riskScore - a.riskScore || a.name.localeCompare(b.name));
    return {
      generatedAt: new Date(s.now()).toISOString(),
      organizations: customers.length,
      assets: customers.reduce((x, c) => x + c.assets, 0),
      activeIncidents: customers.reduce((x, c) => x + c.activeIncidents, 0),
      critical: customers.reduce((x, c) => x + c.critical, 0),
      investigations: customers.reduce((x, c) => x + c.investigations, 0),
      analysts: data.analysts,
      agents: customers.reduce((x, c) => x + c.agents, 0),
      eventsPerDay: Math.round(Number(data.eventsPerDay ?? 0)),
      customers,
    };
  });
}
