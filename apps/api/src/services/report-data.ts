import { AUTORUN_KIND_LABELS, HARDENING_CHECKS, PlanKey, humanRisk, type AttackTechnique, type Criticality, type IncidentStatus, type RiskFactor, type Severity } from "@bloody/contracts";
import { isCrownJewel, type RiskEngine } from "@bloody/engines";
import type {
  AlertStats,
  AwarenessFact,
  AnalystActivityFact,
  EndpointPostureFact,
  EndpointPostureTrendPoint,
  AttackPathStats,
  BillingFact,
  ComplianceControlFact,
  DailyCount,
  EscalationFact,
  EventStats,
  EndpointDetail,
  IncidentDetail,
  IncidentFact,
  IntelStats,
  NamedCount,
  OrganizationFact,
  OrganizationPostureFact,
  PostureStats,
  PostureTrendPoint,
  ReportDataSource,
  ReportQuery,
  ResponseStats,
  RiskyAssetFact,
  UsageFact,
  VulnerabilityFact,
  VulnerabilityStats,
} from "@bloody/reporting";
import { inOrder, type Database, type Queryable } from "../db/pool.js";
import type { Row } from "../repo/mappers.js";
import { AppControlService } from "./app-control.js";
import { AttackReductionService } from "./attack-reduction.js";
import { EndpointDossierService } from "./endpoint-dossier.js";
import { HostInventoryService } from "./host-inventory.js";
import type { AttackPathService } from "./attack-paths.js";
import { FootholdsService } from "./footholds.js";
import { PatchingService } from "./patching.js";
import { RmmGuardService } from "./rmm-guard.js";
import { exposureInputsFor, loadPosture, sumPosture, type OrgPosture } from "./posture.js";

/**
 * `@bloody/reporting` data port on Postgres. Every query runs in the tenant's RLS transaction AND
 * filters on the requested organization scope (`ReportQuery.organizationIds`), so a report can
 * never include another tenant's or an unauthorised organization's rows (the reporting package
 * additionally verifies every organization-scoped row it receives).
 *
 * Flow metrics count `[from, to)`; state metrics are evaluated as of `to`. Where the platform has
 * no historical snapshot (posture trend, previous MRR) the source returns only what it can prove
 * instead of inventing a series.
 */

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
const n = (v: unknown): number => (v === null || v === undefined ? 0 : Number(v));
const nn = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));
const iso = (v: unknown): string | null => (v === null || v === undefined ? null : String(v));
const sevRecord = (): Record<Severity, number> => ({ info: 0, low: 0, medium: 0, high: 0, critical: 0 });
const factorsOf = (risk: unknown): RiskFactor[] => (risk && typeof risk === "object" && Array.isArray((risk as { factors?: unknown }).factors) ? ((risk as { factors: RiskFactor[] }).factors ?? []) : []);

/**
 * Named-parameter binding (`:name`, casts like `:from::timestamptz` work). Only the names a
 * statement uses are sent, so no positional parameter is ever left untyped.
 */
export function bindNamed(text: string, values: Record<string, unknown>): { text: string; params: unknown[] } {
  const params: unknown[] = [];
  const index = new Map<string, number>();
  const out = text.replace(/(?<![:\w]):([a-zA-Z_][a-zA-Z0-9_]*)/g, (_m, name: string) => {
    if (!(name in values)) throw new Error(`unbound SQL parameter :${name}`);
    let i = index.get(name);
    if (i === undefined) {
      params.push(values[name]);
      i = params.length;
      index.set(name, i);
    }
    return `$${i}`;
  });
  return { text: out, params };
}

/** Organization scope predicate on `column` (uses :all_orgs / :orgs). */
const org = (column: string): string => `(:all_orgs::boolean OR ${column} = ANY(:orgs::uuid[]))`;

function baseParams(q: ReportQuery): Record<string, unknown> {
  return {
    all_orgs: q.organizationIds === "all",
    orgs: q.organizationIds === "all" ? [] : [...q.organizationIds],
    from: q.from.toISOString(),
    to: q.to.toISOString(),
  };
}

export class SqlReportDataSource implements ReportDataSource {
  constructor(
    private readonly db: Database,
    private readonly risk: RiskEngine,
    private readonly attackPathsService: AttackPathService,
  ) {}

  private tx<T>(q: ReportQuery, fn: (tx: Queryable) => Promise<T>): Promise<T> {
    return this.db.withTenant(q.tenantId, fn);
  }

  private async sql(tx: Queryable, q: ReportQuery, text: string, extra: Record<string, unknown> = {}): Promise<Row[]> {
    const b = bindNamed(text, { ...baseParams(q), ...extra });
    return (await tx.query<Row>(b.text, b.params)).rows;
  }

  private async orgIds(tx: Queryable, q: ReportQuery): Promise<string[]> {
    if (q.organizationIds !== "all") return [...q.organizationIds];
    return (await tx.query<{ id: string }>("SELECT id FROM organizations ORDER BY name")).rows.map((r) => r.id);
  }

  async organizations(q: ReportQuery): Promise<OrganizationFact[]> {
    return this.tx(q, async (tx) => {
      const rows = await this.sql(tx, q, `SELECT id, name, plan, created_at, settings->'slaTargets' AS sla FROM organizations o WHERE ${org("o.id")} ORDER BY name`);
      return rows.map((r) => {
        const plan = PlanKey.safeParse(r.plan);
        const sla = r.sla && typeof r.sla === "object" && !Array.isArray(r.sla) ? (r.sla as OrganizationFact["slaTargets"]) : null;
        return { id: String(r.id), name: String(r.name), plan: plan.success ? plan.data : null, createdAt: String(r.created_at), slaTargets: sla };
      });
    });
  }

  private incidentFact(r: Row): IncidentFact {
    return {
      id: String(r.id),
      organizationId: String(r.organization_id),
      number: n(r.number),
      title: String(r.title),
      severity: r.severity as Severity,
      status: r.status as IncidentStatus,
      riskScore: n(r.risk_score),
      detectedAt: String(r.detected_at),
      firstActivityAt: iso(r.first_seen_at),
      acknowledgedAt: iso(r.acknowledged_at),
      containedAt: iso(r.contained_at),
      closedAt: iso(r.closed_at),
      assigneeId: (r.assignee_id as string | null) ?? null,
      assigneeName: (r.assignee_name as string | null) ?? null,
      attack: (r.attack as AttackTechnique[]) ?? [],
      alertCount: n(r.alert_count),
      assetCount: ((r.asset_ids as string[] | null) ?? []).length,
      identityCount: ((r.identity_ids as string[] | null) ?? []).length,
      riskFactors: factorsOf(r.risk),
    };
  }

  async incidents(q: ReportQuery): Promise<IncidentFact[]> {
    return this.tx(q, async (tx) => {
      const rows = await this.sql(
        tx,
        q,
        `SELECT i.*, coalesce(u.display_name, u.email) AS assignee_name FROM incidents i LEFT JOIN users u ON u.id = i.assignee_id
         WHERE ${org("i.organization_id")} AND i.merged_into IS NULL
           AND ((i.detected_at >= :from::timestamptz AND i.detected_at < :to::timestamptz)
             OR (i.detected_at < :from::timestamptz AND (i.closed_at IS NULL OR i.closed_at >= :from::timestamptz)))
         ORDER BY i.detected_at DESC LIMIT 5000`,
      );
      return rows.map((r) => this.incidentFact(r));
    });
  }

  async alertStats(q: ReportQuery): Promise<AlertStats> {
    return this.tx(q, async (tx) => {
      const where = `${org("organization_id")} AND created_at >= :from::timestamptz AND created_at < :to::timestamptz`;
      const [totals, daily, sources, rules, techniques] = await inOrder([
        () => this.sql(
          tx,
          q,
          `SELECT count(*) AS total, count(*) FILTER (WHERE status = 'false_positive') AS fp, count(*) FILTER (WHERE status = 'promoted' OR incident_id IS NOT NULL) AS promoted,
                  count(*) FILTER (WHERE status = 'suppressed') AS suppressed,
                  ${SEVERITIES.map((s) => `count(*) FILTER (WHERE severity = '${s}') AS sev_${s}`).join(", ")}
           FROM alerts WHERE ${where}`,
        ),
        () => this.sql(tx, q, `SELECT to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS d, count(*) AS c FROM alerts WHERE ${where} GROUP BY 1 ORDER BY 1`),
        () => this.sql(tx, q, `SELECT source AS name, count(*) AS c FROM alerts WHERE ${where} GROUP BY 1 ORDER BY 2 DESC LIMIT 20`),
        () => this.sql(tx, q, `SELECT rule_id, max(title) AS name, count(*) AS c, count(*) FILTER (WHERE status = 'false_positive') AS fp FROM alerts WHERE ${where} AND rule_id IS NOT NULL GROUP BY rule_id ORDER BY 3 DESC LIMIT 20`),
        () => this.sql(tx, q, `SELECT t->>'id' AS id, max(t->>'name') AS name, max(t->>'tactic') AS tactic, count(*) AS c FROM alerts, jsonb_array_elements(attack) t WHERE ${where} GROUP BY 1 ORDER BY 4 DESC LIMIT 20`),
      ]);
      const r = totals[0] ?? {};
      const bySeverity = sevRecord();
      for (const s of SEVERITIES) bySeverity[s] = n(r[`sev_${s}`]);
      return {
        total: n(r.total),
        bySeverity,
        falsePositives: n(r.fp),
        promoted: n(r.promoted),
        suppressed: n(r.suppressed),
        daily: daily.map((d) => ({ date: String(d.d), count: n(d.c) })),
        bySource: sources.map((s) => ({ name: String(s.name), count: n(s.c) })),
        topRules: rules.map((x) => ({ ruleId: String(x.rule_id), name: String(x.name ?? x.rule_id), count: n(x.c), falsePositives: n(x.fp) })),
        topTechniques: techniques.map((x) => ({ id: String(x.id), name: (x.name as string | null) ?? null, tactic: (x.tactic as string | null) ?? null, count: n(x.c) })),
      };
    });
  }

  async eventStats(q: ReportQuery): Promise<EventStats> {
    return this.tx(q, async (tx) => {
      const where = `${org("organization_id")} AND occurred_at >= :from::timestamptz AND occurred_at < :to::timestamptz`;
      const [daily, sources] = await inOrder([
        () => this.sql(tx, q, `SELECT to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS d, count(*) AS c FROM events WHERE ${where} GROUP BY 1 ORDER BY 1`),
        () => this.sql(tx, q, `SELECT source_product AS name, count(*) AS c FROM events WHERE ${where} GROUP BY 1 ORDER BY 2 DESC LIMIT 20`),
      ]);
      const days: DailyCount[] = daily.map((d) => ({ date: String(d.d), count: n(d.c) }));
      return { total: days.reduce((a, d) => a + d.count, 0), daily: days, bySource: sources.map((s) => ({ name: String(s.name), count: n(s.c) })) };
    });
  }

  async escalations(q: ReportQuery): Promise<EscalationFact[]> {
    return this.tx(q, async (tx) => {
      const rows = await this.sql(
        tx,
        q,
        `SELECT * FROM escalations WHERE ${org("organization_id")}
           AND ((created_at >= :from::timestamptz AND created_at < :to::timestamptz) OR (created_at < :from::timestamptz AND (resolved_at IS NULL OR resolved_at >= :from::timestamptz)))
         ORDER BY created_at DESC LIMIT 5000`,
      );
      return rows.map((r) => ({
        id: String(r.id),
        organizationId: String(r.organization_id),
        incidentId: (r.incident_id as string | null) ?? null,
        title: String(r.title),
        severity: r.severity as Severity,
        status: r.status as EscalationFact["status"],
        createdAt: String(r.created_at),
        dueAt: String(r.due_at),
        acknowledgedAt: iso(r.acknowledged_at),
        resolvedAt: iso(r.resolved_at),
      }));
    });
  }

  async vulnerabilityStats(q: ReportQuery): Promise<VulnerabilityStats> {
    return this.tx(q, async (tx) => {
      const open = `${org("v.organization_id")} AND v.first_seen_at < :to::timestamptz AND (v.status IN ('open', 'in_remediation') OR (v.resolved_at IS NOT NULL AND v.resolved_at >= :to::timestamptz))`;
      const [state, flow, ages, crit] = await inOrder([
        () => this.sql(
          tx,
          q,
          `SELECT ${SEVERITIES.map((s) => `count(*) FILTER (WHERE v.severity = '${s}') AS sev_${s}`).join(", ")},
                  count(*) FILTER (WHERE v.known_exploited) AS kev, count(*) FILTER (WHERE v.sla_due_at < :to::timestamptz) AS overdue,
                  count(*) FILTER (WHERE v.patch_available) AS patchable, count(*) FILTER (WHERE a.internet_facing AND v.severity = 'critical') AS internet_critical
           FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id WHERE ${open}`,
        ),
        () => this.sql(
          tx,
          q,
          `SELECT count(*) FILTER (WHERE v.first_seen_at >= :from::timestamptz AND v.first_seen_at < :to::timestamptz) AS opened,
                  count(*) FILTER (WHERE v.resolved_at >= :from::timestamptz AND v.resolved_at < :to::timestamptz) AS resolved,
                  avg(EXTRACT(EPOCH FROM (v.resolved_at - v.first_seen_at)) / 86400) FILTER (WHERE v.resolved_at >= :from::timestamptz AND v.resolved_at < :to::timestamptz) AS mttr
           FROM vulnerabilities v WHERE ${org("v.organization_id")}`,
        ),
        () => this.sql(
          tx,
          q,
          `SELECT CASE WHEN age <= 30 THEN '0-30 days' WHEN age <= 90 THEN '31-90 days' WHEN age <= 180 THEN '91-180 days' ELSE '180+ days' END AS name, count(*) AS c
           FROM (SELECT EXTRACT(EPOCH FROM (:to::timestamptz - v.first_seen_at)) / 86400 AS age FROM vulnerabilities v WHERE ${open}) x GROUP BY 1`,
        ),
        () => this.sql(tx, q, `SELECT a.criticality, count(*) AS c FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id WHERE ${open} GROUP BY 1`),
      ]);
      const s = state[0] ?? {};
      const f = flow[0] ?? {};
      const openBySeverity = sevRecord();
      for (const sev of SEVERITIES) openBySeverity[sev] = n(s[`sev_${sev}`]);
      const order = ["0-30 days", "31-90 days", "91-180 days", "180+ days"];
      const ageMap = new Map(ages.map((r) => [String(r.name), n(r.c)]));
      const byCrit: Partial<Record<Criticality, number>> = {};
      for (const r of crit) byCrit[r.criticality as Criticality] = n(r.c);
      return {
        openBySeverity,
        knownExploitedOpen: n(s.kev),
        overdueSla: n(s.overdue),
        patchAvailableOpen: n(s.patchable),
        internetFacingCriticalOpen: n(s.internet_critical),
        openedInPeriod: n(f.opened),
        resolvedInPeriod: n(f.resolved),
        meanTimeToRemediateDays: f.mttr === null || f.mttr === undefined ? null : Math.round(Number(f.mttr) * 10) / 10,
        ageBuckets: order.map((name) => ({ name, count: ageMap.get(name) ?? 0 })),
        openByAssetCriticality: byCrit,
      };
    });
  }

  async topVulnerabilities(q: ReportQuery, limit: number): Promise<VulnerabilityFact[]> {
    return this.tx(q, async (tx) => {
      const rows = await this.sql(
        tx,
        q,
        `SELECT v.*, a.name AS asset_name, a.criticality AS asset_criticality, a.internet_facing FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id
         WHERE ${org("v.organization_id")} AND v.status IN ('open', 'in_remediation')
         ORDER BY v.risk_score DESC NULLS LAST, v.known_exploited DESC, v.cvss DESC NULLS LAST, v.id LIMIT :limit`,
        { limit: Math.min(Math.max(limit, 1), 200) },
      );
      return rows.map((r) => ({
        id: String(r.id),
        organizationId: String(r.organization_id),
        cve: (r.cve as string | null) ?? null,
        title: String(r.title),
        severity: r.severity as Severity,
        cvss: nn(r.cvss),
        epss: nn(r.epss),
        knownExploited: Boolean(r.known_exploited),
        assetName: String(r.asset_name),
        assetCriticality: r.asset_criticality as Criticality,
        internetFacing: Boolean(r.internet_facing),
        status: String(r.status),
        firstSeenAt: String(r.first_seen_at),
        slaDueAt: iso(r.sla_due_at),
        riskScore: nn(r.risk_score),
        riskFactors: factorsOf(r.risk),
        patchAvailable: Boolean(r.patch_available),
      }));
    });
  }

  async riskyAssets(q: ReportQuery, limit: number): Promise<RiskyAssetFact[]> {
    return this.tx(q, async (tx) => {
      const rows = await this.sql(
        tx,
        q,
        `SELECT a.*,
                (SELECT count(*) FROM incidents i WHERE a.id = ANY(i.asset_ids) AND i.status IN ('new', 'triage', 'investigating', 'contained') AND i.merged_into IS NULL) AS open_incidents,
                (SELECT count(*) FROM vulnerabilities v WHERE v.asset_id = a.id AND v.severity = 'critical' AND v.status IN ('open', 'in_remediation')) AS crit_vulns
         FROM assets a WHERE ${org("a.organization_id")} AND a.risk_score IS NOT NULL AND a.risk_score > 0
         ORDER BY a.risk_score DESC, a.id LIMIT :limit`,
        { limit: Math.min(Math.max(limit, 1), 200) },
      );
      return rows.map((r) => ({
        id: String(r.id),
        organizationId: String(r.organization_id),
        name: String(r.name),
        kind: String(r.kind),
        criticality: r.criticality as Criticality,
        riskScore: n(r.risk_score),
        factors: factorsOf(r.risk),
        openIncidents: n(r.open_incidents),
        openCriticalVulnerabilities: n(r.crit_vulns),
      }));
    });
  }

  async attackPaths(q: ReportQuery, limit: number): Promise<AttackPathStats> {
    const { orgs, map } = await this.tx(q, async (tx) => ({ orgs: await this.orgIds(tx, q), map: await this.postureMap(tx, q) }));
    let total = 0;
    let toCrownJewels = 0;
    const top: AttackPathStats["top"] = [];
    for (const orgId of orgs) {
      const p = map.get(orgId);
      // Attack paths need an internet-facing entry and a crown jewel; skip the analysis otherwise.
      if (!p || p.assets.internetFacing === 0 || p.assets.crownJewels === 0) continue;
      const a = await this.attackPathsService.analyze(q.tenantId, orgId);
      total += a.paths.length;
      toCrownJewels += a.paths.filter((x) => isCrownJewel(x.target)).length;
      const fix = a.remediations[0]?.action ?? null;
      for (const x of a.paths) {
        top.push({ id: x.id, organizationId: orgId, entry: x.entry.label, target: x.target.label, score: x.risk.score, severity: x.risk.severity, hops: x.length, remediation: fix, factors: x.risk.factors });
      }
    }
    top.sort((x, y) => y.score - x.score || x.hops - y.hops);
    return { total, toCrownJewels, top: top.slice(0, Math.max(limit, 1)) };
  }

  private async postureMap(tx: Queryable, q: ReportQuery): Promise<Map<string, OrgPosture>> {
    return loadPosture(tx, q.organizationIds === "all" ? null : [...q.organizationIds]);
  }

  private async exposureFor(tenantId: string, p: OrgPosture, orgs: string[], name?: string): Promise<number> {
    let total = 0;
    let crown = 0;
    if (p.assets.internetFacing > 0 && p.assets.crownJewels > 0) {
      const c = await this.attackPathsService.counts(tenantId, orgs);
      total = c.total;
      crown = c.toCrownJewels;
    }
    return this.risk.exposureScore(exposureInputsFor(p, { total, toCrownJewels: crown }, name)).score;
  }

  async posture(q: ReportQuery): Promise<PostureStats> {
    const data = await this.tx(q, async (tx) => {
      const map = await this.postureMap(tx, q);
      const [assetRisk, idRisk, logs, cloud] = await inOrder([
        () => this.sql(tx, q, `SELECT percentile_cont(0.9) WITHIN GROUP (ORDER BY risk_score) AS p90 FROM assets WHERE ${org("organization_id")} AND risk_score IS NOT NULL`),
        () => this.sql(tx, q, `SELECT count(*) FILTER (WHERE risk_score >= 70) AS risky FROM identities WHERE ${org("organization_id")} AND enabled`),
        () => this.sql(
          tx,
          q,
          `SELECT count(*) AS total, count(*) FILTER (WHERE last_at > :to::timestamptz - interval '24 hours') AS healthy FROM (
             SELECT source_product, coalesce(sensor_id, '') AS sensor, max(received_at) AS last_at FROM events
             WHERE ${org("organization_id")} AND occurred_at > :to::timestamptz - interval '7 days' AND occurred_at <= :to::timestamptz GROUP BY 1, 2) x`,
        ),
        () => this.sql(
          tx,
          q,
          `SELECT count(*) AS evaluated, count(*) FILTER (WHERE outcome = 'failure') AS failing FROM (
             SELECT DISTINCT ON (coalesce(asset_hostname, ''), coalesce(doc->'labels'->>'control', event_type)) outcome
             FROM events WHERE ${org("organization_id")} AND category IN ('configuration', 'cloud') AND outcome IN ('success', 'failure')
               AND occurred_at > :to::timestamptz - interval '30 days' AND occurred_at <= :to::timestamptz
             ORDER BY coalesce(asset_hostname, ''), coalesce(doc->'labels'->>'control', event_type), occurred_at DESC) x`,
        ),
      ]);
      return { map, assetRisk: assetRisk[0] ?? {}, idRisk: idRisk[0] ?? {}, logs: logs[0] ?? {}, cloud: cloud[0] ?? {} };
    });
    const p = sumPosture(data.map.values());
    const exposure = data.map.size > 0 ? await this.exposureFor(q.tenantId, p, [...data.map.keys()]) : null;
    const evaluated = n(data.cloud.evaluated);
    const failing = n(data.cloud.failing);
    return {
      riskScore: data.assetRisk.p90 === null || data.assetRisk.p90 === undefined ? null : Math.round(Number(data.assetRisk.p90)),
      exposureScore: exposure,
      agents: { total: p.agents.total, protected: p.agents.protected, unresponsive: p.agents.unresponsive, outdated: p.agents.outdated, isolated: p.agents.isolated },
      identities: {
        total: p.identities.total,
        privileged: p.identities.privileged,
        privilegedWithoutMfa: p.identities.privilegedWithoutMfa,
        usersWithoutMfa: Math.max(0, p.identities.users - p.identities.usersWithMfa),
        risky: n(data.idRisk.risky),
      },
      cloud: { score: evaluated === 0 ? null : Math.round((100 * (evaluated - failing)) / evaluated), failingControls: failing },
      logSources: { total: n(data.logs.total), healthy: n(data.logs.healthy), silent: n(data.logs.total) - n(data.logs.healthy) },
    };
  }

  /** No posture history is stored yet: the trend is the single, current, verifiable point. */
  async postureTrend(q: ReportQuery): Promise<PostureTrendPoint[]> {
    const p = await this.posture(q);
    return [{ date: q.to.toISOString().slice(0, 10), riskScore: p.riskScore, exposureScore: p.exposureScore }];
  }

  async organizationPosture(q: ReportQuery): Promise<OrganizationPostureFact[]> {
    const { map, risk, names } = await this.tx(q, async (tx) => {
      const map = await this.postureMap(tx, q);
      const risk = await this.sql(tx, q, `SELECT organization_id, percentile_cont(0.9) WITHIN GROUP (ORDER BY risk_score) AS p90 FROM assets WHERE ${org("organization_id")} AND risk_score IS NOT NULL GROUP BY 1`);
      const names = await this.sql(tx, q, `SELECT id, name FROM organizations WHERE ${org("id")}`);
      return { map, risk: new Map(risk.map((r) => [String(r.organization_id), nn(r.p90)])), names: new Map(names.map((r) => [String(r.id), String(r.name)])) };
    });
    const out: OrganizationPostureFact[] = [];
    for (const [orgId, p] of map) {
      const r = risk.get(orgId);
      out.push({
        organizationId: orgId,
        riskScore: r === null || r === undefined ? null : Math.round(r),
        exposureScore: await this.exposureFor(q.tenantId, p, [orgId], names.get(orgId)),
        agentsTotal: p.agents.total,
        agentsUnhealthy: p.agents.unresponsive + p.agents.outdated,
        criticalVulnerabilities: p.vulns.critical,
        knownExploitedOpen: p.vulns.knownExploited,
      });
    }
    return out;
  }

  async intelStats(q: ReportQuery, limit: number): Promise<IntelStats> {
    return this.tx(q, async (tx) => {
      const visible = `(i.organization_id IS NULL OR ${org("i.organization_id")})`;
      const matched = `${org("m.organization_id")} AND m.matched_at >= :from::timestamptz AND m.matched_at < :to::timestamptz`;
      const extra = { limit: Math.min(Math.max(limit, 1), 100) };
      const named = (col: string) =>
        this.sql(tx, q, `SELECT i.${col} AS name, count(*) AS c FROM indicator_matches m JOIN indicators i ON i.id = m.indicator_id WHERE ${matched} AND i.${col} IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT :limit`, extra);
      const [totals, byType, bySource, matches, daily, actors, malware, campaigns, topMatched] = await inOrder([
        () => this.sql(tx, q, `SELECT count(*) AS total, count(*) FILTER (WHERE i.created_at >= :from::timestamptz AND i.created_at < :to::timestamptz) AS fresh FROM indicators i WHERE ${visible} AND NOT i.revoked`),
        () => this.sql(tx, q, `SELECT i.type AS name, count(*) AS c FROM indicators i WHERE ${visible} AND NOT i.revoked GROUP BY 1 ORDER BY 2 DESC`),
        () => this.sql(tx, q, `SELECT i.source AS name, count(*) AS c FROM indicators i WHERE ${visible} AND NOT i.revoked GROUP BY 1 ORDER BY 2 DESC LIMIT :limit`, extra),
        () => this.sql(tx, q, `SELECT count(*) AS c FROM indicator_matches m WHERE ${matched}`),
        () => this.sql(tx, q, `SELECT to_char(m.matched_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS d, count(*) AS c FROM indicator_matches m WHERE ${matched} GROUP BY 1 ORDER BY 1`),
        () => named("threat_actor"),
        () => named("malware"),
        () => named("campaign"),
        () => this.sql(
          tx,
          q,
          `SELECT i.type, i.value, i.source, i.severity, i.confidence, i.threat_actor, count(*) AS matches, max(m.matched_at) AS last_seen
           FROM indicator_matches m JOIN indicators i ON i.id = m.indicator_id WHERE ${matched}
           GROUP BY i.id, i.type, i.value, i.source, i.severity, i.confidence, i.threat_actor ORDER BY matches DESC, last_seen DESC LIMIT :limit`,
          extra,
        ),
      ]);
      const toNamed = (rows: Row[]): NamedCount[] => rows.map((r) => ({ name: String(r.name), count: n(r.c) }));
      return {
        indicatorsTotal: n(totals[0]?.total),
        indicatorsNew: n(totals[0]?.fresh),
        byType: toNamed(byType),
        bySource: toNamed(bySource),
        matchesTotal: n(matches[0]?.c),
        matchesDaily: daily.map((d) => ({ date: String(d.d), count: n(d.c) })),
        topActors: toNamed(actors),
        topMalware: toNamed(malware),
        topCampaigns: toNamed(campaigns),
        topMatched: topMatched.map((r) => ({
          type: String(r.type),
          value: String(r.value),
          source: String(r.source),
          severity: r.severity as Severity,
          confidence: n(r.confidence),
          matches: n(r.matches),
          lastSeenAt: String(r.last_seen),
          threatActor: (r.threat_actor as string | null) ?? null,
        })),
      };
    });
  }

  /**
   * Controls evaluated from telemetry (configuration / cloud events with a `labels.control`, e.g.
   * Wazuh SCA, Trivy misconfigurations, kube-bench) plus the platform baseline controls computed
   * from inventory (EDR coverage, MFA, KEV remediation, firewall, managed attack surface).
   */
  async complianceControls(q: ReportQuery): Promise<ComplianceControlFact[]> {
    const { events, map, fw } = await this.tx(q, async (tx) => {
      const events = await this.sql(
        tx,
        q,
        `SELECT DISTINCT ON (organization_id, coalesce(doc->'labels'->>'framework', source_product), coalesce(doc->'labels'->>'control', event_type))
                organization_id, coalesce(doc->'labels'->>'framework', source_product) AS framework, coalesce(doc->'labels'->>'control', event_type) AS control,
                coalesce(doc->>'message', event_type) AS title, outcome, severity, occurred_at, asset_hostname
         FROM events WHERE ${org("organization_id")} AND category IN ('configuration', 'cloud') AND outcome IN ('success', 'failure')
           AND occurred_at > :to::timestamptz - interval '30 days' AND occurred_at <= :to::timestamptz
         ORDER BY organization_id, 2, 3, occurred_at DESC LIMIT 2000`,
      );
      const map = await this.postureMap(tx, q);
      const fw = await this.sql(tx, q, `SELECT organization_id, count(*) AS total, count(*) FILTER (WHERE firewall_enabled) AS enabled FROM agents WHERE ${org("organization_id")} GROUP BY 1`);
      return { events, map, fw: new Map(fw.map((r) => [String(r.organization_id), { total: n(r.total), enabled: n(r.enabled) }])) };
    });
    const out: ComplianceControlFact[] = events.map((r) => ({
      organizationId: String(r.organization_id),
      framework: String(r.framework),
      controlId: String(r.control).slice(0, 200),
      title: String(r.title).slice(0, 300),
      status: r.outcome === "success" ? "pass" : "fail",
      severity: r.severity as Severity,
      evidence: r.asset_hostname ? `Last evaluated on ${String(r.asset_hostname)}` : null,
      lastEvaluatedAt: String(r.occurred_at),
      owner: null,
    }));
    const at = q.to.toISOString();
    for (const [orgId, p] of map) {
      const ctl = (controlId: string, title: string, severity: Severity, ok: boolean | null, partial: boolean, evidence: string) =>
        out.push({ organizationId: orgId, framework: "SCIAT baseline", controlId, title, status: ok === null ? "not_applicable" : ok ? "pass" : partial ? "partial" : "fail", severity, evidence, lastEvaluatedAt: at, owner: null });
      const endpoints = p.assets.endpoints;
      const cover = endpoints > 0 ? p.agents.edrCoveredAssets / endpoints : null;
      ctl("BL-EDR-01", "EDR deployed and healthy on every endpoint and server", "high", cover === null ? null : cover >= 0.95, cover !== null && cover >= 0.8, cover === null ? "No endpoints in inventory" : `${p.agents.edrCoveredAssets} of ${endpoints} endpoints covered (${Math.round(cover * 100)}%)`);
      ctl("BL-IAM-01", "MFA enforced for every privileged identity", "critical", p.identities.privileged === 0 ? null : p.identities.privilegedWithoutMfa === 0, false, `${p.identities.privilegedWithoutMfa} of ${p.identities.privileged} privileged identities without MFA`);
      const mfa = p.identities.users > 0 ? p.identities.usersWithMfa / p.identities.users : null;
      ctl("BL-IAM-02", "MFA enabled for user accounts", "high", mfa === null ? null : mfa >= 0.95, mfa !== null && mfa >= 0.7, mfa === null ? "No user identities" : `${p.identities.usersWithMfa} of ${p.identities.users} users with MFA`);
      ctl("BL-IAM-03", "No dormant privileged accounts (90 days)", "medium", p.identities.privileged === 0 ? null : p.identities.dormantPrivileged === 0, false, `${p.identities.dormantPrivileged} dormant privileged account(s)`);
      ctl("BL-VM-01", "No known-exploited vulnerability open past its SLA", "critical", p.vulns.knownExploited === 0 ? true : p.vulns.overdueSla === 0, p.vulns.overdueSla === 0, `${p.vulns.knownExploited} KEV open, ${p.vulns.overdueSla} vulnerabilities past SLA`);
      ctl("BL-ASM-01", "Every internet-facing asset is managed (agent installed)", "high", p.assets.internetFacing === 0 ? null : p.assets.unmanagedInternetFacing === 0, false, `${p.assets.unmanagedInternetFacing} of ${p.assets.internetFacing} internet-facing assets unmanaged`);
      const f = fw.get(orgId);
      ctl("BL-NET-01", "Host firewall enabled on managed endpoints", "medium", !f || f.total === 0 ? null : f.enabled === f.total, !!f && f.total > 0 && f.enabled / f.total >= 0.9, f ? `${f.enabled} of ${f.total} agents report the firewall enabled` : "No managed endpoints");
    }
    return out;
  }

  async analystActivity(q: ReportQuery): Promise<AnalystActivityFact[]> {
    return this.tx(q, async (tx) => {
      const rows = await this.sql(
        tx,
        q,
        `WITH analysts AS (
           SELECT u.id, coalesce(u.display_name, u.email) AS name,
                  (SELECT rb.role FROM role_bindings rb WHERE rb.principal_kind = 'user' AND rb.principal_id = u.id ORDER BY rb.created_at LIMIT 1) AS role
           FROM users u WHERE u.status <> 'disabled' AND EXISTS (
             SELECT 1 FROM role_bindings rb WHERE rb.principal_kind = 'user' AND rb.principal_id = u.id AND rb.role NOT IN ('customer_viewer', 'executive', 'api_service'))
         )
         SELECT a.id, a.name, a.role,
           (SELECT count(*) FROM incidents i WHERE i.assignee_id = a.id AND ${org("i.organization_id")} AND i.detected_at < :to::timestamptz AND (i.closed_at IS NULL OR i.closed_at >= :from::timestamptz)) AS assigned,
           (SELECT count(*) FROM incidents i WHERE i.assignee_id = a.id AND ${org("i.organization_id")} AND i.closed_at >= :from::timestamptz AND i.closed_at < :to::timestamptz) AS closed,
           (SELECT count(*) FROM audit_log l WHERE l.actor_id = a.id::text AND l.action = 'alert.status_changed' AND l.outcome = 'success' AND ${org("l.organization_id")} AND l.at >= :from::timestamptz AND l.at < :to::timestamptz) AS triaged,
           (SELECT count(*) FROM investigations v WHERE v.lead_id = a.id AND ${org("v.organization_id")} AND v.created_at < :to::timestamptz AND (v.closed_at IS NULL OR v.closed_at >= :from::timestamptz)) AS led,
           (SELECT count(*) FROM notes nt WHERE nt.author_id = 'user:' || a.id::text AND ${org("nt.organization_id")} AND nt.created_at >= :from::timestamptz AND nt.created_at < :to::timestamptz) AS notes,
           (SELECT count(*) FROM response_actions r WHERE r.requested_by = a.id::text AND ${org("r.organization_id")} AND r.created_at >= :from::timestamptz AND r.created_at < :to::timestamptz) AS requested,
           (SELECT count(*) FROM response_actions r WHERE a.id::text = ANY(string_to_array(r.approved_by, ',')) AND r.status NOT IN ('rejected', 'pending_approval') AND ${org("r.organization_id")}
              AND r.decided_at >= :from::timestamptz AND r.decided_at < :to::timestamptz) AS approved,
           (SELECT avg(EXTRACT(EPOCH FROM (i.acknowledged_at - i.detected_at)) / 60) FROM incidents i WHERE i.assignee_id = a.id AND ${org("i.organization_id")} AND i.acknowledged_at >= :from::timestamptz AND i.acknowledged_at < :to::timestamptz) AS mta,
           (SELECT avg(EXTRACT(EPOCH FROM (i.closed_at - i.detected_at)) / 60) FROM incidents i WHERE i.assignee_id = a.id AND ${org("i.organization_id")} AND i.closed_at >= :from::timestamptz AND i.closed_at < :to::timestamptz) AS mtr,
           (SELECT count(DISTINCT i.organization_id) FROM incidents i WHERE i.assignee_id = a.id AND ${org("i.organization_id")} AND i.detected_at < :to::timestamptz AND (i.closed_at IS NULL OR i.closed_at >= :from::timestamptz)) AS orgs,
           (SELECT count(*) FROM ai_conversations c WHERE c.principal_id = a.id::text AND ${org("c.organization_id")} AND c.created_at >= :from::timestamptz AND c.created_at < :to::timestamptz) AS ai
         FROM analysts a ORDER BY a.name`,
      );
      const round = (v: unknown) => (v === null || v === undefined ? null : Math.round(Number(v) * 10) / 10);
      return rows
        .map((r) => ({
          analystId: String(r.id),
          name: String(r.name),
          role: (r.role as string | null) ?? null,
          incidentsAssigned: n(r.assigned),
          incidentsClosed: n(r.closed),
          alertsTriaged: n(r.triaged),
          investigationsLed: n(r.led),
          notesWritten: n(r.notes),
          actionsRequested: n(r.requested),
          actionsApproved: n(r.approved),
          meanAcknowledgeMinutes: round(r.mta),
          meanResolveMinutes: round(r.mtr),
          organizationsServed: n(r.orgs),
          aiAssists: n(r.ai),
        }))
        // Organization-scoped reports only list analysts who actually worked on that scope.
        .filter((a) => q.organizationIds === "all" || a.incidentsAssigned + a.alertsTriaged + a.investigationsLed + a.notesWritten + a.actionsRequested + a.actionsApproved + a.aiAssists > 0);
    });
  }

  async responseStats(q: ReportQuery): Promise<ResponseStats> {
    return this.tx(q, async (tx) => {
      const where = `${org("organization_id")} AND created_at >= :from::timestamptz AND created_at < :to::timestamptz`;
      const [totals, byAction, byStatus, runs, sent, savings, pending] = await inOrder([
        () => this.sql(
          tx,
          q,
          `SELECT count(*) AS total, count(*) FILTER (WHERE requested_via = 'playbook') AS automated, count(*) FILTER (WHERE requested_via = 'user') AS manual,
                  count(*) FILTER (WHERE requested_via = 'ai') AS ai,
                  avg(EXTRACT(EPOCH FROM (decided_at - created_at)) / 60) FILTER (WHERE decided_at IS NOT NULL AND approval_id IS NOT NULL AND status NOT IN ('rejected', 'cancelled')) AS approval_minutes
           FROM response_actions WHERE ${where}`,
        ),
        () => this.sql(tx, q, `SELECT action AS name, count(*) AS c FROM response_actions WHERE ${where} GROUP BY 1 ORDER BY 2 DESC`),
        () => this.sql(tx, q, `SELECT status AS name, count(*) AS c FROM response_actions WHERE ${where} GROUP BY 1 ORDER BY 2 DESC`),
        () => this.sql(
          tx,
          q,
          `SELECT count(*) AS runs, count(*) FILTER (WHERE status = 'succeeded') AS ok, count(*) FILTER (WHERE status IN ('failed', 'rejected')) AS failed
           FROM playbook_runs WHERE ${org("organization_id")} AND started_at >= :from::timestamptz AND started_at < :to::timestamptz`,
        ),
        () => this.sql(
          tx,
          q,
          `SELECT coalesce(sum(value), 0) AS c FROM usage_counters WHERE metric = 'notifications.sent' AND (organization_id IS NULL OR ${org("organization_id")})
             AND period_start >= (:from::timestamptz AT TIME ZONE 'UTC')::date AND period_start <= (:to::timestamptz AT TIME ZONE 'UTC')::date`,
        ),
        () => tx.query<Row>("SELECT settings->'automation'->'minutesSavedPerAction' AS m FROM accounts WHERE id = $1", [q.tenantId]).then((r) => r.rows),
        () => this.sql(tx, q, `SELECT count(*) AS c FROM response_actions WHERE ${org("organization_id")} AND status = 'pending_approval'`),
      ]);
      const r = totals[0] ?? {};
      const minutes = savings[0]?.m;
      let estimated: number | null = null;
      if (minutes && typeof minutes === "object" && !Array.isArray(minutes)) {
        const per = minutes as Record<string, unknown>;
        estimated = 0;
        for (const a of byAction) {
          const m = Number(per[String(a.name)]);
          if (Number.isFinite(m) && m > 0) estimated += m * n(a.c);
        }
      }
      return {
        actionsTotal: n(r.total),
        byAction: byAction.map((x) => ({ name: String(x.name), count: n(x.c) })),
        byStatus: byStatus.map((x) => ({ name: String(x.name), count: n(x.c) })),
        automated: n(r.automated),
        manual: n(r.manual),
        aiInitiated: n(r.ai),
        pendingApproval: n(pending[0]?.c),
        meanApprovalMinutes: r.approval_minutes === null || r.approval_minutes === undefined ? null : Math.round(Number(r.approval_minutes) * 10) / 10,
        playbookRuns: n(runs[0]?.runs),
        playbookSucceeded: n(runs[0]?.ok),
        playbookFailed: n(runs[0]?.failed),
        notificationsSent: n(sent[0]?.c),
        estimatedMinutesSaved: estimated,
      };
    });
  }

  async usage(q: ReportQuery): Promise<UsageFact[]> {
    return this.tx(q, async (tx) => {
      const rows = await this.sql(
        tx,
        q,
        `SELECT o.id, CASE WHEN (o.settings->>'licensedEndpoints') ~ '^[0-9]{1,9}$' THEN (o.settings->>'licensedEndpoints')::int END AS licensed,
                (SELECT count(*) FROM agents a WHERE a.organization_id = o.id) AS endpoints,
                (SELECT coalesce(sum(value), 0) FROM usage_counters u WHERE u.organization_id = o.id AND u.metric = 'events_ingested'
                   AND u.period_start >= (:from::timestamptz AT TIME ZONE 'UTC')::date AND u.period_start <= (:to::timestamptz AT TIME ZONE 'UTC')::date) AS events,
                (SELECT coalesce(sum(value), 0) FROM usage_counters u WHERE u.organization_id = o.id AND u.metric = 'ai.calls'
                   AND u.period_start >= (:from::timestamptz AT TIME ZONE 'UTC')::date AND u.period_start <= (:to::timestamptz AT TIME ZONE 'UTC')::date) AS ai
         FROM organizations o WHERE ${org("o.id")} ORDER BY o.name`,
      );
      const days = Math.max(1, (q.to.getTime() - q.from.getTime()) / 86_400_000);
      return rows.map((r) => ({ organizationId: String(r.id), endpoints: n(r.endpoints), endpointsLicensed: nn(r.licensed), eventsPerDay: Math.round(n(r.events) / days), aiRequests: n(r.ai) }));
    });
  }

  async billing(q: ReportQuery): Promise<BillingFact[]> {
    return this.tx(q, async (tx) => {
      const rows = await this.sql(tx, q, `SELECT o.id, o.plan, o.mrr, coalesce(a.settings->>'currency', 'USD') AS currency FROM organizations o JOIN accounts a ON a.id = o.tenant_id WHERE ${org("o.id")} ORDER BY o.name`);
      return rows.map((r) => {
        const plan = PlanKey.safeParse(r.plan);
        // MRR history is not stored; previousMrr stays null rather than guessed.
        return { organizationId: String(r.id), plan: plan.success ? plan.data : null, mrr: n(r.mrr), previousMrr: null, currency: String(r.currency).slice(0, 3).toUpperCase() };
      });
    });
  }

  /** Security awareness: training status at period end, simulations sent in the period, human risk (12 months to period end). */
  async awareness(q: ReportQuery): Promise<AwarenessFact[]> {
    return this.tx(q, async (tx) => {
      const training = await this.sql(
        tx,
        q,
        `SELECT o.id AS organization_id,
                (SELECT count(*) FROM sat_learners l WHERE l.organization_id = o.id AND l.active AND l.created_at <= :to::timestamptz) AS learners,
                (SELECT count(*) FROM sat_enrolments e JOIN sat_assignments a ON a.id = e.assignment_id WHERE e.organization_id = o.id AND a.created_at <= :to::timestamptz) AS assignments,
                (SELECT count(*) FROM sat_enrolments e WHERE e.organization_id = o.id AND e.completed_at <= :to::timestamptz) AS completed,
                (SELECT count(*) FROM sat_enrolments e JOIN sat_assignments a ON a.id = e.assignment_id
                  WHERE e.organization_id = o.id AND a.due_at < :to::timestamptz AND (e.completed_at IS NULL OR e.completed_at > :to::timestamptz)) AS overdue,
                (SELECT round(avg(p.best_score)) FROM sat_progress p JOIN sat_enrolments e ON e.id = p.enrolment_id WHERE e.organization_id = o.id AND p.updated_at <= :to::timestamptz) AS avg_score
           FROM organizations o WHERE ${org("o.id")} ORDER BY o.name`,
      );
      const campaigns = await this.sql(
        tx,
        q,
        `SELECT c.organization_id, c.name, c.template, c.launched_at,
                count(t.id) FILTER (WHERE t.sent_at IS NOT NULL) AS sent,
                count(t.id) FILTER (WHERE t.clicked_at IS NOT NULL AND t.clicked_at <= :to::timestamptz) AS clicked
           FROM sat_phish_campaigns c LEFT JOIN sat_phish_targets t ON t.campaign_id = c.id
          WHERE ${org("c.organization_id")} AND c.launched_at >= :from::timestamptz AND c.launched_at < :to::timestamptz
          GROUP BY c.id ORDER BY c.launched_at`,
      );
      const people = await this.sql(
        tx,
        q,
        `SELECT l.organization_id, l.name, l.email,
                (SELECT count(*) FROM sat_phish_targets t WHERE t.learner_id = l.id AND t.clicked_at BETWEEN :to::timestamptz - interval '365 days' AND :to::timestamptz) AS clicks,
                (SELECT count(*) FROM sat_phish_targets t WHERE t.learner_id = l.id AND t.sent_at BETWEEN :to::timestamptz - interval '365 days' AND :to::timestamptz
                   AND (t.clicked_at IS NULL OR t.clicked_at > :to::timestamptz)) AS spotted,
                (SELECT count(*) FROM sat_enrolments e WHERE e.learner_id = l.id AND e.completed_at BETWEEN :to::timestamptz - interval '365 days' AND :to::timestamptz) AS completed,
                (SELECT count(*) FROM sat_enrolments e JOIN sat_assignments a ON a.id = e.assignment_id
                  WHERE e.learner_id = l.id AND a.due_at < :to::timestamptz AND (e.completed_at IS NULL OR e.completed_at > :to::timestamptz)) AS overdue,
                (SELECT round(avg(p.best_score)) FROM sat_progress p JOIN sat_enrolments e ON e.id = p.enrolment_id WHERE e.learner_id = l.id AND p.updated_at <= :to::timestamptz) AS avg_score
           FROM sat_learners l WHERE ${org("l.organization_id")} AND l.active AND l.created_at <= :to::timestamptz`,
      );
      const scored = people.map((r) => {
        const risk = humanRisk({ phishClicks: n(r.clicks), phishSpotted: n(r.spotted), completedTraining: n(r.completed), overdueTraining: n(r.overdue), averageScore: r.avg_score === null ? null : n(r.avg_score) });
        const main = risk.reasons.find((x) => x.points > 0 && x.text !== "Baseline for everyone") ?? risk.reasons[0]!;
        return { organizationId: String(r.organization_id), name: String(r.name), email: String(r.email), score: risk.score, level: risk.level, mainReason: main.text };
      });
      return training.map((t) => {
        const id = String(t.organization_id);
        const mine = campaigns.filter((c) => String(c.organization_id) === id);
        const theirs = scored.filter((p) => p.organizationId === id);
        return {
          organizationId: id,
          learners: n(t.learners),
          assignments: n(t.assignments),
          completed: n(t.completed),
          overdue: n(t.overdue),
          averageScore: t.avg_score === null ? null : n(t.avg_score),
          phishSent: mine.reduce((s, c) => s + n(c.sent), 0),
          phishClicked: mine.reduce((s, c) => s + n(c.clicked), 0),
          campaigns: mine.map((c) => ({ name: String(c.name), template: String(c.template), sentAt: new Date(String(c.launched_at)).toISOString(), sent: n(c.sent), clicked: n(c.clicked) })),
          atRisk: theirs.filter((p) => p.score >= 35).sort((a, b) => b.score - a.score).slice(0, 25).map(({ organizationId: _o, ...p }) => p),
          highRisk: theirs.filter((p) => p.level === "high").length,
        };
      });
    });
  }

  /**
   * Endpoint posture from the SCIAT Agent, per organization. Agents report current state only,
   * so this is a snapshot at generation time (or the period end, if earlier). The same services
   * as the console compute it, so the report and the screens agree.
   */
  async endpointPosture(q: ReportQuery): Promise<EndpointPostureFact[]> {
    const asOf = new Date(Math.min(Date.now(), q.to.getTime() - 1)).toISOString().slice(0, 10);
    // A period that ended before yesterday is described by the snapshots recorded then.
    if (asOf < new Date(Date.now() - 86_400_000).toISOString().slice(0, 10)) {
      return this.tx(q, async (tx) => {
        const rows = await this.sql(
          tx,
          q,
          `SELECT DISTINCT ON (s.organization_id) s.organization_id, s.day, s.fact
             FROM endpoint_posture_snapshots s JOIN organizations o ON o.id = s.organization_id
            WHERE ${org("s.organization_id")} AND s.day <= :as_of::date
            ORDER BY s.organization_id, s.day DESC`,
          { as_of: asOf },
        );
        return rows.map((r) => ({ ...(r.fact as Omit<EndpointPostureFact, "organizationId" | "asOf">), organizationId: String(r.organization_id), asOf: String(r.day instanceof Date ? r.day.toISOString().slice(0, 10) : r.day).slice(0, 10) }));
      });
    }
    return this.livePosture(q);
  }

  /** Daily posture over the period from the snapshots, aggregated across the requested organizations. */
  async endpointPostureTrend(q: ReportQuery): Promise<EndpointPostureTrendPoint[]> {
    return this.tx(q, async (tx) => {
      const rows = await this.sql(
        tx,
        q,
        `SELECT to_char(s.day, 'YYYY-MM-DD') AS day, s.fact FROM endpoint_posture_snapshots s
          WHERE ${org("s.organization_id")} AND s.day >= :from::date AND s.day < :to::timestamptz::date + 1
          ORDER BY s.day`,
      );
      const byDay = new Map<string, Array<Omit<EndpointPostureFact, "organizationId" | "asOf">>>();
      for (const r of rows) byDay.set(String(r.day), [...(byDay.get(String(r.day)) ?? []), r.fact as Omit<EndpointPostureFact, "organizationId" | "asOf">]);
      const pct = (a: number, b: number) => (b ? Math.round((a / b) * 100) : null);
      return [...byDay].map(([date, facts]) => {
        const sum = (f: (x: (typeof facts)[number]) => number) => facts.reduce((n, x) => n + f(x), 0);
        const scored = facts.filter((x) => x.hardeningScore !== null);
        return {
          date,
          patchCompliance: pct(sum((x) => x.patching.current), sum((x) => x.patching.current + x.patching.behind + x.patching.breached)),
          antivirusProtected: pct(sum((x) => x.antivirus.protected), sum((x) => x.antivirus.protected + x.antivirus.unhealthy + x.antivirus.unmanaged)),
          hardeningScore: scored.length ? Math.round(scored.reduce((n, x) => n + x.hardeningScore! * Math.max(1, x.reporting), 0) / scored.reduce((n, x) => n + Math.max(1, x.reporting), 0)) : null,
          unsupportedOs: sum((x) => x.unsupportedOs.length),
          needingAttention: sum((x) => x.needingAttention ?? x.atRisk.length),
        };
      });
    });
  }

  /** Posture computed now from the agents' latest reports. */
  async livePosture(q: ReportQuery): Promise<EndpointPostureFact[]> {
    const at = Math.min(Date.now(), q.to.getTime());
    const patching = new PatchingService(() => at);
    const footholds = new FootholdsService(() => at);
    const hardening = new AttackReductionService();
    const rmm = new RmmGuardService(new AppControlService(() => at));
    return this.tx(q, async (tx) => {
      const out: EndpointPostureFact[] = [];
      for (const organizationId of await this.orgIds(tx, q)) {
        const agents = await tx.query<Row>(
          `SELECT a.id, a.hostname, a.antivirus_status, a.last_checkin_at, (i.agent_id IS NOT NULL) AS reported
             FROM agents a LEFT JOIN agent_inventory i ON i.agent_id = a.id
            WHERE a.organization_id = $1 AND a.engine = 'sciat' AND a.agent_token_hash IS NOT NULL`,
          [organizationId],
        );
        const [p, f, h, r] = [await patching.overview(tx, organizationId), await footholds.overview(tx, organizationId), await hardening.overview(tx, organizationId), await rmm.findings(tx, organizationId)];
        const issues = new Map<string, string[]>();
        const add = (agentId: string, text: string) => issues.set(agentId, [...(issues.get(agentId) ?? []), text]);
        for (const e of p.endpoints) if (e.grade.state === "breached" || (e.grade.state === "behind" && e.securityCount > 0)) add(e.agentId, e.grade.reasons[0]!);
        for (const a of agents.rows) {
          if (a.antivirus_status === "unhealthy") add(String(a.id), "Antivirus off or out of date");
          else if (a.antivirus_status === "unmanaged" && a.reported) add(String(a.id), "No antivirus");
        }
        for (const e of h.endpoints) if (e.score !== null && e.score < 60) add(e.agentId, `Hardening score ${e.score}`);
        const flagged = f.footholds.filter((x) => x.verdict?.verdict === "malicious" || (!x.verdict && x.assessment.level !== "low"));
        // A cron entry's name is only its schedule; show what it runs too.
        const label = (x: (typeof flagged)[number]) => (x.kind === "cron" && x.command ? `${x.name} ${x.command}`.slice(0, 120) : x.name);
        for (const x of flagged) for (const e of x.endpoints) add(e.agentId, `${x.verdict ? "Malicious" : "Suspicious"} persistence: ${label(x)}`);
        const unapproved = r.filter((x) => !x.approved);
        for (const x of unapproved) for (const e of x.endpoints) add(e.agentId, `Unapproved remote access: ${x.tool.name}`);
        const byId = new Map(p.endpoints.map((e) => [e.agentId, e]));
        const hostname = new Map(agents.rows.map((a) => [String(a.id), String(a.hostname)]));
        const failing = h.checks.filter((c) => c.failing > 0 && !c.exception).sort((a, b) => b.failing - a.failing);
        out.push({
          organizationId,
          asOf: new Date(at).toISOString().slice(0, 10),
          endpoints: agents.rows.length,
          reporting: agents.rows.filter((a) => a.reported).length,
          offline: agents.rows.filter((a) => !a.last_checkin_at || at - new Date(String(a.last_checkin_at)).getTime() > 86_400_000).length,
          antivirus: {
            protected: agents.rows.filter((a) => a.antivirus_status === "protected").length,
            unhealthy: agents.rows.filter((a) => a.antivirus_status === "unhealthy").length,
            unmanaged: agents.rows.filter((a) => a.antivirus_status === "unmanaged" && a.reported).length,
          },
          patching: { current: p.summary.current, behind: p.summary.behind, breached: p.summary.breached, unknown: p.summary.unknown, securityUpdates: p.summary.securityUpdates, rebootPending: p.summary.rebootPending },
          unsupportedOs: p.endpoints.filter((e) => e.osSupport.status === "ended").map((e) => ({ hostname: e.hostname, os: e.os ?? e.osSupport.product, product: e.osSupport.product, endsOn: e.osSupport.endsOn })),
          hardeningScore: h.score,
          weakestChecks: failing.slice(0, 10).map((c) => ({ title: HARDENING_CHECKS.find((k) => k.key === c.key)?.title ?? c.key, failing: c.failing })),
          footholds: {
            suspicious: f.summary.suspicious,
            malicious: f.summary.malicious,
            top: flagged.slice(0, 10).map((x) => ({
              name: label(x),
              kind: AUTORUN_KIND_LABELS[x.kind],
              level: x.verdict?.verdict === "malicious" ? "malicious" : x.assessment.level,
              reason: x.assessment.reasons[0]?.text ?? "—",
              endpoints: x.endpointCount,
            })),
          },
          unapprovedRemoteAccess: unapproved.map((x) => ({ tool: x.tool.name, endpoints: x.endpoints.length })),
          needingAttention: issues.size,
          atRisk: [...issues]
            .map(([agentId, list]) => ({ hostname: hostname.get(agentId) ?? byId.get(agentId)?.hostname ?? agentId, os: byId.get(agentId)?.os ?? null, issues: [...new Set(list)] }))
            .sort((a, b) => b.issues.length - a.issues.length || a.hostname.localeCompare(b.hostname))
            .slice(0, 25),
        });
      }
      return out;
    });
  }

  async endpointDetail(q: ReportQuery, assetId: string): Promise<EndpointDetail | null> {
    if (!/^[0-9a-f-]{36}$/i.test(assetId)) return null;
    return this.tx(q, async (tx) => {
      const found = await this.sql(tx, q, `SELECT a.* FROM assets a WHERE a.id = :id::uuid AND ${org("a.organization_id")}`, { id: assetId });
      const r = found[0];
      if (!r) return null;
      const at = Math.min(Date.now(), q.to.getTime());
      const dossier = (await new EndpointDossierService(() => at).build(tx, assetId, { since: q.from.toISOString(), until: q.to.toISOString() }))!;
      const inv = await new HostInventoryService(() => at).forAsset(tx, assetId);
      const [vulns, alerts, incidents] = await inOrder([
        () => tx.query<Row>("SELECT cve, title, severity, cvss, known_exploited, status, first_seen_at FROM vulnerabilities WHERE asset_id = $1 AND status IN ('open', 'in_remediation', 'accepted') ORDER BY risk_score DESC NULLS LAST, id LIMIT 200", [assetId]),
        () => tx.query<Row>("SELECT title, severity, status, source, first_seen_at FROM alerts WHERE asset_id = $1 AND first_seen_at >= $2 AND first_seen_at < $3 ORDER BY first_seen_at DESC LIMIT 200", [assetId, q.from, q.to]),
        () => tx.query<Row>("SELECT number, title, severity, status, detected_at FROM incidents WHERE $1 = ANY(asset_ids) AND detected_at < $3 AND (detected_at >= $2 OR closed_at IS NULL OR closed_at >= $2) ORDER BY detected_at DESC LIMIT 100", [assetId, q.from, q.to]),
      ]);
      const iso = (v: unknown) => new Date(v instanceof Date ? v : String(v)).toISOString();
      return {
        asset: {
          id: String(r.id),
          organizationId: String(r.organization_id),
          name: String(r.name),
          hostname: (r.hostname as string | null) ?? null,
          kind: String(r.kind),
          criticality: r.criticality as Criticality,
          os: (r.os as string | null) ?? null,
          ips: Array.isArray(r.ip_addresses) ? (r.ip_addresses as unknown[]).map(String) : [],
          owner: (r.owner as string | null) ?? null,
          riskScore: r.risk_score == null ? null : Number(r.risk_score),
          internetFacing: r.internet_facing === true,
          lastSeenAt: r.last_seen_at ? iso(r.last_seen_at) : null,
          tags: Array.isArray(r.tags) ? (r.tags as unknown[]).map(String) : [],
        },
        dossier,
        inventory: inv
          ? {
              collectedAt: inv.collectedAt,
              antivirus: inv.antivirus.map((a) => ({ name: a.name, enabled: a.enabled, upToDate: a.upToDate ?? null, realTimeProtection: a.realTimeProtection ?? null, tamperProtection: a.tamperProtection ?? null, signatureAgeDays: a.signatureAgeDays ?? null })),
              antivirusIssues: inv.antivirusIssues,
              firewall: inv.firewall ? { enabled: inv.firewall.enabled, detail: inv.firewall.detail ?? null } : null,
              software: inv.software.map((x) => ({ name: x.name, version: x.version ?? null, publisher: x.publisher ?? null })),
              services: { running: inv.services.filter((x) => x.state === "running").length, total: inv.services.length },
              users: inv.users.map((u) => ({ name: u.name, admin: u.admin === true, enabled: u.enabled !== false, loggedIn: u.loggedIn === true })),
              ports: inv.ports.map((x) => ({ protocol: x.protocol, address: x.address ?? "", port: x.port, process: x.process ?? null })),
            }
          : null,
        vulnerabilities: vulns.rows.map((v) => ({ cve: (v.cve as string | null) ?? null, title: String(v.title), severity: v.severity as Severity, cvss: v.cvss == null ? null : Number(v.cvss), kev: v.known_exploited === true, status: String(v.status), firstSeenAt: iso(v.first_seen_at) })),
        alerts: alerts.rows.map((a) => ({ title: String(a.title), severity: a.severity as Severity, status: String(a.status), source: String(a.source), firstSeenAt: iso(a.first_seen_at) })),
        incidents: incidents.rows.map((i) => ({ number: Number(i.number), title: String(i.title), severity: i.severity as Severity, status: String(i.status), detectedAt: iso(i.detected_at) })),
      };
    });
  }

  async incidentDetail(q: ReportQuery, incidentId: string): Promise<IncidentDetail | null> {
    if (!/^[0-9a-f-]{36}$/i.test(incidentId)) return null;
    return this.tx(q, async (tx) => {
      const found = await this.sql(
        tx,
        q,
        `SELECT i.*, coalesce(u.display_name, u.email) AS assignee_name FROM incidents i LEFT JOIN users u ON u.id = i.assignee_id WHERE i.id = :id::uuid AND ${org("i.organization_id")}`,
        { id: incidentId },
      );
      const r = found[0];
      if (!r) return null;
      const [timeline, assets, identities, indicators, actions, evidence, notes] = await inOrder([
        () => tx.query<Row>(
          `SELECT at, kind, title, actor_id FROM timeline_entries t WHERE t.investigation_id IN (SELECT id FROM investigations WHERE incident_id = $1)
           UNION ALL SELECT a.first_seen_at, 'alert', a.title, 'system:pipeline' FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.id WHERE ia.incident_id = $1
             AND NOT EXISTS (SELECT 1 FROM investigations v WHERE v.incident_id = $1)
           UNION ALL SELECT l.at, 'audit', l.action, coalesce(l.actor_label, l.actor_id) FROM audit_log l WHERE l.target_kind = 'incident' AND l.target_id = $1::text AND l.outcome = 'success'
           ORDER BY 1 LIMIT 500`,
          [incidentId],
        ),
        () => tx.query<Row>("SELECT name, kind, criticality, risk_score FROM assets WHERE id = ANY($1::uuid[])", [(r.asset_ids as string[]) ?? []]),
        () => tx.query<Row>("SELECT principal, provider, privileged, mfa_enabled FROM identities WHERE id = ANY($1::uuid[])", [(r.identity_ids as string[]) ?? []]),
        () => tx.query<Row>(
          `SELECT DISTINCT i.type, i.value, i.source FROM indicator_matches m JOIN indicators i ON i.id = m.indicator_id
           WHERE m.alert_id IN (SELECT alert_id FROM incident_alerts WHERE incident_id = $1) LIMIT 200`,
          [incidentId],
        ),
        () => tx.query<Row>("SELECT action, status, target, requested_by, approved_by, created_at FROM response_actions WHERE incident_id = $1 ORDER BY created_at", [incidentId]),
        () => tx.query<Row>("SELECT e.name, e.kind, e.sha256, e.collected_by, e.created_at FROM evidence e JOIN investigations v ON v.id = e.investigation_id WHERE v.incident_id = $1 ORDER BY e.created_at", [incidentId]),
        () => tx.query<Row>("SELECT body FROM notes WHERE incident_id = $1 AND body ~* '^(root cause|lessons? learned)' ORDER BY created_at", [incidentId]),
      ]);
      const bodies = notes.rows.map((x) => String(x.body));
      const rootCause = bodies.find((b) => /^root cause/i.test(b))?.replace(/^root cause\s*[:\-—]?\s*/i, "") ?? null;
      const lessons = bodies.filter((b) => /^lessons? learned/i.test(b)).map((b) => b.replace(/^lessons? learned\s*[:\-—]?\s*/i, ""));
      return {
        incident: { ...this.incidentFact(r), summary: (r.summary as string | null) ?? null },
        timeline: timeline.rows.map((t) => ({ at: String(t.at), kind: String(t.kind), title: String(t.title), actor: (t.actor_id as string | null) ?? null })),
        assets: assets.rows.map((a) => ({ name: String(a.name), kind: String(a.kind), criticality: a.criticality as Criticality, riskScore: nn(a.risk_score) })),
        identities: identities.rows.map((i) => ({ principal: String(i.principal), provider: String(i.provider), privileged: Boolean(i.privileged), mfaEnabled: Boolean(i.mfa_enabled) })),
        indicators: indicators.rows.map((i) => ({ type: String(i.type), value: String(i.value), source: (i.source as string | null) ?? null })),
        actions: actions.rows.map((a) => ({
          action: String(a.action),
          status: String(a.status),
          target: String((a.target as { label?: string; id?: string } | null)?.label ?? (a.target as { id?: string } | null)?.id ?? ""),
          requestedBy: String(a.requested_by),
          approvedBy: (a.approved_by as string | null) ?? null,
          at: String(a.created_at),
        })),
        evidence: evidence.rows.map((e) => ({ name: String(e.name), kind: String(e.kind), sha256: String(e.sha256), collectedBy: String(e.collected_by), at: String(e.created_at) })),
        rootCause,
        lessonsLearned: lessons,
      };
    });
  }
}
