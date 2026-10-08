import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { SEVERITY_RANK, Uuid, type CommandCenterSummary, type Severity, type TriageItem } from "@bloody/contracts";
import { DNS_BEACONING, isCrownJewel, type AttackPathAnalysis, type ExposureAssessment } from "@bloody/engines";
import { requireAuth, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { inOrder, type Queryable } from "../db/pool.js";
import type { Row } from "../repo/mappers.js";
import { attackPathCandidates, exposureInputsFor, loadPosture, sumPosture, type OrgPosture } from "../services/posture.js";
import { loadOne, parse } from "./util.js";

const Query = z.object({
  organizationId: Uuid.optional(),
  windowDays: z.coerce.number().int().min(1).max(365).default(30),
});

type Recommendation = CommandCenterSummary["recommendations"][number];

/** The DTO plus the explanations behind its scores (extensions the UI may render). */
export interface CommandCenterSummaryView extends CommandCenterSummary {
  cloudPosture: CommandCenterSummary["cloudPosture"] & { evaluatedControls: number };
  explanations: {
    exposure: Pick<ExposureAssessment, "score" | "severity" | "summary" | "factors" | "domains" | "modelVersion">;
    identityRisk: { method: string; topIdentities: Array<{ id: string; principal: string; organizationId: string; riskScore: number }> };
    mttd: { method: string; incidents: number };
    mttr: { method: string; incidents: number };
  };
  organizations: number;
}

const n = (v: unknown): number => (v === null || v === undefined ? 0 : Number(v));
const rank = (s: string): number => SEVERITY_RANK[s as Severity] ?? 0;

function orgFilter(column: string, orgs: string[] | null, params: unknown[]): string {
  if (orgs === null) return "TRUE";
  params.push(orgs);
  return `${column} = ANY($${params.length}::uuid[])`;
}

async function attackPathAnalyses(s: AppServices, tenantId: string, posture: Map<string, OrgPosture>): Promise<Map<string, AttackPathAnalysis>> {
  const out = new Map<string, AttackPathAnalysis>();
  for (const org of attackPathCandidates(posture)) out.set(org, await s.attackPaths.analyze(tenantId, org));
  return out;
}

function recommendationsFrom(p: OrgPosture, cc: { escalationsOverdue: number; unassignedCritical: number; avAttention: number; firewallDisabled: number }, paths: Map<string, AttackPathAnalysis>, orgNames: Map<string, string>): Recommendation[] {
  const recs: Recommendation[] = [];
  const plural = (count: number, one: string, many: string) => `${count} ${count === 1 ? one : many}`;
  if (p.vulns.knownExploited > 0) {
    recs.push({
      id: "vuln.patch-known-exploited",
      title: `Patch ${plural(p.vulns.knownExploited, "known-exploited vulnerability", "known-exploited vulnerabilities")}${p.vulns.kevInternetFacing > 0 ? ` (${p.vulns.kevInternetFacing} on internet-facing assets)` : ""}`,
      impact: p.vulns.kevInternetFacing > 0 || p.vulns.kevCrownJewel > 0 ? "critical" : "high",
      module: "vuln",
    });
  }
  for (const [org, analysis] of paths) {
    const top = analysis.remediations[0];
    if (!top || top.pathsBroken === 0) continue;
    const crown = analysis.paths.filter((x) => isCrownJewel(x.target)).length;
    recs.push({
      id: `espm.attack-path.${org}.${top.nodeId ?? top.edgeId ?? "cut"}`,
      title: `${top.action} — breaks ${plural(top.pathsBroken, "attack path", "attack paths")}${orgNames.size > 1 ? ` in ${orgNames.get(org) ?? "organization"}` : ""}`,
      impact: crown > 0 ? "critical" : "high",
      module: "espm",
    });
  }
  if (p.identities.privilegedWithoutMfa > 0) {
    recs.push({ id: "ispm.enforce-mfa-privileged", title: `Enforce MFA on ${plural(p.identities.privilegedWithoutMfa, "privileged identity", "privileged identities")}`, impact: "high", module: "ispm" });
  }
  if (cc.unassignedCritical > 0) {
    recs.push({ id: "xdr.assign-critical-incidents", title: `Assign an owner to ${plural(cc.unassignedCritical, "unassigned critical incident", "unassigned critical incidents")}`, impact: "high", module: "xdr" });
  }
  if (cc.escalationsOverdue > 0) {
    recs.push({ id: "command_center.overdue-escalations", title: `Follow up ${plural(cc.escalationsOverdue, "overdue escalation", "overdue escalations")}`, impact: "high", module: "command_center" });
  }
  if (p.agents.unresponsive > 0) {
    recs.push({ id: "edr.unresponsive-agents", title: `Restore ${plural(p.agents.unresponsive, "unresponsive agent", "unresponsive agents")} (no check-in for 24 h)`, impact: "medium", module: "edr" });
  }
  if (p.assets.unmanagedInternetFacing > 0) {
    recs.push({ id: "asm.unmanaged-internet-facing", title: `Deploy an agent on ${plural(p.assets.unmanagedInternetFacing, "internet-facing asset", "internet-facing assets")} without endpoint coverage`, impact: "medium", module: "asm" });
  }
  if (p.vulns.overdueSla > 0) {
    recs.push({ id: "vuln.overdue-sla", title: `Remediate ${plural(p.vulns.overdueSla, "vulnerability", "vulnerabilities")} past the remediation SLA`, impact: "medium", module: "vuln" });
  }
  if (cc.avAttention > 0) {
    recs.push({ id: "edr.antivirus-attention", title: `Fix antivirus on ${plural(cc.avAttention, "endpoint", "endpoints")} reporting unhealthy or unmanaged protection`, impact: "medium", module: "edr" });
  }
  if (p.identities.dormantPrivileged > 0) {
    recs.push({ id: "ispm.dormant-privileged", title: `Disable or review ${plural(p.identities.dormantPrivileged, "dormant privileged account", "dormant privileged accounts")} (90 days inactive)`, impact: "medium", module: "ispm" });
  }
  if (cc.firewallDisabled > 0) {
    recs.push({ id: "espm.host-firewall", title: `Enable the host firewall on ${plural(cc.firewallDisabled, "endpoint", "endpoints")}`, impact: "low", module: "espm" });
  }
  return recs.sort((a, b) => rank(b.impact) - rank(a.impact)).slice(0, 10);
}

async function triageFeed(tx: Queryable, orgs: string[] | null): Promise<TriageItem[]> {
  const p1: unknown[] = [];
  const p2: unknown[] = [];
  const p3: unknown[] = [];
  const [incidents, escalations, alerts] = await inOrder([
    () => tx.query<Row>(
      `SELECT i.id, i.title, i.number, i.severity, i.status, i.organization_id, o.name AS organization_name, i.detected_at AS at
       FROM incidents i JOIN organizations o ON o.id = i.organization_id
       WHERE ${orgFilter("i.organization_id", orgs, p1)} AND i.status IN ('new', 'triage') AND i.merged_into IS NULL
       ORDER BY ${"(CASE i.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)"} DESC, i.detected_at DESC LIMIT 20`,
      p1,
    ),
    () => tx.query<Row>(
      `SELECT e.id, e.title, e.severity, e.status, e.organization_id, o.name AS organization_name, e.due_at, e.created_at AS at, (e.due_at < now()) AS overdue
       FROM escalations e JOIN organizations o ON o.id = e.organization_id
       WHERE ${orgFilter("e.organization_id", orgs, p2)} AND e.status <> 'resolved'
       ORDER BY e.due_at LIMIT 20`,
      p2,
    ),
    () => tx.query<Row>(
      `SELECT a.id, a.title, a.severity, a.status, a.organization_id, o.name AS organization_name, a.last_seen_at AS at
       FROM alerts a JOIN organizations o ON o.id = a.organization_id
       WHERE ${orgFilter("a.organization_id", orgs, p3)} AND a.incident_id IS NULL AND a.status = 'new' AND a.severity IN ('high', 'critical')
         AND a.last_seen_at > now() - interval '24 hours'
       ORDER BY a.last_seen_at DESC LIMIT 20`,
      p3,
    ),
  ]);
  const items: TriageItem[] = [
    ...incidents.rows.map((r): TriageItem => ({
      id: String(r.id),
      kind: "incident",
      title: `#${String(r.number)} ${String(r.title)}`,
      severity: r.severity as Severity,
      organizationId: String(r.organization_id),
      organizationName: String(r.organization_name),
      at: String(r.at),
      status: String(r.status),
    })),
    ...escalations.rows.map((r): TriageItem => ({
      id: String(r.id),
      kind: "escalation",
      title: String(r.title),
      severity: r.severity as Severity,
      organizationId: String(r.organization_id),
      organizationName: String(r.organization_name),
      at: String(r.at),
      status: r.overdue ? "overdue" : String(r.status),
    })),
    ...alerts.rows.map((r): TriageItem => ({
      id: String(r.id),
      kind: "alert",
      title: String(r.title),
      severity: r.severity as Severity,
      organizationId: String(r.organization_id),
      organizationName: String(r.organization_name),
      at: String(r.at),
      status: String(r.status),
    })),
  ];
  // Overdue escalations first, then severity, then most recent.
  return items
    .sort((a, b) => Number(b.status === "overdue") - Number(a.status === "overdue") || rank(b.severity) - rank(a.severity) || b.at.localeCompare(a.at))
    .slice(0, 25);
}

/**
 * GET /command-center/summary — the whole main dashboard in one round-trip. Every counter is a
 * SQL aggregation over the tenant's records within the caller's organization scope; scores come
 * from the Risk Engine with their explanations attached under `explanations`.
 */
export async function commandCenterRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  app.get("/command-center/summary", async (request): Promise<CommandCenterSummaryView> => {
    const auth = requireAuth(request);
    const q = parse(Query, request.query);
    const orgs = resolveOrgFilter(request, "incident:read", q.organizationId);
    const since = new Date(s.now() - q.windowDays * 86_400_000).toISOString();

    const data = await s.db.withTenant(auth.tenantId, async (tx) => {
      // An organization of another tenant is invisible under RLS: report it as unknown.
      if (q.organizationId) await loadOne(tx, "organizations", q.organizationId, "Organization");
      const posture = await loadPosture(tx, orgs);
      const orgNames = new Map(
        (await tx.query<{ id: string; name: string }>(`SELECT id, name FROM organizations WHERE id = ANY($1::uuid[])`, [[...posture.keys()]])).rows.map((r) => [r.id, r.name]),
      );
      const scopeIds = [...posture.keys()];
      const q1 = (sql: string, extra: unknown[] = []) => tx.query<Row>(sql, [scopeIds, since, ...extra]);
      const [incidents, soc, esc, mttd, mttr, av, fw, idRisk, topIds, network, beacons, intel, cloud, ai, automation, unassigned] = await inOrder([
        () => q1(
          `SELECT
             count(*) FILTER (WHERE severity = 'critical') AS critical,
             count(*) FILTER (WHERE severity = 'high') AS high,
             count(*) FILTER (WHERE severity = 'medium') AS medium,
             count(*) FILTER (WHERE severity IN ('low', 'info')) AS low,
             count(*) AS total,
             count(*) FILTER (WHERE cardinality(asset_ids) > 0) AS endpoint,
             count(*) FILTER (WHERE cardinality(identity_ids) > 0) AS identity
           FROM incidents WHERE organization_id = ANY($1::uuid[]) AND status IN ('new', 'triage', 'investigating', 'contained') AND merged_into IS NULL AND $2::text IS NOT NULL`,
        ),
        () => q1(
          `SELECT
             (SELECT count(*) FROM events WHERE organization_id = ANY($1::uuid[]) AND occurred_at >= $2::timestamptz) AS events,
             (SELECT count(*) FROM alerts WHERE organization_id = ANY($1::uuid[]) AND created_at >= $2::timestamptz) AS signals,
             (SELECT count(*) FROM investigations WHERE organization_id = ANY($1::uuid[]) AND (created_at >= $2::timestamptz OR status <> 'closed')) AS investigations,
             (SELECT count(*) FROM incidents WHERE organization_id = ANY($1::uuid[]) AND detected_at >= $2::timestamptz AND merged_into IS NULL) AS incidents`,
        ),
        () => q1(
          `SELECT
             count(*) FILTER (WHERE status <> 'resolved') AS open,
             count(*) FILTER (WHERE status <> 'resolved' AND due_at < now()) AS overdue,
             count(*) FILTER (WHERE status = 'resolved' AND resolved_at >= $2::timestamptz) AS resolved
           FROM escalations WHERE organization_id = ANY($1::uuid[])`,
        ),
        () => q1(
          `SELECT avg(extract(epoch FROM (detected_at - first_seen_at)) / 60) AS minutes, count(*) AS n
           FROM incidents WHERE organization_id = ANY($1::uuid[]) AND detected_at >= $2::timestamptz AND first_seen_at IS NOT NULL
             AND first_seen_at <= detected_at AND merged_into IS NULL AND status <> 'false_positive'`,
        ),
        () => q1(
          `SELECT avg(extract(epoch FROM (coalesce(contained_at, remediated_at, closed_at) - detected_at)) / 60) AS minutes, count(*) AS n
           FROM incidents WHERE organization_id = ANY($1::uuid[]) AND coalesce(contained_at, remediated_at, closed_at) >= $2::timestamptz
             AND merged_into IS NULL AND status <> 'false_positive'`,
        ),
        () => q1(
          `SELECT count(*) FILTER (WHERE antivirus_status = 'protected') AS protected, count(*) FILTER (WHERE antivirus_status = 'unhealthy') AS unhealthy,
                  count(*) FILTER (WHERE antivirus_status = 'unmanaged') AS unmanaged, count(*) FILTER (WHERE antivirus_status = 'incompatible') AS incompatible
           FROM agents WHERE organization_id = ANY($1::uuid[]) AND $2::text IS NOT NULL`,
        ),
        () => q1(`SELECT count(*) FILTER (WHERE firewall_enabled) AS enabled, count(*) FILTER (WHERE NOT firewall_enabled) AS disabled FROM agents WHERE organization_id = ANY($1::uuid[]) AND $2::text IS NOT NULL`),
        () => q1(
          `SELECT percentile_cont(0.9) WITHIN GROUP (ORDER BY risk_score) AS p90, count(*) FILTER (WHERE risk_score >= 70) AS risky
           FROM identities WHERE organization_id = ANY($1::uuid[]) AND enabled AND risk_score IS NOT NULL AND $2::text IS NOT NULL`,
        ),
        () => q1(
          `SELECT id, principal, organization_id, risk_score FROM identities
           WHERE organization_id = ANY($1::uuid[]) AND enabled AND risk_score IS NOT NULL AND $2::text IS NOT NULL ORDER BY risk_score DESC, id LIMIT 5`,
        ),
        () => q1(
          `SELECT count(*) AS sensors, count(*) FILTER (WHERE last_at > now() - interval '1 hour') AS healthy FROM (
             SELECT coalesce(sensor_id, source_product) AS sensor, max(received_at) AS last_at
             FROM events WHERE organization_id = ANY($1::uuid[]) AND source_kind = 'network' AND occurred_at >= $2::timestamptz
             GROUP BY 1) x`,
        ),
        () => q1(
          `SELECT count(DISTINCT coalesce(asset_id::text, entities->0->>'key')) AS hosts FROM alerts
           WHERE organization_id = ANY($1::uuid[]) AND rule_id = $3 AND last_seen_at >= $2::timestamptz`,
          [DNS_BEACONING.id],
        ),
        () => q1(`SELECT count(*) AS n FROM indicator_matches WHERE organization_id = ANY($1::uuid[]) AND matched_at >= $2::timestamptz`),
        () => q1(
          `SELECT count(*) AS evaluated, count(*) FILTER (WHERE outcome = 'failure') AS failing FROM (
             SELECT DISTINCT ON (coalesce(asset_hostname, ''), coalesce(doc->'labels'->>'control', event_type)) outcome
             FROM events WHERE organization_id = ANY($1::uuid[]) AND category IN ('configuration', 'cloud') AND outcome IN ('success', 'failure')
               AND occurred_at >= $2::timestamptz
             ORDER BY coalesce(asset_hostname, ''), coalesce(doc->'labels'->>'control', event_type), occurred_at DESC) x`,
        ),
        () => q1(
          `SELECT (SELECT count(*) FROM ai_conversations WHERE organization_id = ANY($1::uuid[]) AND created_at >= $2::timestamptz) AS conversations,
                  (SELECT count(*) FROM ai_actions WHERE organization_id = ANY($1::uuid[]) AND at >= $2::timestamptz AND tier IN ('recommend', 'require_approval', 'execute')) AS proposed,
                  (SELECT count(*) FROM ai_actions WHERE organization_id = ANY($1::uuid[]) AND at >= $2::timestamptz AND approved_by IS NOT NULL) AS approved`,
        ),
        () => q1(
          `SELECT (SELECT count(*) FROM playbook_runs WHERE organization_id = ANY($1::uuid[]) AND started_at >= $2::timestamptz) AS runs,
                  (SELECT count(*) FROM playbook_runs WHERE organization_id = ANY($1::uuid[]) AND started_at >= $2::timestamptz AND status = 'succeeded') AS succeeded,
                  (SELECT count(*) FROM response_actions WHERE organization_id = ANY($1::uuid[]) AND status = 'pending_approval')
                + (SELECT count(*) FROM playbook_runs WHERE organization_id = ANY($1::uuid[]) AND status = 'waiting_approval') AS pending`,
        ),
        () => q1(`SELECT count(*) AS n FROM incidents WHERE organization_id = ANY($1::uuid[]) AND severity = 'critical' AND assignee_id IS NULL AND status IN ('new', 'triage', 'investigating', 'contained') AND merged_into IS NULL AND $2::text IS NOT NULL`),
      ]);
      const triage = await triageFeed(tx, orgs);
      return { posture, orgNames, incidents: incidents.rows[0]!, soc: soc.rows[0]!, esc: esc.rows[0]!, mttd: mttd.rows[0]!, mttr: mttr.rows[0]!, av: av.rows[0]!, fw: fw.rows[0]!, idRisk: idRisk.rows[0]!, topIds: topIds.rows, network: network.rows[0]!, beacons: beacons.rows[0]!, intel: intel.rows[0]!, cloud: cloud.rows[0]!, ai: ai.rows[0]!, automation: automation.rows[0]!, unassigned: unassigned.rows[0]!, triage };
    });

    const total = sumPosture(data.posture.values());
    const paths = await attackPathAnalyses(s, auth.tenantId, data.posture);
    let pathTotal = 0;
    let pathCrown = 0;
    for (const a of paths.values()) {
      pathTotal += a.paths.length;
      pathCrown += a.paths.filter((p) => isCrownJewel(p.target)).length;
    }
    const exposure = s.risk.exposureScore(exposureInputsFor(total, { total: pathTotal, toCrownJewels: pathCrown }, data.posture.size === 1 ? data.orgNames.values().next().value : undefined));
    const evaluated = n(data.cloud.evaluated);
    const failing = n(data.cloud.failing);
    const avAttention = n(data.av.unhealthy) + n(data.av.unmanaged);
    const round1 = (v: unknown) => (v === null || v === undefined ? null : Math.round(Number(v) * 10) / 10);

    return {
      generatedAt: new Date(s.now()).toISOString(),
      organizationId: q.organizationId ?? null,
      windowDays: q.windowDays,
      organizations: data.posture.size,
      activeIncidents: {
        critical: n(data.incidents.critical),
        high: n(data.incidents.high),
        medium: n(data.incidents.medium),
        low: n(data.incidents.low),
        total: n(data.incidents.total),
        byAssetType: { endpoint: n(data.incidents.endpoint), identity: n(data.incidents.identity) },
      },
      socActions: { eventsAnalyzed: n(data.soc.events), signalsGenerated: n(data.soc.signals), investigations: n(data.soc.investigations), incidentsReported: n(data.soc.incidents) },
      escalations: { open: n(data.esc.open), overdue: n(data.esc.overdue), resolved: n(data.esc.resolved) },
      mttdMinutes: round1(data.mttd.minutes),
      mttrMinutes: round1(data.mttr.minutes),
      agents: { total: total.agents.total, protected: total.agents.protected, unresponsive: total.agents.unresponsive, outdated: total.agents.outdated, isolated: total.agents.isolated },
      antivirus: { protected: n(data.av.protected), unhealthy: n(data.av.unhealthy), unmanaged: n(data.av.unmanaged), incompatible: n(data.av.incompatible) },
      firewall: { enabled: n(data.fw.enabled), disabled: n(data.fw.disabled) },
      identityRisk: { score: Math.round(n(data.idRisk.p90)), riskyIdentities: n(data.idRisk.risky), privilegedWithoutMfa: total.identities.privilegedWithoutMfa },
      exposureScore: exposure.score,
      vulnerabilities: { critical: total.vulns.critical, high: total.vulns.high, knownExploited: total.vulns.knownExploited, overdueSla: total.vulns.overdueSla },
      cloudPosture: { score: evaluated === 0 ? 100 : Math.round((100 * (evaluated - failing)) / evaluated), failingControls: failing, evaluatedControls: evaluated },
      networkHealth: { sensors: n(data.network.sensors), healthy: n(data.network.healthy), beaconingHosts: n(data.beacons.hosts) },
      intelMatches: n(data.intel.n),
      attackPaths: { total: pathTotal, toCrownJewels: pathCrown },
      recommendations: recommendationsFrom(total, { escalationsOverdue: n(data.esc.overdue), unassignedCritical: n(data.unassigned.n), avAttention, firewallDisabled: n(data.fw.disabled) }, paths, data.orgNames),
      triage: data.triage,
      aiActivity: { conversations: n(data.ai.conversations), actionsProposed: n(data.ai.proposed), actionsApproved: n(data.ai.approved) },
      automation: { runs: n(data.automation.runs), succeeded: n(data.automation.succeeded), pendingApproval: n(data.automation.pending) },
      explanations: {
        exposure: { score: exposure.score, severity: exposure.severity, summary: exposure.summary, factors: exposure.factors, domains: exposure.domains, modelVersion: exposure.modelVersion },
        identityRisk: {
          method: "90th percentile of enabled identities' risk scores (Risk Engine); risky = score ≥ 70",
          topIdentities: data.topIds.map((r) => ({ id: String(r.id), principal: String(r.principal), organizationId: String(r.organization_id), riskScore: n(r.risk_score) })),
        },
        mttd: { method: "mean(detected_at − first malicious activity) over incidents detected in the window", incidents: n(data.mttd.n) },
        mttr: { method: "mean(first containment / remediation / closure − detected_at) over incidents responded to in the window", incidents: n(data.mttr.n) },
      },
    };
  });
}
