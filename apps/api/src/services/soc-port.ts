import { randomUUID } from "node:crypto";
import {
  SEVERITY_RANK,
  type Alert,
  type AttackPath,
  type CanonicalEvent,
  type GraphNode,
  type Incident,
  type Indicator,
  type NotificationChannel,
  type Playbook,
  type ResponseActionRecord,
  type RiskAssessment,
  type Subgraph,
  type TimelineEntry,
  type Vulnerability,
} from "@bloody/contracts";
import type {
  AlertFilter,
  AssetDetail,
  AttackPathQuery,
  BlastRadiusResult,
  EventSearchInput as PortSearchInput,
  EventSearchResult as PortSearchResult,
  GraphNeighborsInput,
  HuntInput,
  HuntResult,
  IdentityDetail,
  IncidentDetail,
  IncidentFilter,
  IntelSearchInput,
  IntelSearchResult,
  InvestigationDetail,
  InvestigationNoteInput,
  ReportData as PortReportData,
  ReportDataInput,
  RiskEntityKind,
  RuleValidation,
  SendNotificationInput,
  SocDataPort,
  SocScope,
  SubmitResponseActionInput,
} from "@bloody/ai";
import { ASSET_NODE_KINDS, isCrownJewel, sigmaToRule, validateRule } from "@bloody/engines";
import { buildReport } from "@bloody/reporting";
import { resolveEffectivePlaybooks } from "@bloody/automation";
import { SYSTEM_ACTOR } from "../audit/audit.js";
import type { Database, Queryable } from "../db/pool.js";
import { PostgresGraphStore } from "../graph/postgres-store.js";
import { likePattern } from "../http/params.js";
import { toAgent, toAlert, toAsset, toEvidence, toIdentity, toIncident, toIndicator, toInvestigation, toTimelineEntry, toVulnerability, type Row } from "../repo/mappers.js";
import type { AttackPathService } from "./attack-paths.js";
import type { DetectionService } from "./detections.js";
import type { EventSearchService } from "./event-search.js";
import type { GraphQueries } from "./graph-queries.js";
import { graphFor } from "./inventory.js";
import type { NotificationService } from "./notifications.js";
import type { ReportService } from "./reports.js";
import type { ResponseService } from "./response.js";
import { toChannel } from "./notifications.js";
import { toPlaybook } from "./soar.js";

/**
 * The AI SOC's data port (`@bloody/ai` SocDataPort) on Bloody's repositories. Every method is
 * bound to `scope.tenantId` (RLS transaction) AND `scope.organizationId`: anything outside the
 * conversation's organization is reported as not found / empty, never leaked. The scope always
 * comes from the authenticated principal — never from model output.
 */

const ACTIVE = ["new", "triage", "investigating", "contained"];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (v: unknown): v is string => typeof v === "string" && UUID_RE.test(v);

export interface SocPortDeps {
  db: Database;
  graph: GraphQueries;
  attackPaths: AttackPathService;
  eventSearch: EventSearchService;
  detections: DetectionService;
  responses: ResponseService;
  notifications: NotificationService;
  reports: ReportService;
  now: () => number;
}

export class PgSocDataPort implements SocDataPort {
  constructor(private readonly deps: SocPortDeps) {}

  private tx<T>(scope: SocScope, fn: (tx: Queryable) => Promise<T>): Promise<T> {
    return this.deps.db.withTenant(scope.tenantId, fn);
  }

  // ─── Incidents & alerts ──────────────────────────────────────────────────

  async getIncident(scope: SocScope, id: string, opts: { includeAlerts: boolean; includeTimeline: boolean }): Promise<IncidentDetail | null> {
    if (!isUuid(id)) return null;
    return this.tx(scope, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM incidents WHERE id = $1 AND organization_id = $2", [id, scope.organizationId]);
      if (!rows[0]) return null;
      const alerts = opts.includeAlerts
        ? (await tx.query<Row>("SELECT a.* FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.id WHERE ia.incident_id = $1 ORDER BY a.first_seen_at LIMIT 200", [id])).rows.map(toAlert)
        : [];
      const investigations = (await tx.query<Row>("SELECT * FROM investigations WHERE incident_id = $1 ORDER BY created_at", [id])).rows.map(toInvestigation);
      const timeline = opts.includeTimeline && investigations.length > 0
        ? (await tx.query<Row>("SELECT * FROM timeline_entries WHERE investigation_id = ANY($1::uuid[]) ORDER BY at LIMIT 300", [investigations.map((v) => v.id)])).rows.map(toTimelineEntry)
        : [];
      return { incident: toIncident(rows[0]), alerts, investigations, timeline };
    });
  }

  async listIncidents(scope: SocScope, f: IncidentFilter): Promise<Incident[]> {
    return this.tx(scope, async (tx) => {
      const params: unknown[] = [scope.organizationId];
      const where = ["organization_id = $1", "merged_into IS NULL"];
      if (f.status?.length) where.push(`status = ANY($${params.push(f.status)}::text[])`);
      if (f.severity?.length) where.push(`severity = ANY($${params.push(f.severity)}::text[])`);
      if (f.query) {
        const num = /^#?(\d{1,9})$/.exec(f.query.trim());
        if (num) where.push(`number = $${params.push(Number(num[1]))}`);
        else where.push(`(title ILIKE $${params.push(likePattern(f.query))} OR summary ILIKE $${params.length})`);
      }
      if (isUuid(f.assetId)) where.push(`$${params.push(f.assetId)}::uuid = ANY(asset_ids)`);
      if (isUuid(f.identityId)) where.push(`$${params.push(f.identityId)}::uuid = ANY(identity_ids)`);
      if (f.since) where.push(`detected_at >= $${params.push(f.since)}::timestamptz`);
      params.push(Math.min(Math.max(f.limit, 1), 200));
      const { rows } = await tx.query<Row>(`SELECT * FROM incidents WHERE ${where.join(" AND ")} ORDER BY detected_at DESC LIMIT $${params.length}`, params);
      return rows.map(toIncident);
    });
  }

  async getAlert(scope: SocScope, id: string): Promise<Alert | null> {
    if (!isUuid(id)) return null;
    return this.tx(scope, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM alerts WHERE id = $1 AND organization_id = $2", [id, scope.organizationId]);
      return rows[0] ? toAlert(rows[0]) : null;
    });
  }

  async listAlerts(scope: SocScope, f: AlertFilter): Promise<Alert[]> {
    return this.tx(scope, async (tx) => {
      const params: unknown[] = [scope.organizationId, f.since];
      const where = ["organization_id = $1", "last_seen_at >= $2::timestamptz"];
      if (isUuid(f.incidentId)) where.push(`incident_id = $${params.push(f.incidentId)}`);
      if (isUuid(f.assetId)) where.push(`asset_id = $${params.push(f.assetId)}`);
      if (isUuid(f.identityId)) where.push(`identity_id = $${params.push(f.identityId)}`);
      if (f.severityAtLeast) {
        const allowed = (["info", "low", "medium", "high", "critical"] as const).filter((s) => SEVERITY_RANK[s] >= SEVERITY_RANK[f.severityAtLeast!]);
        where.push(`severity = ANY($${params.push(allowed)}::text[])`);
      }
      params.push(Math.min(Math.max(f.limit, 1), 500));
      const { rows } = await tx.query<Row>(`SELECT * FROM alerts WHERE ${where.join(" AND ")} ORDER BY last_seen_at DESC LIMIT $${params.length}`, params);
      return rows.map(toAlert);
    });
  }

  // ─── Events & hunting ────────────────────────────────────────────────────

  async searchEvents(scope: SocScope, input: PortSearchInput): Promise<PortSearchResult> {
    const res = await this.deps.eventSearch.search(scope.tenantId, [scope.organizationId], { q: input.query, from: input.from, to: input.to, limit: Math.min(Math.max(input.limit, 1), 500) }, { count: true });
    return { events: res.items, total: res.total ?? res.items.length, truncated: res.nextCursor !== null || res.totalCapped };
  }

  async runHunt(scope: SocScope, input: HuntInput): Promise<HuntResult> {
    const limit = Math.min(Math.max(input.limit, 1), 500);
    if (input.language === "sigma") {
      const parsed = sigmaToRule(input.query, { id: `ai-hunt-${randomUUID().slice(0, 8)}` });
      if (!parsed.value) return { queryExecuted: input.query, hits: [], total: 0, truncated: false, aggregations: { errors: parsed.errors.map((e) => ({ key: e, count: 0 })) } };
      const v = validateRule(parsed.value);
      if (!v.valid || !v.rule) return { queryExecuted: input.query, hits: [], total: 0, truncated: false, aggregations: { errors: v.errors.map((e) => ({ key: e, count: 0 })) } };
      const hours = Math.max(1, Math.min(24 * 30, Math.ceil((Date.parse(input.to) - Date.parse(input.from)) / 3_600_000)));
      const out = await this.deps.detections.test(scope.tenantId, [scope.organizationId], v.rule, { lookbackHours: hours, maxEvents: 20_000 });
      const ids = new Set(out.replay.matches.flatMap((m) => m.eventIds));
      const hits = out.events.filter((e) => ids.has(e.id)).slice(0, limit);
      return { queryExecuted: `sigma:${v.rule.id}`, hits, total: ids.size, truncated: out.replay.truncated || ids.size > hits.length, aggregations: {} };
    }
    const search = { q: input.query, from: input.from, to: input.to };
    const res = await this.deps.eventSearch.search(scope.tenantId, [scope.organizationId], { ...search, limit }, { count: true });
    const aggregations = await this.deps.eventSearch.aggregate(scope.tenantId, [scope.organizationId], search, ["asset.hostname", "user.name", "process.name"], 10);
    return { queryExecuted: input.query, hits: res.items, total: res.total ?? res.items.length, truncated: res.nextCursor !== null || res.totalCapped, aggregations };
  }

  // ─── Graph, risk, attack paths ───────────────────────────────────────────

  async graphNeighbors(scope: SocScope, input: GraphNeighborsInput): Promise<Subgraph> {
    const hood = await this.deps.graph.neighbors(scope.tenantId, [scope.organizationId], input.nodeId, {
      depth: Math.min(Math.max(input.depth, 1), 3),
      direction: input.direction,
      ...(input.edgeKinds ? { edgeKinds: input.edgeKinds } : {}),
      limit: Math.min(Math.max(input.limit, 1), 500),
    });
    if (!hood) return { nodes: [], edges: [] };
    return { nodes: [hood.root, ...hood.nodes.map(({ depth: _d, ...n }) => n as GraphNode)], edges: hood.edges };
  }

  async graphBlastRadius(scope: SocScope, input: { nodeId: string; maxDepth: number; limit: number }): Promise<BlastRadiusResult> {
    const r = await this.deps.graph.blastRadius(scope.tenantId, [scope.organizationId], input.nodeId, input.maxDepth, input.limit);
    if (!r) return { nodes: [], edges: [], crownJewels: [] };
    return { nodes: [r.root, ...r.nodes.map((x) => x.node)], edges: [], crownJewels: r.crownJewels.map((n) => n.id) };
  }

  async graphSearch(scope: SocScope, input: { query: string; limit: number }): Promise<GraphNode[]> {
    return this.deps.graph.search(scope.tenantId, [scope.organizationId], { q: input.query, limit: Math.min(Math.max(input.limit, 1), 100) });
  }

  async getAttackPaths(scope: SocScope, input: AttackPathQuery): Promise<AttackPath[]> {
    const a = await this.deps.attackPaths.analyze(scope.tenantId, scope.organizationId);
    const matches = (p: AttackPath) =>
      (!input.assetId || p.target.props?.assetId === input.assetId || p.entry.props?.assetId === input.assetId || p.nodes.some((n) => n.props?.assetId === input.assetId)) &&
      (!input.nodeId || p.nodes.some((n) => n.id === input.nodeId)) &&
      (!input.toCrownJewelsOnly || isCrownJewel(p.target));
    return a.paths
      .filter(matches)
      .slice(0, Math.min(Math.max(input.limit, 1), 50))
      .map((p) => ({ id: p.id, nodes: p.nodes, edges: p.edges, target: p.target, entry: p.entry, risk: p.risk, remediations: p.remediations }));
  }

  async getRiskAssessment(scope: SocScope, input: { entityKind: RiskEntityKind; id: string }): Promise<RiskAssessment | null> {
    if (!isUuid(input.id)) return null;
    const table = { asset: "assets", identity: "identities", incident: "incidents", vulnerability: "vulnerabilities" }[input.entityKind];
    return this.tx(scope, async (tx) => {
      const { rows } = await tx.query<{ risk: RiskAssessment | null }>(`SELECT risk FROM ${table} WHERE id = $1 AND organization_id = $2`, [input.id, scope.organizationId]);
      return rows[0]?.risk ?? null;
    });
  }

  // ─── Entities ────────────────────────────────────────────────────────────

  async getAsset(scope: SocScope, id: string): Promise<AssetDetail | null> {
    if (!isUuid(id)) return null;
    return this.tx(scope, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM assets WHERE id = $1 AND organization_id = $2", [id, scope.organizationId]);
      if (!rows[0]) return null;
      const asset = toAsset(rows[0]);
      const vulns = (await tx.query<Row>("SELECT * FROM vulnerabilities WHERE asset_id = $1 AND status IN ('open', 'in_remediation', 'accepted') ORDER BY risk_score DESC NULLS LAST LIMIT 50", [id])).rows.map(toVulnerability);
      const agentRow = (await tx.query<Row>("SELECT * FROM agents WHERE asset_id = $1 ORDER BY updated_at DESC LIMIT 1", [id])).rows[0];
      const openIncidents = (await tx.query<Row>("SELECT * FROM incidents WHERE $1::uuid = ANY(asset_ids) AND status = ANY($2::text[]) AND merged_into IS NULL ORDER BY detected_at DESC LIMIT 20", [id, ACTIVE])).rows.map(toIncident);
      // Identities with access to the asset, from the Security Graph.
      const store = new PostgresGraphStore(tx, scope.tenantId);
      const [node] = await store.findNodes({ organizationId: scope.organizationId, kind: ASSET_NODE_KINDS, propEquals: { assetId: id }, limit: 1 });
      let identities: AssetDetail["identities"] = [];
      if (node) {
        const reach = await graphFor(tx, scope.tenantId).identitiesReaching(node.id);
        const ids = reach.map((r) => r.node.props?.identityId).filter(isUuid).slice(0, 25);
        if (ids.length) identities = (await tx.query<Row>("SELECT * FROM identities WHERE id = ANY($1::uuid[]) AND organization_id = $2", [ids, scope.organizationId])).rows.map(toIdentity);
      }
      return { asset, risk: (rows[0].risk as RiskAssessment | null) ?? null, vulnerabilities: vulns, agent: agentRow ? toAgent(agentRow) : null, identities, openIncidents };
    });
  }

  async getIdentity(scope: SocScope, id: string): Promise<IdentityDetail | null> {
    if (!isUuid(id)) return null;
    return this.tx(scope, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM identities WHERE id = $1 AND organization_id = $2", [id, scope.organizationId]);
      if (!rows[0]) return null;
      const identity = toIdentity(rows[0]);
      const store = new PostgresGraphStore(tx, scope.tenantId);
      const node = await store.getNodeByKey(scope.organizationId, "identity", `${identity.provider.trim().toLowerCase()}:${identity.principal.trim().toLowerCase()}`);
      let groups: string[] = [];
      if (node) {
        const edges = await store.edgesOf([node.id], { direction: "out", edgeKinds: ["member_of"] });
        groups = (await store.getNodes(edges.map((e) => e.to))).map((g) => g.label).slice(0, 50);
      }
      const auth = await tx.query<{ doc: CanonicalEvent }>(
        "SELECT doc FROM events WHERE organization_id = $1 AND identity_principal = $2 AND category = 'authentication' AND occurred_at > now() - interval '30 days' ORDER BY occurred_at DESC LIMIT 25",
        [scope.organizationId, identity.principal],
      );
      const openIncidents = (await tx.query<Row>("SELECT * FROM incidents WHERE $1::uuid = ANY(identity_ids) AND status = ANY($2::text[]) AND merged_into IS NULL ORDER BY detected_at DESC LIMIT 20", [id, ACTIVE])).rows.map(toIncident);
      return { identity, risk: (rows[0].risk as RiskAssessment | null) ?? null, groups, recentAuthentications: auth.rows.map((r) => r.doc), openIncidents };
    });
  }

  async getInvestigation(scope: SocScope, id: string): Promise<InvestigationDetail | null> {
    if (!isUuid(id)) return null;
    return this.tx(scope, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM investigations WHERE id = $1 AND organization_id = $2", [id, scope.organizationId]);
      if (!rows[0]) return null;
      const timeline = (await tx.query<Row>("SELECT * FROM timeline_entries WHERE investigation_id = $1 ORDER BY at LIMIT 300", [id])).rows.map(toTimelineEntry);
      const evidence = (await tx.query<Row>("SELECT * FROM evidence WHERE investigation_id = $1 ORDER BY created_at", [id])).rows.map(toEvidence);
      return { investigation: toInvestigation(rows[0]), timeline, evidence };
    });
  }

  async listVulnerabilities(scope: SocScope, input: { assetId?: string; limit: number }): Promise<Vulnerability[]> {
    return this.tx(scope, async (tx) => {
      const params: unknown[] = [scope.organizationId];
      const where = ["organization_id = $1", "status IN ('open', 'in_remediation')"];
      if (isUuid(input.assetId)) where.push(`asset_id = $${params.push(input.assetId)}`);
      params.push(Math.min(Math.max(input.limit, 1), 200));
      const { rows } = await tx.query<Row>(`SELECT * FROM vulnerabilities WHERE ${where.join(" AND ")} ORDER BY risk_score DESC NULLS LAST, cvss DESC NULLS LAST LIMIT $${params.length}`, params);
      return rows.map(toVulnerability);
    });
  }

  // ─── Threat intelligence ─────────────────────────────────────────────────

  async searchIntel(scope: SocScope, input: IntelSearchInput): Promise<IntelSearchResult> {
    return this.tx(scope, async (tx) => {
      const params: unknown[] = [scope.organizationId];
      const where = ["(organization_id IS NULL OR organization_id = $1)", "NOT revoked"];
      if (input.value) where.push(`lower(value) = lower($${params.push(input.value.trim())})`);
      if (input.type) where.push(`type = $${params.push(input.type)}`);
      if (input.query) where.push(`(value ILIKE $${params.push(likePattern(input.query))} OR threat_actor ILIKE $${params.length} OR malware ILIKE $${params.length} OR campaign ILIKE $${params.length} OR $${params.length} ILIKE ANY(tags))`);
      params.push(Math.min(Math.max(input.limit, 1), 200));
      const { rows } = await tx.query<Row>(`SELECT * FROM indicators WHERE ${where.join(" AND ")} ORDER BY last_seen_at DESC LIMIT $${params.length}`, params);
      const indicators: Indicator[] = rows.map(toIndicator);
      let matches: IntelSearchResult["matches"] = [];
      if (input.includeMatches && indicators.length > 0) {
        const m = await tx.query<Row>(
          `SELECT m.indicator_id, i.type, i.value, m.asset_id, coalesce(a.name, m.observed_value) AS label, max(m.matched_at) AS last_seen, max(al.incident_id::text) AS incident_id
           FROM indicator_matches m JOIN indicators i ON i.id = m.indicator_id LEFT JOIN assets a ON a.id = m.asset_id LEFT JOIN alerts al ON al.id = m.alert_id
           WHERE m.organization_id = $1 AND m.indicator_id = ANY($2::uuid[])
           GROUP BY m.indicator_id, i.type, i.value, m.asset_id, coalesce(a.name, m.observed_value) ORDER BY last_seen DESC LIMIT 200`,
          [scope.organizationId, indicators.map((i) => i.id)],
        );
        matches = m.rows.map((r) => ({
          indicatorId: String(r.indicator_id),
          type: r.type as Indicator["type"],
          value: String(r.value),
          entity: r.asset_id ? { kind: "asset", id: String(r.asset_id), label: String(r.label) } : { kind: "observable", id: String(r.label), label: String(r.label) },
          lastSeenAt: String(r.last_seen),
          incidentId: (r.incident_id as string | null) ?? null,
        }));
      }
      return { indicators, matches };
    });
  }

  // ─── Detection engineering ───────────────────────────────────────────────

  async validateDetectionRule(scope: SocScope, input: { format: "sigma"; content: string }): Promise<RuleValidation> {
    const parsed = sigmaToRule(input.content, { id: `ai-draft-${randomUUID().slice(0, 8)}` });
    if (!parsed.value) return { valid: false, errors: parsed.errors, warnings: parsed.warnings };
    const v = validateRule(parsed.value);
    if (!v.valid || !v.rule) return { valid: false, errors: [...parsed.errors, ...v.errors], warnings: [...parsed.warnings, ...v.warnings] };
    const out = await this.deps.detections.test(scope.tenantId, [scope.organizationId], v.rule, { lookbackHours: 24, maxEvents: 10_000 });
    return { valid: true, errors: [], warnings: [...parsed.warnings, ...v.warnings], testMatches: out.replay.matched };
  }

  async getReportData(scope: SocScope, input: ReportDataInput): Promise<PortReportData> {
    const days = Math.min(Math.max(Math.floor(input.periodDays), 1), 366);
    const report = await buildReport(
      { type: input.type, tenantId: scope.tenantId, organizationIds: [scope.organizationId], period: { days, endingAt: new Date(this.deps.now()) }, options: input.incidentId ? { incidentId: input.incidentId } : {} },
      { dataSource: this.deps.reports.dataSource, clock: { now: () => new Date(this.deps.now()) } },
    );
    return {
      type: input.type,
      organizationName: report.scope.organizationName,
      period: { from: report.period.from, to: report.period.to },
      metrics: {
        headline: report.summary.headline,
        highlights: report.summary.highlights,
        kpis: report.summary.kpis.map((k) => ({ key: k.key, label: k.label, value: k.value, unit: k.unit, delta: k.delta?.percent ?? null, status: k.status, explanation: k.explanation })),
        sections: report.sections.map((s) => s.title),
        dataQuality: report.dataQuality,
        ...(input.focus ? { focus: input.focus } : {}),
      },
    };
  }

  // ─── SOAR & collaboration ────────────────────────────────────────────────

  async listPlaybooks(scope: SocScope, input: { action?: string }): Promise<Playbook[]> {
    const rows = await this.tx(scope, async (tx) => (await tx.query<Row>("SELECT * FROM playbooks WHERE organization_id IS NULL OR organization_id = $1", [scope.organizationId])).rows);
    return resolveEffectivePlaybooks(rows.map(toPlaybook), scope.tenantId, scope.organizationId)
      .map((e) => e.playbook)
      .filter((p) => p.enabled && (!input.action || p.steps.some((s) => s.action === input.action)));
  }

  /**
   * Called by the gateway when an approved AI action runs (`scope.approvedBy` set): the pending
   * response action created at approval-request time is marked approved and executed. Without a
   * prior record (defensive) a new, gated request is created.
   */
  async submitResponseAction(scope: SocScope, input: SubmitResponseActionInput): Promise<ResponseActionRecord> {
    const existing = await this.tx(scope, async (tx) => (await tx.query<Row>("SELECT * FROM response_actions WHERE ai_action_id = $1 AND organization_id = $2", [input.aiActionId, scope.organizationId])).rows[0] ?? null);
    const actor = { ...SYSTEM_ACTOR(scope.tenantId, "ai-soc"), actorId: `ai:${scope.conversationId}`, actorLabel: "AI SOC analyst" };
    if (existing) {
      if (existing.status === "pending_approval" && scope.approvedBy) {
        const claimed = await this.tx(scope, async (tx) =>
          (await tx.query<Row>("UPDATE response_actions SET status = 'approved', approved_by = $2, decided_at = now() WHERE id = $1 AND status = 'pending_approval' RETURNING id", [existing.id, scope.approvedBy])).rows[0],
        );
        if (claimed) return this.deps.responses.execute(scope.tenantId, String(existing.id), actor);
      }
      return this.deps.responses.get(scope.tenantId, String(existing.id));
    }
    return this.deps.responses.request(
      {
        tenantId: scope.tenantId,
        organizationId: scope.organizationId,
        action: input.action,
        incidentId: input.incidentId ?? null,
        target: input.target,
        parameters: input.parameters,
        reason: input.reason,
        requestedBy: { kind: "ai", id: `ai:${scope.conversationId}`, onBehalfOf: scope.principalId },
        via: "ai",
        aiActionId: input.aiActionId,
        conversationId: scope.conversationId,
        forceApproval: true,
        ...(scope.approvedBy ? { preApproved: { approvalId: null, approvedBy: [scope.approvedBy] } } : {}),
      },
      actor,
    );
  }

  async addInvestigationNote(scope: SocScope, input: InvestigationNoteInput): Promise<TimelineEntry> {
    return this.tx(scope, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT id FROM investigations WHERE id = $1 AND organization_id = $2", [input.investigationId, scope.organizationId]);
      if (!rows[0]) throw new Error("Investigation not found in this organization");
      const body = `${input.body}${input.refs.length ? `\n\nReferences: ${input.refs.join(", ")}` : ""}\n\n— AI SOC analyst acting for ${input.author.onBehalfOf} (conversation ${input.author.conversationId})`;
      const res = await tx.query<Row>(
        `INSERT INTO timeline_entries (tenant_id, organization_id, investigation_id, kind, at, actor_id, title, body, ref_id)
         VALUES ($1, $2, $3, 'ai', now(), $4, $5, $6, $7) RETURNING *`,
        [scope.tenantId, scope.organizationId, input.investigationId, `ai:${input.author.onBehalfOf}`, input.title.slice(0, 500), body.slice(0, 20_000), input.author.aiActionId],
      );
      return toTimelineEntry(res.rows[0]!);
    });
  }

  async listNotificationChannels(scope: SocScope): Promise<NotificationChannel[]> {
    return this.tx(scope, async (tx) =>
      (await tx.query<Row>("SELECT * FROM notification_channels WHERE organization_id IS NULL OR organization_id = $1 ORDER BY name", [scope.organizationId])).rows.map((r) => {
        // Channel secrets are references only; the AI never sees them (it gets id/name/kind).
        const c = toChannel(r);
        return { ...c, config: {} };
      }),
    );
  }

  async sendNotification(scope: SocScope, input: SendNotificationInput): Promise<{ deliveryId: string; channels: number; status: string }> {
    const deliveryId = randomUUID();
    const outcomes = await this.deps.notifications.engine.deliver(
      {
        id: deliveryId,
        tenantId: scope.tenantId,
        organizationId: scope.organizationId,
        event: "ai.notification",
        severity: "info",
        subject: input.subject.replace(/[\r\n]+/g, " ").slice(0, 200),
        text: `${input.body}\n\n(Drafted by the Bloody AI SOC analyst${scope.approvedBy ? `, approved by ${scope.approvedBy}` : ""}.)`,
        facts: [],
        ...(input.incidentId ? { link: this.deps.notifications.link(`/incidents/${input.incidentId}`)! } : {}),
        occurredAt: new Date(this.deps.now()).toISOString(),
        dedupKey: `ai:${input.aiActionId}`,
        origin: { kind: "system", id: input.aiActionId, name: "AI SOC analyst" },
      },
      input.channelIds,
      { tenantId: scope.tenantId, organizationId: scope.organizationId },
    );
    const sent = outcomes.filter((o) => o.status === "sent").length;
    return { deliveryId, channels: sent, status: sent === outcomes.length ? "sent" : sent > 0 ? "partially_sent" : "failed" };
  }
}
