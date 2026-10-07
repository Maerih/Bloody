import {
  AttackTechnique,
  EdgeKind,
  IncidentStatus,
  IndicatorType,
  REPORT_TYPES,
  RESPONSE_ACTIONS,
  ReportType,
  ResponseActionKey,
  SEVERITY_RANK,
  Severity,
  actionRisk,
  type Alert,
  type RiskAssessment,
} from "@bloody/contracts";
import { z } from "zod";
import { AiNotFoundError } from "../errors.js";
import { compactAlert, compactAttackPath, compactEvent, compactIdentity, compactIncident, compactIndicator, compactRisk, compactSubgraph, compactVulnerability } from "./compact.js";
import { buildRemediationPlan } from "./remediation.js";
import { DraftSigmaArgs, checkSigmaStructure, renderSigmaYaml } from "./sigma-draft.js";
import type { AssetDetail, IdentityDetail, IncidentDetail, SocDataPort } from "./soc-port.js";
import { defineTool, type AnyToolDefinition } from "./types.js";

/**
 * Standard AI SOC tool catalog. Every tool is a thin, typed, tier-classified wrapper over the
 * {@link SocDataPort}; the gateway enforces RBAC, tiers, approvals and audit around them.
 *
 * Tier classification:
 *   read             look up specific records (incidents, assets, identities, intel, graph, risk)
 *   investigate      run searches/hunts over telemetry, write investigation notes
 *   recommend        produce recommendations / drafts (remediation, Sigma, reports, SOAR advice)
 *   require_approval queue response actions for a human (isolate, block, disable, revoke…)
 *   execute          low-risk autonomous actions (notifications) — only with maxToolTier=execute
 */

const id = z.string().uuid();
const isoDate = z.string().datetime({ offset: true });
const MAX_WINDOW_HOURS = 24 * 90;

function windowFrom(now: Date, lookbackHours: number, from?: string, to?: string): { from: string; to: string } {
  const end = to ? new Date(to) : now;
  let start = from ? new Date(from) : new Date(end.getTime() - lookbackHours * 3_600_000);
  if (start.getTime() >= end.getTime()) throw new Error("'from' must be earlier than 'to'");
  if (end.getTime() - start.getTime() > MAX_WINDOW_HOURS * 3_600_000) start = new Date(end.getTime() - MAX_WINDOW_HOURS * 3_600_000);
  return { from: start.toISOString(), to: end.toISOString() };
}

function topN(values: Iterable<string | null | undefined>, n: number): Array<{ key: string; count: number }> {
  const counts = new Map<string, number>();
  for (const v of values) if (v) counts.set(v, (counts.get(v) ?? 0) + 1);
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))
    .slice(0, n);
}

/** Deterministic alert statistics for `summarize_alerts` (the model narrates, Bloody counts). */
export function summarizeAlertSet(alerts: readonly Alert[]): Record<string, unknown> {
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byStatus: Record<string, number> = {};
  let first: string | null = null;
  let last: string | null = null;
  let confidence = 0;
  for (const a of alerts) {
    bySeverity[a.severity] = (bySeverity[a.severity] ?? 0) + 1;
    byStatus[a.status] = (byStatus[a.status] ?? 0) + 1;
    if (!first || a.firstSeenAt < first) first = a.firstSeenAt;
    if (!last || a.lastSeenAt > last) last = a.lastSeenAt;
    confidence += a.confidence;
  }
  const highest = [...alerts].sort((a, b) => b.riskScore - a.riskScore || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]).slice(0, 10);
  return {
    total: alerts.length,
    bySeverity,
    byStatus,
    timeRange: { first, last },
    maxRiskScore: alerts.reduce((m, a) => Math.max(m, a.riskScore), 0),
    averageConfidence: alerts.length ? Math.round((confidence / alerts.length) * 100) / 100 : null,
    linkedToIncidents: alerts.filter((a) => a.incidentId).length,
    topSources: topN(alerts.map((a) => a.source), 8),
    topRules: topN(alerts.map((a) => a.ruleId), 8),
    topTechniques: topN(alerts.flatMap((a) => a.attack.map((t) => (t.name ? `${t.id} ${t.name}` : t.id))), 10),
    topTactics: topN(alerts.flatMap((a) => a.attack.map((t) => t.tactic)), 8),
    topAssets: topN(alerts.map((a) => a.assetId), 8),
    topIdentities: topN(alerts.map((a) => a.identityId), 8),
    highestRisk: highest.map(compactAlert),
  };
}

export function explainRiskText(r: RiskAssessment): string {
  const sorted = [...r.factors].sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));
  const drivers = sorted.filter((f) => f.contribution > 0).slice(0, 4);
  const compensating = sorted.filter((f) => f.contribution < 0).slice(0, 3);
  const fmt = (n: number): string => `${n >= 0 ? "+" : ""}${n.toFixed(1)}`;
  const parts = [`Score ${r.score}/100 (${r.severity}); likelihood ${Math.round(r.likelihood * 100)}%, impact ${Math.round(r.impact * 100)}%.`];
  if (drivers.length) parts.push(`Main drivers: ${drivers.map((f) => `${f.label} (${fmt(f.contribution)}) — ${f.explanation}`).join("; ")}.`);
  if (compensating.length) parts.push(`Compensating factors: ${compensating.map((f) => `${f.label} (${fmt(f.contribution)})`).join("; ")}.`);
  return parts.join(" ");
}

const REPORT_OUTLINES: Record<"business" | "soc" | "mssp" | "customer", string[]> = {
  business: ["Executive summary", "Risk posture and trend", "Top risks and business impact", "Decisions and investments requested", "Outlook"],
  soc: ["Operational summary", "Alert and detection volume", "Incidents, MTTD and MTTR", "Notable investigations", "Detection tuning and coverage gaps", "Next actions"],
  mssp: ["Portfolio overview", "SLA performance", "Analyst workload", "Customer risk ranking", "Usage and commercial view", "Actions"],
  customer: ["Service summary", "What we detected and handled for you", "Actions required from you", "Exposure and recommendations", "Next review"],
};

export function reportAudience(type: ReportType): "business" | "soc" | "mssp" | "customer" {
  return REPORT_TYPES.find((r) => r.key === type)!.audience;
}

const ResponseTarget = z
  .object({
    kind: z.enum(["asset", "identity", "indicator", "incident"]),
    id: z.string().min(1).max(512),
    label: z.string().max(200).optional(),
  })
  .strict();

function assertTargetMatches(action: z.infer<typeof ResponseActionKey>, target: z.infer<typeof ResponseTarget>): void {
  const expected = RESPONSE_ACTIONS.find((a) => a.key === action)!.target;
  if (expected !== target.kind) throw new Error(`Action '${action}' targets a ${expected}, not a ${target.kind}`);
}

export const STANDARD_SOC_TOOL_NAMES = [
  "get_incident",
  "list_incidents",
  "summarize_alerts",
  "search_events",
  "query_graph",
  "get_asset",
  "get_identity",
  "get_investigation",
  "search_intel",
  "get_attack_paths",
  "explain_risk",
  "hunt",
  "recommend_remediation",
  "draft_sigma_rule",
  "draft_report",
  "recommend_soar_action",
  "list_notification_channels",
  "request_response_action",
  "add_investigation_note",
  "send_notification",
] as const;
export type StandardSocToolName = (typeof STANDARD_SOC_TOOL_NAMES)[number];

export function createStandardSocTools(port: SocDataPort): AnyToolDefinition[] {
  const tools: AnyToolDefinition[] = [
    defineTool({
      name: "get_incident",
      description: "Fetch one incident with its alerts (and optionally its timeline) by incident id.",
      tier: "read",
      permission: "incident:read",
      parameters: z.object({ incidentId: id, includeAlerts: z.boolean().default(true), includeTimeline: z.boolean().default(false) }).strict(),
      handler: async ({ scope }, args) => {
        const detail = await port.getIncident(scope, args.incidentId, { includeAlerts: args.includeAlerts, includeTimeline: args.includeTimeline });
        if (!detail) throw new AiNotFoundError("not_found", "Incident not found in this organization");
        return {
          incident: compactIncident(detail.incident),
          alerts: detail.alerts.slice(0, 50).map(compactAlert),
          investigations: detail.investigations.map((i) => ({ id: i.id, title: i.title, status: i.status, hypothesis: i.hypothesis })),
          timeline: detail.timeline.slice(-60).map((t) => ({ at: t.at, kind: t.kind, title: t.title, actorId: t.actorId, refId: t.refId })),
        };
      },
    }),
    defineTool({
      name: "list_incidents",
      description: "List incidents filtered by status, severity, free text, asset or identity (newest first). Use to correlate related incidents.",
      tier: "read",
      permission: "incident:read",
      parameters: z
        .object({
          status: z.array(IncidentStatus).max(7).optional(),
          severity: z.array(Severity).max(5).optional(),
          query: z.string().max(200).optional(),
          assetId: id.optional(),
          identityId: id.optional(),
          sinceDays: z.number().int().min(1).max(365).default(30),
          limit: z.number().int().min(1).max(50).default(20),
        })
        .strict(),
      handler: async ({ scope, now }, args) => {
        const incidents = await port.listIncidents(scope, {
          ...(args.status ? { status: args.status } : {}),
          ...(args.severity ? { severity: args.severity } : {}),
          ...(args.query ? { query: args.query } : {}),
          ...(args.assetId ? { assetId: args.assetId } : {}),
          ...(args.identityId ? { identityId: args.identityId } : {}),
          since: new Date(now.getTime() - args.sinceDays * 86_400_000).toISOString(),
          limit: args.limit,
        });
        return { count: incidents.length, incidents: incidents.slice(0, args.limit).map(compactIncident) };
      },
    }),
    defineTool({
      name: "summarize_alerts",
      description: "Compute statistics over alerts (by severity, status, source, rule, ATT&CK technique, asset, identity) for an incident, asset, identity or the whole organization in a time window.",
      tier: "read",
      permission: "alert:read",
      parameters: z
        .object({
          incidentId: id.optional(),
          assetId: id.optional(),
          identityId: id.optional(),
          severityAtLeast: Severity.optional(),
          sinceHours: z.number().int().min(1).max(MAX_WINDOW_HOURS).default(24),
          limit: z.number().int().min(1).max(500).default(200),
        })
        .strict(),
      handler: async ({ scope, now }, args) => {
        const alerts = await port.listAlerts(scope, {
          ...(args.incidentId ? { incidentId: args.incidentId } : {}),
          ...(args.assetId ? { assetId: args.assetId } : {}),
          ...(args.identityId ? { identityId: args.identityId } : {}),
          ...(args.severityAtLeast ? { severityAtLeast: args.severityAtLeast } : {}),
          since: new Date(now.getTime() - args.sinceHours * 3_600_000).toISOString(),
          limit: args.limit,
        });
        return { window: { sinceHours: args.sinceHours }, ...summarizeAlertSet(alerts.slice(0, args.limit)) };
      },
    }),
    defineTool({
      name: "search_events",
      description:
        "Search normalized security events (SIEM) with Bloody query syntax, e.g. `process.name:powershell.exe AND network.dstPort:443`. Returns compact events; narrow the window/filters for large result sets.",
      tier: "investigate",
      permission: "event:read",
      parameters: z
        .object({
          query: z.string().min(1).max(2000),
          from: isoDate.optional(),
          to: isoDate.optional(),
          lookbackHours: z.number().int().min(1).max(MAX_WINDOW_HOURS).default(24),
          limit: z.number().int().min(1).max(200).default(50),
          fields: z.array(z.string().regex(/^[A-Za-z0-9_.]{1,100}$/)).max(30).optional(),
        })
        .strict(),
      handler: async ({ scope, now }, args) => {
        const window = windowFrom(now, args.lookbackHours, args.from, args.to);
        const res = await port.searchEvents(scope, { query: args.query, ...window, limit: args.limit, ...(args.fields ? { fields: args.fields } : {}) });
        return { window, total: res.total, returned: Math.min(res.events.length, args.limit), truncated: res.truncated || res.total > args.limit, events: res.events.slice(0, args.limit).map(compactEvent) };
      },
    }),
    defineTool({
      name: "query_graph",
      description:
        "Query the Security Graph: 'neighbors' of a node, 'blast_radius' (everything reachable from a node, incl. crown jewels) or 'search' nodes by text. Node ids come from other tools or a previous search.",
      tier: "read",
      permission: "graph:read",
      parameters: z
        .object({
          mode: z.enum(["neighbors", "blast_radius", "search"]),
          nodeId: z.string().min(1).max(512).optional(),
          query: z.string().min(1).max(200).optional(),
          depth: z.number().int().min(1).max(4).default(1),
          direction: z.enum(["out", "in", "both"]).default("both"),
          edgeKinds: z.array(EdgeKind).max(10).optional(),
          limit: z.number().int().min(1).max(200).default(100),
        })
        .strict()
        .superRefine((v, ctx) => {
          if (v.mode !== "search" && !v.nodeId) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["nodeId"], message: "nodeId is required for this mode" });
          if (v.mode === "search" && !v.query) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["query"], message: "query is required for search" });
        }),
      handler: async ({ scope }, args) => {
        if (args.mode === "search") {
          const nodes = await port.graphSearch(scope, { query: args.query!, limit: args.limit });
          return { mode: args.mode, count: nodes.length, nodes: nodes.slice(0, args.limit).map((n) => ({ id: n.id, kind: n.kind, label: n.label, key: n.key })) };
        }
        if (args.mode === "blast_radius") {
          const g = await port.graphBlastRadius(scope, { nodeId: args.nodeId!, maxDepth: args.depth, limit: args.limit });
          return { mode: args.mode, crownJewels: g.crownJewels, ...compactSubgraph(g) };
        }
        const g = await port.graphNeighbors(scope, {
          nodeId: args.nodeId!,
          depth: args.depth,
          direction: args.direction,
          limit: args.limit,
          ...(args.edgeKinds ? { edgeKinds: args.edgeKinds } : {}),
        });
        return { mode: args.mode, ...compactSubgraph(g) };
      },
    }),
    defineTool({
      name: "get_asset",
      description: "Fetch an asset with its risk assessment, open vulnerabilities, EDR agent health, related identities and open incidents.",
      tier: "read",
      permission: "asset:read",
      parameters: z.object({ assetId: id }).strict(),
      handler: async ({ scope }, args) => {
        const d = await port.getAsset(scope, args.assetId);
        if (!d) throw new AiNotFoundError("not_found", "Asset not found in this organization");
        const a = d.asset;
        return {
          asset: { id: a.id, kind: a.kind, name: a.name, hostname: a.hostname, ipAddresses: a.ipAddresses.slice(0, 10), os: a.os, criticality: a.criticality, internetFacing: a.internetFacing, tags: a.tags.slice(0, 15), owner: a.owner, lastSeenAt: a.lastSeenAt, riskScore: a.riskScore },
          risk: d.risk ? compactRisk(d.risk) : null,
          agent: d.agent ? { status: d.agent.status, engine: d.agent.engine, version: d.agent.version, lastCheckinAt: d.agent.lastCheckinAt, antivirusStatus: d.agent.antivirusStatus, firewallEnabled: d.agent.firewallEnabled } : null,
          vulnerabilities: d.vulnerabilities.slice(0, 30).map(compactVulnerability),
          identities: d.identities.slice(0, 20).map(compactIdentity),
          openIncidents: d.openIncidents.slice(0, 10).map(compactIncident),
        };
      },
    }),
    defineTool({
      name: "get_identity",
      description: "Fetch an identity (user, service account, service principal…) with risk, group memberships, recent authentications and open incidents.",
      tier: "read",
      permission: "identity:read",
      parameters: z.object({ identityId: id }).strict(),
      handler: async ({ scope }, args) => {
        const d = await port.getIdentity(scope, args.identityId);
        if (!d) throw new AiNotFoundError("not_found", "Identity not found in this organization");
        return {
          identity: compactIdentity(d.identity),
          risk: d.risk ? compactRisk(d.risk) : null,
          groups: d.groups.slice(0, 50),
          recentAuthentications: d.recentAuthentications.slice(0, 30).map(compactEvent),
          openIncidents: d.openIncidents.slice(0, 10).map(compactIncident),
        };
      },
    }),
    defineTool({
      name: "get_investigation",
      description: "Fetch an investigation with its timeline and evidence inventory (hashes and custody, not contents).",
      tier: "read",
      permission: "investigation:read",
      parameters: z.object({ investigationId: id }).strict(),
      handler: async ({ scope }, args) => {
        const d = await port.getInvestigation(scope, args.investigationId);
        if (!d) throw new AiNotFoundError("not_found", "Investigation not found in this organization");
        return {
          investigation: { id: d.investigation.id, title: d.investigation.title, status: d.investigation.status, incidentId: d.investigation.incidentId, hypothesis: d.investigation.hypothesis },
          timeline: d.timeline.slice(-80).map((t) => ({ at: t.at, kind: t.kind, title: t.title, body: t.body ? t.body.slice(0, 500) : null, refId: t.refId })),
          evidence: d.evidence.slice(0, 40).map((e) => ({ id: e.id, name: e.name, kind: e.kind, sha256: e.sha256, sizeBytes: e.sizeBytes, collectedBy: e.collectedBy, custodyEntries: e.custody.length })),
        };
      },
    }),
    defineTool({
      name: "search_intel",
      description: "Search threat intelligence (CTI) indicators by exact value and/or text, and where they were observed in this organization.",
      tier: "read",
      permission: "intel:read",
      parameters: z
        .object({
          value: z.string().min(1).max(2048).optional(),
          type: IndicatorType.optional(),
          query: z.string().min(1).max(200).optional(),
          includeMatches: z.boolean().default(true),
          limit: z.number().int().min(1).max(100).default(20),
        })
        .strict()
        .refine((v) => Boolean(v.value || v.query), "Provide 'value' or 'query'"),
      handler: async ({ scope }, args) => {
        const res = await port.searchIntel(scope, {
          ...(args.value ? { value: args.value } : {}),
          ...(args.type ? { type: args.type } : {}),
          ...(args.query ? { query: args.query } : {}),
          includeMatches: args.includeMatches,
          limit: args.limit,
        });
        return { indicators: res.indicators.slice(0, args.limit).map(compactIndicator), matches: res.matches.slice(0, 50) };
      },
    }),
    defineTool({
      name: "get_attack_paths",
      description: "Get the most likely attack paths (optionally only to crown jewels) from or through an asset / graph node, with explained risk and choke-point remediations.",
      tier: "read",
      permission: "risk:read",
      parameters: z
        .object({ assetId: id.optional(), nodeId: z.string().min(1).max(512).optional(), toCrownJewelsOnly: z.boolean().default(true), limit: z.number().int().min(1).max(20).default(5) })
        .strict(),
      handler: async ({ scope }, args) => {
        const paths = await port.getAttackPaths(scope, {
          ...(args.assetId ? { assetId: args.assetId } : {}),
          ...(args.nodeId ? { nodeId: args.nodeId } : {}),
          toCrownJewelsOnly: args.toCrownJewelsOnly,
          limit: args.limit,
        });
        return { count: paths.length, paths: paths.slice(0, args.limit).map(compactAttackPath) };
      },
    }),
    defineTool({
      name: "explain_risk",
      description: "Explain the risk score of an asset, identity, incident or vulnerability: score, likelihood/impact and the factors that drive it.",
      tier: "read",
      permission: "risk:read",
      parameters: z.object({ entityKind: z.enum(["asset", "identity", "incident", "vulnerability"]), id }).strict(),
      handler: async ({ scope }, args) => {
        const risk = await port.getRiskAssessment(scope, { entityKind: args.entityKind, id: args.id });
        if (!risk) throw new AiNotFoundError("not_found", `No risk assessment for ${args.entityKind} ${args.id}`);
        return { entity: { kind: args.entityKind, id: args.id }, explanation: explainRiskText(risk), assessment: compactRisk(risk, 12) };
      },
    }),
    defineTool({
      name: "hunt",
      description:
        "Run a threat-hunting query over historical telemetry for a stated hypothesis (Bloody query syntax or a Sigma detection expression). Returns hits plus aggregations by host/user/process.",
      tier: "investigate",
      permission: "event:read",
      parameters: z
        .object({
          hypothesis: z.string().min(10).max(1000),
          query: z.string().min(1).max(4000),
          language: z.enum(["bloody_ql", "sigma"]).default("bloody_ql"),
          lookbackHours: z.number().int().min(1).max(MAX_WINDOW_HOURS).default(168),
          limit: z.number().int().min(1).max(500).default(100),
          attack: z.array(AttackTechnique.shape.id).max(10).default([]),
        })
        .strict(),
      describe: (a) => `Hunt: ${a.hypothesis}`,
      timeoutMs: 120_000,
      handler: async ({ scope, now }, args) => {
        const window = windowFrom(now, args.lookbackHours);
        const res = await port.runHunt(scope, { hypothesis: args.hypothesis, query: args.query, language: args.language, ...window, limit: args.limit, attack: args.attack });
        return {
          hypothesis: args.hypothesis,
          window,
          queryExecuted: res.queryExecuted,
          total: res.total,
          truncated: res.truncated,
          aggregations: res.aggregations,
          hits: res.hits.slice(0, Math.min(args.limit, 100)).map(compactEvent),
        };
      },
    }),
    defineTool({
      name: "recommend_remediation",
      description:
        "Rank remediation for an incident, asset or identity: containment, patching (KEV/EPSS/CVSS), identity hygiene, endpoint control health and attack-path choke points — each with evidence and the approval tier it needs.",
      tier: "recommend",
      permission: "risk:read",
      parameters: z
        .object({ incidentId: id.optional(), assetId: id.optional(), identityId: id.optional(), limit: z.number().int().min(1).max(30).default(12) })
        .strict()
        .refine((v) => Boolean(v.incidentId || v.assetId || v.identityId), "Provide incidentId, assetId or identityId"),
      handler: async ({ scope }, args) => {
        let incident: IncidentDetail | null = null;
        const assetIds = new Set<string>();
        const identityIds = new Set<string>();
        if (args.incidentId) {
          incident = await port.getIncident(scope, args.incidentId, { includeAlerts: false, includeTimeline: false });
          if (!incident) throw new AiNotFoundError("not_found", "Incident not found in this organization");
          incident.incident.assetIds.slice(0, 8).forEach((a) => assetIds.add(a));
          incident.incident.identityIds.slice(0, 8).forEach((i) => identityIds.add(i));
        }
        if (args.assetId) assetIds.add(args.assetId);
        if (args.identityId) identityIds.add(args.identityId);
        const assets = (await Promise.all([...assetIds].map((a) => port.getAsset(scope, a)))).filter((a): a is AssetDetail => a !== null);
        const identities = (await Promise.all([...identityIds].map((i) => port.getIdentity(scope, i)))).filter((i): i is IdentityDetail => i !== null);
        const attackPaths = (await Promise.all(assets.slice(0, 4).map((a) => port.getAttackPaths(scope, { assetId: a.asset.id, toCrownJewelsOnly: true, limit: 5 })))).flat();
        const plan = buildRemediationPlan({ incident, assets, identities, attackPaths }, args.limit);
        return {
          basis: { incidentId: args.incidentId ?? null, assets: assets.length, identities: identities.length, attackPaths: attackPaths.length },
          recommendations: plan,
          note: "Recommendations only. Response actions must be queued with request_response_action and approved by a human.",
        };
      },
    }),
    defineTool({
      name: "draft_sigma_rule",
      description:
        "Draft a Sigma detection rule from structured fields. Bloody renders the YAML and validates it with the Detection Engine. The rule is NOT deployed; an engineer must review and deploy it.",
      tier: "recommend",
      permission: "detection:read",
      parameters: DraftSigmaArgs,
      handler: async ({ scope, actionId, now }, args) => {
        const yaml = renderSigmaYaml(args, { id: actionId, date: now.toISOString().slice(0, 10) });
        const structure = checkSigmaStructure(args);
        const engine = structure.errors.length === 0 ? await port.validateDetectionRule(scope, { format: "sigma", content: yaml }) : null;
        const errors = [...structure.errors, ...(engine?.errors ?? [])];
        return {
          status: "draft",
          deployed: false,
          rule: yaml,
          validation: { valid: errors.length === 0, errors, warnings: [...structure.warnings, ...(engine?.warnings ?? [])], ...(engine?.testMatches !== undefined ? { testMatches: engine.testMatches } : {}) },
          nextSteps: "Review the draft in Detections → Rules; deploying requires detection:write and goes through the detection test runner.",
        };
      },
    }),
    defineTool({
      name: "draft_report",
      description:
        "Gather report-ready data and the audience-specific outline for a report draft (executive/CISO, SOC operations, incident, vulnerability, threat intel, compliance, SLA, analyst activity, customer monthly review, MSSP portfolio). Nothing is published or sent.",
      tier: "recommend",
      permission: "report:read",
      parameters: z
        .object({ reportType: ReportType, periodDays: z.number().int().min(1).max(366).default(30), incidentId: id.optional(), focus: z.string().max(500).optional() })
        .strict()
        .refine((v) => v.reportType !== "incident" || Boolean(v.incidentId), "incident reports need incidentId"),
      handler: async ({ scope }, args) => {
        const data = await port.getReportData(scope, {
          type: args.reportType,
          periodDays: args.periodDays,
          ...(args.incidentId ? { incidentId: args.incidentId } : {}),
          ...(args.focus ? { focus: args.focus } : {}),
        });
        const audience = reportAudience(args.reportType);
        return {
          status: "draft",
          published: false,
          reportType: args.reportType,
          label: REPORT_TYPES.find((r) => r.key === args.reportType)!.label,
          audience,
          organizationName: data.organizationName,
          period: data.period,
          outline: REPORT_OUTLINES[audience],
          data: data.metrics,
          guidance:
            audience === "business" || audience === "customer"
              ? "Write in plain language, lead with business impact and required decisions/actions, avoid jargon, quantify trends."
              : "Be precise and operational: metrics, SLAs, MTTD/MTTR, detection gaps and concrete next actions.",
        };
      },
    }),
    defineTool({
      name: "recommend_soar_action",
      description: "Assess a SOAR response action for a target: risk, whether human approval is required, the AI tier needed and matching playbooks. Does not execute anything.",
      tier: "recommend",
      permission: "playbook:read",
      parameters: z.object({ action: ResponseActionKey, target: ResponseTarget, incidentId: id.optional(), reason: z.string().min(3).max(2000) }).strict(),
      handler: async ({ scope }, args) => {
        assertTargetMatches(args.action, args.target);
        const risk = actionRisk(args.action);
        const playbooks = await port.listPlaybooks(scope, { action: args.action });
        const def = RESPONSE_ACTIONS.find((a) => a.key === args.action)!;
        return {
          action: args.action,
          label: def.label,
          target: args.target,
          risk,
          requiresHumanApproval: risk !== "low",
          minimumAiTier: risk === "low" ? "execute" : "require_approval",
          reason: args.reason,
          matchingPlaybooks: playbooks
            .filter((p) => p.enabled)
            .slice(0, 10)
            .map((p) => ({ id: p.id, name: p.name, version: p.version, trigger: p.trigger.on, steps: p.steps.map((s) => s.action) })),
          howToProceed: "To queue it, call request_response_action; a human with response:approve must approve before SOAR executes it.",
        };
      },
    }),
    defineTool({
      name: "list_notification_channels",
      description: "List the organization's notification channels (id, name, kind) available for send_notification. Channel secrets/URLs are never returned.",
      tier: "read",
      permission: "integration:read",
      parameters: z.object({}).strict(),
      handler: async ({ scope }) => {
        const channels = await port.listNotificationChannels(scope);
        return { channels: channels.filter((c) => c.enabled).map((c) => ({ id: c.id, name: c.name, kind: c.kind, scope: c.organizationId ? "organization" : "tenant" })) };
      },
    }),
    defineTool({
      name: "request_response_action",
      description:
        "Queue a SOAR response action (isolate endpoint, block IP/domain, disable identity, revoke sessions/tokens, kill process, quarantine file…) for human approval. It is NOT executed until a human approves it.",
      tier: "require_approval",
      permission: "response:request",
      parameters: z
        .object({ action: ResponseActionKey, target: ResponseTarget, incidentId: id.optional(), parameters: z.record(z.unknown()).default({}), reason: z.string().min(3).max(2000) })
        .strict()
        .superRefine((v, ctx) => {
          const expected = RESPONSE_ACTIONS.find((a) => a.key === v.action)?.target;
          if (expected && expected !== v.target.kind) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["target", "kind"], message: `Action '${v.action}' targets a ${expected}` });
        }),
      risk: (a) => actionRisk(a.action),
      describe: (a) => `${RESPONSE_ACTIONS.find((x) => x.key === a.action)!.label} on ${a.target.kind} ${a.target.label ?? a.target.id}: ${a.reason}`,
      handler: async ({ scope, actionId }, args) => {
        const record = await port.submitResponseAction(scope, {
          action: args.action,
          target: { kind: args.target.kind, id: args.target.id, ...(args.target.label ? { label: args.target.label } : {}) },
          ...(args.incidentId ? { incidentId: args.incidentId } : {}),
          parameters: args.parameters,
          reason: args.reason,
          requestedVia: "ai",
          aiActionId: actionId,
        });
        return { responseActionId: record.id, status: record.status, action: record.action, target: record.target, approvedBy: record.approvedBy };
      },
    }),
    defineTool({
      name: "add_investigation_note",
      description: "Add an AI-authored note to an investigation timeline (clearly attributed to the AI acting for the analyst). Use for findings, hypotheses and evidence references.",
      tier: "investigate",
      permission: "investigation:write",
      parameters: z
        .object({ investigationId: id, title: z.string().min(3).max(200), body: z.string().min(1).max(10_000), refs: z.array(z.string().min(1).max(512)).max(25).default([]) })
        .strict(),
      describe: (a) => `Add note '${a.title}' to investigation ${a.investigationId}`,
      handler: async ({ scope, actionId }, args) => {
        const entry = await port.addInvestigationNote(scope, {
          investigationId: args.investigationId,
          title: args.title,
          body: args.body,
          refs: args.refs,
          author: { kind: "ai", onBehalfOf: scope.principalId, conversationId: scope.conversationId, aiActionId: actionId },
        });
        return { timelineEntryId: entry.id, investigationId: entry.investigationId, at: entry.at };
      },
    }),
    defineTool({
      name: "send_notification",
      description:
        "Send a notification (email / Slack / Teams / webhook channel) about an incident, e.g. a customer or executive update. Runs autonomously only when the model is trusted with the execute tier; otherwise it is queued for approval.",
      tier: "execute",
      permission: "response:request",
      parameters: z
        .object({
          channelIds: z.array(id).min(1).max(10),
          subject: z.string().min(3).max(150).regex(/^[^\r\n]+$/, "subject must be a single line"),
          body: z.string().min(1).max(20_000),
          incidentId: id.optional(),
        })
        .strict(),
      risk: () => actionRisk("send_email"),
      describe: (a) => `Send notification '${a.subject}' to ${a.channelIds.length} channel(s)`,
      handler: async ({ scope, actionId }, args) => {
        const channels = await port.listNotificationChannels(scope);
        const allowed = new Set(channels.filter((c) => c.enabled).map((c) => c.id));
        const channelIds = args.channelIds.filter((c) => allowed.has(c));
        if (channelIds.length === 0) throw new AiNotFoundError("not_found", "None of the requested channels exist or are enabled in this organization");
        const res = await port.sendNotification(scope, {
          channelIds,
          subject: args.subject,
          body: args.body,
          ...(args.incidentId ? { incidentId: args.incidentId } : {}),
          aiGenerated: true,
          aiActionId: actionId,
        });
        return { ...res, skippedChannels: args.channelIds.length - channelIds.length };
      },
    }),
  ];
  return tools;
}

/** Tool catalog for the UI / docs (no handlers). */
export function describeTools(tools: readonly AnyToolDefinition[]): Array<{ name: string; description: string; tier: string; permission: string }> {
  return tools.map((t) => ({ name: t.name, description: t.description, tier: t.tier, permission: t.permission }));
}
