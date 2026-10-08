import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { EdgeKind, NodeKind, Uuid, type ModuleKey } from "@bloody/contracts";
import { narrateAttackPaths, narrateExposure, narrateRisk, type ExplainedRiskAssessment, type ExposureDomain } from "@bloody/engines";
import { assertRecordAccess, requireAuth, resolveOrgFilter } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { notFound } from "../http/errors.js";
import { IdParam, csvOf } from "../http/params.js";
import { toAsset, toIdentity, toIncident, type Row } from "../repo/mappers.js";
import { attackPathCandidates, exposureInputsFor, loadPosture, sumPosture } from "../services/posture.js";
import { QueryBool, loadOne, parse } from "./util.js";

const NeighborQuery = z.object({
  depth: z.coerce.number().int().min(1).max(4).default(1),
  direction: z.enum(["in", "out", "both"]).default("both"),
  edgeKinds: csvOf(EdgeKind).optional(),
  nodeKinds: csvOf(NodeKind).optional(),
  limit: z.coerce.number().int().min(1).max(2000).default(200),
});

const SearchQuery = z.object({
  q: z.string().trim().min(1).max(200),
  kind: csvOf(NodeKind).optional(),
  kinds: csvOf(NodeKind).optional(),
  organizationId: Uuid.optional(),
  limit: z.coerce.number().int().min(1).max(200).default(25),
});

const AttackPathQuery = z.object({
  organizationId: Uuid.optional(),
  targetId: z.string().trim().max(100).optional(),
  entryId: z.string().trim().max(100).optional(),
  toCrownJewels: QueryBool.optional(),
  limit: z.coerce.number().int().min(1).max(1000).default(200),
  audience: z.enum(["executive", "customer", "analyst", "mssp"]).default("analyst"),
});

const RiskQuery = z.object({
  refresh: QueryBool.optional(),
  audience: z.enum(["executive", "customer", "analyst", "mssp"]).default("analyst"),
});

const ExposureQuery = z.object({ organizationId: Uuid.optional(), audience: z.enum(["executive", "customer", "analyst", "mssp"]).default("analyst") });

const DOMAIN_META: Record<ExposureDomain, { label: string; module: ModuleKey }> = {
  external: { label: "External attack surface", module: "asm" },
  vulnerability: { label: "Vulnerabilities", module: "vuln" },
  identity: { label: "Identity", module: "ispm" },
  cloud: { label: "Cloud", module: "cspm" },
  saas: { label: "SaaS", module: "sspm" },
  misconfiguration: { label: "Misconfiguration", module: "espm" },
  attack_path: { label: "Attack paths", module: "espm" },
  threat_intel: { label: "Threat intelligence", module: "cti" },
};

/**
 * Security Graph pivots, explainable risk, attack paths and the unified exposure score.
 * Graph and attack-path reads are scoped to the caller's organizations on top of RLS.
 */
export async function graphRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  const xdr = { config: { module: "xdr" as const } };
  const espm = { config: { module: "espm" as const } };

  app.get("/graph/node/:id", xdr, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const scope = resolveOrgFilter(request, "graph:read", undefined);
    const node = await s.graph.node(auth.tenantId, scope, id);
    if (!node) throw notFound("Graph node");
    return node;
  });

  app.get("/graph/node/:id/neighbors", xdr, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const q = parse(NeighborQuery, request.query);
    const scope = resolveOrgFilter(request, "graph:read", undefined);
    const hood = await s.graph.neighbors(auth.tenantId, scope, id, {
      depth: q.depth,
      direction: q.direction,
      limit: q.limit,
      ...(q.edgeKinds ? { edgeKinds: q.edgeKinds } : {}),
      ...(q.nodeKinds ? { nodeKinds: q.nodeKinds } : {}),
    });
    if (!hood) throw notFound("Graph node");
    return hood;
  });

  app.get("/graph/node/:id/blast-radius", xdr, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const q = parse(z.object({ depth: z.coerce.number().int().min(1).max(5).default(3), limit: z.coerce.number().int().min(10).max(2000).default(300) }), request.query);
    const scope = resolveOrgFilter(request, "graph:read", undefined);
    const radius = await s.graph.blastRadius(auth.tenantId, scope, id, q.depth, q.limit);
    if (!radius) throw notFound("Graph node");
    return radius;
  });

  app.get("/graph/search", xdr, async (request) => {
    const auth = requireAuth(request);
    const q = parse(SearchQuery, request.query);
    const scope = resolveOrgFilter(request, "graph:read", q.organizationId);
    const kinds = [...(q.kind ?? []), ...(q.kinds ?? [])];
    const items = await s.graph.search(auth.tenantId, scope, { q: q.q, ...(kinds.length > 0 ? { kinds } : {}), limit: q.limit });
    return { items, nextCursor: null, query: q.q };
  });

  app.get("/incidents/:id/graph", xdr, async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const q = parse(z.object({ depth: z.coerce.number().int().min(1).max(3).default(2), limit: z.coerce.number().int().min(10).max(2000).default(300) }), request.query);
    const incident = await s.db.withTenant(auth.tenantId, async (tx) => toIncident(await loadOne(tx, "incidents", id, "Incident")));
    assertRecordAccess(request, "incident:read", incident.organizationId, "Incident");
    const scope = resolveOrgFilter(request, "graph:read", incident.organizationId);
    const hood = await s.graph.incidentGraph(auth.tenantId, scope, { id: incident.id, organizationId: incident.organizationId }, q.depth, q.limit);
    if (!hood) return { incidentId: id, root: null, nodes: [], edges: [], truncated: false, hidden: 0 };
    return { incidentId: id, ...hood };
  });

  app.get("/attack-paths", espm, async (request) => {
    const auth = requireAuth(request);
    const q = parse(AttackPathQuery, request.query);
    const orgs = resolveOrgFilter(request, "risk:read", q.organizationId);
    const { orgIds, names } = await s.db.withTenant(auth.tenantId, async (tx) => {
      if (q.organizationId) await loadOne(tx, "organizations", q.organizationId, "Organization");
      const posture = await loadPosture(tx, orgs);
      const { rows } = await tx.query<{ id: string; name: string }>("SELECT id, name FROM organizations WHERE id = ANY($1::uuid[])", [[...posture.keys()]]);
      // Organizations without an internet-facing entry or a crown jewel cannot have paths.
      return { orgIds: attackPathCandidates(posture), names: new Map(rows.map((r) => [r.id, r.name])) };
    });
    const result = await s.graph.attackPathsFor(auth.tenantId, orgIds, {
      ...(q.targetId ? { targetId: q.targetId } : {}),
      ...(q.entryId ? { entryId: q.entryId } : {}),
      ...(q.toCrownJewels ? { toCrownJewelsOnly: true } : {}),
      limit: q.limit,
    });
    const narrative =
      orgIds.length === 1
        ? narrateAttackPaths(await s.attackPaths.analyze(auth.tenantId, orgIds[0]!), { audience: q.audience, ...(names.get(orgIds[0]!) ? { organizationName: names.get(orgIds[0]!)! } : {}) })
        : null;
    return {
      ...result,
      byOrganization: result.byOrganization.map((o) => ({ ...o, organizationName: names.get(o.organizationId) ?? null })),
      narrative,
      generatedAt: new Date(s.now()).toISOString(),
    };
  });

  app.get("/risk/assets/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const q = parse(RiskQuery, request.query);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      let asset = toAsset(await loadOne(tx, "assets", id, "Asset"));
      assertRecordAccess(request, "risk:read", asset.organizationId, "Asset");
      if (q.refresh || !asset.risk) asset = await s.inventory.scoreAsset(tx, auth.tenantId, id);
      const risk = asset.risk as ExplainedRiskAssessment;
      return { ...risk, entity: { kind: "asset", id: asset.id, name: asset.name, organizationId: asset.organizationId }, scoredAt: (await riskTimestamp(tx, "assets", id)) ?? null, narrative: narrateRisk(risk, { audience: q.audience, subject: asset.name }) };
    });
  });

  app.get("/risk/identities/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const q = parse(RiskQuery, request.query);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      let identity = toIdentity(await loadOne(tx, "identities", id, "Identity"));
      assertRecordAccess(request, "risk:read", identity.organizationId, "Identity");
      if (q.refresh || !identity.risk) identity = await s.inventory.scoreIdentity(tx, auth.tenantId, id);
      const risk = identity.risk as ExplainedRiskAssessment;
      return { ...risk, entity: { kind: "identity", id: identity.id, name: identity.principal, organizationId: identity.organizationId }, scoredAt: (await riskTimestamp(tx, "identities", id)) ?? null, narrative: narrateRisk(risk, { audience: q.audience, subject: identity.principal }) };
    });
  });

  app.get("/risk/incidents/:id", async (request) => {
    const auth = requireAuth(request);
    const { id } = parse(IdParam, request.params);
    const q = parse(RiskQuery, request.query);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const row = await loadOne(tx, "incidents", id, "Incident");
      const incident = toIncident(row);
      assertRecordAccess(request, "risk:read", incident.organizationId, "Incident");
      const risk = (row.risk as ExplainedRiskAssessment | null) ?? null;
      if (!risk) return { score: incident.riskScore, severity: incident.severity, factors: [], summary: "No explained assessment is stored for this incident (created manually without correlated evidence).", entity: { kind: "incident", id, name: incident.title, organizationId: incident.organizationId }, narrative: null };
      return { ...risk, entity: { kind: "incident", id, name: incident.title, organizationId: incident.organizationId }, narrative: narrateRisk(risk, { audience: q.audience, subject: `Incident #${incident.number}` }) };
    });
  });

  app.get("/exposure/summary", espm, async (request) => {
    const auth = requireAuth(request);
    const q = parse(ExposureQuery, request.query);
    const orgs = resolveOrgFilter(request, "risk:read", q.organizationId);
    const data = await s.db.withTenant(auth.tenantId, async (tx) => {
      if (q.organizationId) await loadOne(tx, "organizations", q.organizationId, "Organization");
      const posture = await loadPosture(tx, orgs);
      const { rows } = await tx.query<Row>("SELECT id, name FROM organizations WHERE id = ANY($1::uuid[])", [[...posture.keys()]]);
      return { posture, names: new Map(rows.map((r) => [String(r.id), String(r.name)])) };
    });
    const candidates = attackPathCandidates(data.posture);
    const paths = await s.graph.attackPathsFor(auth.tenantId, candidates, { limit: 1 });
    const total = sumPosture(data.posture.values());
    const orgName = data.posture.size === 1 ? [...data.names.values()][0] : undefined;
    const exposure = s.risk.exposureScore(
      exposureInputsFor(total, { total: paths.summary.totalPaths, toCrownJewels: paths.summary.toCrownJewels }, orgName),
    );
    const perOrganization = [...data.posture.values()].map((p) => {
      const o = paths.byOrganization.find((b) => b.organizationId === p.organizationId);
      const e = s.risk.exposureScore(exposureInputsFor(p, o ? { total: o.totalPaths, toCrownJewels: o.toCrownJewels } : { total: 0, toCrownJewels: 0 }, data.names.get(p.organizationId)));
      return { organizationId: p.organizationId, organizationName: data.names.get(p.organizationId) ?? null, score: e.score, severity: e.severity };
    });
    return {
      score: exposure.score,
      severity: exposure.severity,
      summary: exposure.summary,
      likelihood: exposure.likelihood,
      impact: exposure.impact,
      factors: exposure.factors,
      modelVersion: exposure.modelVersion,
      inherentScore: exposure.inherentScore,
      components: (Object.entries(exposure.domains) as Array<[ExposureDomain, { score: number; drivers: string[] }]>).map(([key, d]) => ({
        key,
        label: DOMAIN_META[key].label,
        module: DOMAIN_META[key].module,
        score: d.score,
        drivers: d.drivers,
      })),
      inputs: {
        assets: total.assets,
        vulnerabilities: total.vulns,
        identities: total.identities,
        attackPaths: { total: paths.summary.totalPaths, toCrownJewels: paths.summary.toCrownJewels },
        intel: total.intel,
      },
      organizations: perOrganization.sort((a, b) => b.score - a.score),
      narrative: narrateExposure(exposure, { audience: q.audience, ...(orgName ? { organizationName: orgName } : {}) }),
      generatedAt: new Date(s.now()).toISOString(),
    };
  });
}

async function riskTimestamp(tx: { query: (sql: string, params: unknown[]) => Promise<{ rows: Array<Record<string, unknown>> }> }, table: "assets" | "identities", id: string): Promise<string | null> {
  const { rows } = await tx.query(`SELECT risk_updated_at FROM ${table} WHERE id = $1`, [id]);
  return (rows[0]?.risk_updated_at as string | null) ?? null;
}
