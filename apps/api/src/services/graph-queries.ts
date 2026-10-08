import { NODE_KINDS, type EdgeKind, type GraphEdge, type GraphNode, type NodeKind } from "@bloody/contracts";
import { isCrownJewel, type AttackPathAnalysis, type AttackPathDetail, type BlastRadius, type RemediationPriority } from "@bloody/engines";
import type { Database } from "../db/pool.js";
import { PostgresGraphStore } from "../graph/postgres-store.js";
import type { AttackPathService } from "./attack-paths.js";
import { graphFor } from "./inventory.js";

/**
 * Read side of the Security Graph for the API and the AI SOC. Every query runs inside the
 * tenant's RLS transaction through the tenant-bound store; on top of that, nodes of organizations
 * outside the caller's scope are removed (tenant-global nodes such as ATT&CK techniques stay) and
 * only edges whose both endpoints remain visible are returned — a pivot never leaks a neighbour
 * organization's entities.
 */

export type OrgScope = string[] | null;

export interface ScopedNeighborhood {
  root: GraphNode;
  nodes: Array<GraphNode & { depth: number }>;
  edges: GraphEdge[];
  truncated: boolean;
  /** Nodes removed because they belong to organizations outside the caller's scope. */
  hidden: number;
}

export interface GraphNeighborOptions {
  depth?: number;
  direction?: "in" | "out" | "both";
  edgeKinds?: EdgeKind[];
  nodeKinds?: NodeKind[];
  limit?: number;
}

export function visibleIn(scope: OrgScope, organizationId: string | null): boolean {
  return organizationId === null || scope === null || scope.includes(organizationId);
}

function stripEdge(e: GraphEdge & { organizationId?: string | null }): GraphEdge {
  return { id: e.id, kind: e.kind, from: e.from, to: e.to, props: e.props };
}

export interface ScopedAttackPaths {
  paths: Array<AttackPathDetail & { organizationId: string }>;
  remediations: Array<RemediationPriority & { organizationId: string }>;
  summary: {
    totalPaths: number;
    toCrownJewels: number;
    targetsAtRisk: number;
    entryPoints: number;
    maxRiskScore: number;
    shortestPathLength: number | null;
    fixesToBreakAll: number;
    topRemediation: string | null;
    truncated: boolean;
    organizations: number;
  };
  byOrganization: Array<{ organizationId: string; totalPaths: number; toCrownJewels: number; maxRiskScore: number }>;
}

export class GraphQueries {
  constructor(
    private readonly db: Database,
    private readonly attackPaths: AttackPathService,
  ) {}

  async node(tenantId: string, scope: OrgScope, nodeId: string): Promise<GraphNode | null> {
    const node = await this.db.withTenant(tenantId, (tx) => new PostgresGraphStore(tx, tenantId).getNode(nodeId));
    return node && visibleIn(scope, node.organizationId) ? node : null;
  }

  async neighbors(tenantId: string, scope: OrgScope, nodeId: string, opts: GraphNeighborOptions = {}): Promise<ScopedNeighborhood | null> {
    return this.db.withTenant(tenantId, async (tx) => {
      const store = new PostgresGraphStore(tx, tenantId);
      const root = await store.getNode(nodeId);
      if (!root || !visibleIn(scope, root.organizationId)) return null;
      const hood = await store.neighbors(nodeId, {
        depth: Math.min(Math.max(opts.depth ?? 1, 1), 4),
        direction: opts.direction ?? "both",
        limit: Math.min(Math.max(opts.limit ?? 200, 1), 2000),
        ...(opts.edgeKinds?.length ? { edgeKinds: opts.edgeKinds } : {}),
        ...(opts.nodeKinds?.length ? { nodeKinds: opts.nodeKinds } : {}),
      });
      const kept = hood.nodes.filter((n) => visibleIn(scope, n.node.organizationId));
      const ids = new Set([root.id, ...kept.map((n) => n.node.id)]);
      return {
        root,
        nodes: kept.map((n) => ({ ...n.node, depth: n.depth })),
        edges: hood.edges.filter((e) => ids.has(e.from) && ids.has(e.to)).map(stripEdge),
        truncated: hood.truncated,
        hidden: hood.nodes.length - kept.length,
      };
    });
  }

  /** Label / natural-key search across the organizations in scope. */
  async search(tenantId: string, scope: OrgScope, input: { q: string; kinds?: NodeKind[]; limit?: number }): Promise<GraphNode[]> {
    const limit = Math.min(Math.max(input.limit ?? 25, 1), 200);
    const term = input.q.trim();
    if (term.length === 0) return [];
    const kinds = input.kinds?.filter((k) => (NODE_KINDS as readonly string[]).includes(k));
    return this.db.withTenant(tenantId, async (tx) => {
      const store = new PostgresGraphStore(tx, tenantId);
      const orgTargets: Array<string | null | undefined> = scope === null ? [undefined] : [...scope, null];
      const out = new Map<string, GraphNode>();
      for (const org of orgTargets) {
        const base = { ...(org !== undefined ? { organizationId: org } : {}), ...(kinds && kinds.length > 0 ? { kind: kinds } : {}), limit };
        for (const n of await store.findNodes({ ...base, labelContains: term })) out.set(n.id, n);
        for (const n of await store.findNodes({ ...base, keyPrefix: term.toLowerCase() })) out.set(n.id, n);
        if (out.size >= limit * 2) break;
      }
      const lower = term.toLowerCase();
      const rank = (n: GraphNode) => (n.label.toLowerCase() === lower || n.key === lower ? 0 : n.label.toLowerCase().startsWith(lower) || n.key.startsWith(lower) ? 1 : 2);
      return [...out.values()]
        .filter((n) => visibleIn(scope, n.organizationId))
        .sort((a, b) => rank(a) - rank(b) || a.label.localeCompare(b.label))
        .slice(0, limit);
    });
  }

  /** Incident node and its neighbourhood (entities, techniques, indicators, actors). */
  async incidentGraph(tenantId: string, scope: OrgScope, incident: { id: string; organizationId: string }, depth = 2, limit = 300): Promise<ScopedNeighborhood | null> {
    const node = await this.db.withTenant(tenantId, (tx) => new PostgresGraphStore(tx, tenantId).getNodeByKey(incident.organizationId, "incident", incident.id));
    if (!node) return null;
    return this.neighbors(tenantId, scope, node.id, { depth, direction: "both", limit });
  }

  async blastRadius(tenantId: string, scope: OrgScope, nodeId: string, depth = 3, maxNodes = 300): Promise<(BlastRadius & { hidden: number }) | null> {
    return this.db.withTenant(tenantId, async (tx) => {
      const graph = graphFor(tx, tenantId);
      const store = new PostgresGraphStore(tx, tenantId);
      const root = await store.getNode(nodeId);
      if (!root || !visibleIn(scope, root.organizationId)) return null;
      const radius = await graph.blastRadius(nodeId, Math.min(Math.max(depth, 1), 5), { maxNodes: Math.min(Math.max(maxNodes, 10), 2000) });
      const visible = (n: GraphNode) => visibleIn(scope, n.organizationId);
      const nodes = radius.nodes.filter((x) => visible(x.node));
      const byKind: BlastRadius["byKind"] = {};
      for (const n of nodes) byKind[n.node.kind] = (byKind[n.node.kind] ?? 0) + 1;
      return {
        ...radius,
        nodes,
        byKind,
        total: nodes.length,
        crownJewels: radius.crownJewels.filter(visible),
        hidden: radius.nodes.length - nodes.length,
      };
    });
  }

  /** Attack paths across the organizations in scope (each analysis cached per organization). */
  async attackPathsFor(
    tenantId: string,
    organizationIds: string[],
    filter: { targetId?: string; entryId?: string; toCrownJewelsOnly?: boolean; limit?: number } = {},
  ): Promise<ScopedAttackPaths> {
    const limit = Math.min(Math.max(filter.limit ?? 200, 1), 1000);
    const analyses: Array<{ organizationId: string; analysis: AttackPathAnalysis }> = [];
    for (const org of organizationIds) analyses.push({ organizationId: org, analysis: await this.attackPaths.analyze(tenantId, org) });
    const match = (p: AttackPathDetail) =>
      (!filter.targetId || p.target.id === filter.targetId || p.target.props?.assetId === filter.targetId) &&
      (!filter.entryId || p.entry.id === filter.entryId || p.entry.props?.assetId === filter.entryId) &&
      (!filter.toCrownJewelsOnly || isCrownJewel(p.target));
    const paths = analyses.flatMap((a) => a.analysis.paths.filter(match).map((p) => ({ ...p, organizationId: a.organizationId })));
    paths.sort((a, b) => b.risk.score - a.risk.score || a.length - b.length || a.id.localeCompare(b.id));
    const remediations = analyses.flatMap((a) => a.analysis.remediations.map((r) => ({ ...r, organizationId: a.organizationId })));
    remediations.sort((a, b) => b.pathsBroken - a.pathsBroken || b.riskReduced - a.riskReduced);
    const kept = paths.slice(0, limit);
    const lengths = paths.map((p) => p.length);
    return {
      paths: kept,
      remediations: remediations.slice(0, 50),
      summary: {
        totalPaths: paths.length,
        toCrownJewels: paths.filter((p) => isCrownJewel(p.target)).length,
        targetsAtRisk: new Set(paths.map((p) => p.target.id)).size,
        entryPoints: new Set(paths.map((p) => p.entry.id)).size,
        maxRiskScore: paths.reduce((m, p) => Math.max(m, p.risk.score), 0),
        shortestPathLength: lengths.length > 0 ? Math.min(...lengths) : null,
        fixesToBreakAll: analyses.reduce((n, a) => n + a.analysis.summary.fixesToBreakAll, 0),
        topRemediation: remediations[0]?.action ?? null,
        truncated: analyses.some((a) => a.analysis.summary.truncated) || paths.length > kept.length,
        organizations: analyses.length,
      },
      byOrganization: analyses.map((a) => ({
        organizationId: a.organizationId,
        totalPaths: a.analysis.paths.length,
        toCrownJewels: a.analysis.paths.filter((p) => isCrownJewel(p.target)).length,
        maxRiskScore: a.analysis.summary.maxRiskScore,
      })),
    };
  }
}
