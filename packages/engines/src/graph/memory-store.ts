import type { GraphNode, NodeKind, Subgraph } from "@bloody/contracts";
import { NodeKind as NodeKindSchema, EdgeKind as EdgeKindSchema } from "@bloody/contracts";
import { graphEdgeId, graphNodeId } from "./ids.js";
import { mergeProps } from "./props.js";
import { traverseNeighbors } from "./traverse.js";
import {
  EDGES_OF_LIMIT_DEFAULT,
  FIND_LIMIT_DEFAULT,
  FIND_LIMIT_MAX,
  GraphError,
  type EdgesOfOptions,
  type FindNodesQuery,
  type GraphEdgeInput,
  type GraphEdgeRecord,
  type GraphNodeInput,
  type GraphStore,
  type Neighborhood,
  type NeighborQuery,
  type UpsertOptions,
} from "./types.js";

const MAX_KEY_LENGTH = 2048;

/**
 * In-process `GraphStore` for the single-process deployment, tests and offline analysis.
 * Adjacency is indexed both ways so traversals are O(degree).
 */
export class InMemoryGraphStore implements GraphStore {
  readonly tenantId: string;
  private readonly nodes = new Map<string, GraphNode>();
  private readonly edges = new Map<string, GraphEdgeRecord>();
  private readonly out = new Map<string, Set<string>>();
  private readonly in = new Map<string, Set<string>>();

  constructor(options: { tenantId: string }) {
    if (!options.tenantId) throw new GraphError("invalid_input", "tenantId is required");
    this.tenantId = options.tenantId;
  }

  get size(): { nodes: number; edges: number } {
    return { nodes: this.nodes.size, edges: this.edges.size };
  }

  async upsertNode(input: GraphNodeInput, options?: UpsertOptions): Promise<GraphNode> {
    validateNodeInput(input);
    const id = graphNodeId(this.tenantId, input.organizationId, input.kind, input.key);
    const existing = this.nodes.get(id);
    const node: GraphNode = {
      id,
      kind: input.kind,
      key: input.key,
      label: input.label ?? existing?.label ?? input.key,
      organizationId: input.organizationId,
      props: mergeProps(existing?.props, input.props, options),
    };
    this.nodes.set(id, node);
    return clone(node);
  }

  async upsertEdge(input: GraphEdgeInput, options?: UpsertOptions): Promise<GraphEdgeRecord> {
    if (!EdgeKindSchema.safeParse(input.kind).success) throw new GraphError("invalid_input", `Unknown edge kind ${String(input.kind)}`);
    const from = this.nodes.get(input.from);
    const to = this.nodes.get(input.to);
    if (!from || !to) throw new GraphError("integrity", `Edge ${input.kind} references a node that does not exist in tenant ${this.tenantId}`);
    const organizationId = resolveEdgeOrganization(from, to, input.organizationId);
    const id = graphEdgeId(this.tenantId, from.id, input.kind, to.id);
    const existing = this.edges.get(id);
    const edge: GraphEdgeRecord = {
      id,
      kind: input.kind,
      from: from.id,
      to: to.id,
      organizationId,
      props: mergeProps(existing?.props, input.props, options),
    };
    this.edges.set(id, edge);
    index(this.out, from.id, id);
    index(this.in, to.id, id);
    return clone(edge);
  }

  async getNode(id: string): Promise<GraphNode | null> {
    const n = this.nodes.get(id);
    return n ? clone(n) : null;
  }

  async getNodes(ids: readonly string[]): Promise<GraphNode[]> {
    const out: GraphNode[] = [];
    for (const id of new Set(ids)) {
      const n = this.nodes.get(id);
      if (n) out.push(clone(n));
    }
    return out;
  }

  async getNodeByKey(organizationId: string | null, kind: NodeKind, key: string): Promise<GraphNode | null> {
    return this.getNode(graphNodeId(this.tenantId, organizationId, kind, key));
  }

  async getEdge(id: string): Promise<GraphEdgeRecord | null> {
    const e = this.edges.get(id);
    return e ? clone(e) : null;
  }

  async findNodes(query: FindNodesQuery): Promise<GraphNode[]> {
    const limit = Math.max(1, Math.min(query.limit ?? FIND_LIMIT_DEFAULT, FIND_LIMIT_MAX));
    const out: GraphNode[] = [];
    for (const n of this.sortedMatches(query)) {
      out.push(clone(n));
      if (out.length >= limit) break;
    }
    return out;
  }

  async countNodes(query: Omit<FindNodesQuery, "limit">): Promise<number> {
    let count = 0;
    for (const n of this.nodes.values()) if (matchesQuery(n, query)) count++;
    return count;
  }

  async edgesOf(nodeIds: readonly string[], options: EdgesOfOptions): Promise<GraphEdgeRecord[]> {
    const limit = options.limit ?? EDGES_OF_LIMIT_DEFAULT;
    const kinds = options.edgeKinds ? new Set(options.edgeKinds) : null;
    const ids = new Set<string>();
    for (const nodeId of new Set(nodeIds)) {
      if (options.direction !== "in") for (const e of this.out.get(nodeId) ?? []) ids.add(e);
      if (options.direction !== "out") for (const e of this.in.get(nodeId) ?? []) ids.add(e);
    }
    const out: GraphEdgeRecord[] = [];
    for (const id of [...ids].sort()) {
      const e = this.edges.get(id);
      if (!e || (kinds && !kinds.has(e.kind))) continue;
      out.push(clone(e));
      if (out.length >= limit) break;
    }
    return out;
  }

  async neighbors(nodeId: string, options?: NeighborQuery): Promise<Neighborhood> {
    return traverseNeighbors(this, nodeId, options);
  }

  async subgraph(nodeIds: readonly string[]): Promise<Subgraph> {
    const set = new Set(nodeIds.filter((id) => this.nodes.has(id)));
    const nodes = [...set].map((id) => clone(this.nodes.get(id)!));
    const edges: GraphEdgeRecord[] = [];
    for (const id of set) {
      for (const eid of this.out.get(id) ?? []) {
        const e = this.edges.get(eid);
        if (e && set.has(e.to)) edges.push(clone(e));
      }
    }
    edges.sort((a, b) => a.id.localeCompare(b.id));
    return { nodes, edges };
  }

  async deleteNode(id: string): Promise<boolean> {
    if (!this.nodes.has(id)) return false;
    for (const eid of [...(this.out.get(id) ?? []), ...(this.in.get(id) ?? [])]) this.removeEdge(eid);
    this.nodes.delete(id);
    this.out.delete(id);
    this.in.delete(id);
    return true;
  }

  async deleteEdge(id: string): Promise<boolean> {
    return this.removeEdge(id);
  }

  /** Every node and edge (for snapshots / analytics on small tenants). */
  async dump(): Promise<Subgraph> {
    return { nodes: [...this.nodes.values()].map(clone), edges: [...this.edges.values()].map(clone) };
  }

  private removeEdge(id: string): boolean {
    const e = this.edges.get(id);
    if (!e) return false;
    this.edges.delete(id);
    this.out.get(e.from)?.delete(id);
    this.in.get(e.to)?.delete(id);
    return true;
  }

  private sortedMatches(query: FindNodesQuery): GraphNode[] {
    if (query.key !== undefined && query.organizationId !== undefined && typeof query.kind === "string") {
      const n = this.nodes.get(graphNodeId(this.tenantId, query.organizationId, query.kind, query.key));
      return n && matchesQuery(n, query) ? [n] : [];
    }
    const out: GraphNode[] = [];
    for (const n of this.nodes.values()) if (matchesQuery(n, query)) out.push(n);
    return out.sort((a, b) => (a.kind === b.kind ? (a.key === b.key ? (a.organizationId ?? "").localeCompare(b.organizationId ?? "") : a.key.localeCompare(b.key)) : a.kind.localeCompare(b.kind)));
  }
}

/** One `InMemoryGraphStore` per tenant — the multi-tenant in-process provider. */
export class InMemoryGraphStoreProvider {
  private readonly stores = new Map<string, InMemoryGraphStore>();

  forTenant(tenantId: string): InMemoryGraphStore {
    let s = this.stores.get(tenantId);
    if (!s) {
      s = new InMemoryGraphStore({ tenantId });
      this.stores.set(tenantId, s);
    }
    return s;
  }

  dropTenant(tenantId: string): boolean {
    return this.stores.delete(tenantId);
  }
}

function matchesQuery(n: GraphNode, q: Omit<FindNodesQuery, "limit">): boolean {
  if (q.organizationId !== undefined && n.organizationId !== q.organizationId) return false;
  if (q.kind !== undefined) {
    if (typeof q.kind === "string" ? n.kind !== q.kind : !q.kind.includes(n.kind)) return false;
  }
  if (q.key !== undefined && n.key !== q.key) return false;
  if (q.keyPrefix !== undefined && !n.key.startsWith(q.keyPrefix)) return false;
  if (q.labelContains !== undefined && !n.label.toLowerCase().includes(q.labelContains.toLowerCase())) return false;
  if (q.propEquals) {
    for (const [k, v] of Object.entries(q.propEquals)) if (n.props[k] !== v) return false;
  }
  return true;
}

export function validateNodeInput(input: GraphNodeInput): void {
  if (!NodeKindSchema.safeParse(input.kind).success) throw new GraphError("invalid_input", `Unknown node kind ${String(input.kind)}`);
  if (typeof input.key !== "string" || input.key.length === 0) throw new GraphError("invalid_input", "Node key must be a non-empty string");
  if (input.key.length > MAX_KEY_LENGTH) throw new GraphError("invalid_input", `Node key exceeds ${MAX_KEY_LENGTH} characters`);
}

/**
 * Edges may connect nodes of the same organization, or an organization node with a
 * tenant-global node. Cross-organization edges are rejected (delegated-admin boundary).
 */
export function resolveEdgeOrganization(from: GraphNode, to: GraphNode, requested: string | null | undefined): string | null {
  if (from.organizationId && to.organizationId && from.organizationId !== to.organizationId) {
    throw new GraphError("integrity", `Cross-organization edge rejected (${from.organizationId} → ${to.organizationId})`);
  }
  const expected = from.organizationId ?? to.organizationId ?? null;
  if (requested === undefined) return expected;
  if (expected !== null && requested !== expected) {
    throw new GraphError("integrity", `Edge organization ${String(requested)} does not match its nodes' organization ${expected}`);
  }
  return requested;
}

function index(map: Map<string, Set<string>>, nodeId: string, edgeId: string): void {
  let s = map.get(nodeId);
  if (!s) {
    s = new Set();
    map.set(nodeId, s);
  }
  s.add(edgeId);
}

function clone<T>(v: T): T {
  return structuredClone(v);
}
