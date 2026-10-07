import type { EdgeKind, GraphEdge, GraphNode, NodeKind, Subgraph } from "@bloody/contracts";

/**
 * Security Graph storage abstraction.
 *
 * A `GraphStore` instance is **bound to exactly one tenant** (`tenantId`). Everything it
 * returns belongs to that tenant; it is impossible to address another tenant's nodes through
 * it. Inside a tenant, nodes belong to an organization (`organizationId`) or are tenant-global
 * (`organizationId = null`, e.g. ATT&CK techniques, MSSP-wide threat actors).
 *
 * The interface is async so that a Postgres implementation (see `./sql.ts`) is natural; the
 * in-memory implementation resolves immediately.
 *
 * Node identity: `(organizationId, kind, key)` is unique and maps to a **stable id**
 * (`graphNodeId`, UUIDv5) — upserting the same natural key twice returns the same node.
 * Edge identity: `(from, kind, to)` is unique (dedupe) with a stable id (`graphEdgeId`).
 *
 * Property semantics on upsert: props are shallow-merged (incoming keys win, `undefined`
 * values are ignored). When `observedAt` is supplied the store maintains three reserved
 * props: `firstSeenAt` (min), `lastSeenAt` (max) and `seenCount` (+1).
 */
export interface GraphStore {
  readonly tenantId: string;

  upsertNode(input: GraphNodeInput, options?: UpsertOptions): Promise<GraphNode>;
  upsertEdge(input: GraphEdgeInput, options?: UpsertOptions): Promise<GraphEdgeRecord>;

  getNode(id: string): Promise<GraphNode | null>;
  getNodes(ids: readonly string[]): Promise<GraphNode[]>;
  getNodeByKey(organizationId: string | null, kind: NodeKind, key: string): Promise<GraphNode | null>;
  getEdge(id: string): Promise<GraphEdgeRecord | null>;

  findNodes(query: FindNodesQuery): Promise<GraphNode[]>;
  countNodes(query: Omit<FindNodesQuery, "limit">): Promise<number>;

  /** One-hop batched adjacency: edges touching any of `nodeIds` in the given direction. */
  edgesOf(nodeIds: readonly string[], options: EdgesOfOptions): Promise<GraphEdgeRecord[]>;

  /** Multi-hop breadth-first neighborhood (root excluded from `nodes`). */
  neighbors(nodeId: string, options?: NeighborQuery): Promise<Neighborhood>;

  /** Induced subgraph: the given nodes and every edge whose both endpoints are among them. */
  subgraph(nodeIds: readonly string[]): Promise<Subgraph>;

  /** Delete a node and every edge touching it. Returns false when it did not exist. */
  deleteNode(id: string): Promise<boolean>;
  deleteEdge(id: string): Promise<boolean>;
}

export interface GraphNodeInput {
  organizationId: string | null;
  kind: NodeKind;
  key: string;
  /** Display label; defaults to `key` on insert and is left unchanged on update when omitted. */
  label?: string;
  props?: Record<string, unknown>;
}

export interface GraphEdgeInput {
  /** Must match the organization of the non-global endpoint(s). Defaults to it when omitted. */
  organizationId?: string | null;
  kind: EdgeKind;
  from: string;
  to: string;
  props?: Record<string, unknown>;
}

export interface UpsertOptions {
  /** ISO timestamp of the observation; maintains firstSeenAt / lastSeenAt / seenCount. */
  observedAt?: string;
}

/** Contract edge plus the organization it belongs to (graph_edges.organization_id). */
export interface GraphEdgeRecord extends GraphEdge {
  organizationId: string | null;
}

export interface FindNodesQuery {
  /** undefined = every organization in the tenant, null = tenant-global nodes only. */
  organizationId?: string | null;
  kind?: NodeKind | readonly NodeKind[];
  /** Exact natural key. */
  key?: string;
  keyPrefix?: string;
  /** Case-insensitive substring of the label. */
  labelContains?: string;
  /** Every listed prop must equal the given scalar (Postgres: `props @> $1::jsonb`). */
  propEquals?: Record<string, string | number | boolean>;
  /** Default 100, hard maximum 1000. */
  limit?: number;
}

export type Direction = "out" | "in" | "both";

export interface EdgesOfOptions {
  direction: Direction;
  edgeKinds?: readonly EdgeKind[];
  /** Safety cap on returned edges (default 10 000). */
  limit?: number;
}

export interface NeighborQuery {
  direction?: Direction;
  edgeKinds?: readonly EdgeKind[];
  /** Only these node kinds are returned *and* traversed through. */
  nodeKinds?: readonly NodeKind[];
  /** Hops, default 1, maximum 6. */
  depth?: number;
  /** Maximum nodes returned (default 500, maximum 5000). */
  limit?: number;
}

export interface Neighborhood {
  root: GraphNode;
  nodes: Array<{ node: GraphNode; depth: number }>;
  edges: GraphEdgeRecord[];
  /** True when `limit` cut the traversal short. */
  truncated: boolean;
}

export class GraphError extends Error {
  constructor(
    readonly code: "not_found" | "integrity" | "tenant_mismatch" | "invalid_input",
    message: string,
  ) {
    super(message);
    this.name = "GraphError";
  }
}

export const FIND_LIMIT_DEFAULT = 100;
export const FIND_LIMIT_MAX = 1000;
export const NEIGHBOR_DEPTH_MAX = 6;
export const NEIGHBOR_LIMIT_DEFAULT = 500;
export const NEIGHBOR_LIMIT_MAX = 5000;
export const EDGES_OF_LIMIT_DEFAULT = 10_000;
