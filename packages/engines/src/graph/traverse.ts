import type { GraphNode } from "@bloody/contracts";
import {
  GraphError,
  NEIGHBOR_DEPTH_MAX,
  NEIGHBOR_LIMIT_DEFAULT,
  NEIGHBOR_LIMIT_MAX,
  type GraphEdgeRecord,
  type GraphStore,
  type Neighborhood,
  type NeighborQuery,
} from "./types.js";

/**
 * Store-agnostic multi-hop BFS built only on `edgesOf` + `getNodes` (one batched round trip
 * per hop). Stores may delegate `neighbors()` to this, or override it (e.g. a recursive CTE)
 * as long as the result is identical.
 *
 * Semantics: nodes are returned once, at their shortest hop distance; when `nodeKinds` is set
 * only those kinds are returned *and* traversed; edges are returned when both endpoints are
 * the root or returned nodes. Ordering is deterministic (by hop, then kind, then key).
 */
export async function traverseNeighbors(store: Pick<GraphStore, "getNode" | "getNodes" | "edgesOf">, nodeId: string, query: NeighborQuery = {}): Promise<Neighborhood> {
  const root = await store.getNode(nodeId);
  if (!root) throw new GraphError("not_found", `Graph node ${nodeId} not found`);
  const direction = query.direction ?? "both";
  const depth = Math.max(1, Math.min(query.depth ?? 1, NEIGHBOR_DEPTH_MAX));
  const limit = Math.max(1, Math.min(query.limit ?? NEIGHBOR_LIMIT_DEFAULT, NEIGHBOR_LIMIT_MAX));
  const nodeKinds = query.nodeKinds ? new Set(query.nodeKinds) : null;

  const seen = new Set<string>([root.id]);
  const result: Array<{ node: GraphNode; depth: number }> = [];
  const edges = new Map<string, GraphEdgeRecord>();
  const touched: GraphEdgeRecord[] = [];
  let frontier = [root.id];
  let truncated = false;

  for (let d = 1; d <= depth && frontier.length > 0 && !truncated; d++) {
    const hop = await store.edgesOf(frontier, { direction, ...(query.edgeKinds ? { edgeKinds: query.edgeKinds } : {}) });
    const frontierSet = new Set(frontier);
    const candidates = new Set<string>();
    for (const e of hop) {
      touched.push(e);
      if (frontierSet.has(e.from) && direction !== "in" && !seen.has(e.to)) candidates.add(e.to);
      if (frontierSet.has(e.to) && direction !== "out" && !seen.has(e.from)) candidates.add(e.from);
    }
    const nodes = await store.getNodes([...candidates]);
    nodes.sort((a, b) => (a.kind === b.kind ? a.key.localeCompare(b.key) : a.kind.localeCompare(b.kind)));
    const next: string[] = [];
    for (const n of nodes) {
      if (nodeKinds && !nodeKinds.has(n.kind)) continue;
      if (result.length >= limit) {
        truncated = true;
        break;
      }
      seen.add(n.id);
      result.push({ node: n, depth: d });
      next.push(n.id);
    }
    frontier = next;
  }
  for (const e of touched) if (seen.has(e.from) && seen.has(e.to)) edges.set(e.id, e);
  return { root, nodes: result, edges: [...edges.values()].sort((a, b) => a.id.localeCompare(b.id)), truncated };
}
