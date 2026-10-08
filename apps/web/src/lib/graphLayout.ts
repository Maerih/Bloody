import type { GraphEdge, GraphNode } from "@bloody/contracts";

/**
 * Deterministic graph layout for the Security Graph canvas: breadth-first rings around the
 * focus node(s). Existing positions are preserved so expanding a node never reshuffles what the
 * analyst is already looking at; new nodes are placed on an arc around the node they hang off.
 */

export interface Point {
  x: number;
  y: number;
}

const RING_GAP = 220;
const MIN_ARC = 120;

/** Evenly distribute `count` points on a circle (or an arc starting at `startAngle`). */
export function placeAround(center: Point, count: number, radius: number, startAngle = -Math.PI / 2, sweep = Math.PI * 2): Point[] {
  if (count <= 0) return [];
  const full = sweep >= Math.PI * 2 - 1e-6;
  const step = full ? sweep / count : count === 1 ? 0 : sweep / (count - 1);
  const start = full || count === 1 ? startAngle : startAngle - sweep / 2;
  return Array.from({ length: count }, (_, i) => ({
    x: Math.round(center.x + radius * Math.cos(start + i * step)),
    y: Math.round(center.y + radius * Math.sin(start + i * step)),
  }));
}

function adjacency(nodes: GraphNode[], edges: GraphEdge[]): Map<string, string[]> {
  const ids = new Set(nodes.map((n) => n.id));
  const adj = new Map<string, string[]>(nodes.map((n) => [n.id, []]));
  for (const e of edges) {
    if (!ids.has(e.from) || !ids.has(e.to) || e.from === e.to) continue;
    adj.get(e.from)!.push(e.to);
    adj.get(e.to)!.push(e.from);
  }
  for (const list of adj.values()) list.sort();
  return adj;
}

/**
 * Lay out every node: keep `previous` positions, BFS outward from `roots` (or the
 * highest-degree node), and place unvisited components to the right.
 */
export function layoutGraph(nodes: GraphNode[], edges: GraphEdge[], roots: string[] = [], previous: Map<string, Point> = new Map()): Map<string, Point> {
  const positions = new Map<string, Point>();
  for (const n of nodes) {
    const p = previous.get(n.id);
    if (p) positions.set(n.id, p);
  }
  const adj = adjacency(nodes, edges);
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const sortedIds = [...byId.keys()].sort((a, b) => (adj.get(b)?.length ?? 0) - (adj.get(a)?.length ?? 0) || a.localeCompare(b));
  const visited = new Set<string>();
  let componentOffsetX = 0;

  const seedOrder = [...roots.filter((r) => byId.has(r)), ...sortedIds];
  for (const seed of seedOrder) {
    if (visited.has(seed)) continue;
    if (!positions.has(seed)) {
      positions.set(seed, { x: componentOffsetX, y: 0 });
    }
    visited.add(seed);
    const queue: string[] = [seed];
    let maxX = positions.get(seed)!.x;
    while (queue.length > 0) {
      const id = queue.shift()!;
      const center = positions.get(id)!;
      const fresh = (adj.get(id) ?? []).filter((n) => !visited.has(n));
      const unplaced = fresh.filter((n) => !positions.has(n));
      if (unplaced.length > 0) {
        // Arc pointing away from the node's own parent direction keeps rings readable.
        const radius = Math.max(RING_GAP, (unplaced.length * MIN_ARC) / (2 * Math.PI));
        const isSeed = id === seed && !previous.has(id);
        const outward = Math.atan2(center.y - (positions.get(seed)?.y ?? 0), center.x - (positions.get(seed)?.x ?? 0));
        const pts = isSeed || (center.x === positions.get(seed)?.x && center.y === positions.get(seed)?.y)
          ? placeAround(center, unplaced.length, radius)
          : placeAround(center, unplaced.length, radius, outward, Math.min(Math.PI * 1.2, Math.max(Math.PI / 3, (unplaced.length * MIN_ARC) / radius)));
        unplaced.forEach((n, i) => positions.set(n, pts[i]!));
      }
      for (const n of fresh) {
        visited.add(n);
        queue.push(n);
        maxX = Math.max(maxX, positions.get(n)!.x);
      }
    }
    componentOffsetX = maxX + RING_GAP * 1.5;
  }
  return positions;
}
