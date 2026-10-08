import type { GraphNode, Subgraph } from "@bloody/contracts";
import { useCallback, useMemo, useState } from "react";
import { errorMessage } from "../../api/client";
import { useNeighborFetcher } from "../../api/hooks";
import { mergeSubgraphs } from "../../api/normalize";

const EMPTY: Subgraph = { nodes: [], edges: [] };

export interface GraphExplorerState {
  graph: Subgraph;
  roots: string[];
  expanded: Set<string>;
  expanding: Set<string>;
  error: string | null;
  /** Add a node (search hit) and expand it. */
  open: (node: GraphNode) => Promise<void>;
  expand: (node: GraphNode) => Promise<void>;
  hide: (node: GraphNode) => void;
  /** Replace the canvas with a subgraph (incident graph, attack path). */
  load: (graph: Subgraph, roots?: string[]) => void;
  reset: () => void;
}

/**
 * Incremental Security Graph exploration: the canvas holds the union of every expansion;
 * hidden nodes stay hidden until the canvas is reset. Neighbor responses share the react-query
 * cache, so re-expanding is free.
 */
export function useGraphExplorer(neighborLimit = 50): GraphExplorerState {
  const fetchNeighbors = useNeighborFetcher();
  const [base, setBase] = useState<Subgraph>(EMPTY);
  const [roots, setRoots] = useState<string[]>([]);
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [expanding, setExpanding] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);

  const expand = useCallback(
    async (node: GraphNode) => {
      setError(null);
      setExpanding((s) => new Set(s).add(node.id));
      try {
        const neighbors = await fetchNeighbors(node.id, { depth: 1, direction: "both", limit: neighborLimit });
        setBase((g) => mergeSubgraphs(g, { nodes: [node], edges: [] }, neighbors));
        setHidden((h) => {
          if (h.size === 0) return h;
          const next = new Set(h);
          next.delete(node.id);
          return next;
        });
        setExpanded((s) => new Set(s).add(node.id));
      } catch (e) {
        setError(errorMessage(e));
      } finally {
        setExpanding((s) => {
          const next = new Set(s);
          next.delete(node.id);
          return next;
        });
      }
    },
    [fetchNeighbors, neighborLimit],
  );

  const open = useCallback(
    async (node: GraphNode) => {
      setBase((g) => mergeSubgraphs(g, { nodes: [node], edges: [] }));
      setRoots((r) => (r.includes(node.id) ? r : [...r, node.id]));
      await expand(node);
    },
    [expand],
  );

  const hide = useCallback((node: GraphNode) => setHidden((h) => new Set(h).add(node.id)), []);

  const load = useCallback((graph: Subgraph, nextRoots: string[] = []) => {
    setBase(graph);
    setRoots(nextRoots);
    setHidden(new Set());
    setExpanded(new Set());
    setError(null);
  }, []);

  const reset = useCallback(() => load(EMPTY), [load]);

  const graph = useMemo<Subgraph>(() => {
    if (hidden.size === 0) return base;
    const nodes = base.nodes.filter((n) => !hidden.has(n.id));
    const ids = new Set(nodes.map((n) => n.id));
    return { nodes, edges: base.edges.filter((e) => ids.has(e.from) && ids.has(e.to)) };
  }, [base, hidden]);

  return { graph, roots, expanded, expanding, error, open, expand, hide, load, reset };
}
