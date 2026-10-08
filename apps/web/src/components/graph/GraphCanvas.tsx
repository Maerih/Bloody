import type { GraphEdge, GraphNode, Subgraph } from "@bloody/contracts";
import { Background, Controls, Handle, MiniMap, Position, ReactFlow, useEdgesState, useNodesState, type Edge, type Node, type NodeProps } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { clsx } from "clsx";
import { memo, useEffect, useMemo, useRef } from "react";
import { layoutGraph, type Point } from "../../lib/graphLayout";
import { nodeKindMeta } from "./nodeKinds";

interface SecurityNodeData extends Record<string, unknown> {
  node: GraphNode;
  selected: boolean;
  highlighted: boolean;
  dimmed: boolean;
}
type SecurityFlowNode = Node<SecurityNodeData, "security">;

function riskOf(node: GraphNode): number | null {
  const r = node.props?.riskScore ?? node.props?.risk;
  return typeof r === "number" && Number.isFinite(r) ? r : null;
}

const SecurityNodeView = memo(function SecurityNodeView({ data }: NodeProps<SecurityFlowNode>) {
  const meta = nodeKindMeta(data.node.kind);
  const Icon = meta.icon;
  const risk = riskOf(data.node);
  return (
    <div
      className={clsx("flex w-[150px] flex-col items-center gap-1 text-center transition-opacity", data.dimmed && "opacity-35")}
      title={`${meta.label}: ${data.node.label}`}
      data-testid="graph-node"
      data-kind={data.node.kind}
    >
      <Handle type="target" position={Position.Top} className="!h-1 !w-1 !border-0 !bg-transparent" />
      <span
        className={clsx("relative inline-flex h-10 w-10 items-center justify-center rounded-full text-white shadow-card ring-offset-2 ring-offset-surface", data.selected ? "ring-2 ring-primary" : data.highlighted ? "ring-2 ring-sev-high" : "")}
        style={{ background: meta.color }}
      >
        <Icon size={18} aria-hidden />
        {risk !== null && risk >= 70 ? <span className="absolute -right-1 -top-1 h-3 w-3 rounded-full border-2 border-surface bg-sev-critical" aria-label="High risk" /> : null}
      </span>
      <span className="max-w-full truncate rounded bg-surface/90 px-1 text-2xs font-medium text-fg">{data.node.label}</span>
      <span className="text-[9px] uppercase tracking-wide text-fg-subtle">{meta.label}</span>
      <Handle type="source" position={Position.Bottom} className="!h-1 !w-1 !border-0 !bg-transparent" />
    </div>
  );
});

const NODE_TYPES = { security: SecurityNodeView };

export interface GraphCanvasProps {
  graph: Subgraph;
  /** Layout roots (focus nodes). */
  roots?: string[];
  selectedId?: string | null;
  /** Nodes to emphasise (e.g. an attack path); others are dimmed when non-empty. */
  highlightIds?: string[];
  onSelect?: (node: GraphNode | null) => void;
  /** Double-click: expand neighbors. */
  onExpand?: (node: GraphNode) => void;
  /** Right-click: contextual actions at screen coordinates. */
  onContextMenu?: (node: GraphNode, at: { x: number; y: number }) => void;
  height?: number | string;
  className?: string;
  showMiniMap?: boolean;
}

function toFlowEdge(e: GraphEdge, highlight: Set<string>): Edge {
  const hot = highlight.size > 0 && highlight.has(e.from) && highlight.has(e.to);
  return {
    id: e.id,
    source: e.from,
    target: e.to,
    label: e.kind.replace(/_/g, " "),
    labelStyle: { fontSize: 9, fill: "rgb(var(--fg-muted))" },
    labelBgStyle: { fill: "rgb(var(--surface))" },
    style: { stroke: hot ? "rgb(var(--sev-high))" : "rgb(var(--border-strong))", strokeWidth: hot ? 2 : 1 },
    animated: hot,
  };
}

/**
 * Security Graph canvas (React Flow): typed node badges, deterministic incremental layout,
 * select / expand (double-click) / contextual actions (right-click).
 */
export function GraphCanvas({ graph, roots = [], selectedId = null, highlightIds = [], onSelect, onExpand, onContextMenu, height = 520, className, showMiniMap = true }: GraphCanvasProps) {
  const positionsRef = useRef<Map<string, Point>>(new Map());
  const highlight = useMemo(() => new Set(highlightIds), [highlightIds]);
  const [nodes, setNodes, onNodesChange] = useNodesState<SecurityFlowNode>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  useEffect(() => {
    const positions = layoutGraph(graph.nodes, graph.edges, roots, positionsRef.current);
    positionsRef.current = positions;
    setNodes(
      graph.nodes.map((n) => ({
        id: n.id,
        type: "security",
        position: positions.get(n.id) ?? { x: 0, y: 0 },
        data: { node: n, selected: n.id === selectedId, highlighted: highlight.has(n.id), dimmed: highlight.size > 0 && !highlight.has(n.id) },
      })),
    );
    setEdges(graph.edges.map((e) => toFlowEdge(e, highlight)));
  }, [graph, roots, selectedId, highlight, setNodes, setEdges]);

  return (
    <div className={clsx("relative overflow-hidden rounded border border-line bg-surface-2", className)} style={{ height }} data-testid="graph-canvas">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={NODE_TYPES}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeDragStop={(_e, node) => positionsRef.current.set(node.id, node.position)}
        onNodeClick={(_e, node) => onSelect?.(node.data.node)}
        onNodeDoubleClick={(_e, node) => onExpand?.(node.data.node)}
        onNodeContextMenu={(e, node) => {
          if (!onContextMenu) return;
          e.preventDefault();
          onSelect?.(node.data.node);
          onContextMenu(node.data.node, { x: e.clientX, y: e.clientY });
        }}
        onPaneClick={() => onSelect?.(null)}
        nodesConnectable={false}
        fitView
        fitViewOptions={{ padding: 0.2, maxZoom: 1.2 }}
        minZoom={0.1}
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={24} size={1} />
        <Controls showInteractive={false} />
        {showMiniMap ? <MiniMap pannable zoomable nodeColor={(n) => nodeKindMeta((n.data as SecurityNodeData).node.kind).color} /> : null}
      </ReactFlow>
    </div>
  );
}
