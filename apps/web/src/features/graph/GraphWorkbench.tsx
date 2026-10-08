import type { GraphNode } from "@bloody/contracts";
import { clsx } from "clsx";
import { LoaderCircle } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { CopyButton } from "../../components/CopyButton";
import { GraphCanvas } from "../../components/graph/GraphCanvas";
import { GraphNodeMenu } from "../../components/graph/GraphNodeMenu";
import { nodeKindMeta, PIVOT_KINDS } from "../../components/graph/nodeKinds";
import { nodePropRows, nodeValue } from "../../lib/graphQueries";
import { humanize } from "../../lib/format";
import type { GraphExplorerState } from "./useGraphExplorer";
import { useNodeActions } from "./useNodeActions";

/** Kind legend: icon + colour for the analyst pivot chain (USER → … → THREAT ACTOR). */
export function GraphLegend({ kinds = PIVOT_KINDS, present }: { kinds?: string[]; present?: Set<string> }) {
  return (
    <ul className="flex flex-wrap gap-x-3 gap-y-1" aria-label="Node kinds">
      {kinds.map((k) => {
        const meta = nodeKindMeta(k);
        const Icon = meta.icon;
        return (
          <li key={k} className={clsx("inline-flex items-center gap-1 text-2xs uppercase tracking-wide", present && !present.has(k) ? "text-fg-subtle opacity-60" : "text-fg-muted")}>
            <span className="inline-flex h-4 w-4 items-center justify-center rounded-full text-white" style={{ background: meta.color }} aria-hidden>
              <Icon size={9} />
            </span>
            {meta.label}
          </li>
        );
      })}
    </ul>
  );
}

/** Selected-node detail with the same contextual actions as the right-click menu. */
function NodeInspector({ node, actions, degree, expanded, expanding }: { node: GraphNode; actions: ReturnType<ReturnType<typeof useNodeActions>["actionsFor"]>; degree: number; expanded: boolean; expanding: boolean }) {
  const meta = nodeKindMeta(node.kind);
  const Icon = meta.icon;
  const rows = nodePropRows(node);
  return (
    <div className="space-y-3 p-3" data-testid="node-inspector">
      <div className="flex items-start gap-2">
        <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-white" style={{ background: meta.color }} aria-hidden>
          <Icon size={16} />
        </span>
        <div className="min-w-0">
          <div className="break-words font-semibold text-fg">{node.label}</div>
          <div className="text-2xs uppercase tracking-wide text-fg-subtle">{meta.label}</div>
        </div>
      </div>
      <div className="flex items-center gap-1 text-xs text-fg-muted">
        <code className="min-w-0 truncate font-mono" title={nodeValue(node)}>
          {nodeValue(node)}
        </code>
        <CopyButton value={nodeValue(node)} label="Copy key" />
      </div>
      <div className="flex flex-wrap gap-1.5 text-xs">
        <Badge size="xs" tone="outline">
          {degree} connection{degree === 1 ? "" : "s"} on canvas
        </Badge>
        {expanding ? (
          <Badge size="xs" tone="info" icon={LoaderCircle}>
            Expanding…
          </Badge>
        ) : expanded ? (
          <Badge size="xs" tone="success">
            Neighbors loaded
          </Badge>
        ) : null}
      </div>
      <div className="flex flex-col gap-1">
        {actions.map((a) => (
          <Button key={a.key} size="sm" variant={a.danger ? "danger" : "secondary"} icon={a.icon} onClick={a.onSelect} title={a.hint} className="justify-start">
            {a.label}
          </Button>
        ))}
      </div>
      {rows.length > 0 ? (
        <dl className="space-y-1 border-t border-line pt-2 text-xs">
          {rows.slice(0, 30).map((r) => (
            <div key={r.key} className="grid grid-cols-[110px_1fr] gap-2">
              <dt className="truncate text-fg-subtle" title={r.key}>
                {humanize(r.key)}
              </dt>
              <dd className="min-w-0 break-words font-mono text-fg">{r.value.length > 200 ? `${r.value.slice(0, 200)}…` : r.value}</dd>
            </div>
          ))}
        </dl>
      ) : null}
    </div>
  );
}

/**
 * Security Graph workbench: canvas + right-click contextual actions + node inspector.
 * Double-click expands neighbors; every action is permission-aware and response actions go
 * through the approval gate.
 */
export function GraphWorkbench({
  explorer,
  height = 560,
  incidentId,
  emptyState,
  highlightIds,
  toolbar,
}: {
  explorer: GraphExplorerState;
  height?: number | string;
  incidentId?: string;
  emptyState?: ReactNode;
  highlightIds?: string[];
  toolbar?: ReactNode;
}) {
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [menu, setMenu] = useState<{ node: GraphNode; at: { x: number; y: number } } | null>(null);
  const { actionsFor, dialog } = useNodeActions({
    onExpand: (n) => void explorer.expand(n),
    onHide: (n) => {
      explorer.hide(n);
      setSelected((s) => (s?.id === n.id ? null : s));
    },
    ...(incidentId ? { incidentId } : {}),
  });
  const presentKinds = useMemo(() => new Set(explorer.graph.nodes.map((n) => n.kind as string)), [explorer.graph.nodes]);
  const current = selected ? (explorer.graph.nodes.find((n) => n.id === selected.id) ?? null) : null;
  const degree = current ? explorer.graph.edges.filter((e) => e.from === current.id || e.to === current.id).length : 0;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <GraphLegend present={presentKinds} />
        <div className="ml-auto flex items-center gap-2 text-xs text-fg-muted">
          {explorer.expanding.size > 0 ? (
            <span className="inline-flex items-center gap-1" role="status">
              <LoaderCircle size={12} className="animate-spin" aria-hidden /> Loading neighbors…
            </span>
          ) : null}
          <span>
            {explorer.graph.nodes.length} nodes · {explorer.graph.edges.length} edges
          </span>
          {toolbar}
        </div>
      </div>
      {explorer.error ? (
        <p role="alert" className="text-sm text-sev-critical">
          {explorer.error}
        </p>
      ) : null}
      {explorer.graph.nodes.length === 0 && emptyState ? (
        <div className="rounded border border-line bg-surface">{emptyState}</div>
      ) : (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1fr)_280px]">
          <GraphCanvas
            graph={explorer.graph}
            roots={explorer.roots}
            selectedId={current?.id ?? null}
            highlightIds={highlightIds}
            onSelect={setSelected}
            onExpand={(n) => void explorer.expand(n)}
            onContextMenu={(node, at) => setMenu({ node, at })}
            height={height}
          />
          <aside className="rounded border border-line bg-surface" aria-label="Selected node">
            {current ? (
              <NodeInspector node={current} actions={actionsFor(current)} degree={degree} expanded={explorer.expanded.has(current.id)} expanding={explorer.expanding.has(current.id)} />
            ) : (
              <p className="p-3 text-sm text-fg-muted">Select a node to see its details. Double-click to expand its neighbors, right-click for actions.</p>
            )}
          </aside>
        </div>
      )}
      {menu ? <GraphNodeMenu node={menu.node} at={menu.at} actions={actionsFor(menu.node)} onClose={() => setMenu(null)} /> : null}
      {dialog}
    </div>
  );
}
