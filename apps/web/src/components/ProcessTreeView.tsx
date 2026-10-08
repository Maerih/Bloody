import { clsx } from "clsx";
import { ChevronDown, ChevronRight, Cpu } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import type { HostProcessTree, ProcessNode } from "../lib/processTree";
import { SEVERITY_META } from "../lib/severity";
import { RelativeTime } from "./RelativeTime";

function ProcessRow({ node, depth, onSelectEvent }: { node: ProcessNode; depth: number; onSelectEvent?: (eventId: string) => void }) {
  const [open, setOpen] = useState(depth < 3);
  const hasChildren = node.children.length > 0;
  const sev = SEVERITY_META[node.severity];
  return (
    <li role="treeitem" aria-expanded={hasChildren ? open : undefined} aria-label={node.name}>
      <div className="group flex items-start gap-1 rounded px-1 py-0.5 hover:bg-surface-2" style={{ paddingLeft: depth * 16 }}>
        {hasChildren ? (
          <button type="button" onClick={() => setOpen((v) => !v)} className="mt-0.5 text-fg-subtle hover:text-fg" aria-label={open ? `Collapse ${node.name}` : `Expand ${node.name}`}>
            {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          </button>
        ) : (
          <span className="w-[13px]" />
        )}
        <Cpu size={13} className={clsx("mt-0.5 shrink-0", node.synthetic ? "text-fg-subtle" : sev.text)} aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2">
            <button
              type="button"
              className={clsx("font-mono text-xs font-semibold", node.synthetic ? "text-fg-muted" : "text-heading", onSelectEvent && node.eventIds.length > 0 && "hover:underline")}
              onClick={() => node.eventIds.length > 0 && onSelectEvent?.(node.eventIds[node.eventIds.length - 1]!)}
              disabled={node.eventIds.length === 0}
            >
              {node.name}
            </button>
            {node.pid !== null ? <span className="text-2xs text-fg-subtle">pid {node.pid}</span> : null}
            {node.user ? <span className="text-2xs text-fg-subtle">{node.user}</span> : null}
            {node.severity !== "info" ? <span className={clsx("text-2xs font-semibold", sev.text)}>{sev.label}</span> : null}
            {node.synthetic ? <span className="text-2xs italic text-fg-subtle">parent (not observed)</span> : null}
            {node.firstSeen ? <RelativeTime value={node.firstSeen} className="text-2xs text-fg-subtle" /> : null}
            {node.sha256 ? (
              <Link to={`/cti/indicators?q=${encodeURIComponent(node.sha256)}`} className="font-mono text-2xs text-primary hover:underline" title={node.sha256}>
                {node.sha256.slice(0, 12)}…
              </Link>
            ) : null}
          </div>
          {node.commandLine ? (
            <div className="truncate font-mono text-2xs text-fg-muted" title={node.commandLine}>
              {node.commandLine}
            </div>
          ) : null}
        </div>
      </div>
      {hasChildren && open ? (
        <ul role="group">
          {node.children.map((c) => (
            <ProcessRow key={c.key} node={c} depth={depth + 1} onSelectEvent={onSelectEvent} />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

/** Process lineage per host, reconstructed from process events. */
export function ProcessTreeView({ trees, onSelectEvent }: { trees: HostProcessTree[]; onSelectEvent?: (eventId: string) => void }) {
  return (
    <div className="space-y-3" data-testid="process-tree">
      {trees.map((t) => (
        <section key={t.host}>
          <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-fg-muted">
            {t.host} <span className="font-normal normal-case text-fg-subtle">· {t.processCount} processes</span>
          </h4>
          <ul role="tree" aria-label={`Process tree for ${t.host}`} className="rounded border border-line p-1">
            {t.roots.map((r) => (
              <ProcessRow key={r.key} node={r} depth={0} onSelectEvent={onSelectEvent} />
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}
