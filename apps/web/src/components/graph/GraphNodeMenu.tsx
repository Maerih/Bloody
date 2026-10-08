import type { GraphNode } from "@bloody/contracts";
import { clsx } from "clsx";
import type { LucideIcon } from "lucide-react";
import { useMemo, useRef } from "react";
import { createPortal } from "react-dom";
import { useDismiss } from "../../hooks/useClickOutside";
import { nodeKindMeta } from "./nodeKinds";

export interface NodeAction {
  key: string;
  label: string;
  icon: LucideIcon;
  onSelect: () => void;
  danger?: boolean;
  hint?: string;
}

/** Right-click menu of contextual actions for a graph node (portal, fixed position). */
export function GraphNodeMenu({ node, at, actions, onClose }: { node: GraphNode; at: { x: number; y: number }; actions: NodeAction[]; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const refs = useMemo(() => [ref], []);
  useDismiss(refs, onClose, true);
  const meta = nodeKindMeta(node.kind);
  const left = Math.min(at.x, (typeof window !== "undefined" ? window.innerWidth : 1200) - 240);
  const top = Math.min(at.y, (typeof window !== "undefined" ? window.innerHeight : 800) - 40 - actions.length * 30);
  return createPortal(
    <div ref={ref} role="menu" aria-label={`Actions for ${node.label}`} className="fixed z-[80] w-56 animate-fade-in rounded-md border border-line bg-surface py-1 shadow-pop" style={{ left, top }}>
      <div className="border-b border-line px-3 py-1.5">
        <div className="truncate text-sm font-semibold text-fg">{node.label}</div>
        <div className="text-2xs uppercase tracking-wide text-fg-subtle">{meta.label}</div>
      </div>
      {actions.map((a) => (
        <button
          key={a.key}
          type="button"
          role="menuitem"
          onClick={() => {
            onClose();
            a.onSelect();
          }}
          className={clsx("flex w-full items-center gap-2 px-3 py-1.5 text-left text-base hover:bg-surface-3", a.danger ? "text-sev-critical" : "text-fg")}
          title={a.hint}
        >
          <a.icon size={13} aria-hidden />
          {a.label}
        </button>
      ))}
    </div>,
    document.body,
  );
}
