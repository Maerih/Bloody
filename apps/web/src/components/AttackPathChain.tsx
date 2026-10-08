import type { AttackPath } from "@bloody/contracts";
import { clsx } from "clsx";
import { ArrowRight, Crown, Earth } from "lucide-react";
import { Link } from "react-router-dom";
import { edgeLabel, pathChain } from "../lib/attackPaths";
import { hrefForEntity } from "../lib/entityLinks";
import { nodeKindMeta } from "./graph/nodeKinds";

function nodeHref(node: AttackPath["nodes"][number]): string | null {
  const assetId = typeof node.props?.assetId === "string" ? node.props.assetId : null;
  if (assetId) return hrefForEntity("asset", assetId);
  const identityId = typeof node.props?.identityId === "string" ? node.props.identityId : null;
  if (identityId) return hrefForEntity("identity", identityId);
  return `/graph?node=${encodeURIComponent(node.id)}`;
}

/**
 * Horizontal attack chain: Internet → … → crown jewel. Each hop shows the node (kind badge,
 * label) and the relationship the attacker abuses to move to the next one.
 */
export function AttackPathChain({ path, compact = false, linkNodes = true }: { path: AttackPath; compact?: boolean; linkNodes?: boolean }) {
  const steps = pathChain(path);
  return (
    <ol className="scrollbar-thin flex items-stretch gap-1 overflow-x-auto pb-1" aria-label={`Attack path from ${path.entry.label} to ${path.target.label}`} data-testid="attack-path-chain">
      {steps.map((step, i) => {
        const meta = nodeKindMeta(step.node.kind);
        const Icon = step.node.kind === "internet" ? Earth : meta.icon;
        const isTarget = i === steps.length - 1;
        const crown = isTarget && (step.node.props?.criticality === "crown_jewel" || step.node.props?.crownJewel === true);
        const href = linkNodes ? nodeHref(step.node) : null;
        const label = (
          <span className="flex min-w-0 items-center gap-1.5">
            <span className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-white" style={{ background: meta.color }} aria-hidden>
              <Icon size={12} />
            </span>
            <span className="min-w-0">
              <span className="block max-w-[150px] truncate text-sm font-medium text-fg" title={step.node.label}>
                {step.node.label}
              </span>
              {!compact ? <span className="block text-2xs uppercase tracking-wide text-fg-subtle">{meta.label}</span> : null}
            </span>
            {crown ? <Crown size={13} className="shrink-0 text-sev-high" aria-label="Crown jewel" /> : null}
          </span>
        );
        return (
          <li key={`${step.node.id}-${i}`} className="flex shrink-0 items-center gap-1" data-step-kind={step.node.kind}>
            {i > 0 ? (
              <span className="flex flex-col items-center px-1 text-fg-subtle" data-testid="attack-path-edge">
                <span className="max-w-[110px] truncate text-2xs" title={step.via ? `${edgeLabel(step.via.kind)}${step.reversed ? " (reverse)" : ""}` : "reaches"}>
                  {step.via ? edgeLabel(step.via.kind) : "reaches"}
                </span>
                <ArrowRight size={14} aria-hidden />
              </span>
            ) : null}
            <span
              className={clsx(
                "rounded border px-2 py-1",
                i === 0 ? "border-sev-high/40 bg-sev-high/5" : isTarget ? "border-sev-critical/40 bg-sev-critical/5" : "border-line bg-surface",
              )}
              data-testid="attack-path-node"
            >
              {href ? (
                <Link to={href} className="hover:underline">
                  {label}
                </Link>
              ) : (
                label
              )}
            </span>
          </li>
        );
      })}
    </ol>
  );
}
