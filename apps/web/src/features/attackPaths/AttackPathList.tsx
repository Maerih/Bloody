import type { AttackPath } from "@bloody/contracts";
import { clsx } from "clsx";
import { ChevronDown, ChevronRight, Crown, Network, Wrench } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { RemediationPriorityView } from "../../api/types";
import { AttackPathChain } from "../../components/AttackPathChain";
import { Badge, SeverityBadge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { GraphCanvas } from "../../components/graph/GraphCanvas";
import { RiskScore } from "../../components/RiskScore";
import { pathChain, type RankedRemediation } from "../../lib/attackPaths";
import { formatInteger, humanize } from "../../lib/format";
import { AttackPathFactorBreakdown } from "./AttackPathFactorBreakdown";

interface StepView {
  from: string;
  to: string;
  edgeKind: string;
  technique?: string;
  probability?: number;
  lateral?: boolean;
  privilege?: boolean;
  credential?: boolean;
  exploited?: { label?: string; knownExploited?: boolean; exploitability?: number };
}

/** Engine paths carry ordered steps (technique, probability); contract paths may not. */
function stepsOf(path: AttackPath): StepView[] {
  const raw = (path as AttackPath & { steps?: unknown }).steps;
  if (!Array.isArray(raw)) return [];
  return raw.filter((s): s is StepView => typeof s === "object" && s !== null && typeof (s as StepView).from === "string" && typeof (s as StepView).to === "string");
}

export function isCrownJewelTarget(path: AttackPath): boolean {
  return path.target.props?.criticality === "crown_jewel" || path.target.props?.crownJewel === true;
}

function PathRemediations({ items }: { items: RemediationPriorityView[] }) {
  if (items.length === 0) return <p className="text-xs text-fg-muted">The engine suggested no path-specific remediation.</p>;
  return (
    <ol className="space-y-1">
      {[...items]
        .sort((a, b) => b.pathsBroken - a.pathsBroken)
        .map((r, i) => (
          <li key={`${r.nodeId ?? ""}-${r.edgeId ?? ""}-${i}`} className="flex items-start gap-2 text-sm">
            <Wrench size={13} className="mt-0.5 shrink-0 text-primary" aria-hidden />
            <span className="min-w-0 flex-1">{r.action}</span>
            <Badge size="xs" tone="info">
              breaks {formatInteger(r.pathsBroken)} path{r.pathsBroken === 1 ? "" : "s"}
            </Badge>
          </li>
        ))}
    </ol>
  );
}

/** One attack path: risk, horizontal chain and (expanded) explanation, steps, fixes and graph. */
export function AttackPathCard({ path, highlighted = false, defaultOpen = false }: { path: AttackPath; highlighted?: boolean; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const steps = stepsOf(path);
  const chain = pathChain(path);
  const labelOf = useMemo(() => new Map(path.nodes.map((n) => [n.id, n.label])), [path.nodes]);
  const crown = isCrownJewelTarget(path);
  const graph = useMemo(() => ({ nodes: chain.map((s) => s.node), edges: path.edges.filter((e) => chain.some((s) => s.node.id === e.from) && chain.some((s) => s.node.id === e.to)) }), [chain, path.edges]);
  return (
    <article className={clsx("rounded border bg-surface shadow-card", highlighted ? "border-primary ring-1 ring-primary/30" : "border-line")} data-testid="attack-path-card" aria-label={`Attack path ${path.entry.label} to ${path.target.label}`}>
      <header className="flex flex-wrap items-center gap-2 px-3 pt-3">
        <RiskScore score={path.risk.score} factors={path.risk.factors} summary={path.risk.summary} modelVersion={path.risk.modelVersion} label="Path risk" />
        <SeverityBadge severity={path.risk.severity} size="xs" />
        <span className="min-w-0 flex-1 truncate text-sm font-medium text-fg" title={path.risk.summary}>
          {path.entry.label} → {path.target.label}
        </span>
        {crown ? (
          <Badge size="xs" tone="danger" icon={Crown}>
            Crown jewel
          </Badge>
        ) : null}
        <Badge size="xs" tone="outline">
          {chain.length - 1} hop{chain.length - 1 === 1 ? "" : "s"}
        </Badge>
      </header>
      <div className="px-3 py-2">
        <AttackPathChain path={path} />
      </div>
      <div className="flex items-center gap-2 border-t border-line px-3 py-1.5">
        <p className="min-w-0 flex-1 truncate text-xs text-fg-muted" title={path.risk.summary}>
          {path.risk.summary}
        </p>
        <Button size="xs" variant="ghost" icon={open ? ChevronDown : ChevronRight} onClick={() => setOpen((v) => !v)} aria-expanded={open}>
          {open ? "Hide explanation" : "Explain risk"}
        </Button>
      </div>
      {open ? (
        <div className="space-y-4 border-t border-line px-3 py-3">
          <AttackPathFactorBreakdown risk={path.risk} />
          {steps.length > 0 ? (
            <section>
              <h4 className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-fg-subtle">Attacker steps</h4>
              <ol className="space-y-1 text-sm">
                {steps.map((s, i) => (
                  <li key={`${s.from}-${s.to}-${i}`} className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                    <span className="font-mono text-2xs text-fg-subtle">{i + 1}.</span>
                    <span className="font-medium">{labelOf.get(s.from) ?? s.from}</span>
                    <span className="text-fg-muted">— {humanize(s.edgeKind)} →</span>
                    <span className="font-medium">{labelOf.get(s.to) ?? s.to}</span>
                    {s.technique ? (
                      <a href={`https://attack.mitre.org/techniques/${s.technique.replace(".", "/")}/`} target="_blank" rel="noopener noreferrer" className="font-mono text-2xs text-primary hover:underline">
                        {s.technique}
                      </a>
                    ) : null}
                    {typeof s.probability === "number" ? <span className="text-2xs text-fg-subtle">p={Math.round(s.probability * 100)}%</span> : null}
                    {s.lateral ? <Badge size="xs">lateral</Badge> : null}
                    {s.privilege ? <Badge size="xs" tone="warning">privilege</Badge> : null}
                    {s.credential ? <Badge size="xs" tone="purple">credential</Badge> : null}
                    {s.exploited ? (
                      <Badge size="xs" tone={s.exploited.knownExploited ? "danger" : "warning"}>
                        exploits {s.exploited.label ?? "vulnerability"}
                        {s.exploited.knownExploited ? " (KEV)" : ""}
                      </Badge>
                    ) : null}
                  </li>
                ))}
              </ol>
            </section>
          ) : null}
          <section>
            <h4 className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-fg-subtle">Fixes on this path</h4>
            <PathRemediations items={path.remediations} />
          </section>
          <section>
            <div className="mb-1.5 flex items-center justify-between">
              <h4 className="text-2xs font-semibold uppercase tracking-wide text-fg-subtle">Path in the Security Graph</h4>
              {!path.target.id.startsWith("virtual:") ? (
                <Link to={`/graph?node=${encodeURIComponent(path.target.id)}`} className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
                  <Network size={12} aria-hidden /> Explore from target
                </Link>
              ) : null}
            </div>
            <GraphCanvas graph={graph} roots={[path.entry.id]} highlightIds={graph.nodes.map((n) => n.id)} height={280} showMiniMap={false} />
          </section>
        </div>
      ) : null}
    </article>
  );
}

/** "Fix this → breaks N paths": the greedy remediation ranking across all discovered paths. */
export function RemediationPriorityList({
  items,
  totalPaths,
  activeKey,
  onSelect,
}: {
  items: RankedRemediation[];
  totalPaths: number;
  activeKey: string | null;
  onSelect: (item: RankedRemediation | null) => void;
}) {
  if (items.length === 0) return <p className="p-3 text-sm text-fg-muted">No remediation needed — no attack path was discovered.</p>;
  return (
    <ol className="divide-y divide-line" aria-label="Remediation priorities" data-testid="remediation-priorities">
      {items.map((r, i) => {
        const active = activeKey === r.key;
        const pct = totalPaths > 0 ? Math.min(100, (r.pathsBroken / totalPaths) * 100) : 0;
        return (
          <li key={r.key}>
            <button
              type="button"
              onClick={() => onSelect(active ? null : r)}
              aria-pressed={active}
              className={clsx("block w-full px-3 py-2 text-left hover:bg-surface-2", active && "bg-primary-soft/60")}
            >
              <div className="flex items-start gap-2">
                <span className="mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-primary text-2xs font-semibold text-white">{r.rank ?? i + 1}</span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium text-fg">{r.action}</span>
                  {r.subject ? <span className="block truncate text-2xs text-fg-subtle">{r.subject}</span> : null}
                </span>
              </div>
              <div className="ml-7 mt-1">
                <div className="flex items-center justify-between text-2xs text-fg-muted">
                  <span className="font-semibold text-fg">
                    Fix this → breaks {formatInteger(r.pathsBroken)} path{r.pathsBroken === 1 ? "" : "s"}
                  </span>
                  <span className="flex gap-1">
                    {r.marginalPathsBroken !== undefined && r.marginalPathsBroken !== r.pathsBroken ? <span title="Additional paths broken after the fixes above">+{r.marginalPathsBroken} new</span> : null}
                    {r.riskReduced !== undefined ? <span>−{r.riskReduced.toFixed(1)} risk</span> : null}
                    {r.effort ? <Badge size="xs" tone={r.effort === "low" ? "success" : r.effort === "medium" ? "warning" : "danger"}>{r.effort} effort</Badge> : null}
                  </span>
                </div>
                <div className="mt-0.5 h-1.5 rounded bg-surface-3">
                  <div className="h-1.5 rounded bg-primary" style={{ width: `${pct}%` }} />
                </div>
              </div>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

