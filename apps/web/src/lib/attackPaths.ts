import type { AttackPath, GraphEdge, GraphNode, RiskAssessment, RiskFactor } from "@bloody/contracts";
import type { RemediationPriorityView } from "../api/types";

/**
 * Attack-path presentation helpers: ordered chains (entry → … → target), the explained risk
 * factor breakdown and the "fix this to break N paths" remediation ranking.
 */

export interface ChainStep {
  node: GraphNode;
  /** Edge leading INTO this node from the previous step (null for the entry). */
  via: GraphEdge | null;
  /** True when the edge is stored target → source (e.g. "has_vulnerability" traversed back). */
  reversed: boolean;
}

/**
 * Order a path's nodes from entry to target. Paths from the engine are already ordered; for
 * other producers the chain is rebuilt by walking edges from the entry node.
 */
export function pathChain(path: AttackPath): ChainStep[] {
  const byId = new Map(path.nodes.map((n) => [n.id, n]));
  if (!byId.has(path.entry.id)) byId.set(path.entry.id, path.entry);
  if (!byId.has(path.target.id)) byId.set(path.target.id, path.target);
  const edgeBetween = (a: string, b: string): { edge: GraphEdge; reversed: boolean } | null => {
    for (const e of path.edges) {
      if (e.from === a && e.to === b) return { edge: e, reversed: false };
      if (e.from === b && e.to === a) return { edge: e, reversed: true };
    }
    return null;
  };

  const ordered = path.nodes.length > 0 ? path.nodes : [path.entry, path.target];
  const looksOrdered = ordered[0]?.id === path.entry.id && ordered[ordered.length - 1]?.id === path.target.id;
  let ids: string[];
  if (looksOrdered) {
    ids = ordered.map((n) => n.id);
  } else {
    // Walk edges from the entry, always taking an unvisited neighbour.
    ids = [path.entry.id];
    const seen = new Set(ids);
    let cur = path.entry.id;
    while (cur !== path.target.id) {
      const next = path.edges.map((e) => (e.from === cur ? e.to : e.to === cur ? e.from : null)).find((n): n is string => n !== null && !seen.has(n));
      if (!next) break;
      ids.push(next);
      seen.add(next);
      cur = next;
    }
    if (ids[ids.length - 1] !== path.target.id) ids.push(path.target.id);
  }

  return ids.map((id, i) => {
    const node = byId.get(id)!;
    if (i === 0) return { node, via: null, reversed: false };
    const link = edgeBetween(ids[i - 1]!, id);
    return { node, via: link?.edge ?? null, reversed: link?.reversed ?? false };
  });
}

export function edgeLabel(kind: string): string {
  return kind.replace(/_/g, " ");
}

/** Canonical display order + labels for attack-path / exposure factors (unknown keys follow). */
export const FACTOR_ORDER: { key: string; label: string }[] = [
  { key: "exploitability", label: "Exploitability" },
  { key: "exposure", label: "Exposure" },
  { key: "privilege", label: "Privilege" },
  { key: "asset_criticality", label: "Asset criticality" },
  { key: "identity_privilege", label: "Identity privilege" },
  { key: "known_exploitation", label: "Known exploitation" },
  { key: "threat_intel", label: "Threat intelligence" },
  { key: "lateral_movement", label: "Lateral movement" },
  { key: "blast_radius", label: "Blast radius" },
  { key: "compensating_controls", label: "Compensating controls" },
];

export type FactorGroup = "likelihood" | "impact" | "control";

export interface DisplayFactor extends RiskFactor {
  group: FactorGroup;
}

/** Explained factors grouped (likelihood / impact / compensating controls), strongest first. */
export function groupFactors(risk: Pick<RiskAssessment, "factors">): Record<FactorGroup, DisplayFactor[]> {
  const out: Record<FactorGroup, DisplayFactor[]> = { likelihood: [], impact: [], control: [] };
  const orderIndex = (key: string) => {
    const i = FACTOR_ORDER.findIndex((f) => key === f.key || key.startsWith(`${f.key}_`) || key.endsWith(`_${f.key}`));
    return i === -1 ? FACTOR_ORDER.length : i;
  };
  for (const f of risk.factors) {
    const declared = (f as RiskFactor & { group?: unknown }).group;
    const group: FactorGroup =
      declared === "likelihood" || declared === "impact" || declared === "control"
        ? declared
        : f.contribution < 0 || f.weight < 0 || f.key.startsWith("control_")
          ? "control"
          : /critical|impact|blast|data|crown|business/.test(f.key)
            ? "impact"
            : "likelihood";
    out[group].push({ ...f, group });
  }
  for (const g of Object.keys(out) as FactorGroup[]) {
    out[g].sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution) || orderIndex(a.key) - orderIndex(b.key));
  }
  return out;
}

export interface RankedRemediation extends RemediationPriorityView {
  key: string;
  /** Ids of the loaded paths that list this remediation. */
  pathIds: string[];
  /** Label of the node/edge the fix applies to, when known. */
  subject: string | null;
}

function remediationKey(r: { nodeId?: string | undefined; edgeId?: string | undefined; action: string }): string {
  return `${r.nodeId ?? ""}|${r.edgeId ?? ""}|${r.action}`;
}

/**
 * The remediation ranking: the API's greedy cut when provided, otherwise per-path suggestions
 * merged across paths. `pathsBroken` is the API's count when present, else the number of
 * loaded paths that share the fix.
 */
export function rankRemediations(paths: AttackPath[], provided: RemediationPriorityView[] = []): RankedRemediation[] {
  const nodeLabel = new Map<string, string>();
  const edgeSubject = new Map<string, string>();
  const pathsFor = new Map<string, Set<string>>();
  const merged = new Map<string, RemediationPriorityView>();
  for (const p of paths) {
    for (const n of p.nodes) nodeLabel.set(n.id, n.label);
    for (const e of p.edges) {
      const from = p.nodes.find((n) => n.id === e.from)?.label ?? e.from;
      const to = p.nodes.find((n) => n.id === e.to)?.label ?? e.to;
      edgeSubject.set(e.id, `${from} → ${to}`);
    }
    for (const r of p.remediations) {
      const key = remediationKey(r);
      const set = pathsFor.get(key) ?? new Set<string>();
      set.add(p.id);
      pathsFor.set(key, set);
      const prev = merged.get(key);
      if (!prev || r.pathsBroken > prev.pathsBroken) merged.set(key, { ...r });
    }
  }
  const source = provided.length > 0 ? provided : [...merged.values()];
  const ranked = source.map((r) => {
    const key = remediationKey(r);
    const pathIds = [...(pathsFor.get(key) ?? [])];
    return {
      ...r,
      key,
      pathIds,
      pathsBroken: Math.max(r.pathsBroken, provided.length > 0 ? 0 : pathIds.length),
      subject: r.nodeId ? (nodeLabel.get(r.nodeId) ?? null) : r.edgeId ? (edgeSubject.get(r.edgeId) ?? null) : null,
    };
  });
  return ranked.sort((a, b) => {
    const ra = a.rank ?? Number.POSITIVE_INFINITY;
    const rb = b.rank ?? Number.POSITIVE_INFINITY;
    if (ra !== rb) return ra - rb;
    return b.pathsBroken - a.pathsBroken || (b.riskReduced ?? 0) - (a.riskReduced ?? 0) || a.action.localeCompare(b.action);
  });
}

/** Paths whose chain touches a node with this asset id (asset drawer, crown jewels). */
export function pathsTouchingAsset(paths: AttackPath[], assetId: string): AttackPath[] {
  const matches = (n: GraphNode) => n.props?.assetId === assetId || n.key === assetId || n.id === assetId;
  return paths.filter((p) => matches(p.target) || matches(p.entry) || p.nodes.some(matches));
}
