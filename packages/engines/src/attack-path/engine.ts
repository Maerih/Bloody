import type { AttackPath, Criticality, EdgeKind, GraphEdge, GraphNode, Subgraph } from "@bloody/contracts";
import {
  DEFAULT_ATTACK_EDGE_KINDS,
  isCrownJewel,
  isOpenVulnerabilityEdge,
  isPrivileged,
  nodeControlReduction,
  nodeCriticality,
  rulesFor,
  vulnerabilityNodeExploitability,
  type AttackStepRule,
} from "../graph/attack-semantics.js";
import { propBool, propNumber, propString } from "../graph/props.js";
import { nullSink, type EngineEventSink } from "../notifications.js";
import { RiskEngine } from "../risk/risk-engine.js";
import type { ExplainedRiskAssessment } from "../risk/model.js";
import { systemClock, toIso, type Clock } from "../util/clock.js";
import { MinHeap } from "../util/heap.js";
import { noisyOr, round } from "../util/math.js";
import { stableId } from "../util/uuid.js";
import { buildRemediationCandidates, rankRemediations, type RemediationPriority } from "./remediation.js";

export interface AttackPathOptions {
  /** Maximum attacker steps per path (default 8, max 16). */
  maxDepth?: number;
  /** Best paths kept per target, and expansion cap per node (k-shortest; default 5). */
  k?: number;
  /** Global cap on returned paths (default 200). */
  maxPaths?: number;
  /** Search budget: heap pops (default 200 000). Exceeding it sets `truncated`. */
  maxExpansions?: number;
  /** Minimum exploitability for gated (network) steps (default 0.3). */
  exploitabilityThreshold?: number;
  edgeKinds?: readonly EdgeKind[];
  isTarget?: (node: GraphNode) => boolean;
  isEntry?: (node: GraphNode) => boolean;
  /** Attacker-step depth used for each path's blast-radius factor (default 3). */
  blastRadiusDepth?: number;
  /** Maximum remediation suggestions in the greedy cut (default 20). */
  maxRemediations?: number;
}

export interface AttackStep {
  from: string;
  to: string;
  edgeId: string;
  edgeKind: EdgeKind;
  /** Movement direction relative to the stored edge. */
  direction: "forward" | "reverse";
  technique: string;
  /** Raw success probability of this step (before compensating controls). */
  probability: number;
  lateral: boolean;
  privilege: boolean;
  credential: boolean;
  exploited?: { vulnerabilityId: string; edgeId: string; label: string; exploitability: number; knownExploited: boolean };
}

/** Contract `AttackPath` plus ordered steps and a deterministic rank. */
export interface AttackPathDetail extends AttackPath {
  risk: ExplainedRiskAssessment;
  steps: AttackStep[];
  length: number;
  /** Π step probabilities (before controls). */
  chainProbability: number;
}

export interface AttackPathSummary {
  totalPaths: number;
  targetsAtRisk: number;
  entryPoints: number;
  bySeverity: Record<"critical" | "high" | "medium" | "low" | "info", number>;
  maxRiskScore: number;
  shortestPathLength: number | null;
  /** Number of remediations in the greedy cut needed to break every discovered path. */
  fixesToBreakAll: number;
  topRemediation: string | null;
  truncated: boolean;
}

export interface AttackPathAnalysis {
  paths: AttackPathDetail[];
  /** Greedy cut: the first breaks the most paths; together they break all of them. */
  remediations: RemediationPriority[];
  summary: AttackPathSummary;
}

interface Move {
  rule: AttackStepRule;
  edge: GraphEdge;
  to: string;
}

interface SearchState {
  node: string;
  parent: SearchState | null;
  step: AttackStep | null;
  cost: number;
  depth: number;
}

const VIRTUAL_PREFIX = "virtual:";

/**
 * Proprietary attack-path engine. Works on an in-memory {@link Subgraph} (load it with
 * `SecurityGraph.loadAttackSurface`), so it is pure and deterministic.
 *
 * Search: best-first k-shortest simple paths with cost Σ −ln(p_step·(1 − control_reduction)),
 * i.e. the *most likely* paths come out first. Cycle protection walks the parent chain;
 * every node is expanded at most k times; depth and expansion budgets bound the work.
 * Network steps (`exposes`, `can_reach`, …) are gated on target exploitability
 * (has_vulnerability → exploit). Each path is scored by the Risk Engine and remediations are
 * ranked by a greedy set-cover (min-cut style) over all discovered paths.
 */
export class AttackPathEngine {
  private readonly risk: RiskEngine;
  private readonly sink: EngineEventSink;
  private readonly clock: Clock;

  constructor(options: { riskEngine?: RiskEngine; sink?: EngineEventSink; clock?: Clock } = {}) {
    this.risk = options.riskEngine ?? new RiskEngine();
    this.sink = options.sink ?? nullSink;
    this.clock = options.clock ?? systemClock;
  }

  analyze(graph: Subgraph, options: AttackPathOptions = {}, context?: { tenantId: string; organizationId: string }): AttackPathAnalysis {
    const maxDepth = Math.max(1, Math.min(options.maxDepth ?? 8, 16));
    const k = Math.max(1, options.k ?? 5);
    const maxPaths = Math.max(1, options.maxPaths ?? 200);
    const maxExpansions = options.maxExpansions ?? 200_000;
    const threshold = options.exploitabilityThreshold ?? 0.3;
    const isTarget = options.isTarget ?? isCrownJewel;
    const isEntry = options.isEntry ?? ((n: GraphNode) => n.kind === "internet");
    const rules = rulesFor(options.edgeKinds ?? DEFAULT_ATTACK_EDGE_KINDS);

    const g = indexGraph(graph, isEntry);
    const moves = buildMoves(g, rules);

    // ── best-first k-shortest search ──
    const heap = new MinHeap<SearchState>();
    for (const entry of g.entries) heap.push({ node: entry, parent: null, step: null, cost: 0, depth: 0 }, 0);
    const expanded = new Map<string, number>();
    const perTarget = new Map<string, number>();
    const found: SearchState[] = [];
    let expansions = 0;
    let truncated = false;
    while (heap.size > 0) {
      if (expansions >= maxExpansions) {
        truncated = true;
        break;
      }
      const s = heap.pop()!;
      expansions++;
      const count = expanded.get(s.node) ?? 0;
      if (count >= k) continue;
      expanded.set(s.node, count + 1);
      const node = g.nodes.get(s.node)!;
      if (s.depth > 0 && isTarget(node) && (perTarget.get(s.node) ?? 0) < k) {
        perTarget.set(s.node, (perTarget.get(s.node) ?? 0) + 1);
        found.push(s);
        if (found.length >= maxPaths) {
          truncated = heap.size > 0;
          break;
        }
      }
      if (s.depth >= maxDepth) continue;
      for (const m of moves.get(s.node) ?? []) {
        if (onPath(s, m.to)) continue;
        const from = node;
        const to = g.nodes.get(m.to);
        if (!to) continue;
        if (m.rule.appliesTo && !m.rule.appliesTo(from, to)) continue;
        let probability = m.rule.probability;
        let exploited: AttackStep["exploited"];
        if (m.rule.gated) {
          const best = g.bestVuln.get(to.id);
          const explicit = propNumber(to.props, "exploitability");
          const e = Math.max(best?.exploitability ?? 0, explicit ?? 0);
          if (e < threshold) continue;
          probability *= e;
          if (best && best.exploitability >= (explicit ?? 0)) {
            exploited = { vulnerabilityId: best.vuln.id, edgeId: best.edge.id, label: best.vuln.label, exploitability: round(best.exploitability, 4), knownExploited: propBool(best.vuln.props, "knownExploited") === true };
          }
        }
        if (probability <= 0) continue;
        const control = nodeControlReduction(to).reduction;
        const effective = Math.max(probability * (1 - control), 1e-6);
        const step: AttackStep = {
          from: from.id,
          to: to.id,
          edgeId: m.edge.id,
          edgeKind: m.edge.kind,
          direction: m.rule.direction,
          technique: m.rule.technique,
          probability: round(probability, 4),
          lateral: m.rule.lateral,
          privilege: m.rule.privilege || (m.edge.kind === "member_of" && isPrivileged(to)),
          credential: m.rule.credential,
          ...(exploited ? { exploited } : {}),
        };
        const cost = s.cost - Math.log(effective);
        heap.push({ node: to.id, parent: s, step, cost, depth: s.depth + 1 }, cost);
      }
    }

    // ── materialize + score ──
    const blastCache = new Map<string, { reachableNodes: number; reachableCrownJewels: number }>();
    const paths = found.map((s) => this.materialize(s, g, rules, options.blastRadiusDepth ?? 3, blastCache));
    paths.sort((a, b) => b.risk.score - a.risk.score || a.length - b.length || a.id.localeCompare(b.id));

    // ── remediation ranking ──
    const candidates = buildRemediationCandidates(paths, g.nodes, g.edges);
    const { greedy, perPath } = rankRemediations(paths, candidates, options.maxRemediations ?? 20);
    for (const p of paths) p.remediations = (perPath.get(p.id) ?? []).slice(0, 5).map(({ nodeId, edgeId, action, pathsBroken }) => ({ ...(nodeId ? { nodeId } : {}), ...(edgeId ? { edgeId } : {}), action, pathsBroken }));

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const p of paths) bySeverity[p.risk.severity]++;
    const summary: AttackPathSummary = {
      totalPaths: paths.length,
      targetsAtRisk: new Set(paths.map((p) => p.target.id)).size,
      entryPoints: new Set(paths.map((p) => p.steps[0]?.to ?? p.entry.id)).size,
      bySeverity,
      maxRiskScore: paths.reduce((m, p) => Math.max(m, p.risk.score), 0),
      shortestPathLength: paths.length ? Math.min(...paths.map((p) => p.length)) : null,
      fixesToBreakAll: greedy.length,
      topRemediation: greedy[0]?.action ?? null,
      truncated,
    };
    if (context && paths.length > 0) {
      this.sink.emit({
        type: "attack_path.crown_jewel_exposed",
        tenantId: context.tenantId,
        organizationId: context.organizationId,
        at: toIso(this.clock.now()),
        paths: paths.length,
        targets: [...new Set(paths.map((p) => p.target.label))].slice(0, 20),
        topRemediation: summary.topRemediation,
        maxRiskScore: summary.maxRiskScore,
      });
    }
    return { paths, remediations: greedy, summary };
  }

  private materialize(s: SearchState, g: IndexedGraph, rules: AttackStepRule[], blastDepth: number, blastCache: Map<string, { reachableNodes: number; reachableCrownJewels: number }>): AttackPathDetail {
    const steps: AttackStep[] = [];
    let cur: SearchState | null = s;
    let entryId = s.node;
    while (cur) {
      if (cur.step) steps.unshift(cur.step);
      else entryId = cur.node;
      cur = cur.parent;
    }
    const entry = g.nodes.get(entryId)!;
    const target = g.nodes.get(s.node)!;
    const nodes: GraphNode[] = [entry];
    const edges: GraphEdge[] = [];
    for (const st of steps) {
      edges.push(g.edges.get(st.edgeId)!);
      nodes.push(g.nodes.get(st.to)!);
      if (st.exploited) {
        nodes.push(g.nodes.get(st.exploited.vulnerabilityId)!);
        edges.push(g.edges.get(st.exploited.edgeId)!);
      }
    }
    const chainProbability = steps.reduce((p, st) => p * st.probability, 1);
    const exploitedSteps = steps.filter((st) => st.exploited);
    const pathNodes = steps.map((st) => g.nodes.get(st.to)!);
    const identities = pathNodes.filter((n) => n.kind === "identity" || n.kind === "user" || n.kind === "service_account" || n.kind === "group" || n.kind === "credential");
    const privIds = identities.filter(isPrivileged);
    const intel = noisyOr(pathNodes.map((n) => g.intel.get(n.id) ?? 0));
    const foothold = steps[0]?.to ?? entry.id;
    let blast = blastCache.get(foothold);
    if (!blast) {
      blast = blastRadiusInSubgraph(g, foothold, rules, blastDepth);
      blastCache.set(foothold, blast);
    }
    const controls: Array<{ key: string; label: string; strength: number; on: string }> = [];
    for (const n of pathNodes) for (const c of nodeControlReduction(n).controls) controls.push({ ...c, on: n.label });
    const risk = this.risk.scoreAttackPath({
      entryLabel: steps[0] ? g.nodes.get(steps[0].to)!.label : entry.label,
      targetLabel: target.label,
      steps: steps.length,
      chainProbability,
      exploitability: exploitedSteps.reduce((m, st) => Math.max(m, st.exploited!.exploitability), 0),
      knownExploited: exploitedSteps.some((st) => st.exploited!.knownExploited),
      exploitedCves: [...new Set(exploitedSteps.map((st) => propString(g.nodes.get(st.exploited!.vulnerabilityId)!.props, "cve") ?? st.exploited!.label))],
      exposure: entry.kind === "internet" ? 1 : propBool(entry.props, "internetFacing") ? 1 : 0.4,
      privilegeEscalation: steps.some((st) => st.privilege) || pathNodes.some((n) => propString(n.props, "assetKind") === "domain_controller") ? 1 : 0,
      identityPrivilege: privIds.length > 0 ? 1 : identities.length > 0 ? 0.3 : 0,
      privilegedIdentities: privIds.map((n) => n.label),
      threatIntel: intel,
      lateralHops: steps.filter((st) => st.lateral).length,
      targetCriticality: nodeCriticality(target) ?? ("high" as Criticality),
      blastRadius: blast,
      controls,
    });
    return {
      id: stableId("attack-path", target.organizationId, ...steps.map((st) => `${st.edgeId}:${st.direction}`)),
      nodes,
      edges,
      target,
      entry,
      risk,
      remediations: [],
      steps,
      length: steps.length,
      chainProbability: round(chainProbability, 6),
    };
  }
}

// ─── graph indexing ─────────────────────────────────────────────────────────

export interface IndexedGraph {
  nodes: Map<string, GraphNode>;
  edges: Map<string, GraphEdge>;
  out: Map<string, GraphEdge[]>;
  in: Map<string, GraphEdge[]>;
  entries: string[];
  bestVuln: Map<string, { vuln: GraphNode; edge: GraphEdge; exploitability: number }>;
  intel: Map<string, number>;
}

function indexGraph(graph: Subgraph, isEntry: (n: GraphNode) => boolean): IndexedGraph {
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const edges = new Map<string, GraphEdge>();
  const out = new Map<string, GraphEdge[]>();
  const inn = new Map<string, GraphEdge[]>();
  const add = (e: GraphEdge) => {
    if (!nodes.has(e.from) || !nodes.has(e.to)) return;
    edges.set(e.id, e);
    (out.get(e.from) ?? out.set(e.from, []).get(e.from)!).push(e);
    (inn.get(e.to) ?? inn.set(e.to, []).get(e.to)!).push(e);
  };
  for (const e of [...graph.edges].sort((a, b) => a.id.localeCompare(b.id))) add(e);

  let entries = [...nodes.values()].filter(isEntry).map((n) => n.id);
  if (entries.length === 0) {
    // No explicit internet node: synthesize one exposing every internet-facing asset.
    const exposed = [...nodes.values()].filter((n) => propBool(n.props, "internetFacing") === true);
    if (exposed.length > 0) {
      const org = exposed[0]!.organizationId;
      const internet: GraphNode = { id: `${VIRTUAL_PREFIX}internet`, kind: "internet", key: "internet", label: "Internet", organizationId: org, props: { virtual: true } };
      nodes.set(internet.id, internet);
      for (const n of exposed) add({ id: `${VIRTUAL_PREFIX}exposes:${n.id}`, kind: "exposes", from: internet.id, to: n.id, props: { virtual: true } });
      entries = [internet.id];
    }
  }
  entries.sort();

  const bestVuln = new Map<string, { vuln: GraphNode; edge: GraphEdge; exploitability: number }>();
  const intel = new Map<string, number>();
  for (const e of edges.values()) {
    if (e.kind === "has_vulnerability" && isOpenVulnerabilityEdge(e.props)) {
      const v = nodes.get(e.to)!;
      const x = vulnerabilityNodeExploitability(v);
      const cur = bestVuln.get(e.from);
      if (!cur || x > cur.exploitability) bestVuln.set(e.from, { vuln: v, edge: e, exploitability: x });
    }
    if (e.kind === "observed_on" && nodes.get(e.from)?.kind === "indicator") {
      const ind = nodes.get(e.from)!;
      const conf = (propNumber(ind.props, "confidence") ?? 60) / 100;
      intel.set(e.to, noisyOr([intel.get(e.to) ?? 0, conf]));
    }
    if (e.kind === "mitigated_by") {
      // fold control nodes into the protected node's props for nodeControlReduction()
      const ctl = nodes.get(e.to)!;
      const protectedNode = nodes.get(e.from)!;
      const strength = propNumber(ctl.props, "strength") ?? propNumber(e.props, "strength") ?? 0.3;
      const prev = propNumber(protectedNode.props, "controlStrength") ?? 0;
      nodes.set(protectedNode.id, { ...protectedNode, props: { ...protectedNode.props, controlStrength: 1 - (1 - prev) * (1 - strength), controlLabel: ctl.label } });
    }
  }
  return { nodes, edges, out, in: inn, entries, bestVuln, intel };
}

function buildMoves(g: IndexedGraph, rules: AttackStepRule[]): Map<string, Move[]> {
  const moves = new Map<string, Move[]>();
  const push = (from: string, m: Move) => (moves.get(from) ?? moves.set(from, []).get(from)!).push(m);
  for (const e of g.edges.values()) {
    for (const rule of rules) {
      if (rule.edgeKind !== e.kind) continue;
      if (rule.direction === "forward") push(e.from, { rule, edge: e, to: e.to });
      else push(e.to, { rule, edge: e, to: e.from });
    }
  }
  for (const list of moves.values()) list.sort((a, b) => a.edge.id.localeCompare(b.edge.id) || a.rule.direction.localeCompare(b.rule.direction));
  return moves;
}

function onPath(s: SearchState, nodeId: string): boolean {
  for (let c: SearchState | null = s; c; c = c.parent) if (c.node === nodeId) return true;
  return false;
}

function blastRadiusInSubgraph(g: IndexedGraph, start: string, rules: AttackStepRule[], depth: number): { reachableNodes: number; reachableCrownJewels: number } {
  const moves = buildMovesCached(g, rules);
  const seen = new Set([start]);
  let frontier = [start];
  let crown = 0;
  for (let d = 0; d < depth && frontier.length > 0; d++) {
    const next: string[] = [];
    for (const id of frontier) {
      for (const m of moves.get(id) ?? []) {
        if (seen.has(m.to)) continue;
        const from = g.nodes.get(id)!;
        const to = g.nodes.get(m.to)!;
        if (m.rule.appliesTo && !m.rule.appliesTo(from, to)) continue;
        seen.add(m.to);
        if (isCrownJewel(to)) crown++;
        next.push(m.to);
      }
    }
    frontier = next;
  }
  return { reachableNodes: seen.size - 1, reachableCrownJewels: crown };
}

const moveCache = new WeakMap<IndexedGraph, Map<string, Move[]>>();
function buildMovesCached(g: IndexedGraph, rules: AttackStepRule[]): Map<string, Move[]> {
  let m = moveCache.get(g);
  if (!m) {
    m = buildMoves(g, rules);
    moveCache.set(g, m);
  }
  return m;
}

export function isVirtualId(id: string): boolean {
  return id.startsWith(VIRTUAL_PREFIX);
}
