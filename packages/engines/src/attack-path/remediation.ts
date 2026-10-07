import type { GraphEdge, GraphNode } from "@bloody/contracts";
import { propBool, propString } from "../graph/props.js";
import { round } from "../util/math.js";
import type { AttackPathDetail } from "./engine.js";

export type RemediationCategory = "patch" | "exposure" | "segmentation" | "privilege" | "credential" | "identity" | "harden" | "trust";

export interface RemediationPriority {
  nodeId?: string;
  edgeId?: string;
  action: string;
  category: RemediationCategory;
  effort: "low" | "medium" | "high";
  /** Discovered paths this remediation breaks (total, not marginal). */
  pathsBroken: number;
  /** Paths broken that no earlier remediation in the ranking already broke. */
  marginalPathsBroken: number;
  /** Σ risk score of the marginally broken paths. */
  riskReduced: number;
  /** 1-based position in the greedy cut; null when not part of it. */
  rank: number | null;
}

export interface RemediationCandidate {
  key: string;
  nodeId?: string;
  edgeId?: string;
  action: string;
  category: RemediationCategory;
  effort: 1 | 2 | 3;
  paths: Set<string>;
}

const EFFORT_LABEL = { 1: "low", 2: "medium", 3: "high" } as const;
const IDENTITY_KINDS = new Set(["identity", "user", "service_account"]);
const ASSET_KINDS = new Set(["endpoint", "server", "cloud_asset", "container", "application", "saas_app", "data_store", "k8s_resource"]);

/**
 * Enumerate every "cut" that would break each path: removing an edge (exposure, reachability,
 * right, trust, cached credential), patching an exploited vulnerability (on one asset or
 * everywhere), or neutralizing an intermediate pivot node (identity hygiene, group review,
 * host isolation). Entry and target nodes are never candidates.
 */
export function buildRemediationCandidates(paths: AttackPathDetail[], nodes: Map<string, GraphNode>, edges: Map<string, GraphEdge>): Map<string, RemediationCandidate> {
  const out = new Map<string, RemediationCandidate>();
  const add = (c: Omit<RemediationCandidate, "paths">, pathId: string) => {
    const cur = out.get(c.key) ?? { ...c, paths: new Set<string>() };
    cur.paths.add(pathId);
    out.set(c.key, cur);
  };
  const label = (id: string) => nodes.get(id)?.label ?? id;

  for (const p of paths) {
    p.steps.forEach((st, i) => {
      const edge = edges.get(st.edgeId);
      if (!edge) return;
      const virtual = propBool(edge.props, "virtual") === true;
      if (edge.kind === "exposes") {
        add(
          virtual
            ? { key: `exposure:${edge.to}`, nodeId: edge.to, action: `Remove internet exposure of ${label(edge.to)} (restrict ingress, place behind VPN / ZTNA)`, category: "exposure", effort: 2 }
            : { key: `edge:${edge.id}`, edgeId: edge.id, action: `Remove internet exposure of ${label(edge.to)} (restrict ingress, place behind VPN / ZTNA)`, category: "exposure", effort: 2 },
          p.id,
        );
      } else {
        const c = edgeRemediation(edge, st.direction, label);
        if (c) add(c, p.id);
      }
      if (st.exploited) {
        const vuln = nodes.get(st.exploited.vulnerabilityId);
        const cve = vuln ? (propString(vuln.props, "cve") ?? vuln.label) : st.exploited.label;
        const vulnEdge = edges.get(st.exploited.edgeId);
        const patchable = vulnEdge ? propBool(vulnEdge.props, "patchAvailable") !== false : true;
        add(
          {
            key: `edge:${st.exploited.edgeId}`,
            edgeId: st.exploited.edgeId,
            action: patchable ? `Patch ${cve} on ${label(st.to)}` : `Mitigate ${cve} on ${label(st.to)} (no vendor patch: virtual patching / disable the vulnerable service)`,
            category: "patch",
            effort: 1,
          },
          p.id,
        );
        add({ key: `node:${st.exploited.vulnerabilityId}`, nodeId: st.exploited.vulnerabilityId, action: `Patch ${cve} on every affected asset`, category: "patch", effort: 1 }, p.id);
      }
      const isLast = i === p.steps.length - 1;
      if (!isLast) {
        const n = nodes.get(st.to);
        if (n) {
          const c = nodeRemediation(n);
          if (c) add(c, p.id);
        }
      }
    });
  }
  return out;
}

function edgeRemediation(edge: GraphEdge, direction: "forward" | "reverse", label: (id: string) => string): Omit<RemediationCandidate, "paths"> | null {
  const from = label(edge.from);
  const to = label(edge.to);
  const base = { key: `edge:${edge.id}:${direction}`, edgeId: edge.id };
  switch (edge.kind) {
    case "can_reach":
    case "connected_to":
      return { ...base, action: `Segment the network: block ${from} → ${to}`, category: "segmentation", effort: 2 };
    case "admin_of":
      return { ...base, action: `Remove administrative rights of ${from} on ${to}`, category: "privilege", effort: 2 };
    case "owns":
      return { ...base, action: `Restrict ownership of ${to} held by ${from}`, category: "privilege", effort: 2 };
    case "has_access_to":
      return { ...base, action: `Revoke ${from}'s access to ${to} (least privilege)`, category: "privilege", effort: 2 };
    case "logged_into":
      return direction === "reverse"
        ? { ...base, action: `Prevent credential exposure of ${from} on ${to} (tiered admin model, Credential Guard, end stale sessions)`, category: "credential", effort: 1 }
        : { ...base, action: `Restrict logon rights of ${from} to ${to}`, category: "privilege", effort: 2 };
    case "stores_credential_for":
      return { ...base, action: `Remove the credential for ${to} stored on ${from} and rotate it`, category: "credential", effort: 1 };
    case "authenticates_as":
      return { ...base, action: `Rotate credentials / revoke tokens that let ${from} act as ${to}`, category: "credential", effort: 1 };
    case "member_of":
      return { ...base, action: `Remove ${from} from group ${to}`, category: "privilege", effort: 1 };
    case "trusts":
      return { ...base, action: `Restrict the trust between ${from} and ${to} (selective authentication / SID filtering)`, category: "trust", effort: 3 };
    case "contains":
      return { ...base, action: `Restrict access to ${to} on ${from} (encryption, access control)`, category: "harden", effort: 2 };
    case "runs_on":
      return { ...base, action: `Harden ${from} against escape to ${to} (drop privileges, read-only root, seccomp)`, category: "harden", effort: 2 };
    default:
      return null;
  }
}

function nodeRemediation(n: GraphNode): Omit<RemediationCandidate, "paths"> | null {
  if (IDENTITY_KINDS.has(n.kind)) return { key: `node:${n.id}`, nodeId: n.id, action: `Reset credentials, enforce MFA and reduce privileges of ${n.label}`, category: "identity", effort: 1 };
  if (n.kind === "group") return { key: `node:${n.id}`, nodeId: n.id, action: `Review and reduce membership of group ${n.label}`, category: "privilege", effort: 1 };
  if (n.kind === "credential") return { key: `node:${n.id}`, nodeId: n.id, action: `Rotate and vault credential ${n.label}`, category: "credential", effort: 1 };
  if (ASSET_KINDS.has(n.kind)) return { key: `node:${n.id}`, nodeId: n.id, action: `Harden or isolate pivot host ${n.label}`, category: "harden", effort: 3 };
  return null;
}

/**
 * Greedy weighted set cover over the discovered paths (an approximation of the minimum cut
 * between entry points and crown jewels): repeatedly pick the candidate that breaks the most
 * still-unbroken paths, tie-broken by risk removed, then lower effort, then key (determinism).
 */
export function rankRemediations(paths: AttackPathDetail[], candidates: Map<string, RemediationCandidate>, maxPicks: number): { greedy: RemediationPriority[]; perPath: Map<string, RemediationPriority[]> } {
  const risk = new Map(paths.map((p) => [p.id, p.risk.score]));
  const remaining = new Set(paths.map((p) => p.id));
  const ordered = [...candidates.values()].sort((a, b) => a.key.localeCompare(b.key));
  const greedy: RemediationPriority[] = [];
  const rankOf = new Map<string, number>();
  const pickedByKey = new Map<string, RemediationPriority>();
  while (remaining.size > 0 && greedy.length < maxPicks) {
    let best: { c: RemediationCandidate; marginal: number; riskSum: number } | null = null;
    for (const c of ordered) {
      if (rankOf.has(c.key)) continue;
      let marginal = 0;
      let riskSum = 0;
      for (const pid of c.paths) {
        if (!remaining.has(pid)) continue;
        marginal++;
        riskSum += risk.get(pid) ?? 0;
      }
      if (marginal === 0) continue;
      if (!best || marginal > best.marginal || (marginal === best.marginal && (riskSum > best.riskSum + 1e-9 || (Math.abs(riskSum - best.riskSum) <= 1e-9 && c.effort < best.c.effort)))) {
        best = { c, marginal, riskSum };
      }
    }
    if (!best) break;
    rankOf.set(best.c.key, greedy.length + 1);
    const picked = toPriority(best.c, best.marginal, best.riskSum, greedy.length + 1);
    pickedByKey.set(best.c.key, picked);
    greedy.push(picked);
    for (const pid of best.c.paths) remaining.delete(pid);
  }

  const perPath = new Map<string, RemediationPriority[]>();
  const sortedAll = [...candidates.values()].sort(
    (a, b) => (rankOf.get(a.key) ?? Infinity) - (rankOf.get(b.key) ?? Infinity) || b.paths.size - a.paths.size || a.effort - b.effort || a.key.localeCompare(b.key),
  );
  for (const c of sortedAll) {
    const pr = pickedByKey.get(c.key) ?? toPriority(c, 0, 0, null);
    for (const pid of c.paths) (perPath.get(pid) ?? perPath.set(pid, []).get(pid)!).push(pr);
  }
  return { greedy, perPath };
}

function toPriority(c: RemediationCandidate, marginal: number, riskSum: number, rank: number | null): RemediationPriority {
  return {
    ...(c.nodeId ? { nodeId: c.nodeId } : {}),
    ...(c.edgeId ? { edgeId: c.edgeId } : {}),
    action: c.action,
    category: c.category,
    effort: EFFORT_LABEL[c.effort],
    pathsBroken: c.paths.size,
    marginalPathsBroken: marginal,
    riskReduced: round(riskSum, 1),
    rank,
  };
}
