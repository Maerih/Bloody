import type { Criticality, EdgeKind, GraphNode } from "@bloody/contracts";
import { clamp01 } from "../util/math.js";
import { propBool, propNumber, propString } from "./props.js";

/**
 * Attacker-movement semantics of Security Graph edges.
 *
 * Each rule says: "an attacker who controls node A can gain control of node B over an edge of
 * kind K" with a base success probability and the ATT&CK technique it corresponds to.
 * `forward` rules move from `edge.from` to `edge.to`; `reverse` rules move from `edge.to` to
 * `edge.from` (e.g. `identity -[logged_into]-> host` read backwards = dumping the cached
 * credentials of that identity from the host).
 *
 * `gated` rules (network reachability) only grant control when the destination is
 * exploitable — it has an open vulnerability whose exploitability passes the threshold
 * (`has_vulnerability → exploit`). The step probability is then base × exploitability.
 *
 * Probabilities are calibrated priors for relative ranking of paths, not measured rates;
 * they are deliberately data, so they can be tuned per tenant without code changes.
 */
export interface AttackStepRule {
  edgeKind: EdgeKind;
  direction: "forward" | "reverse";
  probability: number;
  technique: string;
  gated: boolean;
  lateral: boolean;
  privilege: boolean;
  credential: boolean;
  /** Optional extra applicability check (attacker-controlled node first). */
  appliesTo?: (from: GraphNode, to: GraphNode) => boolean;
}

export const ATTACK_STEP_RULES: readonly AttackStepRule[] = [
  { edgeKind: "exposes", direction: "forward", probability: 1, technique: "T1190 Exploit Public-Facing Application", gated: true, lateral: false, privilege: false, credential: false },
  { edgeKind: "can_reach", direction: "forward", probability: 0.9, technique: "T1210 Exploitation of Remote Services", gated: true, lateral: true, privilege: false, credential: false },
  { edgeKind: "connected_to", direction: "forward", probability: 0.75, technique: "T1210 Exploitation of Remote Services", gated: true, lateral: true, privilege: false, credential: false, appliesTo: (_f, to) => to.kind !== "ip" && to.kind !== "domain" && to.kind !== "url" },
  { edgeKind: "authenticates_as", direction: "forward", probability: 0.9, technique: "T1078 Valid Accounts", gated: false, lateral: false, privilege: false, credential: true },
  { edgeKind: "stores_credential_for", direction: "forward", probability: 0.8, technique: "T1555 Credentials from Password Stores", gated: false, lateral: false, privilege: false, credential: true },
  { edgeKind: "admin_of", direction: "forward", probability: 0.9, technique: "T1021 Remote Services (administrative rights)", gated: false, lateral: true, privilege: true, credential: false },
  { edgeKind: "has_access_to", direction: "forward", probability: 0.85, technique: "T1078 Valid Accounts (authorized access)", gated: false, lateral: true, privilege: false, credential: false },
  { edgeKind: "logged_into", direction: "forward", probability: 0.6, technique: "T1021 Remote Services (interactive logon)", gated: false, lateral: true, privilege: false, credential: false },
  { edgeKind: "logged_into", direction: "reverse", probability: 0.7, technique: "T1003 OS Credential Dumping (cached session)", gated: false, lateral: false, privilege: false, credential: true },
  { edgeKind: "member_of", direction: "forward", probability: 1, technique: "Group membership inheritance", gated: false, lateral: false, privilege: false, credential: false },
  { edgeKind: "owns", direction: "forward", probability: 0.9, technique: "Ownership rights", gated: false, lateral: true, privilege: true, credential: false },
  { edgeKind: "trusts", direction: "reverse", probability: 0.7, technique: "T1199 Trusted Relationship", gated: false, lateral: true, privilege: false, credential: false },
  { edgeKind: "contains", direction: "forward", probability: 0.9, technique: "T1005 Data from Local System", gated: false, lateral: false, privilege: false, credential: false, appliesTo: (from) => from.kind !== "internet" },
  {
    edgeKind: "runs_on",
    direction: "forward",
    probability: 0.35,
    technique: "T1611 Escape to Host",
    gated: false,
    lateral: true,
    privilege: true,
    credential: false,
    appliesTo: (from) => from.kind === "container" || from.kind === "k8s_resource",
  },
];

/** Edge kinds the attack-path engine traverses by default. */
export const DEFAULT_ATTACK_EDGE_KINDS: readonly EdgeKind[] = [
  "exposes",
  "can_reach",
  "authenticates_as",
  "stores_credential_for",
  "admin_of",
  "has_access_to",
  "logged_into",
  "member_of",
  "owns",
  "trusts",
  "contains",
  "runs_on",
];

export function rulesFor(kinds: readonly EdgeKind[] = DEFAULT_ATTACK_EDGE_KINDS): AttackStepRule[] {
  const set = new Set(kinds);
  return ATTACK_STEP_RULES.filter((r) => set.has(r.edgeKind));
}

export const CRITICALITY_VALUE: Record<Criticality, number> = { low: 0.25, medium: 0.5, high: 0.75, crown_jewel: 1 };

export function nodeCriticality(node: GraphNode): Criticality | null {
  const c = propString(node.props, "criticality");
  if (c === "low" || c === "medium" || c === "high" || c === "crown_jewel") return c;
  if (propBool(node.props, "crownJewel") === true) return "crown_jewel";
  return null;
}

export function isCrownJewel(node: GraphNode): boolean {
  return nodeCriticality(node) === "crown_jewel";
}

export function isPrivileged(node: GraphNode): boolean {
  return propBool(node.props, "privileged") === true || propBool(node.props, "admin") === true;
}

/**
 * Exploitability of one vulnerability in [0, 1] from CVSS, EPSS and KEV:
 *   cvssPart = 0.6 · (cvss/10)²                     (severity alone is a weak predictor)
 *   e        = 1 − (1 − epss)(1 − 0.25·cvssPart)    when EPSS is known, else cvssPart
 *   KEV      ⇒ e ≥ 0.95                             (exploitation observed in the wild)
 */
export function vulnerabilityExploitability(v: { cvss?: number | null; epss?: number | null; knownExploited?: boolean | null }): number {
  const cvssPart = v.cvss !== null && v.cvss !== undefined ? 0.6 * (clamp01(v.cvss / 10) ** 2) : 0.15;
  const e = v.epss !== null && v.epss !== undefined ? 1 - (1 - clamp01(v.epss)) * (1 - 0.25 * cvssPart) : cvssPart;
  return v.knownExploited ? Math.max(e, 0.95) : clamp01(e);
}

/** Exploitability of a vulnerability graph node (props cvss / epss / knownExploited). */
export function vulnerabilityNodeExploitability(node: GraphNode): number {
  return vulnerabilityExploitability({
    cvss: propNumber(node.props, "cvss") ?? null,
    epss: propNumber(node.props, "epss") ?? null,
    knownExploited: propBool(node.props, "knownExploited") ?? false,
  });
}

const OPEN_VULN_STATUSES = new Set(["open", "in_remediation", "accepted", undefined]);

/** Whether a `has_vulnerability` edge still represents an exploitable, unremediated finding. */
export function isOpenVulnerabilityEdge(props: Record<string, unknown>): boolean {
  const status = propString(props, "status");
  return OPEN_VULN_STATUSES.has(status as never);
}

/**
 * Multiplicative reduction of an attacker step *into* `node` from compensating controls
 * recorded on the node: EDR (`edr`: true | "healthy" | "degraded"), MFA (`mfa`/`mfaEnabled`,
 * identities), network segmentation (`segmented`), isolation (`isolated`) and an explicit
 * `controlStrength` in [0, 1] for custom controls (WAF, virtual patching, PAM …).
 */
export function nodeControlReduction(node: GraphNode): { reduction: number; controls: Array<{ key: string; label: string; strength: number }> } {
  const controls: Array<{ key: string; label: string; strength: number }> = [];
  const edr = node.props.edr;
  if (edr === true || edr === "healthy") controls.push({ key: "edr", label: "EDR coverage", strength: 0.3 });
  else if (edr === "degraded") controls.push({ key: "edr", label: "EDR coverage (degraded)", strength: 0.15 });
  if (node.kind === "identity" || node.kind === "user" || node.kind === "service_account") {
    if (propBool(node.props, "mfa") === true || propBool(node.props, "mfaEnabled") === true) controls.push({ key: "mfa", label: "MFA enforced", strength: 0.5 });
  }
  if (propBool(node.props, "segmented") === true) controls.push({ key: "segmentation", label: "Network segmentation", strength: 0.35 });
  if (propBool(node.props, "isolated") === true) controls.push({ key: "isolation", label: "Host isolated", strength: 0.95 });
  const custom = propNumber(node.props, "controlStrength");
  if (custom !== undefined && custom > 0) controls.push({ key: "custom_control", label: propString(node.props, "controlLabel") ?? "Compensating control", strength: clamp01(custom) });
  let keep = 1;
  for (const c of controls) keep *= 1 - c.strength;
  return { reduction: 1 - keep, controls };
}
