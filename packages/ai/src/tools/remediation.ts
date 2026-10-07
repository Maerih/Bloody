import {
  ACTIVE_INCIDENT_STATUSES,
  SEVERITY_RANK,
  actionRisk,
  type ActionRisk,
  type AiToolTier,
  type AttackPath,
  type Criticality,
  type ResponseActionKey,
} from "@bloody/contracts";
import type { AssetDetail, IdentityDetail, IncidentDetail } from "./soc-port.js";

/**
 * Deterministic, explainable remediation ranking used by the `recommend_remediation` tool. The
 * model receives ranked, evidence-backed candidates (with the response action and approval
 * tier each would need) instead of inventing remediation from scratch.
 */

export type RemediationCategory = "containment" | "patch" | "identity" | "hardening" | "attack_path";

export interface RemediationRecommendation {
  id: string;
  title: string;
  category: RemediationCategory;
  /** 0-100, higher first. */
  priority: number;
  rationale: string;
  evidence: string[];
  effort: "low" | "medium" | "high";
  responseAction?: {
    action: ResponseActionKey;
    risk: ActionRisk;
    target: { kind: "asset" | "identity" | "indicator" | "incident"; id: string; label?: string };
    requiresHumanApproval: boolean;
    /** Lowest AI tier that could execute it (low-risk actions may run at "execute"). */
    minimumAiTier: AiToolTier;
  };
}

const CRITICALITY_BONUS: Record<Criticality, number> = { low: 0, medium: 4, high: 8, crown_jewel: 14 };
const ISOLATABLE = new Set(["endpoint", "server", "cloud_instance", "domain_controller", "database"]);

function responseAction(action: ResponseActionKey, target: { kind: "asset" | "identity" | "indicator" | "incident"; id: string; label?: string }): RemediationRecommendation["responseAction"] {
  const risk = actionRisk(action);
  return { action, risk, target, requiresHumanApproval: risk !== "low", minimumAiTier: risk === "low" ? "execute" : "require_approval" };
}

function clampPriority(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)));
}

export interface RemediationInput {
  incident: IncidentDetail | null;
  assets: AssetDetail[];
  identities: IdentityDetail[];
  attackPaths: AttackPath[];
}

export function buildRemediationPlan(input: RemediationInput, limit = 15): RemediationRecommendation[] {
  const recs = new Map<string, RemediationRecommendation>();
  const add = (r: RemediationRecommendation): void => {
    const existing = recs.get(r.id);
    if (!existing || existing.priority < r.priority) recs.set(r.id, { ...r, priority: clampPriority(r.priority) });
  };

  const incident = input.incident?.incident ?? null;
  const activeHigh =
    incident !== null &&
    ACTIVE_INCIDENT_STATUSES.includes(incident.status) &&
    incident.status !== "contained" &&
    SEVERITY_RANK[incident.severity] >= SEVERITY_RANK.high;

  // 1. Containment for active high/critical incidents.
  if (incident && activeHigh) {
    const base = incident.severity === "critical" ? 92 : 82;
    for (const detail of input.assets.filter((a) => incident.assetIds.includes(a.asset.id))) {
      const { asset, agent } = detail;
      if (!ISOLATABLE.has(asset.kind) || !agent || agent.status === "isolated") continue;
      const disruptive = asset.criticality === "crown_jewel" || asset.kind === "domain_controller";
      add({
        id: `contain:isolate:${asset.id}`,
        title: `Isolate ${asset.hostname ?? asset.name} from the network`,
        category: "containment",
        priority: base - (disruptive ? 8 : 0),
        rationale: `Incident #${incident.number} is ${incident.severity} and still ${incident.status}; ${asset.name} is involved and its agent (${agent.engine}) can enforce isolation.${
          disruptive ? " Business-critical system: coordinate with the owner before isolating." : ""
        }`,
        evidence: [`incident:${incident.id}`, `asset:${asset.id}`],
        effort: "low",
        responseAction: responseAction("isolate_endpoint", { kind: "asset", id: asset.id, label: asset.hostname ?? asset.name }),
      });
    }
    for (const detail of input.identities.filter((i) => incident.identityIds.includes(i.identity.id))) {
      const { identity } = detail;
      add({
        id: `contain:revoke:${identity.id}`,
        title: `Revoke active sessions of ${identity.principal}`,
        category: "containment",
        priority: base - 2,
        rationale: `${identity.principal} is part of ${incident.severity} incident #${incident.number}; revoking sessions evicts an attacker holding stolen tokens.`,
        evidence: [`incident:${incident.id}`, `identity:${identity.id}`],
        effort: "low",
        responseAction: responseAction("revoke_sessions", { kind: "identity", id: identity.id, label: identity.principal }),
      });
      if (identity.privileged && incident.severity === "critical") {
        add({
          id: `contain:disable:${identity.id}`,
          title: `Temporarily disable privileged identity ${identity.principal}`,
          category: "containment",
          priority: base - 4,
          rationale: `Privileged identity involved in a critical incident; disabling prevents further privileged actions until credentials are reset.`,
          evidence: [`incident:${incident.id}`, `identity:${identity.id}`],
          effort: "medium",
          responseAction: responseAction("disable_identity", { kind: "identity", id: identity.id, label: identity.principal }),
        });
      }
    }
    add({
      id: `contain:evidence:${incident.id}`,
      title: "Collect forensic evidence before remediation",
      category: "containment",
      priority: base - 12,
      rationale: "Preserve volatile evidence (memory, process lists, logs) before reimaging or patching affected hosts.",
      evidence: [`incident:${incident.id}`],
      effort: "low",
      responseAction: responseAction("collect_evidence", { kind: "incident", id: incident.id, label: `#${incident.number}` }),
    });
  }

  // 2. Vulnerabilities on involved assets.
  for (const { asset, vulnerabilities } of input.assets) {
    for (const v of vulnerabilities) {
      if (v.status !== "open" && v.status !== "in_remediation") continue;
      const exposure = asset.internetFacing ? 10 : 0;
      const priority = v.knownExploited
        ? 90 + Math.min(8, CRITICALITY_BONUS[asset.criticality] / 2 + exposure / 5)
        : (v.cvss ?? 5) * 5.5 + (v.epss ?? 0) * 30 + CRITICALITY_BONUS[asset.criticality] + exposure;
      const label = v.cve ?? v.title;
      add({
        id: `patch:${v.id}`,
        title: v.patchAvailable ? `Patch ${label} on ${asset.hostname ?? asset.name}` : `Mitigate ${label} on ${asset.hostname ?? asset.name} (no patch available)`,
        category: "patch",
        priority,
        rationale: [
          v.knownExploited ? "Known exploited in the wild (KEV)." : null,
          v.cvss !== null ? `CVSS ${v.cvss}.` : null,
          v.epss !== null ? `EPSS ${(v.epss * 100).toFixed(1)}% exploitation probability.` : null,
          asset.internetFacing ? "Asset is internet-facing." : null,
          `Asset criticality: ${asset.criticality}.`,
          v.slaDueAt ? `SLA due ${v.slaDueAt}.` : null,
        ]
          .filter(Boolean)
          .join(" "),
        evidence: [`vulnerability:${v.id}`, `asset:${asset.id}`],
        effort: v.patchAvailable ? "low" : "medium",
      });
    }
  }

  // 3. Endpoint control health.
  for (const { asset, agent } of input.assets) {
    if (!agent) continue;
    const exposure = asset.internetFacing ? 10 : 0;
    if (agent.status === "unresponsive" || agent.status === "outdated") {
      add({
        id: `hardening:agent:${asset.id}`,
        title: `Restore EDR agent health on ${asset.hostname ?? asset.name} (${agent.status})`,
        category: "hardening",
        priority: 58 + CRITICALITY_BONUS[asset.criticality] / 2 + exposure / 2,
        rationale: `Agent is ${agent.status}; detection and response coverage for this asset is degraded.`,
        evidence: [`asset:${asset.id}`],
        effort: "low",
      });
    }
    if (agent.antivirusStatus === "unhealthy" || agent.antivirusStatus === "unmanaged") {
      add({
        id: `hardening:av:${asset.id}`,
        title: `Fix antivirus status (${agent.antivirusStatus}) on ${asset.hostname ?? asset.name}`,
        category: "hardening",
        priority: 52 + CRITICALITY_BONUS[asset.criticality] / 2,
        rationale: "Malware prevention is not functioning on this host.",
        evidence: [`asset:${asset.id}`],
        effort: "low",
      });
    }
    if (!agent.firewallEnabled) {
      add({
        id: `hardening:fw:${asset.id}`,
        title: `Enable the host firewall on ${asset.hostname ?? asset.name}`,
        category: "hardening",
        priority: 45 + exposure + CRITICALITY_BONUS[asset.criticality] / 2,
        rationale: `Host firewall is disabled${asset.internetFacing ? " on an internet-facing asset" : ""}, widening lateral-movement and exposure paths.`,
        evidence: [`asset:${asset.id}`],
        effort: "low",
      });
    }
  }

  // 4. Identity hygiene.
  for (const { identity } of input.identities) {
    if (identity.privileged && !identity.mfaEnabled) {
      add({
        id: `identity:mfa:${identity.id}`,
        title: `Enforce MFA for privileged identity ${identity.principal}`,
        category: "identity",
        priority: 80,
        rationale: "Privileged identity without MFA — a single stolen password grants administrative access.",
        evidence: [`identity:${identity.id}`],
        effort: "low",
      });
    }
    if ((identity.riskScore ?? 0) >= 70) {
      add({
        id: `identity:reset:${identity.id}`,
        title: `Reset credentials and review entitlements of ${identity.principal}`,
        category: "identity",
        priority: 60 + ((identity.riskScore ?? 70) - 70) / 2,
        rationale: `Identity risk score ${identity.riskScore}/100.`,
        evidence: [`identity:${identity.id}`],
        effort: "medium",
      });
    }
  }

  // 5. Attack-path choke points (aggregated across paths).
  const chokepoints = new Map<string, { action: string; broken: number; paths: string[]; maxRisk: number }>();
  for (const path of input.attackPaths) {
    for (const r of path.remediations) {
      const key = r.edgeId ?? r.nodeId ?? r.action;
      const entry = chokepoints.get(key) ?? { action: r.action, broken: 0, paths: [], maxRisk: 0 };
      entry.broken = Math.max(entry.broken, r.pathsBroken);
      entry.paths.push(path.id);
      entry.maxRisk = Math.max(entry.maxRisk, path.risk.score);
      chokepoints.set(key, entry);
    }
  }
  for (const [key, c] of chokepoints) {
    add({
      id: `path:${key}`,
      title: c.action,
      category: "attack_path",
      priority: 45 + Math.min(30, c.broken * 6) + c.maxRisk / 10,
      rationale: `Breaks ${c.broken} attack path(s) (highest path risk ${c.maxRisk}/100).`,
      evidence: [...new Set(c.paths)].slice(0, 5).map((p) => `attack_path:${p}`),
      effort: "medium",
    });
  }

  // 6. Internet exposure of crown jewels with serious open vulnerabilities.
  for (const { asset, vulnerabilities } of input.assets) {
    if (!asset.internetFacing || asset.criticality !== "crown_jewel") continue;
    const serious = vulnerabilities.filter((v) => (v.status === "open" || v.status === "in_remediation") && SEVERITY_RANK[v.severity] >= SEVERITY_RANK.high);
    if (serious.length === 0) continue;
    add({
      id: `hardening:exposure:${asset.id}`,
      title: `Reduce internet exposure of crown-jewel ${asset.hostname ?? asset.name}`,
      category: "hardening",
      priority: 76,
      rationale: `Internet-facing crown-jewel asset with ${serious.length} open high/critical vulnerabilities; restrict access (WAF/VPN/allow-list) until patched.`,
      evidence: [`asset:${asset.id}`, ...serious.slice(0, 3).map((v) => `vulnerability:${v.id}`)],
      effort: "medium",
    });
  }

  return [...recs.values()].sort((a, b) => b.priority - a.priority || a.title.localeCompare(b.title)).slice(0, limit);
}
