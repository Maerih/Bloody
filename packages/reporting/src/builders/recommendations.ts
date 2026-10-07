import type { Recommendation, RecommendationPriority } from "../model.js";
import { formatDuration, formatPercent } from "../format.js";

/**
 * Rule-based, explainable recommendations. Each one cites the metric that triggered it, so a
 * reader can see exactly why it is on the list. Builders pass only the signals they have.
 */
export interface RecommendationSignals {
  audience: "business" | "soc" | "mssp" | "customer";
  knownExploitedOpen?: number;
  overdueVulnerabilities?: number;
  internetFacingCritical?: number;
  attackPathsToCrownJewels?: number;
  privilegedWithoutMfa?: number;
  unresponsiveAgents?: number;
  outdatedAgents?: number;
  silentLogSources?: number;
  slaAttainmentPct?: number | null;
  slaTargetPct?: number;
  falsePositiveRatePct?: number | null;
  noisyRules?: string[];
  openEscalationsForCustomer?: number;
  overdueEscalations?: number;
  mttaMinutes?: number | null;
  mttaTargetMinutes?: number;
  backlogOlderThan7d?: number;
  failingCriticalControls?: number;
  playbookFailures?: number;
  pendingApprovals?: number;
}

const ORDER: Record<RecommendationPriority, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function deriveRecommendations(s: RecommendationSignals): Recommendation[] {
  const out: Recommendation[] = [];
  const customer = s.audience === "customer" || s.audience === "business";
  const n = (v: number | undefined): number => v ?? 0;

  if (n(s.knownExploitedOpen) > 0) {
    out.push({
      priority: "critical",
      title: `Patch ${n(s.knownExploitedOpen)} known-exploited ${n(s.knownExploitedOpen) === 1 ? "vulnerability" : "vulnerabilities"}`,
      rationale: "These vulnerabilities are being actively exploited in the wild (KEV). Patch or apply vendor mitigations first; they are the most likely initial-access route.",
      owner: customer ? "it" : "security_engineering",
    });
  }
  if (n(s.attackPathsToCrownJewels) > 0) {
    out.push({
      priority: "high",
      title: `Break ${n(s.attackPathsToCrownJewels)} attack ${n(s.attackPathsToCrownJewels) === 1 ? "path" : "paths"} to crown-jewel assets`,
      rationale: "The Security Graph found exploitable chains from exposed entry points to critical assets. The first remediation listed for each path removes the most paths at once.",
      owner: "security_engineering",
    });
  }
  if (n(s.privilegedWithoutMfa) > 0) {
    out.push({
      priority: "high",
      title: `Enforce MFA on ${n(s.privilegedWithoutMfa)} privileged ${n(s.privilegedWithoutMfa) === 1 ? "account" : "accounts"}`,
      rationale: "Privileged identities without MFA are the most common path to domain-wide compromise after credential theft or phishing.",
      owner: customer ? "it" : "security_engineering",
    });
  }
  if (n(s.openEscalationsForCustomer) > 0) {
    out.push({
      priority: n(s.overdueEscalations) > 0 ? "high" : "medium",
      title: `Respond to ${n(s.openEscalationsForCustomer)} open ${n(s.openEscalationsForCustomer) === 1 ? "escalation" : "escalations"}`,
      rationale: `The SOC is waiting for your input to complete investigations${n(s.overdueEscalations) > 0 ? `; ${n(s.overdueEscalations)} ${n(s.overdueEscalations) === 1 ? "is" : "are"} past due` : ""}.`,
      owner: "customer",
    });
  }
  if (n(s.internetFacingCritical) > 0) {
    out.push({
      priority: "high",
      title: `Remediate ${n(s.internetFacingCritical)} critical ${n(s.internetFacingCritical) === 1 ? "vulnerability" : "vulnerabilities"} on internet-facing assets`,
      rationale: "Internet exposure removes the attacker's need for initial access; these carry the highest likelihood in the risk model.",
      owner: customer ? "it" : "security_engineering",
    });
  }
  if (s.slaAttainmentPct !== undefined && s.slaAttainmentPct !== null && s.slaAttainmentPct < (s.slaTargetPct ?? 95)) {
    out.push({
      priority: s.slaAttainmentPct < (s.slaTargetPct ?? 95) - 10 ? "high" : "medium",
      title: "Restore SLA attainment",
      rationale: `SLA attainment was ${formatPercent(s.slaAttainmentPct)} against a ${formatPercent(s.slaTargetPct ?? 95, 0)} objective. Review breach reasons below and analyst coverage for the affected severities.`,
      owner: s.audience === "customer" ? "mssp" : "soc",
    });
  }
  if (s.mttaMinutes !== undefined && s.mttaMinutes !== null && s.mttaTargetMinutes !== undefined && s.mttaMinutes > s.mttaTargetMinutes) {
    out.push({
      priority: "medium",
      title: "Shorten time to acknowledge",
      rationale: `Mean time to acknowledge was ${formatDuration(s.mttaMinutes)} (objective ${formatDuration(s.mttaTargetMinutes)}). Consider auto-assignment and AI triage for high-severity incidents.`,
      owner: "soc",
    });
  }
  if (n(s.overdueVulnerabilities) > 0) {
    out.push({
      priority: "medium",
      title: `Clear ${n(s.overdueVulnerabilities)} vulnerabilities past their remediation SLA`,
      rationale: "Overdue findings accumulate risk and are a frequent audit finding. Patch, mitigate, or record a risk acceptance with an owner and expiry.",
      owner: customer ? "it" : "security_engineering",
    });
  }
  if (n(s.unresponsiveAgents) > 0) {
    out.push({
      priority: "medium",
      title: `Restore ${n(s.unresponsiveAgents)} unresponsive ${n(s.unresponsiveAgents) === 1 ? "agent" : "agents"}`,
      rationale: "Devices with silent agents are not monitored; confirm they are online or decommissioned.",
      owner: customer ? "it" : "soc",
    });
  }
  if (n(s.silentLogSources) > 0) {
    out.push({
      priority: "medium",
      title: `Investigate ${n(s.silentLogSources)} silent log ${n(s.silentLogSources) === 1 ? "source" : "sources"}`,
      rationale: "A data source that stopped sending events creates a detection blind spot.",
      owner: "security_engineering",
    });
  }
  if (s.falsePositiveRatePct !== undefined && s.falsePositiveRatePct !== null && s.falsePositiveRatePct > 30) {
    out.push({
      priority: "medium",
      title: "Tune noisy detections",
      rationale: `${formatPercent(s.falsePositiveRatePct)} of alerts were false positives${s.noisyRules && s.noisyRules.length > 0 ? `; start with ${s.noisyRules.slice(0, 3).join(", ")}` : ""}. Tuning frees analyst time for real threats.`,
      owner: "security_engineering",
    });
  }
  if (n(s.backlogOlderThan7d) > 0) {
    out.push({
      priority: "medium",
      title: `Close out ${n(s.backlogOlderThan7d)} incidents open for more than 7 days`,
      rationale: "Aged incidents indicate blocked investigations or missing customer input.",
      owner: "soc",
    });
  }
  if (n(s.failingCriticalControls) > 0) {
    out.push({
      priority: "high",
      title: `Fix ${n(s.failingCriticalControls)} failing high-severity controls`,
      rationale: "High-severity control failures are the gaps most likely to be cited in audits and exploited by attackers.",
      owner: customer ? "it" : "security_engineering",
    });
  }
  if (n(s.outdatedAgents) > 0) {
    out.push({ priority: "low", title: `Update ${n(s.outdatedAgents)} outdated agents`, rationale: "Older agent versions miss detection content and fixes.", owner: customer ? "it" : "soc" });
  }
  if (n(s.playbookFailures) > 0) {
    out.push({ priority: "low", title: `Review ${n(s.playbookFailures)} failed playbook runs`, rationale: "Failed automations usually point at expired integration credentials or changed APIs.", owner: "security_engineering" });
  }
  if (n(s.pendingApprovals) > 0) {
    out.push({ priority: "medium", title: `Decide ${n(s.pendingApprovals)} pending response approvals`, rationale: "High-risk containment actions are waiting for a human approver.", owner: "soc" });
  }
  return out.sort((a, b) => ORDER[a.priority] - ORDER[b.priority]);
}
