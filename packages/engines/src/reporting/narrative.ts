import type { AttackPathAnalysis } from "../attack-path/engine.js";
import type { IncidentDraft } from "../correlation/correlator.js";
import type { ExplainedRiskAssessment } from "../risk/model.js";
import type { ExposureAssessment, ExposureDomain } from "../risk/risk-engine.js";
import { pct, round } from "../util/math.js";

/**
 * Audience-aware narratives of engine outputs, for reports, emails/chat notifications and
 * the AI SOC. Every sentence is derived from the explained factors — nothing is invented.
 *
 *  - executive: business language, no jargon, the "so what" and the decision needed
 *  - customer:  what happened / what we are doing / what you need to do
 *  - analyst:   factor-level detail with weights and contributions
 *  - mssp:      one-line portfolio comparison
 */
export type NarrativeAudience = "executive" | "customer" | "analyst" | "mssp";

export interface Narrative {
  headline: string;
  paragraphs: string[];
  actions: string[];
}

const LEVEL_WORDS: Record<string, string> = { critical: "critical", high: "high", medium: "moderate", low: "low", info: "minimal" };

export function narrateRisk(a: ExplainedRiskAssessment, options: { audience: NarrativeAudience; subject: string; actions?: string[] }): Narrative {
  const { audience, subject } = options;
  const drivers = a.factors.filter((f) => f.contribution > 0.05);
  const controls = a.factors.filter((f) => f.group === "control" && f.contribution < -0.05);
  const reduced = round(-controls.reduce((s, f) => s + f.contribution, 0), 1);
  const actions = options.actions ?? [];
  switch (audience) {
    case "analyst":
      return {
        headline: `${subject}: ${a.score}/100 (${a.severity}) — likelihood ${pct(a.likelihood)}, impact ${pct(a.impact)} [${a.modelVersion}]`,
        paragraphs: [
          ...a.factors.map((f) => `${f.contribution >= 0 ? "+" : ""}${f.contribution.toFixed(2)} ${f.label} [${f.group}, value ${f.value}, weight ${f.weight}] — ${f.explanation}`),
          `Inherent score without controls: ${a.inherentScore}/100.`,
        ],
        actions,
      };
    case "mssp":
      return {
        headline: `${subject} ${a.score}/100 ${a.severity}${drivers[0] ? ` · top driver: ${drivers[0].label.toLowerCase()}` : ""}${reduced > 0 ? ` · controls −${reduced}` : ""}`,
        paragraphs: [],
        actions: actions.slice(0, 1),
      };
    case "customer":
      return {
        headline: `${subject} is at ${LEVEL_WORDS[a.severity]} risk (${a.score} out of 100).`,
        paragraphs: [
          drivers.length ? `What we found: ${drivers.slice(0, 3).map((f) => sentence(f.explanation)).join(" ")}` : "We found no significant risk signals.",
          controls.length ? `What is protecting you: ${controls.map((f) => f.label.toLowerCase()).join(", ")} lowered this score by ${reduced} points.` : "No compensating controls were credited.",
        ],
        actions: actions.length ? actions : drivers.length ? [`Review the findings for ${subject} with your security team.`] : [],
      };
    case "executive":
    default: {
      const likely = drivers.filter((f) => f.group === "likelihood").slice(0, 2).map((f) => f.label.toLowerCase());
      const impact = drivers.filter((f) => f.group === "impact").slice(0, 2).map((f) => f.label.toLowerCase());
      return {
        headline: `${subject}: ${LEVEL_WORDS[a.severity]} risk (${a.score}/100).`,
        paragraphs: [
          `${likely.length ? `An attack is ${a.likelihood >= 0.6 ? "likely" : a.likelihood >= 0.3 ? "plausible" : "unlikely"} because of ${likely.join(" and ")}.` : "No meaningful attack likelihood signals."} ${impact.length ? `Consequences would be ${a.impact >= 0.7 ? "severe" : a.impact >= 0.4 ? "significant" : "limited"} given ${impact.join(" and ")}.` : ""}`.trim(),
          ...(reduced > 0 ? [`Existing safeguards (${controls.map((f) => f.label.toLowerCase()).join(", ")}) already reduce the risk by ${reduced} points.`] : []),
        ],
        actions,
      };
    }
  }
}

export function narrateAttackPaths(analysis: AttackPathAnalysis, options: { audience: NarrativeAudience; organizationName?: string }): Narrative {
  const s = analysis.summary;
  const org = options.organizationName ?? "the organization";
  if (s.totalPaths === 0) return { headline: `No attack paths from the internet to crown-jewel assets were found for ${org}.`, paragraphs: [], actions: [] };
  const top = analysis.paths[0]!;
  const route = top.steps.map((st) => top.nodes.find((n) => n.id === st.to)?.label ?? st.to);
  const fixes = analysis.remediations.slice(0, 5).map((r) => `${r.action} (breaks ${r.pathsBroken} path${r.pathsBroken === 1 ? "" : "s"}, ${r.effort} effort)`);
  switch (options.audience) {
    case "analyst":
      return {
        headline: `${s.totalPaths} attack path(s) to ${s.targetsAtRisk} crown jewel(s); max risk ${s.maxRiskScore}; shortest ${s.shortestPathLength} step(s)${s.truncated ? " (search truncated)" : ""}`,
        paragraphs: analysis.paths.slice(0, 5).map((p) => `${p.risk.score} ${p.risk.severity}: ${[p.entry.label, ...p.steps.map((st) => `-[${st.technique}]-> ${p.nodes.find((n) => n.id === st.to)?.label ?? st.to}`)].join(" ")}`),
        actions: fixes,
      };
    case "mssp":
      return { headline: `${org}: ${s.totalPaths} path(s) to crown jewels, max ${s.maxRiskScore}, ${s.fixesToBreakAll} fix(es) close all`, paragraphs: [], actions: fixes.slice(0, 1) };
    case "customer":
    case "executive":
    default:
      return {
        headline: `An attacker on the internet could reach ${s.targetsAtRisk} of ${org}'s most critical system(s) through ${s.totalPaths} route(s).`,
        paragraphs: [
          `The most dangerous route goes ${route.join(" → ")} (risk ${top.risk.score}/100).`,
          `${s.fixesToBreakAll} targeted fix${s.fixesToBreakAll === 1 ? "" : "es"} would close every route we found${analysis.remediations[0] ? `; the single most effective is: ${analysis.remediations[0].action.toLowerCase()}` : ""}.`,
        ],
        actions: fixes,
      };
  }
}

const DOMAIN_LABEL: Record<ExposureDomain, string> = {
  external: "external attack surface",
  vulnerability: "exploitable vulnerabilities",
  identity: "identity",
  cloud: "cloud",
  saas: "SaaS",
  misconfiguration: "configuration",
  attack_path: "attack paths",
  threat_intel: "active threats",
};

export function narrateExposure(e: ExposureAssessment, options: { audience: NarrativeAudience; organizationName?: string }): Narrative {
  const org = options.organizationName ?? "The organization";
  const domains = (Object.keys(e.domains) as ExposureDomain[]).filter((d) => e.domains[d].score > 0).sort((a, b) => e.domains[b].score - e.domains[a].score);
  const base = narrateRisk(e, { audience: options.audience, subject: `${org} exposure` });
  if (options.audience === "analyst") {
    base.paragraphs.push(...domains.map((d) => `${DOMAIN_LABEL[d]}: ${e.domains[d].score}/100 — ${e.domains[d].drivers.join("; ")}`));
  } else if (options.audience !== "mssp" && domains.length > 0) {
    base.paragraphs.push(`Largest exposure areas: ${domains.slice(0, 3).map((d) => `${DOMAIN_LABEL[d]} (${e.domains[d].score})`).join(", ")}.`);
  }
  return base;
}

export function narrateIncident(d: IncidentDraft, options: { audience: NarrativeAudience; organizationName?: string }): Narrative {
  switch (options.audience) {
    case "analyst":
      return { headline: `[${d.severity.toUpperCase()}] ${d.title} — risk ${d.riskScore}`, paragraphs: [d.summary, ...d.escalationReasons], actions: [] };
    case "mssp":
      return { headline: `${options.organizationName ?? d.organizationId}: ${d.severity} incident "${d.title}" (risk ${d.riskScore}, ${d.alertIds.length} alert(s))`, paragraphs: [], actions: [] };
    case "customer":
      return {
        headline: `We are investigating a ${LEVEL_WORDS[d.severity]}-severity security incident: ${d.title}.`,
        paragraphs: [
          `First activity ${d.firstSeenAt}, latest ${d.lastSeenAt}. Affected: ${d.assetKeys.length} system(s) and ${d.identityKeys.length} account(s).`,
          "Our analysts are investigating; containment actions that affect your systems are only taken after the approvals agreed with you.",
        ],
        actions: d.identityKeys.length ? ["Be ready to confirm whether the affected accounts' recent activity was legitimate."] : [],
      };
    case "executive":
    default: {
      const level = LEVEL_WORDS[d.severity] ?? d.severity;
      return {
        headline: `${level.charAt(0).toUpperCase()}${level.slice(1)}-severity incident: ${d.title}.`,
        paragraphs: [`${d.alertIds.length} related detection(s) across ${d.assetKeys.length} system(s) and ${d.identityKeys.length} account(s); risk ${d.riskScore}/100. ${d.risk.summary}`],
        actions: [],
      };
    }
  }
}

function sentence(s: string): string {
  const t = s.trim();
  return /[.!?]$/.test(t) ? t : `${t}.`;
}
