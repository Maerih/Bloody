import { SEVERITY_RANK, type Severity } from "@bloody/contracts";
import type { RuleMetrics } from "../detection/engine.js";
import type { RuleFeedbackStats } from "../detection/suppression.js";
import type { DetectionMatch, DetectionRule } from "../detection/types.js";
import { ATTACK_TACTICS, killChainOrder, tacticOf } from "../risk/tactics.js";
import { round } from "../util/math.js";

/**
 * Report-ready aggregates computed from engine outputs. `@bloody/reporting` renders them
 * (HTML/PDF/CSV/JSON) for SOC, CISO/executive, customer and MSSP audiences; the Command
 * Center uses them for coverage and tuning widgets.
 */

export interface AttackCoverage {
  enabledRules: number;
  disabledRules: number;
  rulesWithTests: number;
  techniques: Array<{ id: string; tactic: string | null; rules: string[] }>;
  tactics: Array<{ tactic: string; techniques: number; rules: number }>;
  /** Tactics of the ATT&CK enterprise matrix with no enabled rule. */
  uncoveredTactics: string[];
}

/** ATT&CK coverage of the enabled rule set (detection-engineering & CISO reporting). */
export function detectionCoverage(rules: readonly DetectionRule[]): AttackCoverage {
  const enabled = rules.filter((r) => r.enabled);
  const techniques = new Map<string, { id: string; tactic: string | null; rules: Set<string> }>();
  for (const r of enabled) {
    for (const t of r.attack) {
      const cur = techniques.get(t.id) ?? { id: t.id, tactic: tacticOf(t), rules: new Set<string>() };
      cur.rules.add(r.id);
      if (!cur.tactic) cur.tactic = tacticOf(t);
      techniques.set(t.id, cur);
    }
  }
  const byTactic = new Map<string, { techniques: Set<string>; rules: Set<string> }>();
  for (const t of techniques.values()) {
    if (!t.tactic) continue;
    const cur = byTactic.get(t.tactic) ?? { techniques: new Set(), rules: new Set() };
    cur.techniques.add(t.id);
    t.rules.forEach((r) => cur.rules.add(r));
    byTactic.set(t.tactic, cur);
  }
  return {
    enabledRules: enabled.length,
    disabledRules: rules.length - enabled.length,
    rulesWithTests: rules.filter((r) => r.tests.length > 0).length,
    techniques: [...techniques.values()].map((t) => ({ id: t.id, tactic: t.tactic, rules: [...t.rules].sort() })).sort((a, b) => a.id.localeCompare(b.id)),
    tactics: killChainOrder(byTactic.keys()).map((tactic) => ({ tactic, techniques: byTactic.get(tactic)!.techniques.size, rules: byTactic.get(tactic)!.rules.size })),
    uncoveredTactics: ATTACK_TACTICS.filter((t) => !byTactic.has(t)),
  };
}

export interface MatchSummary {
  total: number;
  bySeverity: Record<Severity, number>;
  byRule: Array<{ ruleId: string; name: string; count: number; maxSeverity: Severity }>;
  byTactic: Array<{ tactic: string; count: number }>;
  byTechnique: Array<{ id: string; count: number }>;
  topEntities: Array<{ kind: string; key: string; label: string; count: number }>;
  byOrganization: Array<{ organizationId: string; count: number; critical: number }>;
}

/** Volume / severity / ATT&CK / entity breakdown of detections over a reporting period. */
export function summarizeMatches(matches: readonly DetectionMatch[], options: { top?: number } = {}): MatchSummary {
  const top = options.top ?? 10;
  const bySeverity: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  const byRule = new Map<string, { ruleId: string; name: string; count: number; maxSeverity: Severity }>();
  const byTactic = new Map<string, number>();
  const byTechnique = new Map<string, number>();
  const entities = new Map<string, { kind: string; key: string; label: string; count: number }>();
  const byOrg = new Map<string, { organizationId: string; count: number; critical: number }>();
  for (const m of matches) {
    bySeverity[m.severity]++;
    const r = byRule.get(m.rule.id) ?? { ruleId: m.rule.id, name: m.rule.name, count: 0, maxSeverity: "info" as Severity };
    r.count++;
    if (SEVERITY_RANK[m.severity] > SEVERITY_RANK[r.maxSeverity]) r.maxSeverity = m.severity;
    byRule.set(m.rule.id, r);
    const tactics = new Set<string>();
    for (const t of m.attack) {
      byTechnique.set(t.id, (byTechnique.get(t.id) ?? 0) + 1);
      const tac = tacticOf(t);
      if (tac) tactics.add(tac);
    }
    for (const tac of tactics) byTactic.set(tac, (byTactic.get(tac) ?? 0) + 1);
    for (const e of m.entities) {
      if (e.kind === "technique" || e.kind === "process" || e.kind === "file") continue;
      const k = `${e.kind}:${e.key}`;
      const cur = entities.get(k) ?? { kind: e.kind, key: e.key, label: e.label, count: 0 };
      cur.count++;
      entities.set(k, cur);
    }
    const o = byOrg.get(m.organizationId) ?? { organizationId: m.organizationId, count: 0, critical: 0 };
    o.count++;
    if (m.severity === "critical") o.critical++;
    byOrg.set(m.organizationId, o);
  }
  return {
    total: matches.length,
    bySeverity,
    byRule: [...byRule.values()].sort((a, b) => b.count - a.count || a.ruleId.localeCompare(b.ruleId)).slice(0, top),
    byTactic: killChainOrder(byTactic.keys()).map((tactic) => ({ tactic, count: byTactic.get(tactic)! })),
    byTechnique: [...byTechnique.entries()].map(([id, count]) => ({ id, count })).sort((a, b) => b.count - a.count || a.id.localeCompare(b.id)).slice(0, top),
    topEntities: [...entities.values()].sort((a, b) => b.count - a.count || a.key.localeCompare(b.key)).slice(0, top),
    byOrganization: [...byOrg.values()].sort((a, b) => b.critical - a.critical || b.count - a.count),
  };
}

export interface RuleEfficacy {
  ruleId: string;
  name: string;
  matched: number;
  suppressed: number;
  cooledDown: number;
  errors: number;
  /** Analyst-confirmed precision (TP / (TP + FP)); null without verdicts. */
  precision: number | null;
  /** Share of firings silenced by tuning — high values mean the rule needs rework. */
  noiseRatio: number;
  recommendation: "healthy" | "tune" | "review" | "fix" | "silent";
}

/** Detection tuning report: joins engine metrics with analyst feedback. */
export function ruleEfficacy(metrics: readonly RuleMetrics[], feedback: readonly RuleFeedbackStats[] = []): RuleEfficacy[] {
  const fb = new Map(feedback.map((f) => [f.ruleId, f]));
  return metrics
    .map((m) => {
      const f = fb.get(m.ruleId);
      const fired = m.matched + m.suppressed;
      const noiseRatio = fired > 0 ? round(m.suppressed / fired, 4) : 0;
      const precision = f?.precision ?? null;
      let recommendation: RuleEfficacy["recommendation"] = "healthy";
      if (m.errors > 0) recommendation = "fix";
      else if (fired === 0) recommendation = "silent";
      else if ((precision !== null && precision < 0.3) || noiseRatio > 0.6) recommendation = "review";
      else if ((precision !== null && precision < 0.7) || noiseRatio > 0.3) recommendation = "tune";
      return { ruleId: m.ruleId, name: m.name, matched: m.matched, suppressed: m.suppressed, cooledDown: m.cooledDown, errors: m.errors, precision, noiseRatio, recommendation };
    })
    .sort((a, b) => order(a.recommendation) - order(b.recommendation) || b.matched - a.matched || a.ruleId.localeCompare(b.ruleId));
}

function order(r: RuleEfficacy["recommendation"]): number {
  return { fix: 0, review: 1, tune: 2, silent: 3, healthy: 4 }[r];
}
