import { severityFromScore, type RiskAssessment, type RiskFactor } from "@bloody/contracts";
import { clamp01, pct, round } from "../util/math.js";

/**
 * Bloody explainable risk model — the math shared by every score (asset, identity, incident,
 * vulnerability, exposure, attack path).
 *
 * ── Inputs ──────────────────────────────────────────────────────────────────────────────
 *  Likelihood factors  i : value vᵢ ∈ [0,1], weight wᵢ ∈ [0,1]   ("how likely is compromise")
 *  Impact factors      k : value vₖ ∈ [0,1], weight wₖ ∈ [0,1]   ("how bad would it be")
 *  Reductions          j : value sⱼ ∈ [0,1], weight cⱼ ∈ [0,1]   (compensating controls, path
 *                                                                complexity — multiplicative)
 *  A weight is the probability the signal alone contributes when fully present (v = 1);
 *  pᵢ = wᵢ·vᵢ (capped at 0.995).
 *
 * ── Combination (not a sum of alerts) ───────────────────────────────────────────────────
 *  Evidence is combined with a noisy-OR, i.e. additively in *hazard* space:
 *      hᵢ = −ln(1 − pᵢ)         H = Σ hᵢ (likelihood)      G = Σ hₖ (impact)
 *      L₀ = 1 − e^(−H)           I = 1 − e^(−G)
 *  so independent signals reinforce each other but saturate — ten weak signals can never
 *  outweigh one strong one by volume alone. Compensating controls scale likelihood:
 *      L = L₀ · Πⱼ (1 − cⱼ·sⱼ)
 *  Raw risk is the product R = L × I ∈ [0,1].
 *
 * ── Calibration curve ───────────────────────────────────────────────────────────────────
 *  score = 100 · f(R),  f(r) = (σ(k(r − m)) − σ(−k·m)) / (σ(k(1 − m)) − σ(−k·m)),  σ = logistic
 *  with steepness k = 6 and midpoint m = 0.24. f is monotone with f(0) = 0 and f(1) = 1; the
 *  S-shape keeps weak evidence low (R = 0.09 → 12, "info") and saturates strong evidence
 *  (R = 0.64 → 90, "critical"). Anchors: (L, I) = (0.5, 0.5) → 41 medium,
 *  (0.7, 0.7) → 78 high, (0.8, 0.8) → 90 critical.
 *
 * ── Attribution (contributions sum exactly to the score) ────────────────────────────────
 *  1. S₀ = 100·f(L₀·I) is the score without reductions; S = 100·f(L·I) the final score.
 *  2. Positive factors share S₀ in proportion to their hazard (the additive unit of the
 *     noisy-OR):  φᵢ = S₀ · hᵢ / (H + G)   (likelihood and impact factors alike).
 *  3. Reductions share the (negative) difference S − S₀ in proportion to their log-reduction
 *     rⱼ = −ln(1 − cⱼ·sⱼ):   φⱼ = (S − S₀) · rⱼ / Σ r.
 *  Hence Σφ = S₀ + (S − S₀) = S. Contributions are rounded to 2 decimals and the rounding
 *  residual is assigned to the largest-magnitude factor so the displayed numbers add up to
 *  the displayed (1-decimal) score exactly.
 */
export const RISK_MODEL_VERSION = "bloody-risk/1.0.0";

export interface RiskCurve {
  steepness: number;
  midpoint: number;
}

export const DEFAULT_RISK_CURVE: RiskCurve = { steepness: 6, midpoint: 0.24 };

export type FactorGroup = "likelihood" | "impact" | "control";

export interface FactorInput {
  key: string;
  label: string;
  /** Normalized signal in [0, 1]. */
  value: number;
  /** Likelihood/impact: max probability contributed. Control: max fractional reduction. Both in [0, 1]. */
  weight: number;
  explanation: string;
}

/** Contract `RiskFactor` plus the model group it belongs to. Control factors carry a negative weight. */
export interface ExplainedRiskFactor extends RiskFactor {
  group: FactorGroup;
}

export interface ExplainedRiskAssessment extends RiskAssessment {
  factors: ExplainedRiskFactor[];
  /** Score before compensating controls / structural reductions (for "what if controls failed"). */
  inherentScore: number;
}

export interface RiskModelInput {
  /** Subject used in the summary sentence, e.g. "Asset db-prod-01". */
  subject: string;
  likelihood: FactorInput[];
  impact: FactorInput[];
  controls?: FactorInput[];
  curve?: RiskCurve;
  modelVersion?: string;
}

const MAX_P = 0.995;

const sigmoid = (x: number) => 1 / (1 + Math.exp(-x));

/** The calibration curve f: [0,1] → [0,1]. */
export function calibrate(r: number, curve: RiskCurve = DEFAULT_RISK_CURVE): number {
  const { steepness: k, midpoint: m } = curve;
  const lo = sigmoid(-k * m);
  const hi = sigmoid(k * (1 - m));
  return clamp01((sigmoid(k * (clamp01(r) - m)) - lo) / (hi - lo));
}

function probability(f: FactorInput): number {
  return Math.min(clamp01(f.weight) * clamp01(f.value), MAX_P);
}

function hazard(p: number): number {
  return -Math.log(1 - p);
}

export function computeRisk(input: RiskModelInput): ExplainedRiskAssessment {
  const curve = input.curve ?? DEFAULT_RISK_CURVE;
  const controls = input.controls ?? [];
  const lh = input.likelihood.map((f) => hazard(probability(f)));
  const ih = input.impact.map((f) => hazard(probability(f)));
  const cr = controls.map((f) => hazard(probability(f)));
  const H = lh.reduce((a, b) => a + b, 0);
  const G = ih.reduce((a, b) => a + b, 0);
  const R = cr.reduce((a, b) => a + b, 0);

  const L0 = 1 - Math.exp(-H);
  const I = 1 - Math.exp(-G);
  const L = L0 * Math.exp(-R);
  const S0 = 100 * calibrate(L0 * I, curve);
  const S = 100 * calibrate(L * I, curve);
  const score = round(S, 1);

  const raw: Array<{ f: FactorInput; group: FactorGroup; contribution: number }> = [];
  input.likelihood.forEach((f, i) => raw.push({ f, group: "likelihood", contribution: H + G > 0 ? (S0 * (lh[i] ?? 0)) / (H + G) : 0 }));
  input.impact.forEach((f, i) => raw.push({ f, group: "impact", contribution: H + G > 0 ? (S0 * (ih[i] ?? 0)) / (H + G) : 0 }));
  controls.forEach((f, i) => raw.push({ f, group: "control", contribution: R > 0 ? ((S - S0) * (cr[i] ?? 0)) / R : 0 }));

  const factors: ExplainedRiskFactor[] = raw.map(({ f, group, contribution }) => ({
    key: f.key,
    label: f.label,
    value: round(clamp01(f.value), 4),
    weight: group === "control" ? -round(clamp01(f.weight), 4) : round(clamp01(f.weight), 4),
    contribution: round(contribution, 2),
    explanation: f.explanation,
    group,
  }));
  reconcile(factors, raw.map((r) => r.contribution), score);
  factors.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution) || a.key.localeCompare(b.key));

  return {
    score,
    severity: severityFromScore(score),
    likelihood: round(L, 4),
    impact: round(I, 4),
    factors,
    summary: summarize(input.subject, score, L, I, factors),
    modelVersion: input.modelVersion ?? RISK_MODEL_VERSION,
    inherentScore: round(S0, 1),
  };
}

/** Push the rounding residual into the largest-magnitude factor so Σ contributions = score. */
function reconcile(factors: ExplainedRiskFactor[], rawContributions: number[], score: number): void {
  if (factors.length === 0) return;
  const total = factors.reduce((a, f) => a + f.contribution, 0);
  const residual = round(score - total, 2);
  if (residual === 0) return;
  let idx = 0;
  rawContributions.forEach((c, i) => {
    if (Math.abs(c) > Math.abs(rawContributions[idx] ?? 0)) idx = i;
  });
  const target = factors[idx]!;
  target.contribution = round(target.contribution + residual, 2);
}

function summarize(subject: string, score: number, L: number, I: number, factors: ExplainedRiskFactor[]): string {
  const severity = severityFromScore(score);
  if (score === 0 && factors.every((f) => f.contribution === 0)) return `${subject}: no risk signals present (0/100, info).`;
  const top = (group: FactorGroup) =>
    factors
      .filter((f) => f.group === group && f.contribution > 0.05)
      .slice(0, 2)
      .map((f) => f.label.toLowerCase());
  const likely = top("likelihood");
  const impact = top("impact");
  const reductions = factors.filter((f) => f.group === "control" && f.contribution < -0.05);
  const reducedBy = round(-reductions.reduce((a, f) => a + f.contribution, 0), 1);
  const parts = [`${subject} risk ${score}/100 (${severity})`];
  parts.push(`likelihood ${pct(L)}${likely.length ? ` driven by ${likely.join(" and ")}` : ""}`);
  parts.push(`impact ${pct(I)}${impact.length ? ` driven by ${impact.join(" and ")}` : ""}`);
  let sentence = `${parts[0]}: ${parts.slice(1).join("; ")}`;
  if (reductions.length > 0) sentence += `; reduced by ${reducedBy} points through ${reductions.slice(0, 3).map((f) => f.label.toLowerCase()).join(", ")}`;
  return `${sentence}.`;
}

/** Ordered factors of one group, strongest first (helpers for UIs and narratives). */
export function factorsOf(assessment: ExplainedRiskAssessment, group: FactorGroup): ExplainedRiskFactor[] {
  return assessment.factors.filter((f) => f.group === group);
}
