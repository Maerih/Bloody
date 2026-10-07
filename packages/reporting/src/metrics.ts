import { SEVERITY_RANK, type Severity } from "@bloody/contracts";
import type { DailyCount, IncidentFact } from "./datasource.js";
import type { Kpi, KpiDelta, Sentiment, ValueUnit } from "./model.js";

/** Pure metric helpers used by every builder. */

export const SEVERITIES_DESC: Severity[] = ["critical", "high", "medium", "low", "info"];

export function emptySeverityCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function minutesBetween(from: string | Date, to: string | Date): number {
  const a = from instanceof Date ? from.getTime() : Date.parse(from);
  const b = to instanceof Date ? to.getTime() : Date.parse(to);
  return (b - a) / 60_000;
}

export interface Distribution {
  n: number;
  mean: number | null;
  median: number | null;
  p90: number | null;
}

export function distribution(values: readonly number[]): Distribution {
  const v = values.filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  if (v.length === 0) return { n: 0, mean: null, median: null, p90: null };
  const q = (p: number): number => {
    const pos = (v.length - 1) * p;
    const lo = Math.floor(pos);
    const hi = Math.ceil(pos);
    return v[lo]! + (v[hi]! - v[lo]!) * (pos - lo);
  };
  return { n: v.length, mean: v.reduce((s, x) => s + x, 0) / v.length, median: q(0.5), p90: q(0.9) };
}

export function inWindow(iso: string | null | undefined, from: Date, to: Date): boolean {
  if (!iso) return false;
  const t = Date.parse(iso);
  return t >= from.getTime() && t < to.getTime();
}

export interface IncidentTimings {
  /** Detection: first malicious activity → detectedAt. */
  mttd: Distribution;
  /** Acknowledge: detectedAt → acknowledgedAt. */
  mtta: Distribution;
  /** Contain: detectedAt → containedAt. */
  mttc: Distribution;
  /** Resolve: detectedAt → closedAt (incidents closed in the window). */
  mttr: Distribution;
}

/** Response-time distributions for incidents of a period (minutes). */
export function incidentTimings(incidents: readonly IncidentFact[], from: Date, to: Date): IncidentTimings {
  const detected = incidents.filter((i) => inWindow(i.detectedAt, from, to));
  const mttd = detected.filter((i) => i.firstActivityAt && Date.parse(i.firstActivityAt) <= Date.parse(i.detectedAt)).map((i) => minutesBetween(i.firstActivityAt!, i.detectedAt));
  const mtta = detected.filter((i) => i.acknowledgedAt).map((i) => Math.max(0, minutesBetween(i.detectedAt, i.acknowledgedAt!)));
  const mttc = detected.filter((i) => i.containedAt).map((i) => Math.max(0, minutesBetween(i.detectedAt, i.containedAt!)));
  const mttr = incidents.filter((i) => inWindow(i.closedAt, from, to)).map((i) => Math.max(0, minutesBetween(i.detectedAt, i.closedAt!)));
  return { mttd: distribution(mttd), mtta: distribution(mtta), mttc: distribution(mttc), mttr: distribution(mttr) };
}

export function countBySeverity<T extends { severity: Severity }>(items: readonly T[]): Record<Severity, number> {
  const out = emptySeverityCounts();
  for (const i of items) out[i.severity] += 1;
  return out;
}

export function bySeverityDesc<T extends { severity: Severity }>(a: T, b: T): number {
  return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
}

/** Change vs previous period. `betterWhen` decides whether "up" is good news. */
export function computeDelta(current: number | null, previous: number | null, betterWhen: "higher" | "lower" | "neutral"): KpiDelta | null {
  if (current === null || previous === null || !Number.isFinite(current) || !Number.isFinite(previous)) return null;
  const absolute = current - previous;
  const percent = previous === 0 ? null : (absolute / Math.abs(previous)) * 100;
  const flat = Math.abs(absolute) < 1e-9 || (percent !== null && Math.abs(percent) < 0.5);
  const direction: KpiDelta["direction"] = flat ? "flat" : absolute > 0 ? "up" : "down";
  let sentiment: Sentiment = "neutral";
  if (!flat && betterWhen !== "neutral") sentiment = (direction === "up") === (betterWhen === "higher") ? "good" : "bad";
  return { previous, absolute, percent, direction, sentiment };
}

export interface KpiInput {
  key: string;
  label: string;
  value: number | null;
  unit: ValueUnit;
  previous?: number | null;
  betterWhen?: "higher" | "lower" | "neutral";
  target?: number | null;
  /** Thresholds → status. For higher-is-better: good ≥ good, warn ≥ warn, else bad. */
  thresholds?: { good: number; warn: number };
  explanation: string;
  currency?: string;
}

export function kpi(input: KpiInput): Kpi {
  const betterWhen = input.betterWhen ?? "neutral";
  let status: Kpi["status"] = null;
  if (input.thresholds && input.value !== null && Number.isFinite(input.value)) {
    const { good, warn } = input.thresholds;
    if (betterWhen === "lower") status = input.value <= good ? "good" : input.value <= warn ? "warn" : "bad";
    else status = input.value >= good ? "good" : input.value >= warn ? "warn" : "bad";
  }
  return {
    key: input.key,
    label: input.label,
    value: input.value === null || !Number.isFinite(input.value) ? null : input.value,
    unit: input.unit,
    ...(input.currency ? { currency: input.currency } : {}),
    delta: input.previous === undefined ? null : computeDelta(input.value, input.previous ?? null, betterWhen),
    target: input.target ?? null,
    status,
    explanation: input.explanation,
  };
}

export function percent(numerator: number, denominator: number): number | null {
  return denominator > 0 ? (numerator / denominator) * 100 : null;
}

/** Coefficient of variation (stddev / mean) — 0 = perfectly balanced workload. */
export function coefficientOfVariation(values: readonly number[]): number | null {
  if (values.length < 2) return null;
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  if (mean === 0) return null;
  const variance = values.reduce((s, v) => s + (v - mean) ** 2, 0) / values.length;
  return Math.sqrt(variance) / mean;
}

export type Granularity = "day" | "week" | "month";

export function granularityFor(days: number): Granularity {
  if (days <= 45) return "day";
  if (days <= 190) return "week";
  return "month";
}

export interface TimeBuckets {
  granularity: Granularity;
  keys: string[];
  labels: string[];
  indexOf(date: string | Date): number;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function utcDay(t: number): number {
  return Math.floor(t / 86_400_000) * 86_400_000;
}

/** Calendar buckets (UTC) covering [from, to). Weeks start on Monday. */
export function timeBuckets(from: Date, to: Date, granularity: Granularity = granularityFor((to.getTime() - from.getTime()) / 86_400_000)): TimeBuckets {
  const keys: string[] = [];
  const labels: string[] = [];
  const startOf = (t: number): number => {
    const d = new Date(utcDay(t));
    if (granularity === "week") return d.getTime() - ((d.getUTCDay() + 6) % 7) * 86_400_000;
    if (granularity === "month") return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
    return d.getTime();
  };
  const next = (t: number): number => {
    const d = new Date(t);
    if (granularity === "week") return t + 7 * 86_400_000;
    if (granularity === "month") return Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1);
    return t + 86_400_000;
  };
  for (let t = startOf(from.getTime()); t < to.getTime() && keys.length < 400; t = next(t)) {
    const d = new Date(t);
    keys.push(d.toISOString().slice(0, 10));
    const day = `${d.getUTCDate().toString().padStart(2, "0")} ${MONTHS[d.getUTCMonth()]}`;
    labels.push(granularity === "month" ? `${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}` : granularity === "week" ? `Wk ${day}` : day);
  }
  const starts = keys.map((k) => Date.parse(`${k}T00:00:00Z`));
  return {
    granularity,
    keys,
    labels,
    indexOf(date: string | Date): number {
      const t = date instanceof Date ? date.getTime() : Date.parse(date.length === 10 ? `${date}T00:00:00Z` : date);
      if (!Number.isFinite(t)) return -1;
      for (let i = starts.length - 1; i >= 0; i--) if (t >= starts[i]!) return t < to.getTime() ? i : -1;
      return -1;
    },
  };
}

/** Re-bucket daily counts to the period's granularity. */
export function bucketDaily(daily: readonly DailyCount[], buckets: TimeBuckets): number[] {
  const out = new Array<number>(buckets.keys.length).fill(0);
  for (const d of daily) {
    const i = buckets.indexOf(d.date);
    if (i >= 0) out[i]! += d.count;
  }
  return out;
}

/** Count items per bucket (e.g. incidents by detectedAt) split by severity. */
export function bucketBySeverity<T extends { severity: Severity }>(items: readonly T[], dateOf: (t: T) => string, buckets: TimeBuckets): Record<Severity, number[]> {
  const out = Object.fromEntries(SEVERITIES_DESC.map((s) => [s, new Array<number>(buckets.keys.length).fill(0)])) as Record<Severity, number[]>;
  for (const it of items) {
    const i = buckets.indexOf(dateOf(it));
    if (i >= 0) out[it.severity][i]! += 1;
  }
  return out;
}

export interface TechniqueCount {
  id: string;
  name: string | null;
  tactic: string | null;
  count: number;
}

/** Merge ATT&CK techniques from incidents and alert statistics, most frequent first. */
export function topTechniques(incidents: readonly IncidentFact[], alertTechniques: readonly { id: string; name?: string | null; tactic?: string | null; count: number }[], limit: number): TechniqueCount[] {
  const map = new Map<string, TechniqueCount>();
  for (const inc of incidents) {
    for (const t of inc.attack) {
      const cur = map.get(t.id) ?? { id: t.id, name: t.name ?? null, tactic: t.tactic ?? null, count: 0 };
      cur.count += 1;
      cur.name ??= t.name ?? null;
      cur.tactic ??= t.tactic ?? null;
      map.set(t.id, cur);
    }
  }
  for (const t of alertTechniques) {
    const cur = map.get(t.id) ?? { id: t.id, name: t.name ?? null, tactic: t.tactic ?? null, count: 0 };
    cur.count += t.count;
    cur.name ??= t.name ?? null;
    cur.tactic ??= t.tactic ?? null;
    map.set(t.id, cur);
  }
  return [...map.values()].sort((a, b) => b.count - a.count || a.id.localeCompare(b.id)).slice(0, limit);
}

export function sumBy<T>(items: readonly T[], f: (t: T) => number): number {
  return items.reduce((s, x) => s + (Number.isFinite(f(x)) ? f(x) : 0), 0);
}

export function round(value: number | null, digits = 1): number | null {
  if (value === null || !Number.isFinite(value)) return null;
  const p = 10 ** digits;
  return Math.round(value * p) / p;
}
