import { getEventField, maxSeverity, type CanonicalEvent, type Severity } from "@bloody/contracts";
import { toEpochMs } from "../util/clock.js";
import { haversineKm, mean, round, stddev } from "../util/math.js";
import type { IndicatorProvider } from "./indicators.js";
import { extractObservables, lookupCandidates } from "./indicators.js";
import { compileDetection, type CompiledDetection } from "./sigma/compiler.js";
import { compileSigma, type CompiledSigmaRule } from "./sigma/sigma.js";
import type { DetectionRule, IndicatorHit, IocDetectionRule, MatchExpression, SequenceConstraint, SequenceDetectionRule, ThresholdDetectionRule } from "./types.js";

/** Output of one evaluator before the engine turns it into a `DetectionMatch`. */
export interface RawMatch {
  events: CanonicalEvent[];
  explanation: string[];
  groupKey?: string;
  indicators?: IndicatorHit[];
  severity?: Severity;
  confidence?: number;
  /** Total events behind the match when `events` was capped. */
  totalEvents?: number;
}

export interface EvaluationContext {
  indicators?: IndicatorProvider | undefined;
  maxEventsPerMatch: number;
}

export interface RuleEvaluator {
  readonly rule: DetectionRule;
  evaluate(event: CanonicalEvent, ctx: EvaluationContext): RawMatch[];
  /** Drop window state older than `nowMs`; returns the number of evicted groups/runs. */
  gc(nowMs: number): number;
  stateSize(): number;
  reset(): void;
}

export class RuleCompileError extends Error {
  constructor(
    readonly ruleId: string,
    readonly errors: string[],
  ) {
    super(`Rule ${ruleId} failed to compile: ${errors.join("; ")}`);
    this.name = "RuleCompileError";
  }
}

export interface EvaluatorOptions {
  strictFields?: boolean;
  /** Bound on concurrent group/entity states per rule (LRU eviction). */
  maxStatesPerRule?: number;
}

export function compileRule(rule: DetectionRule, options: EvaluatorOptions = {}): RuleEvaluator {
  switch (rule.kind) {
    case "sigma": {
      const r = compileSigma(rule.sigma, { fieldMapping: rule.fieldMapping, strictFields: options.strictFields ?? true });
      if (!r.value) throw new RuleCompileError(rule.id, r.errors);
      return new SigmaEvaluator(rule, r.value);
    }
    case "threshold":
      return new ThresholdEvaluator(rule, compileExpression(rule.id, rule.filter, options), options.maxStatesPerRule ?? 100_000);
    case "sequence":
      return new SequenceEvaluator(
        rule,
        rule.steps.map((s) => compileExpression(rule.id, s.filter, options)),
        options.maxStatesPerRule ?? 100_000,
      );
    case "ioc":
      return new IocEvaluator(rule, rule.filter ? compileExpression(rule.id, rule.filter, options) : null);
  }
}

export function compileExpression(ruleId: string, expr: MatchExpression, options: EvaluatorOptions = {}): CompiledDetection {
  const r = compileDetection(expr.detection, expr.condition, { strictFields: options.strictFields ?? true });
  if (!r.compiled) throw new RuleCompileError(ruleId, r.errors);
  return r.compiled;
}

/** String key for group-by / correlation fields; undefined when any field is missing. */
export function fieldKey(event: CanonicalEvent, fields: readonly string[]): string | undefined {
  const parts: string[] = [];
  for (const f of fields) {
    const v = getEventField(event, f);
    if (v === undefined || v === null || v === "") return undefined;
    if (Array.isArray(v)) {
      if (v.length === 0) return undefined;
      parts.push(v.map(String).sort().join(","));
    } else if (typeof v === "object") return undefined;
    else parts.push(String(v).toLowerCase());
  }
  return parts.join("␟");
}

function describeSelections(compiled: CompiledDetection, names: string[]): string[] {
  return names.map((n) => `selection "${n}" matched: ${compiled.selections.get(n)?.description ?? n}`);
}

function cap<T>(items: T[], max: number): T[] {
  return items.length <= max ? items : items.slice(items.length - max);
}

// ─── Sigma ──────────────────────────────────────────────────────────────────

class SigmaEvaluator implements RuleEvaluator {
  constructor(
    readonly rule: DetectionRule,
    private readonly compiled: CompiledSigmaRule,
  ) {}

  evaluate(event: CanonicalEvent): RawMatch[] {
    const r = this.compiled.evaluate(event);
    if (!r.matched) return [];
    return [{ events: [event], explanation: describeSelections(this.compiled.detection, r.matchedSelections) }];
  }
  gc(): number {
    return 0;
  }
  stateSize(): number {
    return 0;
  }
  reset(): void {}
}

// ─── Threshold ──────────────────────────────────────────────────────────────

interface ThresholdEntry {
  t: number;
  event: CanonicalEvent;
  distinct?: string;
}

/**
 * Count matching events per (tenant, organization, group-by values) in a sliding event-time
 * window. Fires when the count (or distinct count) reaches the threshold — and, for
 * `regularity`, when inter-arrival times are periodic (coefficient of variation ≤ max). After
 * firing the group's window is cleared, so a sustained attack fires once per `threshold`
 * new events rather than on every event.
 */
class ThresholdEvaluator implements RuleEvaluator {
  private readonly groups = new Map<string, ThresholdEntry[]>();

  constructor(
    readonly rule: ThresholdDetectionRule,
    private readonly filter: CompiledDetection,
    private readonly maxStates: number,
  ) {}

  evaluate(event: CanonicalEvent, ctx: EvaluationContext): RawMatch[] {
    const f = this.filter.evaluate(event);
    if (!f.matched) return [];
    const gk = fieldKey(event, this.rule.groupBy);
    if (gk === undefined) return [];
    let distinct: string | undefined;
    if (this.rule.distinctField) {
      distinct = fieldKey(event, [this.rule.distinctField]);
      if (distinct === undefined) return [];
    }
    const key = `${event.tenantId}|${event.organizationId}|${gk}`;
    const t = toEpochMs(event.timestamp);
    const entries = this.groups.get(key) ?? [];
    this.groups.delete(key); // re-insert → LRU order
    // ordered insert (tolerates out-of-order arrival)
    let i = entries.length;
    while (i > 0 && entries[i - 1]!.t > t) i--;
    entries.splice(i, 0, { t, event, ...(distinct !== undefined ? { distinct } : {}) });
    const newest = entries[entries.length - 1]!.t;
    const windowMs = this.rule.windowSeconds * 1000;
    while (entries.length > 0 && entries[0]!.t < newest - windowMs) entries.shift();
    const hardCap = Math.max(this.rule.threshold * 4, 1000);
    if (entries.length > hardCap) entries.splice(0, entries.length - hardCap);
    this.groups.set(key, entries);
    this.enforceCap();

    const count = this.rule.distinctField ? new Set(entries.map((e) => e.distinct)).size : entries.length;
    if (count < this.rule.threshold) return [];
    const explanation = [
      this.rule.distinctField
        ? `${count} distinct ${this.rule.distinctField} value(s) for ${this.rule.groupBy.join(", ")} = ${gk.split("␟").join(", ")} within ${this.rule.windowSeconds}s (threshold ${this.rule.threshold})`
        : `${count} matching event(s) for ${this.rule.groupBy.join(", ")} = ${gk.split("␟").join(", ")} within ${this.rule.windowSeconds}s (threshold ${this.rule.threshold})`,
    ];
    if (this.rule.regularity) {
      const gaps: number[] = [];
      for (let j = 1; j < entries.length; j++) gaps.push((entries[j]!.t - entries[j - 1]!.t) / 1000);
      if (gaps.length < 2) return [];
      const m = mean(gaps);
      if (m <= 0 || m < this.rule.regularity.minIntervalSeconds) return [];
      const cv = stddev(gaps) / m;
      if (cv > this.rule.regularity.maxCoefficientOfVariation) return [];
      explanation.push(`Periodic timing: mean interval ${round(m, 1)}s, coefficient of variation ${round(cv, 3)} (≤ ${this.rule.regularity.maxCoefficientOfVariation})`);
    }
    explanation.push(...describeSelections(this.filter, f.matchedSelections));
    this.groups.delete(key);
    return [{ events: cap(entries.map((e) => e.event), ctx.maxEventsPerMatch), totalEvents: entries.length, explanation, groupKey: gk }];
  }

  gc(nowMs: number): number {
    const windowMs = this.rule.windowSeconds * 1000;
    let n = 0;
    for (const [k, entries] of this.groups) {
      const last = entries[entries.length - 1];
      if (!last || last.t < nowMs - windowMs) {
        this.groups.delete(k);
        n++;
      }
    }
    return n;
  }
  stateSize(): number {
    return this.groups.size;
  }
  reset(): void {
    this.groups.clear();
  }
  private enforceCap(): void {
    while (this.groups.size > this.maxStates) {
      const oldest = this.groups.keys().next().value;
      if (oldest === undefined) break;
      this.groups.delete(oldest);
    }
  }
}

// ─── Sequence ───────────────────────────────────────────────────────────────

interface SequenceRun {
  step: number;
  counts: number[];
  events: Array<Array<{ t: number; event: CanonicalEvent }>>;
  startedAt: number;
}

const MAX_RUNS_PER_KEY = 16;

/**
 * Ordered multi-step detection by the same entity (`by` fields) within a window. Each step may
 * require `minCount` events and constraints relative to the previous step's last event
 * (geo-velocity for impossible travel, field differs/equals). Several partial runs per entity
 * are tracked (bounded) so e.g. every successful logon can anchor an impossible-travel check.
 * Events are expected in approximate time order.
 */
class SequenceEvaluator implements RuleEvaluator {
  private readonly runs = new Map<string, SequenceRun[]>();

  constructor(
    readonly rule: SequenceDetectionRule,
    private readonly filters: CompiledDetection[],
    private readonly maxStates: number,
  ) {}

  evaluate(event: CanonicalEvent, ctx: EvaluationContext): RawMatch[] {
    const memo = new Map<number, { matched: boolean; matchedSelections: string[] }>();
    const stepMatch = (i: number) => {
      let r = memo.get(i);
      if (!r) {
        r = this.filters[i]!.evaluate(event);
        memo.set(i, r);
      }
      return r.matched;
    };
    // cheap exit: the event matches no step at all
    if (!this.filters.some((_, i) => stepMatch(i))) return [];
    const by = fieldKey(event, this.rule.by);
    if (by === undefined) return [];
    const key = `${event.tenantId}|${event.organizationId}|${by}`;
    const t = toEpochMs(event.timestamp);
    const windowMs = this.rule.windowSeconds * 1000;
    const steps = this.rule.steps;
    let runs = this.runs.get(key) ?? [];
    this.runs.delete(key);

    // expire / slide
    runs = runs.filter((run) => {
      if (run.step === 0) {
        run.events[0] = run.events[0]!.filter((x) => x.t >= t - windowMs);
        run.counts[0] = run.events[0].length;
        if (run.counts[0] === 0) return false;
        run.startedAt = run.events[0][0]!.t;
        return true;
      }
      return run.startedAt >= t - windowMs;
    });

    let consumedByCollector = false;
    for (const run of runs) {
      const idx = run.step;
      const step = steps[idx]!;
      const prev = idx > 0 ? lastEvent(run, idx - 1) : undefined;
      if (stepMatch(idx) && (idx === 0 || constraintsHold(step.constraints, prev, event))) {
        run.events[idx]!.push({ t, event });
        run.counts[idx]!++;
        if (idx === 0) consumedByCollector = true;
        if (run.counts[idx]! >= step.minCount) {
          if (idx === steps.length - 1) {
            this.runs.delete(key);
            return [this.toMatch(run, by, ctx)];
          }
          run.step++;
        }
      } else if (idx > 0 && steps[idx - 1]!.minCount > 1 && stepMatch(idx - 1)) {
        // keep repeated evidence of the previous counted step (e.g. further failures)
        const bucket = run.events[idx - 1]!;
        bucket.push({ t, event });
        if (bucket.length > ctx.maxEventsPerMatch) bucket.shift();
      }
    }
    if (stepMatch(0) && !consumedByCollector) {
      const fresh: SequenceRun = { step: 0, counts: steps.map(() => 0), events: steps.map(() => []), startedAt: t };
      fresh.events[0]!.push({ t, event });
      fresh.counts[0] = 1;
      if (steps[0]!.minCount <= 1) fresh.step = 1;
      runs.push(fresh);
    }
    if (runs.length > MAX_RUNS_PER_KEY) runs = runs.slice(runs.length - MAX_RUNS_PER_KEY);
    if (runs.length > 0) this.runs.set(key, runs);
    while (this.runs.size > this.maxStates) {
      const oldest = this.runs.keys().next().value;
      if (oldest === undefined) break;
      this.runs.delete(oldest);
    }
    return [];
  }

  private toMatch(run: SequenceRun, by: string, ctx: EvaluationContext): RawMatch {
    const all = run.events.flat().sort((a, b) => a.t - b.t);
    const explanation = this.rule.steps.map((s, i) => {
      const evs = run.events[i]!;
      const first = evs[0];
      const last = evs[evs.length - 1];
      return `step ${i + 1} "${s.name}": ${run.counts[i]} event(s)${first && last ? ` between ${new Date(first.t).toISOString()} and ${new Date(last.t).toISOString()}` : ""}`;
    });
    const span = all.length > 1 ? (all[all.length - 1]!.t - all[0]!.t) / 1000 : 0;
    explanation.unshift(`Sequence completed by ${this.rule.by.join(", ")} = ${by.split("␟").join(", ")} in ${round(span, 1)}s (window ${this.rule.windowSeconds}s)`);
    const geo = this.rule.steps.flatMap((s) => s.constraints).find((c) => c.type === "geo_velocity");
    if (geo) {
      for (let i = 1; i < this.rule.steps.length; i++) {
        const a = lastEvent(run, i - 1);
        const b = run.events[i]![0]?.event;
        if (a && b) {
          const d = geoDelta(a, b);
          if (d) explanation.push(`Travel ${d.from} → ${d.to}: ${d.km !== null ? `${round(d.km, 0)} km in ${round(d.hours * 60, 1)} min (${d.kmh === Infinity ? "∞" : round(d.kmh ?? 0, 0)} km/h)` : "country change"}`);
        }
      }
    }
    return { events: cap(all.map((x) => x.event), ctx.maxEventsPerMatch), totalEvents: all.length, explanation, groupKey: by };
  }

  gc(nowMs: number): number {
    const windowMs = this.rule.windowSeconds * 1000;
    let n = 0;
    for (const [k, runs] of this.runs) {
      const alive = runs.filter((r) => r.startedAt >= nowMs - windowMs || (r.step === 0 && (r.events[0]!.at(-1)?.t ?? 0) >= nowMs - windowMs));
      n += runs.length - alive.length;
      if (alive.length === 0) this.runs.delete(k);
      else this.runs.set(k, alive);
    }
    return n;
  }
  stateSize(): number {
    let n = 0;
    for (const r of this.runs.values()) n += r.length;
    return n;
  }
  reset(): void {
    this.runs.clear();
  }
}

function lastEvent(run: SequenceRun, step: number): CanonicalEvent | undefined {
  const evs = run.events[step];
  return evs && evs.length > 0 ? evs[evs.length - 1]!.event : undefined;
}

interface GeoDelta {
  from: string;
  to: string;
  km: number | null;
  hours: number;
  kmh: number | null;
  countryChanged: boolean;
}

function geoDelta(a: CanonicalEvent, b: CanonicalEvent): GeoDelta | null {
  const ga = a.identity?.geo;
  const gb = b.identity?.geo;
  if (!ga || !gb) return null;
  const hours = Math.abs(toEpochMs(b.timestamp) - toEpochMs(a.timestamp)) / 3_600_000;
  const label = (g: NonNullable<typeof ga>) => [g.city, g.country].filter(Boolean).join(", ") || "unknown";
  const countryChanged = !!ga.country && !!gb.country && ga.country.toLowerCase() !== gb.country.toLowerCase();
  if (ga.lat !== undefined && ga.lon !== undefined && gb.lat !== undefined && gb.lon !== undefined) {
    const km = haversineKm(ga.lat, ga.lon, gb.lat, gb.lon);
    return { from: label(ga), to: label(gb), km, hours, kmh: hours > 0 ? km / hours : km > 0 ? Infinity : 0, countryChanged };
  }
  return { from: label(ga), to: label(gb), km: null, hours, kmh: null, countryChanged };
}

/** All constraints of a step must hold between the previous step's last event and `cur`. */
export function constraintsHold(constraints: readonly SequenceConstraint[], prev: CanonicalEvent | undefined, cur: CanonicalEvent): boolean {
  for (const c of constraints) {
    if (!prev) return false;
    switch (c.type) {
      case "geo_velocity": {
        const d = geoDelta(prev, cur);
        if (!d) return false;
        if (d.km !== null) {
          if (d.km < c.minDistanceKm) return false;
          if ((d.kmh ?? 0) <= c.maxKmh) return false;
        } else if (!(c.fallbackCountryChange && d.countryChanged)) return false;
        break;
      }
      case "field_differs": {
        const a = getEventField(prev, c.field);
        const b = getEventField(cur, c.field);
        if (a === undefined || b === undefined || String(a).toLowerCase() === String(b).toLowerCase()) return false;
        break;
      }
      case "field_equals": {
        const a = getEventField(prev, c.field);
        const b = getEventField(cur, c.field);
        if (a === undefined || b === undefined || String(a).toLowerCase() !== String(b).toLowerCase()) return false;
        break;
      }
    }
  }
  return true;
}

// ─── IOC ────────────────────────────────────────────────────────────────────

class IocEvaluator implements RuleEvaluator {
  constructor(
    readonly rule: IocDetectionRule,
    private readonly filter: CompiledDetection | null,
  ) {}

  evaluate(event: CanonicalEvent, ctx: EvaluationContext): RawMatch[] {
    if (!ctx.indicators) return [];
    if (this.filter && !this.filter.evaluate(event).matched) return [];
    const types = this.rule.indicatorTypes ? new Set(this.rule.indicatorTypes) : null;
    const hits: IndicatorHit[] = [];
    const seen = new Set<string>();
    for (const o of extractObservables(event, { ignoreNonPublicIps: this.rule.ignoreNonPublicIps })) {
      if (types && !types.has(o.type)) continue;
      for (const candidate of lookupCandidates(o, this.rule.matchSubdomains)) {
        for (const ind of ctx.indicators.lookup(event.tenantId, event.organizationId, o.type, candidate)) {
          if (ind.confidence < this.rule.minConfidence) continue;
          const k = `${ind.type}:${ind.value}:${ind.source}`;
          if (seen.has(k)) continue;
          seen.add(k);
          hits.push({
            ...(ind.id ? { indicatorId: ind.id } : {}),
            type: ind.type,
            value: ind.value,
            observed: o.value,
            field: o.field,
            source: ind.source,
            confidence: ind.confidence,
            severity: ind.severity,
            threatActor: ind.threatActor ?? null,
            malware: ind.malware ?? null,
            campaign: ind.campaign ?? null,
          });
        }
      }
    }
    if (hits.length === 0) return [];
    const best = hits.reduce((a, b) => (b.confidence > a.confidence ? b : a));
    const severity = hits.reduce<Severity>((s, h) => maxSeverity(s, h.severity), "info");
    return [
      {
        events: [event],
        indicators: hits,
        severity,
        confidence: round((best.confidence / 100) * this.rule.confidence, 4),
        explanation: hits.map(
          (h) => `${h.field} ${h.observed} matched ${h.type} indicator ${h.value} from ${h.source} (confidence ${h.confidence}, ${h.severity})${h.threatActor || h.malware || h.campaign ? ` — ${[h.threatActor, h.malware, h.campaign].filter(Boolean).join(" / ")}` : ""}`,
        ),
      },
    ];
  }
  gc(): number {
    return 0;
  }
  stateSize(): number {
    return 0;
  }
  reset(): void {}
}
