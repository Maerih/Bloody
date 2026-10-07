import { maxSeverity, SEVERITY_RANK, type CanonicalEvent, type Severity } from "@bloody/contracts";
import { ASSET_NODE_KINDS, extractEntities, type EntityRef } from "../entities/keys.js";
import { nullSink, safeSink, type EngineEventSink } from "../notifications.js";
import { systemClock, toEpochMs, toIso, type Clock } from "../util/clock.js";
import { stableId } from "../util/uuid.js";
import { compileRule, RuleCompileError, type EvaluationContext, type RawMatch, type RuleEvaluator } from "./evaluators.js";
import type { IndicatorProvider } from "./indicators.js";
import type { SuppressionStore } from "./suppression.js";
import { DetectionRuleSchema, type DetectionMatch, type DetectionRule, type DetectionRuleInput } from "./types.js";

export interface DetectionEngineOptions {
  rules?: ReadonlyArray<DetectionRuleInput | DetectionRule>;
  clock?: Clock;
  indicators?: IndicatorProvider;
  suppressions?: SuppressionStore;
  sink?: EngineEventSink;
  /** Events kept on one match (newest kept; default 50). */
  maxEventsPerMatch?: number;
  /** Concurrent window states per rule before LRU eviction (default 100 000). */
  maxStatesPerRule?: number;
  /** Reject rules referencing unmapped Sigma fields (default true). */
  strictFields?: boolean;
}

export interface RuleMetrics {
  ruleId: string;
  name: string;
  version: number;
  kind: DetectionRule["kind"];
  enabled: boolean;
  evaluated: number;
  matched: number;
  suppressed: number;
  cooledDown: number;
  errors: number;
  lastMatchAt: string | null;
  lastError: string | null;
  activeStates: number;
}

export interface LoadResult {
  loaded: string[];
  rejected: Array<{ ruleId: string; errors: string[] }>;
}

interface Slot {
  rule: DetectionRule;
  evaluator: RuleEvaluator;
  metrics: Omit<RuleMetrics, "activeStates" | "ruleId" | "name" | "version" | "kind" | "enabled">;
}

/**
 * Streaming detection engine. Feed canonical events (approximately time-ordered) through
 * `process`; it evaluates every enabled, in-scope rule and returns `DetectionMatch`es after
 * cooldown and false-positive suppression. Stateful windows are partitioned by tenant and
 * organization — state can never mix customers. A failing rule is isolated (counted, reported
 * via the sink) and never breaks the pipeline.
 */
export class DetectionEngine {
  private readonly slots = new Map<string, Slot>();
  private readonly cooldowns = new Map<string, number>();
  private readonly clock: Clock;
  private readonly sink: EngineEventSink;
  private indicators: IndicatorProvider | undefined;
  private readonly suppressions: SuppressionStore | undefined;
  private readonly maxEventsPerMatch: number;
  private readonly maxStatesPerRule: number;
  private readonly strictFields: boolean;

  constructor(options: DetectionEngineOptions = {}) {
    this.clock = options.clock ?? systemClock;
    this.sink = safeSink(options.sink ?? nullSink);
    this.indicators = options.indicators;
    this.suppressions = options.suppressions;
    this.maxEventsPerMatch = Math.max(1, options.maxEventsPerMatch ?? 50);
    this.maxStatesPerRule = options.maxStatesPerRule ?? 100_000;
    this.strictFields = options.strictFields ?? true;
    if (options.rules) {
      const r = this.loadRules(options.rules);
      if (r.rejected.length > 0) throw new RuleCompileError(r.rejected.map((x) => x.ruleId).join(","), r.rejected.flatMap((x) => x.errors.map((e) => `${x.ruleId}: ${e}`)));
    }
  }

  /** Replace the active rule set. Invalid rules are rejected (reported), valid ones loaded. */
  loadRules(rules: ReadonlyArray<DetectionRuleInput | DetectionRule>): LoadResult {
    const loaded: string[] = [];
    const rejected: LoadResult["rejected"] = [];
    const next = new Map<string, Slot>();
    for (const input of rules) {
      const r = this.prepare(input);
      if ("errors" in r) {
        rejected.push(r);
        continue;
      }
      if (next.has(r.rule.id)) {
        rejected.push({ ruleId: r.rule.id, errors: ["duplicate rule id in rule set"] });
        continue;
      }
      // keep state & metrics when the same version is reloaded
      const prev = this.slots.get(r.rule.id);
      next.set(r.rule.id, prev && prev.rule.version === r.rule.version && prev.rule.kind === r.rule.kind ? { ...prev, rule: r.rule } : r);
      loaded.push(r.rule.id);
    }
    this.slots.clear();
    for (const [k, v] of next) this.slots.set(k, v);
    return { loaded, rejected };
  }

  /** Add or replace one rule. A new version starts with fresh window state. */
  upsertRule(input: DetectionRuleInput | DetectionRule): { ok: true; rule: DetectionRule } | { ok: false; errors: string[] } {
    const r = this.prepare(input);
    if ("errors" in r) return { ok: false, errors: r.errors };
    const prev = this.slots.get(r.rule.id);
    this.slots.set(r.rule.id, prev && prev.rule.version === r.rule.version && prev.rule.kind === r.rule.kind ? { ...prev, rule: r.rule } : r);
    return { ok: true, rule: r.rule };
  }

  removeRule(ruleId: string): boolean {
    return this.slots.delete(ruleId);
  }

  rules(): DetectionRule[] {
    return [...this.slots.values()].map((s) => s.rule);
  }

  setIndicatorProvider(provider: IndicatorProvider | undefined): void {
    this.indicators = provider;
  }

  process(event: CanonicalEvent): DetectionMatch[] {
    const out: DetectionMatch[] = [];
    const ctx: EvaluationContext = { indicators: this.indicators, maxEventsPerMatch: this.maxEventsPerMatch };
    for (const slot of this.slots.values()) {
      const rule = slot.rule;
      if (!rule.enabled || !inScope(rule, event)) continue;
      slot.metrics.evaluated++;
      let raws: RawMatch[];
      try {
        raws = slot.evaluator.evaluate(event, ctx);
      } catch (err) {
        slot.metrics.errors++;
        slot.metrics.lastError = err instanceof Error ? err.message : String(err);
        this.sink.emit({ type: "detection.rule_error", tenantId: event.tenantId, organizationId: event.organizationId, at: toIso(this.clock.now()), ruleId: rule.id, error: slot.metrics.lastError });
        continue;
      }
      for (const raw of raws) {
        const match = this.toMatch(rule, event, raw);
        if (rule.cooldownSeconds > 0) {
          const ck = `${rule.id}|${match.tenantId}|${match.organizationId}|${primaryKey(match)}`;
          const last = this.cooldowns.get(ck);
          const at = toEpochMs(match.lastSeenAt);
          if (last !== undefined && at - last < rule.cooldownSeconds * 1000 && at >= last) {
            slot.metrics.cooledDown++;
            continue;
          }
          this.cooldowns.set(ck, at);
        }
        const suppression = this.suppressions?.find(match, this.clock.now()) ?? null;
        if (suppression) {
          slot.metrics.suppressed++;
          this.sink.emit({ type: "detection.suppressed", tenantId: match.tenantId, organizationId: match.organizationId, at: match.detectedAt, matchId: match.id, ruleId: rule.id, suppressionId: suppression.id, reason: suppression.reason });
          continue;
        }
        slot.metrics.matched++;
        slot.metrics.lastMatchAt = match.detectedAt;
        out.push(match);
        const labels = match.entities.filter((e) => ASSET_NODE_KINDS.includes(e.kind) || e.kind === "user" || e.kind === "identity").map((e) => e.label);
        this.sink.emit({ type: "detection.matched", tenantId: match.tenantId, organizationId: match.organizationId, at: match.detectedAt, matchId: match.id, ruleId: rule.id, ruleName: rule.name, severity: match.severity, confidence: match.confidence, entityLabels: labels });
        if (match.indicators && match.indicators.length > 0) {
          this.sink.emit({
            type: "indicator.matched",
            tenantId: match.tenantId,
            organizationId: match.organizationId,
            at: match.detectedAt,
            matchId: match.id,
            indicators: match.indicators.map((h) => ({ type: h.type, value: h.value, source: h.source, confidence: h.confidence, severity: h.severity })),
            entityLabels: labels,
          });
        }
      }
    }
    return out;
  }

  /** Process a batch in event-time order. */
  processBatch(events: readonly CanonicalEvent[]): DetectionMatch[] {
    const ordered = [...events].sort((a, b) => toEpochMs(a.timestamp) - toEpochMs(b.timestamp));
    return ordered.flatMap((e) => this.process(e));
  }

  /** Evict window state and cooldowns older than the clock allows. Returns evicted count. */
  gc(): number {
    const now = this.clock.now();
    let n = 0;
    for (const s of this.slots.values()) n += s.evaluator.gc(now);
    for (const [k, at] of this.cooldowns) {
      const ruleId = k.split("|")[0]!;
      const cd = (this.slots.get(ruleId)?.rule.cooldownSeconds ?? 0) * 1000;
      if (now - at >= cd) {
        this.cooldowns.delete(k);
        n++;
      }
    }
    return n;
  }

  resetState(): void {
    for (const s of this.slots.values()) s.evaluator.reset();
    this.cooldowns.clear();
  }

  metrics(): RuleMetrics[] {
    return [...this.slots.values()]
      .map((s) => ({ ruleId: s.rule.id, name: s.rule.name, version: s.rule.version, kind: s.rule.kind, enabled: s.rule.enabled, ...s.metrics, activeStates: s.evaluator.stateSize() }))
      .sort((a, b) => b.matched - a.matched || a.ruleId.localeCompare(b.ruleId));
  }

  private prepare(input: DetectionRuleInput | DetectionRule): Slot | { ruleId: string; errors: string[] } {
    const parsed = DetectionRuleSchema.safeParse(input);
    const ruleId = typeof (input as { id?: unknown }).id === "string" ? (input as { id: string }).id : "(unknown)";
    if (!parsed.success) return { ruleId, errors: parsed.error.issues.map((i) => `${i.path.join(".") || "rule"}: ${i.message}`) };
    try {
      const evaluator = compileRule(parsed.data, { strictFields: this.strictFields, maxStatesPerRule: this.maxStatesPerRule });
      return { rule: parsed.data, evaluator, metrics: { evaluated: 0, matched: 0, suppressed: 0, cooledDown: 0, errors: 0, lastMatchAt: null, lastError: null } };
    } catch (err) {
      return { ruleId, errors: err instanceof RuleCompileError ? err.errors : [String(err)] };
    }
  }

  private toMatch(rule: DetectionRule, trigger: CanonicalEvent, raw: RawMatch): DetectionMatch {
    const events = raw.events.length > 0 ? raw.events : [trigger];
    const times = events.map((e) => toEpochMs(e.timestamp));
    const eventSeverity = events.reduce<Severity>((s, e) => maxSeverity(s, e.severity), "info");
    let severity: Severity;
    if (rule.severityMode === "event") severity = trigger.severity;
    else if (rule.severityMode === "max") severity = maxSeverity(maxSeverity(rule.severity, eventSeverity), raw.severity ?? "info");
    else severity = rule.severity;
    const entities = collectEntities(events, raw);
    const primary = entities.find((e) => ASSET_NODE_KINDS.includes(e.kind)) ?? entities.find((e) => e.kind === "identity" || e.kind === "user");
    const explanation = [...raw.explanation];
    if (raw.totalEvents && raw.totalEvents > events.length) explanation.push(`${raw.totalEvents} events contributed; the newest ${events.length} are attached`);
    return {
      id: stableId("detection-match", rule.id, rule.version, trigger.tenantId, trigger.organizationId, ...events.map((e) => e.id)),
      tenantId: trigger.tenantId,
      organizationId: trigger.organizationId,
      rule: { id: rule.id, name: rule.name, version: rule.version, kind: rule.kind },
      title: primary ? `${rule.name} on ${primary.label}` : rule.name,
      severity,
      confidence: raw.confidence ?? rule.confidence,
      attack: rule.attack.length > 0 ? rule.attack : dedupeAttack(events.flatMap((e) => e.attack ?? [])),
      events,
      entities,
      explanation,
      ...(raw.indicators ? { indicators: raw.indicators } : {}),
      ...(raw.groupKey ? { groupKey: raw.groupKey } : {}),
      firstSeenAt: toIso(Math.min(...times)),
      lastSeenAt: toIso(Math.max(...times)),
      detectedAt: toIso(this.clock.now()),
    };
  }
}

function inScope(rule: DetectionRule, event: CanonicalEvent): boolean {
  const s = rule.scope;
  if (!s) return true;
  if (s.tenantId && s.tenantId !== event.tenantId) return false;
  if (s.organizationIds && s.organizationIds.length > 0 && !s.organizationIds.includes(event.organizationId)) return false;
  return true;
}

const MAX_ENTITIES = 50;

function collectEntities(events: CanonicalEvent[], raw: RawMatch): EntityRef[] {
  const out = new Map<string, EntityRef>();
  for (const e of events) {
    for (const ref of extractEntities(e)) {
      const k = `${ref.kind}:${ref.key}`;
      if (!out.has(k)) out.set(k, ref);
      if (out.size >= MAX_ENTITIES) break;
    }
  }
  for (const h of raw.indicators ?? []) {
    const k = `indicator:${h.type}:${h.value}`;
    if (!out.has(k) && out.size < MAX_ENTITIES) out.set(k, { kind: "indicator", key: `${h.type}:${h.value}`, label: h.value, role: "observable" });
  }
  return [...out.values()];
}

function primaryKey(m: DetectionMatch): string {
  const p = m.entities.find((e) => ASSET_NODE_KINDS.includes(e.kind)) ?? m.entities.find((e) => e.kind === "identity" || e.kind === "user") ?? m.entities[0];
  return p ? `${p.kind}:${p.key}` : (m.groupKey ?? "-");
}

function dedupeAttack(ts: CanonicalEvent["attack"]): CanonicalEvent["attack"] {
  const m = new Map<string, CanonicalEvent["attack"][number]>();
  for (const t of ts) if (!m.has(t.id)) m.set(t.id, t);
  return [...m.values()];
}

/** Highest severity first, then newest. Handy for triage feeds. */
export function compareMatches(a: DetectionMatch, b: DetectionMatch): number {
  return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.lastSeenAt.localeCompare(a.lastSeenAt) || a.id.localeCompare(b.id);
}
