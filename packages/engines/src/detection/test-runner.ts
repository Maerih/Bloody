import { CanonicalEvent as CanonicalEventSchema, type CanonicalEvent } from "@bloody/contracts";
import { ManualClock, toEpochMs } from "../util/clock.js";
import { stableId } from "../util/uuid.js";
import { DetectionEngine } from "./engine.js";
import { IndicatorSet } from "./indicators.js";
import type { DetectionMatch, DetectionRule, RuleTestCase } from "./types.js";
import { validateRule } from "./validate.js";

export interface RuleTestResult {
  name: string;
  passed: boolean;
  expect: "match" | "no_match";
  matches: number;
  expectedMatches?: number;
  /** Event-building or engine error, when the test could not run. */
  error?: string;
  explanation: string[];
}

export interface RuleTestReport {
  ruleId: string;
  version: number | null;
  passed: boolean;
  validation: { valid: boolean; errors: string[]; warnings: string[] };
  results: RuleTestResult[];
}

/** Synthetic tenancy used for rule tests (never real customer identifiers). */
export const RULE_TEST_TENANT_ID = "00000000-0000-4000-8000-00000000a001";
export const RULE_TEST_ORGANIZATION_ID = "00000000-0000-4000-8000-00000000b001";
const RULE_TEST_BASE_TIME = Date.parse("2025-01-01T00:00:00.000Z");

/**
 * Build a complete canonical event from a partial test sample. `offsetSeconds` (or the event
 * index) positions it in time relative to a fixed base so tests are deterministic.
 */
export function buildTestEvent(sample: Record<string, unknown>, index: number, scope: { ruleId: string; testName: string; tenantId?: string; organizationId?: string }): CanonicalEvent {
  const { offsetSeconds, ...rest } = sample as { offsetSeconds?: unknown } & Record<string, unknown>;
  const offset = typeof offsetSeconds === "number" ? offsetSeconds : index;
  const timestamp = typeof rest.timestamp === "string" ? rest.timestamp : new Date(RULE_TEST_BASE_TIME + offset * 1000).toISOString();
  const candidate = {
    id: stableId("rule-test-event", scope.ruleId, scope.testName, index),
    tenantId: scope.tenantId ?? RULE_TEST_TENANT_ID,
    organizationId: scope.organizationId ?? RULE_TEST_ORGANIZATION_ID,
    source: { kind: "endpoint", product: "rule-test" },
    category: "process",
    eventType: "rule_test",
    provenance: { adapter: "rule-test", adapterVersion: "1", receivedAt: timestamp },
    ...rest,
    timestamp,
  };
  return CanonicalEventSchema.parse(candidate);
}

/**
 * Run a rule's embedded tests. Each test gets a fresh engine containing only this rule, a
 * clock that follows event time, and the test's indicators (IOC rules). A rule passes when it
 * validates and every test's expectation (and optional exact match count) holds.
 */
export function runRuleTests(input: unknown, extraTests: RuleTestCase[] = []): RuleTestReport {
  const validation = validateRule(input);
  const ruleId = typeof (input as { id?: unknown })?.id === "string" ? (input as { id: string }).id : "(unknown)";
  if (!validation.valid || !validation.rule) {
    return { ruleId, version: null, passed: false, validation: { valid: false, errors: validation.errors, warnings: validation.warnings }, results: [] };
  }
  const rule: DetectionRule = validation.rule;
  const results: RuleTestResult[] = [];
  for (const test of [...rule.tests, ...extraTests]) results.push(runOne(rule, test));
  return {
    ruleId: rule.id,
    version: rule.version,
    passed: results.every((r) => r.passed),
    validation: { valid: true, errors: [], warnings: validation.warnings },
    results,
  };
}

function runOne(rule: DetectionRule, test: RuleTestCase): RuleTestResult {
  let events: CanonicalEvent[];
  try {
    events = test.events.map((e, i) => buildTestEvent(e, i, { ruleId: rule.id, testName: test.name }));
  } catch (err) {
    return { name: test.name, passed: false, expect: test.expect, matches: 0, error: `invalid test event: ${(err as Error).message}`, explanation: [] };
  }
  const clock = new ManualClock(RULE_TEST_BASE_TIME);
  const indicators = new IndicatorSet({ clock });
  for (const ind of test.indicators) {
    indicators.add({
      tenantId: RULE_TEST_TENANT_ID,
      organizationId: null,
      type: ind.type,
      value: ind.value,
      confidence: ind.confidence,
      severity: ind.severity,
      source: ind.source,
      threatActor: ind.threatActor ?? null,
    });
  }
  // Rule tests exercise the rule itself: scope restrictions are lifted for the synthetic tenant.
  const { scope: _scope, ...unscoped } = rule;
  const engine = new DetectionEngine({ rules: [{ ...unscoped, enabled: true, cooldownSeconds: rule.cooldownSeconds } as DetectionRule], clock, indicators });
  const matches: DetectionMatch[] = [];
  try {
    for (const e of [...events].sort((a, b) => toEpochMs(a.timestamp) - toEpochMs(b.timestamp))) {
      clock.set(e.timestamp);
      matches.push(...engine.process(e));
    }
  } catch (err) {
    return { name: test.name, passed: false, expect: test.expect, matches: matches.length, error: (err as Error).message, explanation: [] };
  }
  const expectationMet = test.expect === "match" ? matches.length > 0 : matches.length === 0;
  const countMet = test.expectedMatches === undefined || matches.length === test.expectedMatches;
  return {
    name: test.name,
    passed: expectationMet && countMet,
    expect: test.expect,
    matches: matches.length,
    ...(test.expectedMatches !== undefined ? { expectedMatches: test.expectedMatches } : {}),
    explanation: matches.flatMap((m) => m.explanation).slice(0, 20),
  };
}
