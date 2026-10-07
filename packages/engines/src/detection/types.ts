import { AttackTechnique, IndicatorType, Severity, type CanonicalEvent } from "@bloody/contracts";
import { z } from "zod";
import type { EntityRef } from "../entities/keys.js";

/**
 * Detection-as-code rule model. Rules are versioned, validated (`validateRule`), carry their
 * own tests (`runRuleTests`) and ATT&CK mappings. Four kinds:
 *
 *  - `sigma`     — a Sigma rule (YAML) compiled by Bloody's own Sigma-subset compiler.
 *  - `threshold` — N matching events (or N distinct values) per group-by key within a window,
 *                  optionally requiring periodic timing (beaconing).
 *  - `sequence`  — ordered steps by the same entity within a window, with per-step counts and
 *                  constraints (geo-velocity, field differs/equals).
 *  - `ioc`       — event observables matched against the tenant's indicator set.
 *
 * `filter` / step filters use the Sigma *detection* syntax (`{ detection: {...}, condition }`)
 * with either Sigma field names (mapped) or Bloody Canonical Event (BCE) dotted paths.
 */
export const MatchExpression = z.object({
  detection: z.record(z.unknown()),
  condition: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
});
export type MatchExpression = z.infer<typeof MatchExpression>;

export const RuleTestCase = z.object({
  name: z.string().min(1).max(200),
  /** Partial canonical events; ids/tenancy/provenance are filled in by the test runner. */
  events: z.array(z.record(z.unknown())).min(1).max(1000),
  expect: z.enum(["match", "no_match"]),
  /** Exact number of matches expected (optional, for threshold/sequence tests). */
  expectedMatches: z.number().int().min(0).optional(),
  /** Indicators loaded for this test (IOC rules). */
  indicators: z
    .array(
      z.object({
        type: IndicatorType,
        value: z.string().min(1),
        confidence: z.number().min(0).max(100).default(80),
        severity: Severity.default("high"),
        source: z.string().default("rule-test"),
        threatActor: z.string().nullable().optional(),
      }),
    )
    .max(1000)
    .default([]),
});
export type RuleTestCase = z.infer<typeof RuleTestCase>;

const RULE_ID = z
  .string()
  .min(3)
  .max(128)
  .regex(/^[a-z0-9][a-z0-9._:-]*$/i, "rule id may contain letters, digits, '.', '_', ':' and '-' only");

const RuleBase = z.object({
  id: RULE_ID,
  name: z.string().min(3).max(200),
  description: z.string().max(4000).default(""),
  version: z.number().int().min(1),
  enabled: z.boolean().default(true),
  severity: Severity,
  /** rule: fixed severity; event: the triggering event's severity; max: the higher of both / indicator severity. */
  severityMode: z.enum(["rule", "event", "max"]).default("rule"),
  /** Prior precision of the rule (0..1); refined by false-positive feedback in metrics. */
  confidence: z.number().min(0).max(1).default(0.7),
  attack: z.array(AttackTechnique).default([]),
  tags: z.array(z.string().max(100)).max(50).default([]),
  author: z.string().max(200).optional(),
  references: z.array(z.string().max(1000)).max(50).default([]),
  falsePositives: z.array(z.string().max(500)).max(50).default([]),
  /** Restrict a rule to one tenant and/or organizations (built-in rules are global). */
  scope: z.object({ tenantId: z.string().uuid().optional(), organizationIds: z.array(z.string().uuid()).optional() }).optional(),
  /** Suppress repeat matches of this rule for the same primary entity for this long (0 = off). */
  cooldownSeconds: z.number().int().min(0).max(30 * 86400).default(0),
  tests: z.array(RuleTestCase).max(100).default([]),
});

export const SigmaRuleDefinition = RuleBase.extend({
  kind: z.literal("sigma"),
  sigma: z.string().min(1).max(100_000),
  /** Per-rule Sigma field → BCE path overrides. */
  fieldMapping: z.record(z.string()).default({}),
});

export const ThresholdRuleDefinition = RuleBase.extend({
  kind: z.literal("threshold"),
  filter: MatchExpression,
  groupBy: z.array(z.string().min(1)).min(1).max(8),
  threshold: z.number().int().min(1).max(1_000_000),
  windowSeconds: z.number().int().min(1).max(7 * 86400),
  /** Count distinct values of this field instead of events (e.g. distinct users for spraying). */
  distinctField: z.string().min(1).optional(),
  /** Require periodic arrivals (beaconing): coefficient of variation of inter-arrival gaps ≤ max. */
  regularity: z.object({ maxCoefficientOfVariation: z.number().positive().max(5), minIntervalSeconds: z.number().min(0).default(0) }).optional(),
});

export const SequenceConstraint = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("geo_velocity"),
    /** Faster than this between consecutive steps is impossible travel (default airliner ~900 km/h). */
    maxKmh: z.number().positive().default(900),
    /** Ignore hops shorter than this (geo-IP noise). */
    minDistanceKm: z.number().min(0).default(100),
    /** Without coordinates, treat a country change within the window as a violation. */
    fallbackCountryChange: z.boolean().default(true),
  }),
  z.object({ type: z.literal("field_differs"), field: z.string().min(1) }),
  z.object({ type: z.literal("field_equals"), field: z.string().min(1) }),
]);
export type SequenceConstraint = z.infer<typeof SequenceConstraint>;

export const SequenceStep = z.object({
  name: z.string().min(1).max(100),
  filter: MatchExpression,
  /** The step completes after this many matching events (e.g. 5 failures). */
  minCount: z.number().int().min(1).max(100_000).default(1),
  /** Constraints between the previous step's last event and this step's event. */
  constraints: z.array(SequenceConstraint).default([]),
});
export type SequenceStep = z.infer<typeof SequenceStep>;

export const SequenceRuleDefinition = RuleBase.extend({
  kind: z.literal("sequence"),
  by: z.array(z.string().min(1)).min(1).max(8),
  windowSeconds: z.number().int().min(1).max(7 * 86400),
  steps: z.array(SequenceStep).min(2).max(10),
});

export const IocRuleDefinition = RuleBase.extend({
  kind: z.literal("ioc"),
  indicatorTypes: z.array(IndicatorType).optional(),
  /** Minimum indicator confidence (0..100). */
  minConfidence: z.number().min(0).max(100).default(50),
  /** Also match parent domains of observed domains. */
  matchSubdomains: z.boolean().default(true),
  /** Ignore private / reserved IP observables (default true). */
  ignoreNonPublicIps: z.boolean().default(true),
  filter: MatchExpression.optional(),
});

export const DetectionRuleSchema = z.discriminatedUnion("kind", [SigmaRuleDefinition, ThresholdRuleDefinition, SequenceRuleDefinition, IocRuleDefinition]);
export type DetectionRule = z.infer<typeof DetectionRuleSchema>;
export type DetectionRuleInput = z.input<typeof DetectionRuleSchema>;
export type SigmaDetectionRule = z.infer<typeof SigmaRuleDefinition>;
export type ThresholdDetectionRule = z.infer<typeof ThresholdRuleDefinition>;
export type SequenceDetectionRule = z.infer<typeof SequenceRuleDefinition>;
export type IocDetectionRule = z.infer<typeof IocRuleDefinition>;
export type DetectionRuleKind = DetectionRule["kind"];

export interface IndicatorHit {
  indicatorId?: string;
  type: z.infer<typeof IndicatorType>;
  value: string;
  observed: string;
  field: string;
  source: string;
  confidence: number;
  severity: z.infer<typeof Severity>;
  threatActor?: string | null;
  malware?: string | null;
  campaign?: string | null;
}

/** A rule firing. `id` is deterministic (rule, version, tenant, org, events) → usable as alert id. */
export interface DetectionMatch {
  id: string;
  tenantId: string;
  organizationId: string;
  rule: { id: string; name: string; version: number; kind: DetectionRuleKind };
  title: string;
  severity: z.infer<typeof Severity>;
  confidence: number;
  attack: z.infer<typeof AttackTechnique>[];
  events: CanonicalEvent[];
  entities: EntityRef[];
  /** Why it fired — matched selections, counts, step timings, indicator sources. */
  explanation: string[];
  indicators?: IndicatorHit[];
  groupKey?: string;
  firstSeenAt: string;
  lastSeenAt: string;
  detectedAt: string;
}
