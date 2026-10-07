import { resolveField } from "./field-mapping.js";
import { compileDetection } from "./sigma/compiler.js";
import { compileSigma } from "./sigma/sigma.js";
import { DetectionRuleSchema, type DetectionRule, type MatchExpression } from "./types.js";

export interface RuleValidationResult {
  valid: boolean;
  /** Blocking problems (schema, compile, unmapped fields, bad regex/CIDR …). */
  errors: string[];
  /** Non-blocking quality findings (no tests, no ATT&CK mapping, unused selections …). */
  warnings: string[];
  rule: DetectionRule | null;
}

/**
 * Validate a detection rule definition end to end: schema, kind-specific compilation and
 * field mapping, plus detection-engineering hygiene warnings. Used by the API before a rule
 * is saved/deployed and by AI-assisted rule authoring (AI drafts must pass this gate).
 */
export function validateRule(input: unknown, options: { strictFields?: boolean } = {}): RuleValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const parsed = DetectionRuleSchema.safeParse(input);
  if (!parsed.success) {
    return { valid: false, errors: parsed.error.issues.map((i) => `${i.path.join(".") || "rule"}: ${i.message}`), warnings, rule: null };
  }
  const rule = parsed.data;
  const strict = options.strictFields ?? true;

  const checkExpr = (where: string, expr: MatchExpression) => {
    const r = compileDetection(expr.detection, expr.condition, { strictFields: strict });
    errors.push(...r.errors.map((e) => `${where}.${e}`));
    warnings.push(...r.warnings.map((w) => `${where}.${w}`));
  };
  const checkField = (where: string, field: string) => {
    if (resolveField(field).path === null) errors.push(`${where}: field "${field}" has no mapping to the Bloody Canonical Event`);
  };

  switch (rule.kind) {
    case "sigma": {
      const r = compileSigma(rule.sigma, { fieldMapping: rule.fieldMapping, strictFields: strict });
      errors.push(...r.errors);
      warnings.push(...r.warnings);
      if (r.value?.ast.level && r.value.ast.level !== rule.severity) warnings.push(`severity: rule severity "${rule.severity}" differs from Sigma level "${r.value.ast.level}"`);
      break;
    }
    case "threshold":
      checkExpr("filter", rule.filter);
      rule.groupBy.forEach((f, i) => checkField(`groupBy[${i}]`, f));
      if (rule.distinctField) checkField("distinctField", rule.distinctField);
      if (rule.regularity && rule.threshold < 3) errors.push("regularity: requires threshold ≥ 3 (periodicity needs at least two intervals)");
      break;
    case "sequence":
      rule.steps.forEach((s, i) => {
        checkExpr(`steps[${i}].filter`, s.filter);
        if (i === 0 && s.constraints.length > 0) errors.push("steps[0].constraints: the first step has no previous step to compare with");
        s.constraints.forEach((c, j) => {
          if (c.type !== "geo_velocity") checkField(`steps[${i}].constraints[${j}].field`, c.field);
        });
      });
      rule.by.forEach((f, i) => checkField(`by[${i}]`, f));
      break;
    case "ioc":
      if (rule.filter) checkExpr("filter", rule.filter);
      break;
  }

  if (rule.attack.length === 0) warnings.push("attack: no ATT&CK technique mapping (coverage reporting will not count this rule)");
  if (rule.tests.length === 0) warnings.push("tests: no tests — detection-as-code rules should ship positive and negative tests");
  else {
    if (!rule.tests.some((t) => t.expect === "match")) warnings.push("tests: no positive test (expect: match)");
    if (!rule.tests.some((t) => t.expect === "no_match")) warnings.push("tests: no negative test (expect: no_match)");
  }
  if (rule.description.trim().length === 0) warnings.push("description: empty");
  return { valid: errors.length === 0, errors, warnings, rule: errors.length === 0 ? rule : null };
}
