import { PlaybookCondition, SEVERITY_RANK, Severity } from "@bloody/contracts";
import { getPath, isValidPath } from "./util/path.js";

/**
 * Condition evaluation shared by SOAR playbooks and automation rules.
 *
 * Conditions are AND-ed. Each result carries a human-readable explanation so the UI can show
 * *why* a playbook or rule did or did not fire ("severity = high ≥ high ✓").
 *
 * Semantics per operator (field is a dotted path into the event context):
 *  - eq / neq   strict equality; numbers and numeric strings compare numerically; arrays and
 *               objects compare structurally.
 *  - gte / lte  numbers, severities ("high" ≥ "medium" by the shared severity ladder) or ISO
 *               date-times. Any other pairing is "not comparable" → false.
 *  - in         `value` must be an array; the field (or any element if the field is an array)
 *               must equal one of its entries.
 *  - contains   string field: case-insensitive substring; array field: contains an equal
 *               element (strings case-insensitively); object field: has the key.
 *  - exists     value omitted/true → field present and not null; value false → absent/null.
 */
export interface ConditionResult {
  condition: PlaybookCondition;
  matched: boolean;
  actual: unknown;
  explanation: string;
}

export interface ConditionsEvaluation {
  matched: boolean;
  results: ConditionResult[];
}

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})$/;

function isSeverity(v: unknown): v is Severity {
  return typeof v === "string" && Object.prototype.hasOwnProperty.call(SEVERITY_RANK, v);
}

function asNumber(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "" && /^-?\d+(\.\d+)?$/.test(v.trim())) return Number(v);
  return null;
}

function structuralEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  const an = asNumber(a);
  const bn = asNumber(b);
  if (an !== null && bn !== null && (typeof a === "number" || typeof b === "number")) return an === bn;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => structuralEqual(x, b[i]));
  }
  const ak = Object.keys(a as object);
  const bk = Object.keys(b as object);
  if (ak.length !== bk.length) return false;
  return ak.every((k) => Object.prototype.hasOwnProperty.call(b, k) && structuralEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}

function looseEqual(a: unknown, b: unknown): boolean {
  if (typeof a === "string" && typeof b === "string") return a.toLowerCase() === b.toLowerCase();
  return structuralEqual(a, b);
}

/** Order two values: negative/zero/positive, or null when they are not comparable. */
export function compareValues(actual: unknown, expected: unknown): number | null {
  if (isSeverity(actual) && isSeverity(expected)) return SEVERITY_RANK[actual] - SEVERITY_RANK[expected];
  const an = asNumber(actual);
  const en = asNumber(expected);
  if (an !== null && en !== null) return an - en;
  const ad = actual instanceof Date ? actual.getTime() : typeof actual === "string" && ISO_RE.test(actual) ? Date.parse(actual) : NaN;
  const ed = expected instanceof Date ? expected.getTime() : typeof expected === "string" && ISO_RE.test(expected) ? Date.parse(expected) : NaN;
  if (Number.isFinite(ad) && Number.isFinite(ed)) return ad - ed;
  return null;
}

function show(v: unknown): string {
  if (v === undefined) return "(missing)";
  if (v === null) return "null";
  if (typeof v === "string") return JSON.stringify(v.length > 80 ? `${v.slice(0, 79)}…` : v);
  try {
    const s = JSON.stringify(v);
    return s.length > 80 ? `${s.slice(0, 79)}…` : s;
  } catch {
    return String(v);
  }
}

const OP_TEXT: Record<PlaybookCondition["op"], string> = {
  eq: "=",
  neq: "≠",
  gte: "≥",
  lte: "≤",
  in: "in",
  contains: "contains",
  exists: "exists",
};

export function evaluateCondition(condition: PlaybookCondition, context: unknown): ConditionResult {
  const actual = getPath(context, condition.field);
  const expected = condition.value;
  let matched = false;
  let note = "";
  switch (condition.op) {
    case "eq":
      matched = structuralEqual(actual, expected);
      break;
    case "neq":
      matched = !structuralEqual(actual, expected);
      break;
    case "gte":
    case "lte": {
      const cmp = compareValues(actual, expected);
      if (cmp === null) {
        note = " (not comparable)";
        matched = false;
      } else {
        matched = condition.op === "gte" ? cmp >= 0 : cmp <= 0;
      }
      break;
    }
    case "in": {
      if (!Array.isArray(expected)) {
        note = " (value must be a list)";
        matched = false;
      } else if (Array.isArray(actual)) {
        matched = actual.some((a) => expected.some((e) => looseEqual(a, e)));
      } else {
        matched = expected.some((e) => looseEqual(actual, e));
      }
      break;
    }
    case "contains": {
      if (typeof actual === "string") {
        matched = typeof expected === "string" || typeof expected === "number" ? actual.toLowerCase().includes(String(expected).toLowerCase()) : false;
      } else if (Array.isArray(actual)) {
        matched = actual.some((a) => looseEqual(a, expected));
      } else if (actual !== null && typeof actual === "object" && typeof expected === "string") {
        matched = Object.prototype.hasOwnProperty.call(actual, expected);
      }
      break;
    }
    case "exists": {
      const present = actual !== undefined && actual !== null;
      matched = expected === false ? !present : present;
      break;
    }
  }
  const expectation = condition.op === "exists" ? (expected === false ? "is absent" : "exists") : `${OP_TEXT[condition.op]} ${show(expected)}`;
  return {
    condition,
    matched,
    actual,
    explanation: `${condition.field} ${expectation} — actual ${show(actual)}${note} → ${matched ? "match" : "no match"}`,
  };
}

/** AND all conditions. An empty list always matches (the trigger alone decides). */
export function evaluateConditions(conditions: readonly PlaybookCondition[], context: unknown): ConditionsEvaluation {
  const results = conditions.map((c) => evaluateCondition(c, context));
  return { matched: results.every((r) => r.matched), results };
}

/** Static validation for the rule/playbook editors (run on save). */
export function validateConditions(conditions: unknown): { path: string; message: string }[] {
  const issues: { path: string; message: string }[] = [];
  if (!Array.isArray(conditions)) return [{ path: "conditions", message: "conditions must be a list" }];
  if (conditions.length > 50) issues.push({ path: "conditions", message: "at most 50 conditions are allowed" });
  conditions.forEach((raw, i) => {
    const parsed = PlaybookCondition.safeParse(raw);
    if (!parsed.success) {
      issues.push({ path: `conditions.${i}`, message: parsed.error.issues.map((x) => `${x.path.join(".")}: ${x.message}`).join("; ") });
      return;
    }
    const c = parsed.data;
    if (!isValidPath(c.field)) issues.push({ path: `conditions.${i}.field`, message: `invalid field path "${c.field}"` });
    if (c.op === "in" && !Array.isArray(c.value)) issues.push({ path: `conditions.${i}.value`, message: "'in' requires a list value" });
    if ((c.op === "gte" || c.op === "lte") && asNumber(c.value) === null && !isSeverity(c.value) && !(typeof c.value === "string" && ISO_RE.test(c.value))) {
      issues.push({ path: `conditions.${i}.value`, message: `'${c.op}' requires a number, a severity or an ISO date-time` });
    }
    if (c.op === "exists" && c.value !== undefined && typeof c.value !== "boolean") {
      issues.push({ path: `conditions.${i}.value`, message: "'exists' takes an optional boolean" });
    }
    if (c.op !== "exists" && c.value === undefined) issues.push({ path: `conditions.${i}.value`, message: `'${c.op}' requires a value` });
  });
  return issues;
}
