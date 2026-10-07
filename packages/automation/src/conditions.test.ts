import { describe, expect, it } from "vitest";
import { compareValues, evaluateCondition, evaluateConditions, validateConditions } from "./conditions.js";

const ctx = {
  severity: "high",
  incident: {
    riskScore: 82,
    title: "Ransomware precursor on FIN-WS-042",
    detectedAt: "2026-10-07T10:00:00Z",
    attack: ["T1059.001", "T1486"],
    tags: ["Finance", "crown_jewel"],
    assignee: null,
    labels: { env: "prod" },
  },
};

describe("conditions", () => {
  it("eq / neq with numeric coercion and structural equality", () => {
    expect(evaluateCondition({ field: "incident.riskScore", op: "eq", value: "82" }, ctx).matched).toBe(true);
    expect(evaluateCondition({ field: "incident.attack", op: "eq", value: ["T1059.001", "T1486"] }, ctx).matched).toBe(true);
    expect(evaluateCondition({ field: "severity", op: "neq", value: "low" }, ctx).matched).toBe(true);
    expect(evaluateCondition({ field: "missing.field", op: "neq", value: "x" }, ctx).matched).toBe(true);
  });

  it("gte / lte understand severities, numbers and ISO dates", () => {
    expect(evaluateCondition({ field: "severity", op: "gte", value: "medium" }, ctx).matched).toBe(true);
    expect(evaluateCondition({ field: "severity", op: "gte", value: "critical" }, ctx).matched).toBe(false);
    expect(evaluateCondition({ field: "incident.riskScore", op: "lte", value: 90 }, ctx).matched).toBe(true);
    expect(evaluateCondition({ field: "incident.detectedAt", op: "gte", value: "2026-10-07T09:00:00Z" }, ctx).matched).toBe(true);
    const notComparable = evaluateCondition({ field: "incident.title", op: "gte", value: 3 }, ctx);
    expect(notComparable.matched).toBe(false);
    expect(notComparable.explanation).toContain("not comparable");
    expect(compareValues("low", "info")).toBeGreaterThan(0);
  });

  it("in / contains / exists", () => {
    expect(evaluateCondition({ field: "severity", op: "in", value: ["high", "critical"] }, ctx).matched).toBe(true);
    expect(evaluateCondition({ field: "incident.tags", op: "in", value: ["finance"] }, ctx).matched).toBe(true);
    expect(evaluateCondition({ field: "severity", op: "in", value: "high" }, ctx).matched).toBe(false);
    expect(evaluateCondition({ field: "incident.title", op: "contains", value: "ransomware" }, ctx).matched).toBe(true);
    expect(evaluateCondition({ field: "incident.attack", op: "contains", value: "T1486" }, ctx).matched).toBe(true);
    expect(evaluateCondition({ field: "incident.labels", op: "contains", value: "env" }, ctx).matched).toBe(true);
    expect(evaluateCondition({ field: "incident.riskScore", op: "exists" }, ctx).matched).toBe(true);
    expect(evaluateCondition({ field: "incident.assignee", op: "exists" }, ctx).matched).toBe(false);
    expect(evaluateCondition({ field: "incident.assignee", op: "exists", value: false }, ctx).matched).toBe(true);
  });

  it("ANDs conditions and explains each result", () => {
    const res = evaluateConditions(
      [
        { field: "severity", op: "gte", value: "high" },
        { field: "incident.riskScore", op: "gte", value: 90 },
      ],
      ctx,
    );
    expect(res.matched).toBe(false);
    expect(res.results.map((r) => r.matched)).toEqual([true, false]);
    expect(res.results[1]!.explanation).toMatch(/incident\.riskScore ≥ 90 — actual 82 → no match/);
    expect(evaluateConditions([], ctx).matched).toBe(true);
  });

  it("never walks the prototype chain", () => {
    expect(evaluateCondition({ field: "incident.constructor", op: "exists" }, ctx).matched).toBe(false);
    expect(evaluateCondition({ field: "__proto__.polluted", op: "exists" }, ctx).matched).toBe(false);
    expect(evaluateCondition({ field: "incident.toString", op: "exists" }, ctx).matched).toBe(false);
  });

  it("validates condition definitions for editors", () => {
    expect(validateConditions([{ field: "severity", op: "gte", value: "high" }])).toEqual([]);
    const issues = validateConditions([
      { field: "a..b", op: "eq", value: 1 },
      { field: "x", op: "in", value: "nope" },
      { field: "y", op: "gte", value: { a: 1 } },
      { field: "z", op: "eq" },
      { field: "w", op: "regex", value: ".*" },
    ]);
    expect(issues.map((i) => i.path)).toEqual(["conditions.0.field", "conditions.1.value", "conditions.2.value", "conditions.3.value", "conditions.4"]);
  });
});
