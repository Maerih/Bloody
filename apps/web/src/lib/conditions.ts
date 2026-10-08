import { PlaybookCondition } from "@bloody/contracts";

/**
 * Condition helpers shared by automation rules and SOAR playbooks
 * (`{ field, op, value }` evaluated by the automation engine).
 */
export const CONDITION_OPS = PlaybookCondition.shape.op.options;
export type ConditionOp = (typeof CONDITION_OPS)[number];

export const CONDITION_OP_LABELS: Record<ConditionOp, string> = { eq: "equals", neq: "not equal", gte: "≥", lte: "≤", in: "is one of", contains: "contains", exists: "exists" };

export interface ConditionDraft {
  field: string;
  op: ConditionOp;
  value: string;
}

function coerceScalar(text: string): unknown {
  if (text === "true") return true;
  if (text === "false") return false;
  if (text !== "" && !Number.isNaN(Number(text))) return Number(text);
  return text;
}

/** Turn the text value into the typed condition value the engine compares against. */
export function coerceConditionValue(op: ConditionOp, raw: string): unknown {
  if (op === "exists") return undefined;
  const text = raw.trim();
  if (op === "in") return text.split(",").map((v) => coerceScalar(v.trim())).filter((v) => v !== "");
  return coerceScalar(text);
}

/** Inverse of coerceConditionValue for editing stored conditions. */
export function conditionValueText(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (Array.isArray(value)) return value.map((v) => String(v)).join(", ");
  return String(value);
}
