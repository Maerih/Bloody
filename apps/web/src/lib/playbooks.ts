import { PlaybookStep, PlaybookTrigger, RESPONSE_ACTIONS, actionRisk, type Playbook, type ResponseActionKey } from "@bloody/contracts";
import type { UpsertPlaybookInput } from "../api/types";
import { coerceConditionValue, conditionValueText, type ConditionDraft } from "./conditions";

/**
 * SOAR playbook editing model: trigger → conditions → ordered steps. High-risk steps always
 * require approval (the engine enforces it; the editor shows it and cannot turn it off).
 */

export type TriggerOn = Playbook["trigger"]["on"];
export const TRIGGERS = PlaybookTrigger.shape.on.options;

export const TRIGGER_LABELS: Record<TriggerOn, string> = {
  "incident.created": "Incident created",
  "incident.updated": "Incident updated",
  "alert.created": "Alert created",
  "indicator.matched": "Indicator matched in the environment",
  "escalation.overdue": "Escalation overdue",
  schedule: "On a schedule",
  manual: "Run manually",
};

export interface StepDraft {
  id: string;
  action: ResponseActionKey;
  /** JSON object text. */
  parameters: string;
  requireApproval: boolean;
  continueOnError: boolean;
}

export interface PlaybookDraft {
  name: string;
  description: string;
  organizationId: string | null;
  enabled: boolean;
  trigger: { on: TriggerOn; cron: string };
  conditions: ConditionDraft[];
  steps: StepDraft[];
}

export interface PlaybookDraftErrors {
  name?: string;
  cron?: string;
  conditions?: Record<number, string>;
  steps?: Record<number, string>;
  general?: string;
}

let seq = 0;
export function newStepId(): string {
  seq += 1;
  return `step-${Date.now().toString(36)}-${seq}`;
}

export function newStep(action: ResponseActionKey = "notify_analyst"): StepDraft {
  return { id: newStepId(), action, parameters: "{}", requireApproval: actionRisk(action) === "high", continueOnError: false };
}

export function emptyPlaybookDraft(organizationId: string | null): PlaybookDraft {
  return {
    name: "",
    description: "",
    organizationId,
    enabled: false,
    trigger: { on: "incident.created", cron: "0 * * * *" },
    conditions: [{ field: "severity", op: "in", value: "critical, high" }],
    steps: [newStep("create_case"), newStep("notify_analyst")],
  };
}

export function draftFromPlaybook(p: Playbook): PlaybookDraft {
  return {
    name: p.name,
    description: p.description ?? "",
    organizationId: p.organizationId,
    enabled: p.enabled,
    trigger: { on: p.trigger.on, cron: p.trigger.cron ?? "0 * * * *" },
    conditions: p.conditions.map((c) => ({ field: c.field, op: c.op, value: conditionValueText(c.value) })),
    steps: p.steps.map((s) => ({ id: s.id, action: s.action, parameters: JSON.stringify(s.parameters ?? {}, null, 2), requireApproval: s.requireApproval || actionRisk(s.action) === "high", continueOnError: s.continueOnError })),
  };
}

export function isHighRisk(action: ResponseActionKey): boolean {
  return actionRisk(action) === "high";
}

export function actionLabelOf(action: ResponseActionKey): string {
  return RESPONSE_ACTIONS.find((a) => a.key === action)?.label ?? action;
}

const CRON_PART = /^[\d*/,\-]+$/;

/** Validate the editor draft and build the POST/PATCH body. */
export function validatePlaybookDraft(d: PlaybookDraft): { errors: PlaybookDraftErrors; input: UpsertPlaybookInput | null } {
  const errors: PlaybookDraftErrors = {};
  if (d.name.trim().length < 3) errors.name = "Name the playbook (min. 3 characters)";
  if (d.trigger.on === "schedule") {
    const parts = d.trigger.cron.trim().split(/\s+/);
    if (parts.length !== 5 || !parts.every((p) => CRON_PART.test(p))) errors.cron = "Use a 5-field cron expression, e.g. 0 * * * *";
  }
  const condErrors: Record<number, string> = {};
  d.conditions.forEach((c, i) => {
    if (!/^[A-Za-z_][A-Za-z0-9_.]*$/.test(c.field.trim())) condErrors[i] = "Field must be a dotted path like severity or asset.criticality";
    else if (c.op !== "exists" && c.value.trim() === "") condErrors[i] = "Enter a value";
  });
  if (Object.keys(condErrors).length > 0) errors.conditions = condErrors;
  const stepErrors: Record<number, string> = {};
  const steps: Playbook["steps"] = [];
  d.steps.forEach((s, i) => {
    let params: unknown;
    try {
      params = s.parameters.trim() === "" ? {} : JSON.parse(s.parameters);
    } catch {
      stepErrors[i] = "Parameters must be valid JSON";
      return;
    }
    if (typeof params !== "object" || params === null || Array.isArray(params)) {
      stepErrors[i] = "Parameters must be a JSON object";
      return;
    }
    const parsed = PlaybookStep.safeParse({ id: s.id, action: s.action, parameters: params, requireApproval: s.requireApproval || isHighRisk(s.action), continueOnError: s.continueOnError });
    if (!parsed.success) stepErrors[i] = parsed.error.issues[0]?.message ?? "Invalid step";
    else steps.push(parsed.data);
  });
  if (d.steps.length === 0) errors.general = "Add at least one step";
  if (Object.keys(stepErrors).length > 0) errors.steps = stepErrors;
  if (Object.keys(errors).length > 0) return { errors, input: null };
  return {
    errors,
    input: {
      name: d.name.trim(),
      description: d.description.trim() || null,
      organizationId: d.organizationId,
      enabled: d.enabled,
      trigger: d.trigger.on === "schedule" ? { on: "schedule", cron: d.trigger.cron.trim() } : { on: d.trigger.on },
      conditions: d.conditions.map((c) => ({ field: c.field.trim(), op: c.op, ...(c.op === "exists" ? {} : { value: coerceConditionValue(c.op, c.value) }) })),
      steps,
    },
  };
}
