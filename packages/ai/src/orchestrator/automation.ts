import type { AiChatRequest } from "@bloody/contracts";

/**
 * Standard AI work items the automation engine (@bloody/automation) can trigger from
 * automation rules / playbooks, e.g. "on incident.created → AI triage note", "on
 * escalation.created → draft customer update". They run through the same orchestrator, so the
 * service principal's RBAC, the provider's tool tier, approvals and audit all still apply —
 * automations can never send or execute anything the configured tier would not allow.
 */
export type AiAutomationTask = "incident_triage" | "alert_summary" | "customer_update" | "executive_brief" | "hunt_followup";

export interface AiAutomationInput {
  organizationId: string;
  /** Incident id (incident tasks) or alert id (alert_summary). */
  entityId: string;
  /** Investigation to attach findings to (incident_triage / hunt_followup). */
  investigationId?: string;
  /** Notification channels the AI may address (customer_update / executive_brief). */
  channelIds?: string[];
  providerId?: string;
}

const PROMPTS: Record<AiAutomationTask, (i: AiAutomationInput) => string> = {
  incident_triage: (i) =>
    [
      "Automated triage of the incident in context.",
      "1. Summarize what happened, affected assets and identities, and the time window.",
      "2. Map the activity to MITRE ATT&CK and state the most likely root cause with confidence.",
      "3. Assess blast radius and risk using the graph and risk tools.",
      "4. Recommend prioritized next steps; queue containment only via request_response_action (human approval).",
      i.investigationId ? `5. Record your findings with add_investigation_note on investigation ${i.investigationId}.` : "",
    ]
      .filter(Boolean)
      .join("\n"),
  alert_summary: () => "Summarize the alert in context: what it detected, how confident it is, related alerts/incidents for the same asset or identity, and whether it should be promoted, tuned or closed as a false positive. Do not take any action.",
  customer_update: (i) =>
    [
      "Prepare a customer-facing status update for the incident in context: what happened, impact, what the SOC has done, and exactly what the customer must do.",
      i.channelIds?.length
        ? `Send it with send_notification to channel(s) ${i.channelIds.join(", ")} (it will be queued for approval if your tier does not allow autonomous sending).`
        : "Return the draft only; do not send it.",
    ].join("\n"),
  executive_brief: (i) =>
    [
      "Write a short executive brief for the incident in context: business impact, current status, decisions needed and next update time. Plain language, no jargon.",
      i.channelIds?.length ? `Send it with send_notification to channel(s) ${i.channelIds.join(", ")}.` : "Return the draft only; do not send it.",
    ].join("\n"),
  hunt_followup: (i) =>
    [
      "Hunt for related activity of the incident in context across the last 7 days (other hosts, identities, indicators).",
      "Report confirmed related activity with evidence ids and propose Sigma detections for gaps (draft_sigma_rule; never deploy).",
      i.investigationId ? `Record the hunt results on investigation ${i.investigationId} with add_investigation_note.` : "",
    ]
      .filter(Boolean)
      .join("\n"),
};

/** Build the chat request for an automation-triggered AI task. */
export function buildAutomationRequest(task: AiAutomationTask, input: AiAutomationInput): AiChatRequest {
  return {
    organizationId: input.organizationId,
    message: PROMPTS[task](input),
    context: { kind: task === "alert_summary" ? "alert" : "incident", id: input.entityId },
    ...(input.providerId ? { providerId: input.providerId } : {}),
  };
}
