import { AutomationEvent, Severity } from "@bloody/contracts";
import { z } from "zod";

/**
 * Adapter → automation bridge.
 *
 * Adapters never send email or call webhooks. They emit typed {@link AdapterSignal}s that the
 * control plane hands to `@bloody/automation` (automation rules → email / Slack / Teams /
 * webhook / syslog channels, SOAR playbooks) and to reporting. Each signal carries:
 *
 *  - `event` from the shared `AUTOMATION_EVENTS` vocabulary, so existing rules match;
 *  - `audience` — who should hear about it (SOC analysts, the MSSP/business operator, the
 *    customer's own contacts), letting one signal fan out to role-appropriate channels;
 *  - `title` / `summary` written to be usable verbatim as an email subject and body, plus
 *    structured `facts` for templates and conditions;
 *  - `dedupKey` + `emit` so rules can throttle and the API only notifies on real changes.
 */
export const SignalAudience = z.enum(["soc", "mssp", "customer"]);
export type SignalAudience = z.infer<typeof SignalAudience>;

export const AdapterSignal = z.object({
  event: AutomationEvent,
  severity: Severity,
  at: z.string().datetime({ offset: true }),
  /** Stable key for throttling / de-duplication (same subject + condition). */
  dedupKey: z.string().min(1).max(300),
  /**
   * always    — emit on every run while the condition holds (rules throttle it);
   * on_create — emit only when the API inserted the subject for the first time;
   * on_change — emit only when the subject's mapped state changed since last sync.
   */
  emit: z.enum(["always", "on_create", "on_change"]),
  /** Organization reference: an `externalRef` from a sync plan, or an organization UUID. */
  organizationRef: z.string().nullable(),
  subject: z.object({
    kind: z.enum(["agent", "asset", "vulnerability", "incident", "escalation", "alert", "indicator", "integration"]),
    ref: z.string(),
    label: z.string(),
  }),
  title: z.string().max(200),
  summary: z.string().max(4000),
  facts: z.record(z.union([z.string(), z.number(), z.boolean()])),
  audience: z.array(SignalAudience).min(1),
});
export type AdapterSignal = z.infer<typeof AdapterSignal>;

/** Validate and collect signals; invalid ones are dropped (they are produced by our own code). */
export function signal(input: AdapterSignal): AdapterSignal | undefined {
  const parsed = AdapterSignal.safeParse({ ...input, title: input.title.slice(0, 200), summary: input.summary.slice(0, 4000) });
  return parsed.success ? parsed.data : undefined;
}
