import type { AutomationEvent, PlaybookTrigger, Severity } from "@bloody/contracts";
import { z } from "zod";

/**
 * Engine → automation bridge.
 *
 * Engines are pure and never send email, call webhooks or write to the database themselves.
 * Instead they emit typed, tenant-scoped notifications to an injected {@link EngineEventSink}.
 * The control plane forwards them to `@bloody/automation` (automation rules → email / Slack /
 * Teams / webhook / syslog channels, SOAR playbooks) and to reporting/metrics.
 *
 * `automationEventFor` / `playbookTriggerFor` map a notification onto the shared
 * `AUTOMATION_EVENTS` / playbook trigger vocabulary from `@bloody/contracts` so "email the
 * on-call analyst when a KEV vulnerability lands on a crown-jewel asset" or "run the
 * containment playbook when an incident is created" work without engine-specific glue.
 */
export type EngineNotification =
  | {
      type: "detection.matched";
      tenantId: string;
      organizationId: string;
      at: string;
      matchId: string;
      ruleId: string;
      ruleName: string;
      severity: Severity;
      confidence: number;
      entityLabels: string[];
    }
  | {
      type: "detection.suppressed";
      tenantId: string;
      organizationId: string;
      at: string;
      matchId: string;
      ruleId: string;
      suppressionId: string;
      reason: string;
    }
  | {
      type: "detection.rule_error";
      tenantId: string;
      organizationId: string;
      at: string;
      ruleId: string;
      error: string;
    }
  | {
      type: "indicator.matched";
      tenantId: string;
      organizationId: string;
      at: string;
      matchId: string;
      indicators: Array<{ type: string; value: string; source: string; confidence: number; severity: Severity }>;
      entityLabels: string[];
    }
  | {
      type: "incident.created";
      tenantId: string;
      organizationId: string;
      at: string;
      incidentDraftId: string;
      title: string;
      severity: Severity;
      riskScore: number;
    }
  | {
      type: "incident.updated" | "incident.severity_changed";
      tenantId: string;
      organizationId: string;
      at: string;
      incidentDraftId: string;
      title: string;
      severity: Severity;
      previousSeverity: Severity;
      riskScore: number;
      reasons: string[];
    }
  | {
      type: "vulnerability.kev_detected";
      tenantId: string;
      organizationId: string;
      at: string;
      cve: string;
      assetNodeId: string;
      assetLabel: string;
      internetFacing: boolean;
      criticality: string | null;
    }
  | {
      type: "attack_path.crown_jewel_exposed";
      tenantId: string;
      organizationId: string;
      at: string;
      paths: number;
      targets: string[];
      topRemediation: string | null;
      maxRiskScore: number;
    };

export type EngineNotificationType = EngineNotification["type"];

export interface EngineEventSink {
  emit(notification: EngineNotification): void;
}

/** Sink that discards everything (default when no automation is wired). */
export const nullSink: EngineEventSink = { emit: () => undefined };

/** Sink that buffers notifications in memory — used by tests and batch jobs that flush later. */
export class BufferingSink implements EngineEventSink {
  readonly items: EngineNotification[] = [];
  emit(notification: EngineNotification): void {
    this.items.push(notification);
  }
  drain(): EngineNotification[] {
    return this.items.splice(0, this.items.length);
  }
}

/**
 * Wrap a sink so that a throwing consumer can never break the analytics pipeline.
 * Errors are reported to `onError` (metrics / logs) and swallowed.
 */
export function safeSink(sink: EngineEventSink, onError: (err: unknown, n: EngineNotification) => void = () => undefined): EngineEventSink {
  return {
    emit(n) {
      try {
        sink.emit(n);
      } catch (err) {
        onError(err, n);
      }
    },
  };
}

/** Map a notification onto the automation-rule event vocabulary (emails, chat, webhooks). */
export function automationEventFor(n: EngineNotification): AutomationEvent | null {
  switch (n.type) {
    case "indicator.matched":
      return "indicator.matched";
    case "incident.created":
      return "incident.created";
    case "incident.severity_changed":
      return "incident.severity_changed";
    case "vulnerability.kev_detected":
      return "vulnerability.kev_detected";
    default:
      return null;
  }
}

type PlaybookTriggerOn = z.infer<typeof PlaybookTrigger>["on"];

/** Map a notification onto SOAR playbook triggers. */
export function playbookTriggerFor(n: EngineNotification): PlaybookTriggerOn | null {
  switch (n.type) {
    case "detection.matched":
      return "alert.created";
    case "indicator.matched":
      return "indicator.matched";
    case "incident.created":
      return "incident.created";
    case "incident.updated":
    case "incident.severity_changed":
      return "incident.updated";
    default:
      return null;
  }
}

/**
 * Flat key/value context for notification templates (`{{severity}}`, `{{title}}` …) so
 * automation templates can render engine outcomes without knowing engine internals.
 */
export function notificationTemplateContext(n: EngineNotification): Record<string, string> {
  const ctx: Record<string, string> = { type: n.type, tenantId: n.tenantId, organizationId: n.organizationId, at: n.at };
  for (const [k, v] of Object.entries(n)) {
    if (k in ctx) continue;
    if (v === null || v === undefined) continue;
    ctx[k] = Array.isArray(v) ? v.map((x) => (typeof x === "object" ? JSON.stringify(x) : String(x))).join(", ") : String(v);
  }
  return ctx;
}
