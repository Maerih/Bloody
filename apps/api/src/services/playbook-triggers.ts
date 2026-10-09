import type { PlaybookEngine, PlaybookTriggerType } from "@bloody/automation";
import type { Database } from "../db/pool.js";
import type { PipelineLogger } from "../pipeline/analytics.js";
import type { EntitlementService } from "./commercial.js";
import type { DomainEvent, DomainEventHandler } from "./domain-events.js";
import { loadEventContext } from "./event-context.js";

/**
 * Domain events → playbook triggers. Playbooks run only for SOAR-entitled tenants and only for
 * events that belong to an organization; the playbook condition context is the tenant-scoped
 * entity behind the event (incident, alert, escalation…) loaded fresh from the database. The
 * idempotency key is derived from the event, so a redelivered event never starts a second run.
 */

const TRIGGERS: Partial<Record<DomainEvent["event"], PlaybookTriggerType>> = {
  "incident.created": "incident.created",
  "incident.updated": "incident.updated",
  "incident.severity_changed": "incident.updated",
  "incident.closed": "incident.updated",
  "alert.created": "alert.created",
  "indicator.matched": "indicator.matched",
  "escalation.overdue": "escalation.overdue",
};

export function playbookTriggerHandler(deps: { db: Database; engine: PlaybookEngine; entitlements: EntitlementService; log: PipelineLogger; now: () => number }): DomainEventHandler {
  return async (e) => {
    const type = TRIGGERS[e.event];
    if (!type || !e.organizationId) return;
    if (!(await deps.entitlements.isEntitled(e.tenantId, "soar"))) return;
    const ctx = await loadEventContext(deps.db, e, deps.now());
    const result = await deps.engine.handleEvent({
      tenantId: e.tenantId,
      organizationId: e.organizationId,
      type,
      subject: { ...ctx.data, severity: e.severity ?? ctx.data.severity ?? null, organization: { id: e.organizationId, name: ctx.organizationName } },
      subjectRef: e.subject,
      occurredAt: e.occurredAt,
      idempotencyKey: `${e.event}:${e.subject.kind}:${e.subject.id}:${e.occurredAt}`,
      ...(e.initiatedBy ? { initiatedBy: e.initiatedBy } : {}),
    });
    const started = result.matches.filter((m) => m.matched && !m.deduplicated);
    if (started.length > 0) deps.log.info({ tenantId: e.tenantId, event: e.event, playbooks: started.map((m) => m.playbookName) }, "playbooks triggered");
  };
}
