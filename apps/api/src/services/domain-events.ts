import type { AutomationEvent, Severity } from "@bloody/contracts";
import type { AutomationEnvelope, AutomationSink, PipelineLogger } from "../pipeline/analytics.js";
import type { Metrics } from "../metrics.js";

/**
 * In-process domain event bus. Every state change other modules react to — incident created,
 * severity raised, escalation opened or overdue, approval pending, agent silent, indicator
 * matched, KEV detected, report generated, trial ending, quota exceeded — is published here once,
 * after its transaction committed. Subscribers (automation rules → notification channels,
 * playbook triggers, in-app notifications) run asynchronously, in publication order, and a failing
 * subscriber never affects the publisher or the other subscribers.
 *
 * It also implements the analytics pipeline's `AutomationSink`, so detections, correlations and
 * escalations created by the pipeline flow through the same path as API-originated events.
 */

/** Automation events plus the internal playbook triggers that are not notification events. */
export type DomainEventName = AutomationEvent | "alert.created" | "incident.updated";

export interface DomainEvent {
  tenantId: string;
  /** null = tenant-level event (trial ending, quota exceeded). */
  organizationId: string | null;
  event: DomainEventName;
  occurredAt: string;
  severity?: Severity;
  subject: { kind: string; id: string; label?: string };
  data: Record<string, unknown>;
  /** Throttling / de-duplication key (defaults to subject kind + id downstream). */
  dedupKey?: string;
  /** Who caused it (for playbook execution records). */
  initiatedBy?: { kind: "user" | "service" | "ai" | "system"; id: string };
}

export type DomainEventHandler = (event: DomainEvent) => Promise<void>;

export class DomainEventBus implements AutomationSink {
  private readonly handlers: Array<{ name: string; fn: DomainEventHandler }> = [];
  private tail: Promise<void> = Promise.resolve();
  private pending = 0;
  private closed = false;

  constructor(
    private readonly deps: { log: PipelineLogger; metrics?: Metrics; forward?: AutomationSink | undefined },
  ) {}

  subscribe(name: string, fn: DomainEventHandler): () => void {
    const entry = { name, fn };
    this.handlers.push(entry);
    return () => {
      const i = this.handlers.indexOf(entry);
      if (i >= 0) this.handlers.splice(i, 1);
    };
  }

  /** Queue an event for every subscriber. Never throws and never blocks the caller. */
  publish(event: DomainEvent): void {
    if (this.closed) return;
    this.pending++;
    this.tail = this.tail
      .then(() => this.deliver(event))
      .catch(() => undefined)
      .finally(() => {
        this.pending--;
      });
  }

  /** AutomationSink (analytics pipeline hand-off). */
  emit(envelope: AutomationEnvelope): void {
    this.publish(envelope);
    if (this.deps.forward) {
      try {
        void Promise.resolve(this.deps.forward.emit(envelope)).catch(() => undefined);
      } catch {
        // a broken forward sink must not affect the pipeline
      }
    }
  }

  /** Resolve once every queued event (including events published by subscribers) was handled. */
  async drain(): Promise<void> {
    for (let i = 0; i < 1000 && this.pending > 0; i++) await this.tail;
  }

  get queued(): number {
    return this.pending;
  }

  close(): void {
    this.closed = true;
  }

  private async deliver(event: DomainEvent): Promise<void> {
    for (const h of [...this.handlers]) {
      try {
        await h.fn(event);
      } catch (err) {
        this.deps.metrics?.pipelineErrors.inc({ stage: `domain_event.${h.name}` });
        this.deps.log.warn({ tenantId: event.tenantId, event: event.event, handler: h.name, err: err instanceof Error ? err.message : String(err) }, "domain event handler failed");
      }
    }
  }
}
