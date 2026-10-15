import type { Metrics } from "../metrics.js";
import type { OpenSearchEventIndex } from "../services/opensearch-events.js";
import { TOPICS, type EventBus } from "./event-bus.js";
import type { IngestBatchMessage } from "./ingest.js";

/**
 * Mirrors every committed ingest batch into the search engine. It consumes the same
 * `events.ingested` topic as the analytics pipeline, so it inherits the bus guarantees: ordered per
 * tenant, retried, dead-lettered after max attempts (Kafka). Indexing is idempotent (doc id =
 * tenant:event id), so redelivery is harmless.
 */
export class SearchIndexer {
  private unsubscribe: (() => void) | null = null;

  constructor(
    private readonly deps: { bus: EventBus; index: OpenSearchEventIndex; metrics: Metrics; log: { warn: (obj: object, msg: string) => void } },
  ) {}

  start(): void {
    if (this.unsubscribe) return;
    this.unsubscribe = this.deps.bus.subscribe<IngestBatchMessage>(TOPICS.eventsIngested, async (msg) => {
      const { tenantId, organizationId, events } = msg.payload;
      try {
        const n = await this.deps.index.index(tenantId, organizationId, events);
        this.deps.metrics.searchIndexed.inc({ result: "indexed" }, n);
      } catch (err) {
        this.deps.metrics.searchIndexed.inc({ result: "failed" }, events.length);
        this.deps.log.warn({ err: err instanceof Error ? err.message : String(err), tenantId, events: events.length, attempt: msg.attempt }, "search indexing failed");
        throw err; // let the bus retry / dead-letter
      }
    });
  }

  stop(): void {
    this.unsubscribe?.();
    this.unsubscribe = null;
  }
}
