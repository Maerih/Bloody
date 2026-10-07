import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from "prom-client";

/** Prometheus metrics, one registry per app instance (tests build many apps per process). */
export class Metrics {
  readonly registry = new Registry();
  readonly httpDuration: Histogram<"method" | "route" | "status_code">;
  readonly ingestEvents: Counter<"result" | "source">;
  readonly ingestBatches: Counter<"source">;
  readonly pipelineEvents: Counter;
  readonly pipelineDetections: Counter<"severity">;
  readonly pipelineIncidents: Counter<"kind">;
  readonly pipelineErrors: Counter<"stage">;
  readonly pipelineBatchDuration: Histogram;
  readonly queueLag: Gauge;
  readonly queueDepth: Gauge;

  constructor(options: { defaultMetrics?: boolean } = {}) {
    this.registry.setDefaultLabels({ service: "bloody-api" });
    if (options.defaultMetrics ?? true) collectDefaultMetrics({ register: this.registry, prefix: "bloody_" });
    this.httpDuration = new Histogram({
      name: "bloody_http_request_duration_seconds",
      help: "HTTP request duration by route template",
      labelNames: ["method", "route", "status_code"],
      buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
      registers: [this.registry],
    });
    this.ingestEvents = new Counter({ name: "bloody_ingest_events_total", help: "Events received by the ingest API", labelNames: ["result", "source"], registers: [this.registry] });
    this.ingestBatches = new Counter({ name: "bloody_ingest_batches_total", help: "Ingest batches accepted", labelNames: ["source"], registers: [this.registry] });
    this.pipelineEvents = new Counter({ name: "bloody_pipeline_events_processed_total", help: "Events processed by the analytics pipeline", registers: [this.registry] });
    this.pipelineDetections = new Counter({ name: "bloody_pipeline_detections_total", help: "Detections (alerts) produced", labelNames: ["severity"], registers: [this.registry] });
    this.pipelineIncidents = new Counter({ name: "bloody_pipeline_incidents_total", help: "Incidents created or updated by correlation", labelNames: ["kind"], registers: [this.registry] });
    this.pipelineErrors = new Counter({ name: "bloody_pipeline_errors_total", help: "Pipeline stage failures", labelNames: ["stage"], registers: [this.registry] });
    this.pipelineBatchDuration = new Histogram({
      name: "bloody_pipeline_batch_duration_seconds",
      help: "Time to process one ingest batch through graph, detection, correlation and risk",
      buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10, 30, 60],
      registers: [this.registry],
    });
    this.queueLag = new Gauge({ name: "bloody_pipeline_queue_lag_seconds", help: "Age of the oldest unprocessed ingest batch", registers: [this.registry] });
    this.queueDepth = new Gauge({ name: "bloody_pipeline_queue_depth", help: "Ingest batches waiting for the pipeline", registers: [this.registry] });
  }
}
