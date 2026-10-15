import { context, SpanKind, SpanStatusCode, trace, type Span, type Tracer } from "@opentelemetry/api";
import { W3CTraceContextPropagator } from "@opentelemetry/core";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { Resource } from "@opentelemetry/resources";
import { BatchSpanProcessor, SimpleSpanProcessor, type SpanExporter } from "@opentelemetry/sdk-trace-base";
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import type { FastifyInstance, FastifyRequest } from "fastify";

export interface TracingOptions {
  /** OTLP/HTTP base endpoint (OTEL_EXPORTER_OTLP_ENDPOINT), e.g. http://otel-collector:4318. */
  endpoint?: string | null;
  serviceName?: string;
  serviceVersion?: string;
  /** OTEL_RESOURCE_ATTRIBUTES ("k=v,k2=v2"). */
  resourceAttributes?: string;
  /** Tests inject an in-memory exporter (spans exported synchronously). */
  exporter?: SpanExporter;
}

const SPAN = Symbol("bloodySpan");
type TracedRequest = FastifyRequest & { [SPAN]?: Span };

function parseAttributes(raw: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (raw ?? "").split(",")) {
    const i = part.indexOf("=");
    if (i > 0) out[decodeURIComponent(part.slice(0, i).trim())] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

/**
 * OpenTelemetry tracing for the control plane: one SERVER span per HTTP request, continuing an
 * incoming W3C `traceparent`, exported over OTLP/HTTP to the OpenTelemetry Collector. Disabled
 * (zero overhead) unless an endpoint or exporter is configured. Spans carry route patterns, status
 * codes and the tenant id — never request bodies, credentials or query strings.
 */
export function registerTracing(app: FastifyInstance, opts: TracingOptions): Tracer | null {
  const exporter = opts.exporter ?? (opts.endpoint ? new OTLPTraceExporter({ url: `${opts.endpoint.replace(/\/+$/, "")}/v1/traces` }) : null);
  if (!exporter) return null;
  const provider = new NodeTracerProvider({
    resource: new Resource({
      ...parseAttributes(opts.resourceAttributes),
      "service.name": opts.serviceName ?? "bloody-api",
      "service.version": opts.serviceVersion ?? "0.0.0",
    }),
    spanProcessors: [opts.exporter ? new SimpleSpanProcessor(exporter) : new BatchSpanProcessor(exporter)],
  });
  const tracer = provider.getTracer("bloody-api");
  const propagator = new W3CTraceContextPropagator();

  app.addHook("onRequest", async (request) => {
    const parent = propagator.extract(context.active(), request.headers, {
      get: (carrier, key) => {
        const v = (carrier as Record<string, string | string[] | undefined>)[key];
        return Array.isArray(v) ? v[0] : v;
      },
      keys: (carrier) => Object.keys(carrier as object),
    });
    const route = request.routeOptions.url ?? "unmatched";
    (request as TracedRequest)[SPAN] = tracer.startSpan(
      `${request.method} ${route}`,
      { kind: SpanKind.SERVER, attributes: { "http.request.method": request.method, "http.route": route, "url.path": request.url.split("?")[0] ?? "", "bloody.request_id": request.id } },
      parent,
    );
  });

  app.addHook("onResponse", async (request, reply) => {
    const span = (request as TracedRequest)[SPAN];
    if (!span) return;
    span.setAttribute("http.response.status_code", reply.statusCode);
    const tenantId = (request as FastifyRequest & { auth?: { tenantId?: string } }).auth?.tenantId;
    if (tenantId) span.setAttribute("bloody.tenant_id", tenantId);
    if (reply.statusCode >= 500) span.setStatus({ code: SpanStatusCode.ERROR });
    span.end();
  });

  app.addHook("onSend", async (request, reply, payload) => {
    const span = (request as TracedRequest)[SPAN];
    if (span) {
      const carrier: Record<string, string> = {};
      propagator.inject(trace.setSpan(context.active(), span), carrier, { set: (c, k, v) => ((c as Record<string, string>)[k] = v) });
      if (carrier.traceparent) void reply.header("traceparent", carrier.traceparent);
    }
    return payload;
  });

  app.addHook("onClose", async () => {
    await provider.shutdown();
  });
  return tracer;
}
