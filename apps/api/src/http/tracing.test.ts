import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { InMemorySpanExporter } from "@opentelemetry/sdk-trace-base";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, login, type TestApp, type TestTenant } from "../test/harness.js";

const exporter = new InMemorySpanExporter();
let t: TestApp;
let tenant: TestTenant;

beforeAll(async () => {
  t = await createTestApp({ deps: { spanExporter: exporter } });
  tenant = await createTenant(t, { orgs: 1 });
});
afterAll(async () => {
  await t?.close();
});

describe("OpenTelemetry request tracing", () => {
  it("emits a SERVER span per request with route, status and tenant", async () => {
    exporter.reset();
    const client = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
    await client.get(`/incidents?organizationId=${tenant.orgIds[0]}`);
    const span = exporter.getFinishedSpans().find((s) => s.name === "GET /api/v1/incidents");
    expect(span).toBeTruthy();
    expect(span!.attributes["http.response.status_code"]).toBe(200);
    expect(span!.attributes["bloody.tenant_id"]).toBe(tenant.tenantId);
    expect(span!.attributes["url.path"]).toBe("/api/v1/incidents");
    expect(JSON.stringify(span!.attributes)).not.toContain("organizationId=");
    expect(span!.resource.attributes["service.name"]).toBe("bloody-api");
  });

  it("continues an incoming W3C traceparent and returns one", async () => {
    exporter.reset();
    const traceId = "4bf92f3577b34da6a3ce929d0e0e4736";
    const res = await t.app.inject({ method: "GET", url: "/api/v1/healthz", headers: { traceparent: `00-${traceId}-00f067aa0ba902b7-01` } });
    expect(res.headers.traceparent).toMatch(new RegExp(`^00-${traceId}-[0-9a-f]{16}-01$`));
    const span = exporter.getFinishedSpans().find((s) => s.name === "GET /api/v1/healthz");
    expect(span!.spanContext().traceId).toBe(traceId);
    expect(span!.parentSpanId ?? (span as unknown as { parentSpanContext?: { spanId: string } }).parentSpanContext?.spanId).toBe("00f067aa0ba902b7");
  });

  it("is off when no endpoint is configured", async () => {
    const plain = await createTestApp();
    try {
      const res = await plain.app.inject({ method: "GET", url: "/api/v1/healthz" });
      expect(res.headers.traceparent).toBeUndefined();
    } finally {
      await plain.close();
    }
  });

  it("exports over OTLP/HTTP to the configured collector", async () => {
    const received: { path: string; type: string; bytes: number }[] = [];
    const collector = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        received.push({ path: req.url ?? "", type: String(req.headers["content-type"]), bytes: Buffer.concat(chunks).length });
        res.writeHead(200, { "content-type": "application/json" }).end("{}");
      });
    });
    await new Promise<void>((r) => collector.listen(0, "127.0.0.1", r));
    const port = (collector.address() as AddressInfo).port;
    const traced = await createTestApp({ env: { OTEL_EXPORTER_OTLP_ENDPOINT: `http://127.0.0.1:${port}`, OTEL_SERVICE_NAME: "bloody-api-test" } });
    try {
      await traced.app.inject({ method: "GET", url: "/api/v1/healthz" });
    } finally {
      await traced.close(); // shutdown flushes the batch processor
      collector.close();
    }
    expect(received.some((r) => r.path === "/v1/traces" && r.bytes > 0)).toBe(true);
  });
});
