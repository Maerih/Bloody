import { describe, expect, it } from "vitest";
import { assertSchemaValid, byType, ctx, fixtureText } from "../test-support/fixtures.js";
import { createSuricataAdapter, suricataSeverity } from "./suricata.js";

const adapter = createSuricataAdapter();

describe("Suricata EVE adapter", () => {
  const result = adapter.normalizeDetailed(fixtureText("suricata/eve.json"), ctx());

  it("maps alert/dns/http/tls/flow/fileinfo and skips stats", () => {
    expect(result.events.map((e) => e.eventType)).toEqual(["suricata.alert", "suricata.dns", "suricata.http", "suricata.tls", "suricata.flow", "suricata.fileinfo"]);
    expect(result.skipped[0]?.reason).toContain('"stats"');
    assertSchemaValid(result.events);
  });

  it("alert: severity 1 + Major → high, MITRE metadata → attack, sensor from host, TLS app-layer", () => {
    const e = byType(result.events, "suricata.alert");
    expect(e.timestamp).toBe("2026-10-07T10:00:06.123Z");
    expect(e.severity).toBe("high");
    expect(e.detection).toMatchObject({ ruleId: "2027865", engine: "suricata" });
    expect(e.attack).toEqual([{ id: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" }]);
    expect(e.source.sensorId).toBe("ids-sensor-01");
    expect(e.network).toMatchObject({ protocol: "tls", direction: "outbound", tlsSni: "cdn-update.badcdn.net" });
    expect(e.indicators).toEqual(expect.arrayContaining([{ type: "domain", value: "cdn-update.badcdn.net" }, { type: "ip", value: "198.51.100.23" }]));
    expect(e.labels["suricata.category"]).toBe("Domain Observed Used for C2 Detected");
  });

  it("dns answers, http url reconstruction, flow bytes and fileinfo hashes", () => {
    expect(byType(result.events, "suricata.dns").network?.dnsQuery).toBe("cdn-update.badcdn.net");
    expect(byType(result.events, "suricata.http").network?.httpUrl).toBe("http://dl.badcdn.net/payload/stage2.bin");
    const flow = byType(result.events, "suricata.flow");
    expect(flow.network).toMatchObject({ bytesOut: 48211, bytesIn: 1048576 });
    expect(flow.timestamp).toBe("2026-10-07T10:00:04.000Z");
    const fi = byType(result.events, "suricata.fileinfo");
    expect(fi.file).toMatchObject({ name: "/payload/stage2.bin", size: 73802 });
    expect(fi.severity).toBe("low");
  });

  it("severity ladder honours signature_severity", () => {
    expect(suricataSeverity(1)).toBe("high");
    expect(suricataSeverity(2)).toBe("medium");
    expect(suricataSeverity(3)).toBe("low");
    expect(suricataSeverity(3, "Critical")).toBe("critical");
    expect(suricataSeverity(3, "Major")).toBe("high");
    expect(suricataSeverity(1, "Informational")).toBe("high");
  });

  it("never retains header dumps or payloads in provenance", () => {
    const line = JSON.stringify({
      timestamp: "2026-10-07T10:00:00Z",
      event_type: "alert",
      src_ip: "10.0.0.1",
      dest_ip: "198.51.100.1",
      alert: { signature_id: 1, signature: "x", severity: 2 },
      payload: "c2VjcmV0",
      http: { hostname: "a.example.net", url: "/", request_headers: [{ name: "Cookie", value: "session=abc" }] },
    });
    const [e] = adapter.normalize(line, ctx());
    const raw = JSON.stringify(e?.provenance.raw);
    expect(raw).not.toContain("session=abc");
    expect(raw).not.toContain("c2VjcmV0");
  });
});
