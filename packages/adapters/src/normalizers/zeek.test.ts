import { describe, expect, it } from "vitest";
import { assertSchemaValid, byType, ctx, fixtureText } from "../test-support/fixtures.js";
import { createZeekAdapter, zeekLogType } from "./zeek.js";

const adapter = createZeekAdapter();

describe("Zeek adapter", () => {
  const result = adapter.normalizeDetailed(fixtureText("zeek/mixed.jsonl"), ctx());

  it("maps conn/dns/http/ssl/files/notice and skips unmodelled logs", () => {
    expect(result.events.map((e) => e.eventType)).toEqual(["zeek.conn", "zeek.conn", "zeek.dns", "zeek.http", "zeek.ssl", "zeek.files", "zeek.notice"]);
    expect(result.skipped).toEqual([{ index: 7, reason: 'Zeek log "weird" is not modelled' }]);
    assertSchemaValid(result.events);
  });

  it("conn: epoch ts, byte counts from the originator's view, local_orig/local_resp direction", () => {
    const [ok, rejected] = result.events;
    expect(ok?.timestamp).toBe("2026-10-07T08:00:00.123Z");
    expect(ok?.network).toMatchObject({ srcIp: "10.0.10.21", dstIp: "198.51.100.23", dstPort: 443, protocol: "ssl", direction: "outbound", bytesOut: 48211, bytesIn: 1048576 });
    expect(ok?.outcome).toBe("success");
    expect(ok?.labels["zeek.conn_state"]).toBe("SF");
    expect(rejected?.network?.direction).toBe("inbound");
    expect(rejected?.outcome).toBe("failure");
  });

  it("dns / http / ssl carry protocol fields and observables", () => {
    const dns = byType(result.events, "zeek.dns");
    expect(dns.network?.dnsQuery).toBe("cdn-update.badcdn.net");
    expect(dns.indicators).toEqual(expect.arrayContaining([{ type: "domain", value: "cdn-update.badcdn.net" }, { type: "ip", value: "198.51.100.23" }]));
    const http = byType(result.events, "zeek.http");
    expect(http.network).toMatchObject({ httpHost: "dl.badcdn.net", httpUrl: "http://dl.badcdn.net/payload/stage2.bin" });
    expect(http.indicators).toContainEqual({ type: "user_agent", value: "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" });
    const ssl = byType(result.events, "zeek.ssl");
    expect(ssl.network).toMatchObject({ tlsSni: "cdn-update.badcdn.net" });
    expect(ssl.network?.ja3).toMatch(/^[0-9a-f]{32}$/);
    expect(ssl.severity).toBe("low");
  });

  it("files: executable transferred inbound gets low severity with an explanation", () => {
    const f = byType(result.events, "zeek.files");
    expect(f.file).toMatchObject({ name: "stage2.bin", size: 73802 });
    expect(f.network).toMatchObject({ srcIp: "198.51.100.99", dstIp: "10.0.10.21", direction: "inbound" });
    expect(f.severity).toBe("low");
    expect(f.labels["severity_basis"]).toBe("executable file transferred from outside");
  });

  it("notice: Scan::Port_Scan → detection with T1046", () => {
    const n = byType(result.events, "zeek.notice");
    expect(n.category).toBe("detection");
    expect(n.severity).toBe("medium");
    expect(n.detection).toEqual({ ruleId: "Scan::Port_Scan", ruleName: expect.stringContaining("scanned"), engine: "zeek" });
    expect(n.attack).toEqual([{ id: "T1046", name: "Network Service Discovery", tactic: "Discovery" }]);
  });

  it("infers the log type for single-log files without _path", () => {
    const events = adapter.normalize(fixtureText("zeek/conn.log"), ctx());
    expect(events).toHaveLength(1);
    expect(events[0]?.eventType).toBe("zeek.conn");
    expect(zeekLogType({ query: "x", qtype_name: "A" })).toBe("dns");
    expect(zeekLogType({ note: "x", msg: "y" })).toBe("notice");
    expect(zeekLogType({ anything: 1 }, "ssl")).toBe("ssl");
  });
});
