import { describe, expect, it } from "vitest";
import { assertSchemaValid, ctx, fixtureText } from "../test-support/fixtures.js";
import { createOpenCanaryAdapter } from "./opencanary.js";

const result = createOpenCanaryAdapter().normalizeDetailed(fixtureText("opencanary/events.jsonl"), ctx());
const [ssh, http, scan] = result.events;

describe("OpenCanary adapter", () => {
  it("maps honeypot interactions and skips housekeeping log types", () => {
    expect(result.events).toHaveLength(3);
    expect(result.skipped).toEqual([{ index: 3, reason: "OpenCanary housekeeping log type 1001" }]);
    assertSchemaValid(result.events);
  });

  it("SSH login attempt: high severity, T1110, canary node as asset/sensor, attacker indicator", () => {
    expect(ssh?.eventType).toBe("opencanary.ssh_login_attempt");
    expect(ssh?.category).toBe("authentication");
    expect(ssh?.severity).toBe("high");
    expect(ssh?.timestamp).toBe("2026-10-07T10:40:01.120Z");
    expect(ssh?.asset).toEqual({ hostname: "canary-fin-share", ip: ["10.0.9.50"] });
    expect(ssh?.source).toMatchObject({ kind: "network", sensorId: "canary-fin-share" });
    expect(ssh?.identity).toMatchObject({ provider: "honeypot:ssh", principal: "admin", sourceIp: "203.0.113.9", outcome: "failure" });
    expect(ssh?.indicators).toEqual([{ type: "ip", value: "203.0.113.9" }]);
    expect(ssh?.attack[0]?.id).toBe("T1110");
    expect(ssh?.detection?.confidence).toBe(0.95);
    expect(ssh?.labels["canary.password_captured"]).toBe("true");
  });

  it("never stores captured passwords anywhere in the event", () => {
    const serialized = JSON.stringify(result.events);
    expect(serialized).not.toContain("Winter2026!");
    expect(serialized).not.toContain("hunter2");
    expect(JSON.stringify(ssh?.provenance.raw)).toContain("[REDACTED]");
  });

  it("internal attacker (lateral movement) and port scans", () => {
    expect(http?.network?.direction).toBe("lateral");
    expect(http?.indicators).toEqual([]);
    expect(scan?.eventType).toBe("opencanary.port_syn");
    expect(scan?.severity).toBe("medium");
    expect(scan?.attack[0]?.id).toBe("T1046");
  });
});
