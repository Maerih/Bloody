import { describe, expect, it } from "vitest";
import { assertSchemaValid, ctx, fixtureText } from "../test-support/fixtures.js";
import { createNucleiAdapter } from "./nuclei.js";

const events = createNucleiAdapter().normalize(fixtureText("nuclei/findings.jsonl"), ctx());
const [log4j, tech, git] = events;

describe("Nuclei adapter", () => {
  it("maps each JSONL finding to a vulnerability event", () => {
    expect(events).toHaveLength(3);
    assertSchemaValid(events);
  });

  it("CVE template: severity, CVE indicator, classification labels, internet-facing asset", () => {
    expect(log4j?.eventType).toBe("nuclei.vulnerability");
    expect(log4j?.severity).toBe("critical");
    expect(log4j?.timestamp).toBe("2026-10-07T03:10:11.123Z");
    expect(log4j?.indicators).toEqual([{ type: "cve", value: "CVE-2021-44228" }]);
    expect(log4j?.asset).toEqual({ hostname: "portal.acme-corp.example.com", ip: ["93.184.216.34"] });
    expect(log4j?.network).toMatchObject({ protocol: "https", httpUrl: "https://portal.acme-corp.example.com/api/login", direction: "inbound" });
    expect(log4j?.detection).toMatchObject({ ruleId: "CVE-2021-44228", engine: "nuclei", confidence: 0.9 });
    expect(log4j?.labels).toMatchObject({ "vuln.cvss": "10", "vuln.epss": "0.97544", "vuln.cwe": "CWE-502", internet_facing: "true" });
  });

  it("drops request/response bodies and curl reproductions (session cookies)", () => {
    const raw = JSON.stringify(log4j?.provenance.raw);
    expect(raw).not.toContain("SECRET");
    expect(raw).not.toContain("Set-Cookie");
    expect(raw).toContain("CVE-2021-44228");
  });

  it("exposures without CVE and IP-only hosts", () => {
    expect(tech?.eventType).toBe("nuclei.exposure");
    expect(tech?.severity).toBe("info");
    expect(git?.severity).toBe("medium");
    expect(git?.asset).toEqual({ ip: ["203.0.113.200"] });
    expect(git?.network?.dstIp).toBe("203.0.113.200");
  });
});
