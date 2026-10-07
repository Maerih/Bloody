import { describe, expect, it } from "vitest";
import { parseXml, XmlParseError, xmlText } from "../core/xml.js";
import { assertSchemaValid, ctx, fixtureText } from "../test-support/fixtures.js";
import { createGreenboneAdapter } from "./greenbone.js";

const adapter = createGreenboneAdapter();

describe("Greenbone / OpenVAS adapter", () => {
  const result = adapter.normalizeDetailed(fixtureText("greenbone/report.xml"), ctx());

  it("parses GMP get_reports XML: one event per result, False Positive overrides skipped", () => {
    expect(result.records).toBe(4);
    expect(result.events).toHaveLength(3);
    expect(result.skipped).toEqual([{ index: 2, reason: "result overridden as False Positive" }]);
    assertSchemaValid(result.events);
  });

  it("maps severity, CVE refs, host/port, QoD confidence and VendorFix solution", () => {
    const e = result.events[0];
    expect(e?.eventType).toBe("greenbone.vulnerability");
    expect(e?.severity).toBe("high");
    expect(e?.message).toBe("Apache HTTP Server < 2.4.59 Multiple Vulnerabilities on 443/tcp");
    expect(e?.indicators).toEqual([
      { type: "cve", value: "CVE-2024-27316" },
      { type: "cve", value: "CVE-2024-24795" },
    ]);
    expect(e?.asset).toEqual({ hostname: "www.acme-corp.example.com", ip: ["203.0.113.10"] });
    expect(e?.network).toEqual({ dstIp: "203.0.113.10", dstPort: 443, protocol: "tcp" });
    expect(e?.detection).toMatchObject({ ruleId: "1.3.6.1.4.1.25623.1.0.126670", confidence: 0.8 });
    expect(e?.labels).toMatchObject({
      "vuln.patch_available": "true",
      "vuln.cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
      "greenbone.task": "ACME weekly external scan",
      "greenbone.report_id": "7a7b1f0e-1111-4c5e-9d1a-0f0e0d0c0b0a",
    });
  });

  it("Log results are informational; minQod filters low-quality detections", () => {
    expect(result.events[1]?.severity).toBe("info");
    expect(result.events[1]?.network).toBeUndefined();
    const strict = adapter.normalizeDetailed(fixtureText("greenbone/report.xml"), ctx({ options: { minQod: 70 } }));
    expect(strict.events).toHaveLength(2);
    expect(strict.skipped.some((s) => s.reason.includes("quality of detection 50"))).toBe(true);
  });

  it("accepts the JSON export shape", () => {
    const [e] = adapter.normalize(fixtureText("greenbone/results.json"), ctx());
    expect(e?.indicators).toEqual([{ type: "cve", value: "CVE-2024-6387" }]);
    expect(e?.severity).toBe("high");
    expect(e?.asset?.hostname).toBe("bastion.acme-corp.example.com");
  });

  it("refuses DOCTYPE / entity declarations (XXE, billion laughs)", () => {
    const evil = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><get_reports_response><report><results><result id="1"><name>&x;</name></result></results></report></get_reports_response>';
    const r = adapter.normalizeDetailed(evil, ctx());
    expect(r.events).toHaveLength(0);
    expect(r.rejected[0]?.reason).toContain("not allowed");
    expect(() => parseXml(evil)).toThrow(XmlParseError);
  });

  it("XML parser decodes entities/CDATA and rejects malformed nesting", () => {
    const doc = parseXml("<a x='1 &amp; 2'><b>&lt;tag&gt; &#65;&#x42;</b><c><![CDATA[<raw & text>]]></c><d/></a>");
    expect(doc.attrs["x"]).toBe("1 & 2");
    expect(xmlText(doc, "b")).toBe("<tag> AB");
    expect(xmlText(doc, "c")).toBe("<raw & text>");
    expect(() => parseXml("<a><b></a></b>")).toThrow(/mismatched/);
    expect(() => parseXml("<a><b>")).toThrow(/unclosed/);
  });
});
