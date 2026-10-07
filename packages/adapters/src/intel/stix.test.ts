import { describe, expect, it } from "vitest";
import { fixtureText } from "../test-support/fixtures.js";
import { parseStixBundle, parseStixPattern } from "./stix.js";
import { IndicatorRecord } from "./types.js";

const NOW = "2026-10-07T12:00:00.000Z";

describe("STIX 2.1 patterns", () => {
  it("extracts atomic observables joined by OR", () => {
    const r = parseStixPattern("[domain-name:value = 'evil.example.net'] OR [url:value = 'http://evil.example.net/a'] OR [file:hashes.'SHA-256' = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA']");
    expect(r.conjunctive).toBe(false);
    expect(r.observables).toEqual([
      { type: "domain", value: "evil.example.net" },
      { type: "url", value: "http://evil.example.net/a" },
      { type: "sha256", value: "a".repeat(64) },
    ]);
  });

  it("keeps only hashes from conjunctive expressions and rejects CIDR / non-equality", () => {
    const r = parseStixPattern("[ipv4-addr:value = '203.0.113.5' AND network-traffic:dst_port = 4444] AND [file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']");
    expect(r.conjunctive).toBe(true);
    expect(r.observables).toEqual([{ type: "md5", value: "d41d8cd98f00b204e9800998ecf8427e" }]);
    expect(r.unsupported.join(";")).toContain("conjunctive");
    expect(parseStixPattern("[ipv4-addr:value = '198.51.100.0/24']").observables).toEqual([]);
    expect(parseStixPattern("[ipv4-addr:value = '198.51.100.7/32']").observables).toEqual([{ type: "ip", value: "198.51.100.7" }]);
    expect(parseStixPattern("[url:value LIKE '%evil%']").observables).toEqual([]);
    // escaped quotes inside string literals are decoded
    expect(parseStixPattern("[email-addr:value = 'it\\'s@evil.example.net']").observables).toEqual([{ type: "email", value: "it's@evil.example.net" }]);
  });
});

describe("STIX 2.1 bundles", () => {
  const out = parseStixBundle(fixtureText("stix/bundle.json"), { now: NOW, source: "stix:acme-feed" });

  it("produces validated records and explains every skip", () => {
    expect(out.records).toHaveLength(3);
    for (const r of out.records) expect(IndicatorRecord.safeParse(r).success).toBe(true);
    const reasons = out.skipped.map((s) => s.reason).join(" | ");
    expect(reasons).toContain("benign indicator");
    expect(reasons).toContain("CIDR");
    expect(reasons).toContain('pattern type "snort"');
  });

  it("resolves indicates-relationships, TLP marking ids and external references", () => {
    const domain = out.records.find((r) => r.type === "domain");
    expect(domain).toMatchObject({
      value: "cdn-update.badcdn.net",
      externalRef: "stix:indicator--a1#0",
      source: "stix:acme-feed",
      confidence: 90,
      severity: "high",
      tlp: "amber",
      malware: "Cobalt Strike",
      threatActor: "FIN-SPIDER",
      references: ["https://intel.acme.example/r/9"],
      tags: ["c2"],
    });
    expect(domain?.attack).toEqual([{ id: "T1071.001", name: "Web Protocols", tactic: "Command and Control" }]);
    expect(out.records.find((r) => r.type === "url")?.externalRef).toBe("stix:indicator--a1#1");
  });

  it("caps confidence for conjunctive patterns and explains it", () => {
    const md5 = out.records.find((r) => r.type === "md5");
    expect(md5).toMatchObject({ confidence: 80, severity: "medium" });
    expect(md5?.scoring.join(" ")).toContain("conjunctive");
  });

  it("rejects non-bundles and invalid JSON", () => {
    expect(parseStixBundle("{", { now: NOW }).skipped[0]?.reason).toBe("invalid JSON");
    expect(parseStixBundle({ hello: "world" }, { now: NOW }).skipped[0]?.reason).toBe("not a STIX bundle");
  });
});
