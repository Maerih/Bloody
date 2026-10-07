import { describe, expect, it } from "vitest";
import { assertSchemaValid, ctx, fixtureText } from "../test-support/fixtures.js";
import { createTrivyAdapter, trivyCvss } from "./trivy.js";

const adapter = createTrivyAdapter();
const events = adapter.normalize(fixtureText("trivy/image-report.json"), ctx());

describe("Trivy adapter", () => {
  it("emits one event per vulnerability, failed misconfiguration and secret", () => {
    expect(events.map((e) => e.eventType)).toEqual(["trivy.vulnerability", "trivy.vulnerability", "trivy.vulnerability", "trivy.misconfiguration", "trivy.secret"]);
    assertSchemaValid(events);
  });

  it("vulnerability events carry CVE, CVSS (NVD preferred), package and fix data", () => {
    const xz = events[0];
    expect(xz?.category).toBe("vulnerability");
    expect(xz?.severity).toBe("critical");
    expect(xz?.timestamp).toBe("2026-10-07T06:00:00.123Z");
    expect(xz?.indicators).toEqual([{ type: "cve", value: "CVE-2024-3094" }]);
    expect(xz?.labels).toMatchObject({
      "vuln.cvss": "10",
      "vuln.cvss_source": "nvd",
      "pkg.name": "xz-utils",
      "pkg.fixed_version": "5.6.1+really5.4.5-1",
      "vuln.patch_available": "true",
      "artifact.name": "registry.local/payments-api:2.4.1",
      "artifact.os": "debian 12.5",
    });
    expect(events[2]?.labels["vuln.patch_available"]).toBe("false");
    expect(events[2]?.action).toBe("affected");
  });

  it("only failed misconfigurations by default; secrets never keep the matched value", () => {
    expect(events.filter((e) => e.eventType === "trivy.misconfiguration")).toHaveLength(1);
    const withPassed = adapter.normalize(fixtureText("trivy/image-report.json"), ctx({ options: { includePassedMisconfigurations: true } }));
    expect(withPassed.filter((e) => e.eventType === "trivy.misconfiguration")).toHaveLength(2);
    const secret = events[4];
    expect(secret?.severity).toBe("critical");
    expect(secret?.attack[0]?.id).toBe("T1552.001");
    expect(JSON.stringify(secret)).not.toContain("AKIA");
    expect(JSON.stringify(events[3]?.provenance.raw)).not.toContain("FROM debian");
  });

  it("k8s reports map resources to kubernetes cloud resources", () => {
    const [e] = adapter.normalize(fixtureText("trivy/k8s-report.json"), ctx());
    expect(e?.cloudResource).toEqual({ provider: "kubernetes", accountId: "prod-eks", resourceType: "Deployment", resourceId: "prod/payments-api" });
    expect(e?.severity).toBe("high");
  });

  it("attributes host scans only when the collector names the host", () => {
    const [e] = adapter.normalize(fixtureText("trivy/image-report.json"), ctx({ options: { hostname: "build-02" } }));
    expect(e?.asset?.hostname).toBe("build-02");
    expect(events[0]?.asset).toBeUndefined();
  });

  it("CVSS selection falls back across vendors and versions", () => {
    expect(trivyCvss({ redhat: { V3Score: 8.1 }, nvd: { V2Score: 5 } })).toEqual({ score: 8.1, source: "redhat" });
    expect(trivyCvss({ nvd: { V2Score: 5, V2Vector: "AV:N" } })).toEqual({ score: 5, vector: "AV:N", source: "nvd" });
    expect(trivyCvss(undefined)).toEqual({});
  });
});
