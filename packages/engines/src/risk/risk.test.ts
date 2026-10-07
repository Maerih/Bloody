import { RiskAssessment as RiskAssessmentSchema, severityFromScore } from "@bloody/contracts";
import { describe, expect, it } from "vitest";
import { ManualClock } from "../util/clock.js";
import { calibrate, computeRisk, type ExplainedRiskAssessment, type FactorInput } from "./model.js";
import { RiskEngine, type AssetRiskInput } from "./risk-engine.js";

function contributionSum(a: ExplainedRiskAssessment): number {
  return a.factors.reduce((s, f) => s + f.contribution, 0);
}

function expectExplained(a: ExplainedRiskAssessment) {
  expect(Math.abs(contributionSum(a) - a.score)).toBeLessThan(1e-6);
  expect(a.severity).toBe(severityFromScore(a.score));
  expect(a.score).toBeGreaterThanOrEqual(0);
  expect(a.score).toBeLessThanOrEqual(100);
  expect(a.summary.length).toBeGreaterThan(10);
  for (const f of a.factors) {
    expect(f.explanation.length).toBeGreaterThan(3);
    if (f.group === "control") {
      expect(f.contribution).toBeLessThanOrEqual(0);
      expect(f.weight).toBeLessThanOrEqual(0);
    } else expect(f.contribution).toBeGreaterThanOrEqual(0);
  }
  // conforms to the shared contract
  expect(RiskAssessmentSchema.safeParse(a).success).toBe(true);
}

/** Deterministic PRNG (mulberry32) for property-style tests. */
function rng(seed: number) {
  let t = seed;
  return () => {
    t += 0x6d2b79f5;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

describe("risk model math", () => {
  it("calibration curve is monotone with f(0)=0, f(1)=1 and documented anchors", () => {
    expect(calibrate(0)).toBe(0);
    expect(calibrate(1)).toBeCloseTo(1, 10);
    let prev = -1;
    for (let r = 0; r <= 1.0001; r += 0.01) {
      const v = calibrate(r);
      expect(v).toBeGreaterThan(prev);
      prev = v;
    }
    expect(100 * calibrate(0.25)).toBeCloseTo(40.5, 0);
    expect(100 * calibrate(0.49)).toBeCloseTo(78.4, 0);
    expect(100 * calibrate(0.64)).toBeCloseTo(90.9, 0);
    expect(100 * calibrate(0.09)).toBeCloseTo(12.2, 0);
  });

  it("combines likelihood × impact (both required)", () => {
    const L: FactorInput[] = [{ key: "l", label: "L", value: 1, weight: 0.9, explanation: "x" }];
    const I: FactorInput[] = [{ key: "i", label: "I", value: 1, weight: 0.9, explanation: "x" }];
    expect(computeRisk({ subject: "s", likelihood: L, impact: [] }).score).toBe(0);
    expect(computeRisk({ subject: "s", likelihood: [], impact: I }).score).toBe(0);
    const both = computeRisk({ subject: "s", likelihood: L, impact: I });
    expect(both.likelihood).toBeCloseTo(0.9);
    expect(both.impact).toBeCloseTo(0.9);
    expect(both.score).toBeCloseTo(100 * calibrate(0.81), 1);
  });

  it("is not a sum: repeated weak signals saturate below one strong signal", () => {
    const impact: FactorInput[] = [{ key: "c", label: "C", value: 1, weight: 0.85, explanation: "x" }];
    const weak = Array.from({ length: 200 }, (_, i) => ({ key: `w${i}`, label: "weak", value: 0.05, weight: 0.5, explanation: "x" }));
    const many = computeRisk({ subject: "s", likelihood: weak, impact });
    const one = computeRisk({ subject: "s", likelihood: [{ key: "s", label: "strong", value: 1, weight: 0.95, explanation: "x" }], impact });
    expect(many.score).toBeLessThan(100);
    expect(one.score).toBeGreaterThan(computeRisk({ subject: "s", likelihood: weak.slice(0, 10), impact }).score);
  });

  it("controls only reduce, and inherent score reflects the score without them", () => {
    const base = { subject: "s", likelihood: [{ key: "l", label: "L", value: 1, weight: 0.8, explanation: "x" }], impact: [{ key: "i", label: "I", value: 1, weight: 0.85, explanation: "x" }] };
    const without = computeRisk(base);
    const withCtl = computeRisk({ ...base, controls: [{ key: "edr", label: "EDR", value: 1, weight: 0.3, explanation: "x" }] });
    expect(withCtl.score).toBeLessThan(without.score);
    expect(withCtl.inherentScore).toBeCloseTo(without.score, 1);
    expect(withCtl.factors.find((f) => f.key === "edr")!.contribution).toBeCloseTo(withCtl.score - withCtl.inherentScore, 0);
    expect(withCtl.summary).toMatch(/reduced by .* through edr/);
  });

  it("contributions sum exactly to the score for 500 random factor sets", () => {
    const rand = rng(42);
    for (let n = 0; n < 500; n++) {
      const mk = (k: string, count: number): FactorInput[] => Array.from({ length: count }, (_, i) => ({ key: `${k}${i}`, label: `${k}${i}`, value: rand(), weight: rand(), explanation: "random" }));
      const a = computeRisk({ subject: "random", likelihood: mk("l", Math.floor(rand() * 8)), impact: mk("i", Math.floor(rand() * 5)), controls: mk("c", Math.floor(rand() * 4)) });
      expectExplained(a);
    }
  });

  it("explains an empty input", () => {
    const a = computeRisk({ subject: "Nothing", likelihood: [], impact: [] });
    expect(a.score).toBe(0);
    expect(a.summary).toMatch(/no risk signals/);
  });
});

describe("RiskEngine.scoreAsset", () => {
  const engine = new RiskEngine();
  const exposedCrownJewel: AssetRiskInput = {
    asset: { name: "pay-gw", criticality: "crown_jewel", internetFacing: true },
    exposure: { exposedServices: ["https", "ssh"], exposedAdminInterfaces: 1 },
    vulnerabilities: [
      { cve: "CVE-2024-3400", cvss: 10, epss: 0.96, knownExploited: true, severity: "critical", status: "open" },
      { cve: "CVE-2023-0001", cvss: 5.3, epss: 0.01, severity: "medium", status: "resolved" },
    ],
    identities: [{ principal: "da-admin", privileged: true }],
  };

  it("scores an internet-facing crown jewel with a KEV vulnerability as critical/high and explains why", () => {
    const a = engine.scoreAsset(exposedCrownJewel);
    expectExplained(a);
    expect(a.score).toBeGreaterThanOrEqual(85);
    const keys = a.factors.map((f) => f.key);
    expect(keys).toEqual(expect.arrayContaining(["exposure", "exploitability", "active_exploitation", "criticality", "identity_privilege"]));
    expect(a.factors.find((f) => f.key === "active_exploitation")!.explanation).toContain("CVE-2024-3400");
    expect(a.factors.find((f) => f.key === "vulnerability_severity")!.explanation).not.toContain("medium"); // resolved findings ignored
    expect(a.modelVersion).toMatch(/#asset$/);
  });

  it("lower exposure, lower criticality and compensating controls each lower the score", () => {
    const base = engine.scoreAsset(exposedCrownJewel).score;
    expect(engine.scoreAsset({ ...exposedCrownJewel, asset: { ...exposedCrownJewel.asset, internetFacing: false } }).score).toBeLessThan(base);
    expect(engine.scoreAsset({ ...exposedCrownJewel, asset: { ...exposedCrownJewel.asset, criticality: "low" } }).score).toBeLessThan(base);
    const ctl = engine.scoreAsset({ ...exposedCrownJewel, controls: { edr: true, segmentation: true, virtualPatching: true } });
    expectExplained(ctl);
    expect(ctl.score).toBeLessThan(base);
    expect(ctl.factors.filter((f) => f.group === "control").map((f) => f.key).sort()).toEqual(["edr", "segmentation", "virtual_patching"]);
  });

  it("does not sum alerts: 50 copies of one alert ≈ one alert", () => {
    const one = engine.scoreAsset({ asset: { name: "ws", criticality: "medium", internetFacing: false }, detections: [{ ruleId: "r1", title: "Encoded PowerShell", severity: "high", confidence: 0.7 }] });
    const fifty = engine.scoreAsset({ asset: { name: "ws", criticality: "medium", internetFacing: false }, detections: Array.from({ length: 50 }, () => ({ ruleId: "r1", title: "Encoded PowerShell", severity: "high" as const, confidence: 0.7 })) });
    expect(fifty.score).toBeCloseTo(one.score, 5);
    const two = engine.scoreAsset({ asset: { name: "ws", criticality: "medium", internetFacing: false }, detections: [{ ruleId: "r1", severity: "high", confidence: 0.7 }, { ruleId: "r2", severity: "high", confidence: 0.7 }] });
    expect(two.score).toBeGreaterThan(one.score);
  });

  it("uses intel, history, attack paths, blast radius and business impact", () => {
    const a = engine.scoreAsset({
      asset: { name: "erp", criticality: "high", internetFacing: false },
      intelMatches: [{ value: "198.51.100.23", confidence: 90, severity: "critical", threatActor: "TA-Example" }],
      history: { incidentsLast90d: 2, anomalyScore: 0.4 },
      attackPaths: { total: 3, toCrownJewels: 2 },
      blastRadius: { reachableNodes: 40, reachableCrownJewels: 1 },
      businessImpact: { dataSensitivity: "restricted", regulated: true },
    });
    expectExplained(a);
    expect(a.factors.map((f) => f.key)).toEqual(expect.arrayContaining(["threat_intel", "historical_behavior", "attack_path", "blast_radius", "business_impact"]));
    expect(a.factors.find((f) => f.key === "threat_intel")!.explanation).toContain("TA-Example");
  });

  it("honours tenant weight overrides", () => {
    const tuned = new RiskEngine({ weights: { "asset.exposure": 0 } });
    const a = tuned.scoreAsset({ asset: { name: "x", criticality: "high", internetFacing: true } });
    expect(a.factors.find((f) => f.key === "exposure")!.contribution).toBe(0);
  });
});

describe("RiskEngine.scoreIdentity", () => {
  const clock = new ManualClock("2026-06-01T00:00:00Z");
  const engine = new RiskEngine({ clock });
  it("privileged identity without MFA and with leaked credentials is high risk; MFA lowers it", () => {
    const input = {
      identity: { principal: "da-admin", privileged: true, mfaEnabled: false },
      adminOfAssets: 25,
      crownJewelAccess: 2,
      credentialExposure: { leaked: true, cachedOnHosts: 6 },
      signIns: { impossibleTravel: 1, failures: 30 },
    };
    const noMfa = engine.scoreIdentity(input);
    expectExplained(noMfa);
    expect(noMfa.score).toBeGreaterThanOrEqual(70);
    const mfa = engine.scoreIdentity({ ...input, identity: { ...input.identity, mfaEnabled: true } });
    expect(mfa.score).toBeLessThan(noMfa.score);
    expect(mfa.factors.find((f) => f.key === "mfa")).toBeDefined();
    const disabled = engine.scoreIdentity({ ...input, identity: { ...input.identity, enabled: false } });
    expect(disabled.score).toBeLessThan(15);
  });
  it("flags dormant privileged accounts using the injected clock", () => {
    const a = engine.scoreIdentity({ identity: { principal: "old-admin", privileged: true, mfaEnabled: false, lastActivityAt: "2025-09-01T00:00:00Z" } });
    expectExplained(a);
    expect(a.factors.find((f) => f.key === "dormancy")!.explanation).toMatch(/No activity for 273 days/);
    const recent = engine.scoreIdentity({ identity: { principal: "fresh", privileged: true, mfaEnabled: false, lastActivityAt: "2026-05-30T00:00:00Z" } });
    expect(recent.factors.find((f) => f.key === "dormancy")).toBeUndefined();
  });
  it("treats non-human identities as broader impact", () => {
    const svc = engine.scoreIdentity({ identity: { principal: "ci-deployer", kind: "service_principal", privileged: false, mfaEnabled: false }, credentialExposure: { nonExpiringPassword: true } });
    expect(svc.factors.find((f) => f.key === "identity_type")!.value).toBeCloseTo(0.7);
  });
});

describe("RiskEngine.scoreIncident", () => {
  const engine = new RiskEngine();
  const alerts = [
    { ruleId: "office", title: "Office spawned shell", severity: "high" as const, confidence: 0.8, source: "wazuh", attack: [{ id: "T1204.002", tactic: "execution" }] },
    { ruleId: "lsass", title: "LSASS access", severity: "critical" as const, confidence: 0.8, source: "wazuh", attack: [{ id: "T1003.001" }] },
    { ruleId: "beacon", title: "DNS beaconing", severity: "medium" as const, confidence: 0.6, source: "zeek", attack: [{ id: "T1071.004" }] },
  ];
  it("multi-stage, multi-source incidents on critical assets score higher than a lone alert", () => {
    const multi = engine.scoreIncident({ title: "Intrusion", alerts, assets: [{ name: "ws-042", criticality: "high" }, { name: "dc-01", criticality: "crown_jewel" }], identities: [{ principal: "bob", privileged: true }] });
    const lone = engine.scoreIncident({ alerts: alerts.slice(0, 1), assets: [{ criticality: "medium" }], identities: [] });
    expectExplained(multi);
    expectExplained(lone);
    expect(multi.score).toBeGreaterThan(lone.score);
    expect(multi.factors.find((f) => f.key === "attack_progression")!.explanation).toMatch(/credential-access/);
    expect(multi.factors.find((f) => f.key === "corroboration")!.explanation).toMatch(/2 source/);
  });
  it("containment and closure reduce the score", () => {
    const base = { alerts, assets: [{ criticality: "high" as const, edr: true }], identities: [] };
    const open = engine.scoreIncident(base).score;
    const contained = engine.scoreIncident({ ...base, status: "contained" }).score;
    const closed = engine.scoreIncident({ ...base, status: "closed" }).score;
    expect(contained).toBeLessThan(open);
    expect(closed).toBeLessThan(contained);
  });
  it("exfiltration / impact tactics raise impact", () => {
    const withImpact = engine.scoreIncident({ alerts: [{ ruleId: "x", severity: "high", confidence: 0.8, attack: [{ id: "T1486" }] }], assets: [{ criticality: "medium" }], identities: [] });
    expect(withImpact.factors.find((f) => f.key === "impact_tactics")).toBeDefined();
  });
});

describe("RiskEngine.scoreVulnerability — risk-based prioritization", () => {
  const engine = new RiskEngine();
  it("KEV on an internet-facing asset is P1 patch_now", () => {
    const p = engine.scoreVulnerability({ vulnerability: { cve: "CVE-2024-3400", title: "PAN-OS RCE", cvss: 10, epss: 0.96, knownExploited: true, patchAvailable: true }, asset: { name: "vpn-gw", criticality: "high", internetFacing: true } });
    expectExplained(p);
    expect(p.priority).toBe("P1");
    expect(p.recommendedAction).toBe("patch_now");
    expect(p.slaDays).toBe(7);
    expect(p.rationale).toMatch(/known exploited/);
  });
  it("a high CVSS but unlikely-to-be-exploited internal finding ranks below a medium CVSS KEV", () => {
    const highCvss = engine.scoreVulnerability({ vulnerability: { cve: "CVE-A", title: "a", cvss: 9.8, epss: 0.002, knownExploited: false }, asset: { name: "lab", criticality: "low", internetFacing: false } });
    const kev = engine.scoreVulnerability({ vulnerability: { cve: "CVE-B", title: "b", cvss: 6.5, epss: 0.4, knownExploited: true }, asset: { name: "lab", criticality: "low", internetFacing: false } });
    expect(kev.score).toBeGreaterThan(highCvss.score);
    expect(["P3", "P4"]).toContain(highCvss.priority);
  });
  it("no vendor patch → mitigate; mitigation status reduces risk", () => {
    const p = engine.scoreVulnerability({ vulnerability: { cve: "CVE-Z", title: "zero-day", cvss: 9.8, epss: 0.9, knownExploited: true, patchAvailable: false }, asset: { name: "edge", criticality: "crown_jewel", internetFacing: true } });
    expect(p.recommendedAction).toBe("mitigate");
    expect(p.factors.find((f) => f.key === "no_patch")).toBeDefined();
    const mitigated = engine.scoreVulnerability({ vulnerability: { cve: "CVE-Z", title: "zero-day", cvss: 9.8, epss: 0.9, knownExploited: true, patchAvailable: false, status: "mitigated" }, asset: { name: "edge", criticality: "crown_jewel", internetFacing: true } });
    expect(mitigated.score).toBeLessThan(p.score);
  });
  it("estimates exploit likelihood from CVSS when EPSS is missing", () => {
    const p = engine.scoreVulnerability({ vulnerability: { title: "no epss", cvss: 7.5 }, asset: { name: "a", criticality: "medium", internetFacing: false } });
    expect(p.factors.find((f) => f.key === "exploit_prediction")!.label).toMatch(/estimated/);
    expectExplained(p);
  });
});

describe("RiskEngine.exposureScore", () => {
  const engine = new RiskEngine();
  it("does not reduce to a vulnerability count", () => {
    const manyLowVulns = engine.exposureScore({
      assets: { total: 500, internetFacing: 2, crownJewels: 3 },
      vulnerabilities: { open: 1000, critical: 0, high: 0, knownExploited: 0, highEpss: 0 },
      controls: { edrCoverage: 0.98, mfaCoverage: 0.99 },
    });
    const fewButExploitable = engine.exposureScore({
      assets: { total: 500, internetFacing: 2, crownJewels: 3 },
      vulnerabilities: { open: 2, critical: 2, knownExploited: 2, knownExploitedOnInternetFacing: 2, knownExploitedOnCrownJewels: 1 },
      attackPaths: { total: 4, toCrownJewels: 2, shortestHopsToCrownJewel: 3 },
    });
    expectExplained(manyLowVulns);
    expectExplained(fewButExploitable);
    expect(fewButExploitable.score).toBeGreaterThan(manyLowVulns.score + 30);
    expect(fewButExploitable.domains.vulnerability.drivers.join(" ")).toMatch(/internet-facing/);
    expect(fewButExploitable.domains.attack_path.score).toBeGreaterThan(0);
  });
  it("breaks exposure down by domain with drivers", () => {
    const e = engine.exposureScore({
      organizationName: "Contoso",
      assets: { total: 200, internetFacing: 20, crownJewels: 4 },
      external: { exposedAdminInterfaces: 3, unmanagedExternalAssets: 5 },
      identities: { total: 1000, privileged: 40, privilegedWithoutMfa: 6, dormantPrivileged: 3 },
      cloud: { publicStorage: 2, failingControls: 30, totalControls: 200 },
      saas: { riskyOauthApps: 4 },
      misconfigurations: { failing: 50, total: 400, critical: 2 },
      threatIntel: { activeCampaignsTargeting: 1 },
      controls: { segmentation: true },
    });
    expectExplained(e);
    for (const d of ["external", "identity", "cloud", "saas", "misconfiguration", "threat_intel"] as const) {
      expect(e.domains[d].score).toBeGreaterThan(0);
      expect(e.domains[d].drivers.length).toBeGreaterThan(0);
    }
    expect(e.summary).toMatch(/^Exposure of Contoso risk/);
  });
});

describe("RiskEngine.scoreAttackPath", () => {
  it("path complexity and controls appear as negative contributions", () => {
    const a = new RiskEngine().scoreAttackPath({
      entryLabel: "vpn-gw",
      targetLabel: "pay-db",
      steps: 5,
      chainProbability: 0.3,
      exploitability: 0.97,
      knownExploited: true,
      exploitedCves: ["CVE-2024-3400"],
      exposure: 1,
      privilegeEscalation: 1,
      identityPrivilege: 1,
      privilegedIdentities: ["da-admin"],
      threatIntel: 0.5,
      lateralHops: 3,
      targetCriticality: "crown_jewel",
      blastRadius: { reachableNodes: 30, reachableCrownJewels: 2 },
      controls: [{ key: "edr", label: "EDR coverage", strength: 0.3, on: "dc-01" }],
    });
    expectExplained(a);
    expect(a.factors.find((f) => f.key === "path_complexity")!.contribution).toBeLessThan(0);
    expect(a.factors.find((f) => f.key === "control_edr")!.label).toBe("EDR coverage on dc-01");
    expect(a.factors.map((f) => f.key)).toEqual(
      expect.arrayContaining(["exploitability", "known_exploitation", "exposure", "threat_intel", "lateral_movement", "asset_criticality", "identity_privilege", "privilege", "blast_radius"]),
    );
  });
});
