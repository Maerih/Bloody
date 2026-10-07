import type { CanonicalEvent } from "@bloody/contracts";
import { describe, expect, it } from "vitest";
import { BufferingSink } from "../notifications.js";
import { makeEvent, ORG_1, ORG_2, TENANT_A, TENANT_B } from "../test-support/fixtures.js";
import { ManualClock } from "../util/clock.js";
import { DetectionEngine } from "./engine.js";
import { IndicatorSet, type IndicatorProvider } from "./indicators.js";
import { RuleRegistry } from "./registry.js";
import { FeedbackTracker, InMemorySuppressionList } from "./suppression.js";
import { runRuleTests } from "./test-runner.js";
import type { DetectionRuleInput } from "./types.js";
import { validateRule } from "./validate.js";

const failedLogin = (src: string, principal: string, offsetSeconds: number, extra: Record<string, unknown> = {}) =>
  makeEvent({ category: "authentication", outcome: "failure", offsetSeconds, identity: { provider: "idp", principal, sourceIp: src }, ...extra });

const sprayRule: DetectionRuleInput = {
  kind: "threshold",
  id: "t-spray",
  name: "Spray",
  version: 1,
  severity: "high",
  filter: { detection: { sel: { category: "authentication", outcome: "failure" } }, condition: "sel" },
  groupBy: ["identity.sourceIp"],
  distinctField: "identity.principal",
  threshold: 3,
  windowSeconds: 60,
};

function run(engine: DetectionEngine, clock: ManualClock, events: CanonicalEvent[]) {
  const out = [];
  for (const e of events) {
    clock.set(e.timestamp);
    out.push(...engine.process(e));
  }
  return out;
}

describe("threshold rules", () => {
  it("counts distinct values per group inside a sliding window and resets after firing", () => {
    const clock = new ManualClock();
    const engine = new DetectionEngine({ rules: [sprayRule], clock });
    const m = run(engine, clock, [failedLogin("1.1.1.1", "a", 0), failedLogin("1.1.1.1", "a", 1), failedLogin("1.1.1.1", "b", 2), failedLogin("1.1.1.1", "c", 3)]);
    expect(m).toHaveLength(1);
    expect(m[0]!.events).toHaveLength(4);
    expect(m[0]!.groupKey).toBe("1.1.1.1");
    expect(m[0]!.explanation[0]).toMatch(/3 distinct identity.principal value\(s\)/);
    // window was reset: one more event does not re-fire
    expect(run(engine, clock, [failedLogin("1.1.1.1", "d", 4)])).toHaveLength(0);
  });

  it("evicts events outside the window (event time) and tolerates out-of-order arrival", () => {
    const clock = new ManualClock();
    const engine = new DetectionEngine({ rules: [sprayRule], clock });
    expect(run(engine, clock, [failedLogin("2.2.2.2", "a", 0), failedLogin("2.2.2.2", "b", 30), failedLogin("2.2.2.2", "c", 100)])).toHaveLength(0);
    // late event inside the window of the newest one
    expect(run(engine, clock, [failedLogin("2.2.2.2", "d", 90)])).toHaveLength(0);
    expect(run(engine, clock, [failedLogin("2.2.2.2", "e", 95)])).toHaveLength(1);
  });

  it("never mixes tenants or organizations in one window", () => {
    const clock = new ManualClock();
    const engine = new DetectionEngine({ rules: [sprayRule], clock });
    const m = run(engine, clock, [
      failedLogin("3.3.3.3", "a", 0),
      failedLogin("3.3.3.3", "b", 1, { organizationId: ORG_2 }),
      failedLogin("3.3.3.3", "c", 2, { tenantId: TENANT_B }),
      failedLogin("3.3.3.3", "d", 3, { organizationId: ORG_2 }),
    ]);
    expect(m).toHaveLength(0);
    const m2 = run(engine, clock, [failedLogin("3.3.3.3", "e", 4, { organizationId: ORG_2 })]);
    expect(m2).toHaveLength(1);
    expect(m2[0]!.organizationId).toBe(ORG_2);
    expect(m2[0]!.tenantId).toBe(TENANT_A);
  });

  it("skips events missing group-by fields and garbage-collects idle groups", () => {
    const clock = new ManualClock();
    const engine = new DetectionEngine({ rules: [sprayRule], clock });
    run(engine, clock, [makeEvent({ category: "authentication", outcome: "failure", identity: { principal: "x" } }), failedLogin("4.4.4.4", "a", 0)]);
    expect(engine.metrics()[0]!.activeStates).toBe(1);
    clock.advance(120_000);
    expect(engine.gc()).toBe(1);
    expect(engine.metrics()[0]!.activeStates).toBe(0);
  });

  it("requires periodic timing when `regularity` is set (beaconing)", () => {
    const rule: DetectionRuleInput = {
      kind: "threshold",
      id: "t-beacon",
      name: "Beacon",
      version: 1,
      severity: "medium",
      filter: { detection: { sel: { "network.dnsQuery|exists": true } }, condition: "sel" },
      groupBy: ["asset.hostname", "network.dnsQuery"],
      threshold: 6,
      windowSeconds: 3600,
      regularity: { maxCoefficientOfVariation: 0.2, minIntervalSeconds: 5 },
    };
    const q = (t: number, host = "h1") => makeEvent({ category: "dns", offsetSeconds: t, asset: { hostname: host }, network: { dnsQuery: "c2.example" } });
    const clock = new ManualClock();
    const engine = new DetectionEngine({ rules: [rule], clock });
    const periodic = run(engine, clock, [0, 60, 121, 180, 241, 300].map((t) => q(t)));
    expect(periodic).toHaveLength(1);
    expect(periodic[0]!.explanation.join(" ")).toMatch(/Periodic timing: mean interval 60s/);
    const jittery = run(engine, clock, [0, 5, 200, 210, 900, 1800].map((t) => q(t, "h2")));
    expect(jittery).toHaveLength(0);
    const tooFast = run(engine, clock, [0, 1, 2, 3, 4, 5].map((t) => q(t, "h3")));
    expect(tooFast).toHaveLength(0);
  });

  it("caps attached events and records the total", () => {
    const clock = new ManualClock();
    const rule: DetectionRuleInput = { ...sprayRule, id: "t-cap", distinctField: undefined, threshold: 10 } as DetectionRuleInput;
    const engine = new DetectionEngine({ rules: [rule], clock, maxEventsPerMatch: 4 });
    const m = run(engine, clock, Array.from({ length: 10 }, (_, i) => failedLogin("5.5.5.5", "a", i)));
    expect(m[0]!.events).toHaveLength(4);
    expect(m[0]!.explanation.join(" ")).toMatch(/10 events contributed; the newest 4/);
  });
});

describe("sequence rules", () => {
  const ok = (principal: string, t: number, geo?: Record<string, unknown>, src = "198.51.100.1") => makeEvent({ category: "authentication", outcome: "success", offsetSeconds: t, identity: { provider: "idp", principal, sourceIp: src, ...(geo ? { geo } : {}) } });
  const bruteForce: DetectionRuleInput = {
    kind: "sequence",
    id: "s-bf",
    name: "BF then success",
    version: 1,
    severity: "high",
    by: ["identity.principal"],
    windowSeconds: 300,
    steps: [
      { name: "fail", filter: { detection: { s: { category: "authentication", outcome: "failure" } }, condition: "s" }, minCount: 3 },
      { name: "ok", filter: { detection: { s: { category: "authentication", outcome: "success" } }, condition: "s" } },
    ],
  };

  it("requires ordered steps, step counts and the window", () => {
    const clock = new ManualClock();
    const engine = new DetectionEngine({ rules: [bruteForce], clock });
    // success before failures: no match
    expect(run(engine, clock, [ok("u1", 0), failedLogin("x", "u1", 1), failedLogin("x", "u1", 2)])).toHaveLength(0);
    const m = run(engine, clock, [failedLogin("x", "u1", 3), failedLogin("x", "u1", 4), ok("u1", 5)]);
    expect(m).toHaveLength(1);
    expect(m[0]!.explanation[0]).toMatch(/Sequence completed by identity.principal = u1/);
    expect(m[0]!.events.length).toBeGreaterThanOrEqual(4);
    // too slow
    expect(run(engine, clock, [failedLogin("x", "u2", 0), failedLogin("x", "u2", 10), failedLogin("x", "u2", 20), ok("u2", 1000)])).toHaveLength(0);
    // other principals do not interfere
    expect(run(engine, clock, [failedLogin("x", "u3", 0), failedLogin("x", "u3", 1), failedLogin("x", "u3", 2), ok("u4", 3)])).toHaveLength(0);
  });

  it("slides counted first steps so stale failures fall out of the window", () => {
    const clock = new ManualClock();
    const engine = new DetectionEngine({ rules: [bruteForce], clock });
    expect(run(engine, clock, [failedLogin("x", "u5", 0), failedLogin("x", "u5", 10), failedLogin("x", "u5", 400), ok("u5", 410)])).toHaveLength(0);
    // only failures at 400 / 420 / 425 are inside the 300 s window when the success arrives
    expect(run(engine, clock, [failedLogin("x", "u5", 420), failedLogin("x", "u5", 425), ok("u5", 430)])).toHaveLength(1);
  });

  it("geo-velocity constraint detects impossible travel; field constraints compare steps", () => {
    const travel: DetectionRuleInput = {
      kind: "sequence",
      id: "s-travel",
      name: "Travel",
      version: 1,
      severity: "high",
      by: ["identity.principal"],
      windowSeconds: 7200,
      steps: [
        { name: "a", filter: { detection: { s: { outcome: "success" } }, condition: "s" } },
        { name: "b", filter: { detection: { s: { outcome: "success" } }, condition: "s" }, constraints: [{ type: "geo_velocity", maxKmh: 900, minDistanceKm: 500 }, { type: "field_differs", field: "identity.sourceIp" }] },
      ],
    };
    const clock = new ManualClock();
    const engine = new DetectionEngine({ rules: [travel], clock });
    const paris = { country: "FR", city: "Paris", lat: 48.8566, lon: 2.3522 };
    const nyc = { country: "US", city: "New York", lat: 40.7128, lon: -74.006 };
    const m = run(engine, clock, [ok("v", 0, paris, "192.0.2.1"), ok("v", 600, paris, "192.0.2.1"), ok("v", 1200, nyc, "203.0.113.5")]);
    expect(m).toHaveLength(1);
    expect(m[0]!.explanation.join(" ")).toMatch(/Travel Paris, FR → New York, US: \d+ km/);
    // plausible travel speed
    expect(run(engine, clock, [ok("w", 0, paris, "192.0.2.1"), ok("w", 9 * 3600, nyc, "203.0.113.5")])).toHaveLength(0);
    // fallback: country change without coordinates
    expect(run(engine, clock, [ok("y", 0, { country: "FR" }, "192.0.2.1"), ok("y", 60, { country: "BR" }, "203.0.113.9")])).toHaveLength(1);
    // same IP → field_differs fails
    expect(run(engine, clock, [ok("z", 0, paris, "192.0.2.1"), ok("z", 60, nyc, "192.0.2.1")])).toHaveLength(0);
  });
});

describe("IOC rules", () => {
  const iocRule: DetectionRuleInput = { kind: "ioc", id: "i-ioc", name: "IOC", version: 1, severity: "medium", severityMode: "max", minConfidence: 50 };
  function intel(clock: ManualClock) {
    const set = new IndicatorSet({ clock });
    set.add({ tenantId: TENANT_A, organizationId: null, type: "ip", value: "198.51.100.0/24", confidence: 80, severity: "high", source: "feed", threatActor: "TA1" });
    set.add({ tenantId: TENANT_A, organizationId: ORG_2, type: "domain", value: "evil.example", confidence: 90, severity: "critical", source: "org-feed" });
    set.add({ tenantId: TENANT_A, organizationId: null, type: "sha256", value: "B".repeat(64), confidence: 95, severity: "critical", source: "sandbox", expiresAt: "2026-03-01T10:05:00.000Z" });
    set.add({ tenantId: TENANT_A, organizationId: null, type: "ip", value: "203.0.113.7", confidence: 20, severity: "low", source: "noisy" });
    set.add({ tenantId: TENANT_B, organizationId: null, type: "ip", value: "192.0.2.200", confidence: 99, severity: "critical", source: "other-tenant" });
    expect(set.add({ tenantId: TENANT_A, organizationId: null, type: "ip", value: "not-an-ip", confidence: 99, severity: "low", source: "x" })).toBe(false);
    return set;
  }

  it("matches CIDR, subdomains, hashes; respects org scope, expiry, confidence and tenants", () => {
    const clock = new ManualClock();
    const sink = new BufferingSink();
    const engine = new DetectionEngine({ rules: [iocRule], clock, indicators: intel(clock), sink });
    const conn = (dst: string, extra: Record<string, unknown> = {}) => makeEvent({ category: "network", network: { dstIp: dst }, asset: { hostname: "h" }, ...extra });
    const m1 = run(engine, clock, [conn("198.51.100.77")]);
    expect(m1).toHaveLength(1);
    expect(m1[0]!.severity).toBe("high");
    expect(m1[0]!.indicators![0]).toMatchObject({ value: "198.51.100.0/24", observed: "198.51.100.77", threatActor: "TA1" });
    expect(m1[0]!.entities.some((e) => e.kind === "indicator")).toBe(true);
    expect(sink.items.map((n) => n.type)).toEqual(["detection.matched", "indicator.matched"]);
    // org-scoped indicator only matches its organization; subdomains match
    const dns = (org: string) => makeEvent({ organizationId: org, category: "dns", network: { dnsQuery: "a.b.evil.example" } });
    expect(run(engine, clock, [dns(ORG_1)])).toHaveLength(0);
    const m2 = run(engine, clock, [dns(ORG_2)]);
    expect(m2).toHaveLength(1);
    expect(m2[0]!.severity).toBe("critical");
    // hash, then expired
    const file = (t: number) => makeEvent({ category: "file", offsetSeconds: t, file: { path: "c:\\x.exe", sha256: "b".repeat(64) } });
    expect(run(engine, clock, [file(0)])).toHaveLength(1);
    expect(run(engine, clock, [file(600)])).toHaveLength(0);
    // low confidence, private address space and other tenants' intel never match
    expect(run(engine, clock, [conn("203.0.113.7"), conn("10.0.0.1"), conn("192.0.2.200")])).toHaveLength(0);
  });

  it("does nothing without an indicator provider and isolates provider failures", () => {
    const clock = new ManualClock();
    const sink = new BufferingSink();
    const engine = new DetectionEngine({ rules: [iocRule, sprayRule], clock, sink });
    expect(run(engine, clock, [makeEvent({ category: "network", network: { dstIp: "198.51.100.1" } })])).toHaveLength(0);
    const broken: IndicatorProvider = {
      lookup: () => {
        throw new Error("cache unavailable");
      },
    };
    engine.setIndicatorProvider(broken);
    const out = run(engine, clock, [makeEvent({ category: "network", network: { dstIp: "198.51.100.1" } }), failedLogin("9.9.9.9", "a", 1), failedLogin("9.9.9.9", "b", 2), failedLogin("9.9.9.9", "c", 3)]);
    expect(out.map((m) => m.rule.id)).toEqual(["t-spray"]); // other rules unaffected
    const ioc = engine.metrics().find((x) => x.ruleId === "i-ioc")!;
    expect(ioc.errors).toBe(4); // every event with a public observable hit the failing provider
    expect(ioc.lastError).toBe("cache unavailable");
    expect(sink.items.some((n) => n.type === "detection.rule_error")).toBe(true);
  });
});

describe("engine behaviour: cooldown, suppression, feedback, scope, severity", () => {
  const sigma: DetectionRuleInput = {
    kind: "sigma",
    id: "s-cmd",
    name: "Cmd",
    version: 1,
    severity: "medium",
    cooldownSeconds: 60,
    sigma: "title: cmd\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    Image|endswith: '\\cmd.exe'\n  condition: sel\n",
  };
  const cmd = (t: number, host = "ws-1", extra: Record<string, unknown> = {}) => makeEvent({ category: "process", offsetSeconds: t, asset: { hostname: host }, process: { path: "C:\\Windows\\System32\\cmd.exe", pid: t }, ...extra });

  it("cooldown suppresses repeats per primary entity", () => {
    const clock = new ManualClock();
    const engine = new DetectionEngine({ rules: [sigma], clock });
    const m = run(engine, clock, [cmd(0), cmd(10), cmd(20, "ws-2"), cmd(61)]);
    expect(m.map((x) => x.title)).toEqual(["Cmd on ws-1", "Cmd on ws-2", "Cmd on ws-1"]);
    expect(engine.metrics()[0]).toMatchObject({ matched: 3, cooledDown: 1 });
  });

  it("entity-scoped suppressions silence matches until they expire, and are reported", () => {
    const clock = new ManualClock();
    const sink = new BufferingSink();
    const suppressions = new InMemorySuppressionList();
    suppressions.add({ tenantId: TENANT_A, organizationId: ORG_1, ruleId: "s-cmd", entity: { kind: "endpoint", key: "ws-1" }, reason: "admin jump host", createdBy: "analyst", createdAt: "2026-03-01T00:00:00Z", expiresAt: "2026-03-01T10:30:00.000Z" });
    suppressions.add({ tenantId: TENANT_B, organizationId: null, ruleId: "*", reason: "other tenant", createdBy: "x", createdAt: "2026-03-01T00:00:00Z", expiresAt: null });
    const engine = new DetectionEngine({ rules: [{ ...sigma, cooldownSeconds: 0 }], clock, sink, suppressions });
    expect(run(engine, clock, [cmd(0), cmd(1, "ws-2")]).map((m) => m.title)).toEqual(["Cmd on ws-2"]);
    expect(sink.items.find((n) => n.type === "detection.suppressed")).toMatchObject({ reason: "admin jump host" });
    expect(run(engine, clock, [cmd(3600)])).toHaveLength(1); // expired
    expect(engine.metrics()[0]!.suppressed).toBe(1);
    expect(suppressions.list(TENANT_A)).toHaveLength(1);
  });

  it("false-positive feedback tracks precision and auto-suppresses noisy entities", () => {
    const clock = new ManualClock("2026-03-01T00:00:00Z");
    const suppressions = new InMemorySuppressionList();
    const fb = new FeedbackTracker({ suppressions, autoSuppressAfter: 2, autoSuppressDays: 7, clock });
    const base = { tenantId: TENANT_A, organizationId: ORG_1, ruleId: "s-cmd", analyst: "t1", entity: { kind: "endpoint" as const, key: "ws-1" } };
    expect(fb.record({ ...base, verdict: "true_positive" }).stats.precision).toBe(1);
    expect(fb.record({ ...base, verdict: "false_positive" }).autoSuppression).toBeNull();
    const second = fb.record({ ...base, verdict: "benign_positive" });
    expect(second.autoSuppression).toMatchObject({ ruleId: "s-cmd", entity: { key: "ws-1" }, expiresAt: "2026-03-08T00:00:00.000Z" });
    expect(fb.stats(TENANT_A)[0]).toMatchObject({ truePositives: 1, falsePositives: 1, benignPositives: 1, precision: 0.5 });
    expect(fb.stats(TENANT_B)).toEqual([]);
    const engine = new DetectionEngine({ rules: [{ ...sigma, cooldownSeconds: 0 }], clock, suppressions });
    clock.set("2026-03-01T10:00:00Z");
    expect(run(engine, clock, [cmd(0)])).toHaveLength(0);
  });

  it("honours rule scope, enabled flag and severity modes; ids are deterministic", () => {
    const clock = new ManualClock();
    const scoped = { ...sigma, id: "s-scoped", cooldownSeconds: 0, scope: { organizationIds: [ORG_2] } };
    const disabled = { ...sigma, id: "s-off", enabled: false };
    const eventSev = { ...sigma, id: "s-event", cooldownSeconds: 0, severityMode: "event" as const };
    const engine = new DetectionEngine({ rules: [scoped, disabled, eventSev], clock });
    const e = cmd(0, "ws-1", { severity: "critical" });
    const m = run(engine, clock, [e]);
    expect(m.map((x) => [x.rule.id, x.severity])).toEqual([["s-event", "critical"]]);
    const again = new DetectionEngine({ rules: [eventSev], clock }).process(e);
    expect(again[0]!.id).toBe(m[0]!.id);
    expect(engine.rules().map((r) => r.id).sort()).toEqual(["s-event", "s-off", "s-scoped"]);
  });

  it("loadRules reports invalid rules and keeps state for unchanged versions; upsert resets on new version", () => {
    const clock = new ManualClock();
    const engine = new DetectionEngine({ clock });
    const r = engine.loadRules([sprayRule, { ...sprayRule }, { ...sigma, sigma: "title: broken\ndetection:\n  sel:\n    Bogus: 1\n  condition: sel\n" }]);
    expect(r.loaded).toEqual(["t-spray"]);
    expect(r.rejected.map((x) => x.ruleId)).toEqual(["t-spray", "s-cmd"]);
    run(engine, clock, [failedLogin("7.7.7.7", "a", 0), failedLogin("7.7.7.7", "b", 1)]);
    engine.loadRules([sprayRule]);
    expect(run(engine, clock, [failedLogin("7.7.7.7", "c", 2)])).toHaveLength(1); // state survived reload
    run(engine, clock, [failedLogin("7.7.7.7", "a", 3), failedLogin("7.7.7.7", "b", 4)]);
    expect(engine.upsertRule({ ...sprayRule, version: 2 }).ok).toBe(true);
    expect(run(engine, clock, [failedLogin("7.7.7.7", "c", 5)])).toHaveLength(0); // fresh state for v2
    expect(engine.upsertRule({ ...sprayRule, threshold: 0 })).toMatchObject({ ok: false });
    expect(() => new DetectionEngine({ rules: [{ ...sprayRule, groupBy: [] }] })).toThrow();
    expect(engine.removeRule("t-spray")).toBe(true);
  });

  it("processBatch orders by event time", () => {
    const clock = new ManualClock();
    const engine = new DetectionEngine({ rules: [sprayRule], clock });
    const m = engine.processBatch([failedLogin("8.8.4.4", "c", 2), failedLogin("8.8.4.4", "a", 0), failedLogin("8.8.4.4", "b", 1)]);
    expect(m).toHaveLength(1);
    expect(m[0]!.firstSeenAt < m[0]!.lastSeenAt).toBe(true);
  });
});

describe("validateRule, runRuleTests and RuleRegistry", () => {
  const good: DetectionRuleInput = {
    kind: "sigma",
    id: "v-good",
    name: "Good rule",
    description: "d",
    version: 1,
    severity: "high",
    attack: [{ id: "T1059" }],
    sigma: "title: g\nlevel: high\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    Image|endswith: '\\cmd.exe'\n  condition: sel\n",
    tests: [
      { name: "hit", expect: "match", events: [{ category: "process", process: { path: "C:\\cmd.exe" } }] },
      { name: "miss", expect: "no_match", events: [{ category: "process", process: { path: "C:\\calc.exe" } }] },
    ],
  };

  it("validates schema, compilation and fields with errors and hygiene warnings", () => {
    expect(validateRule(good)).toMatchObject({ valid: true, errors: [], warnings: [] });
    expect(validateRule({ ...good, id: "bad id!" }).errors.join()).toMatch(/^id:/);
    expect(validateRule({ ...good, attack: [{ id: "TX" }] }).errors.join()).toMatch(/attack/);
    expect(validateRule({ ...good, sigma: "title: x\ndetection:\n  sel:\n    Image|re: '('\n  condition: sel\n" }).errors.join()).toMatch(/regular expression/);
    expect(validateRule({ ...good, severity: "low" }).warnings.join()).toMatch(/differs from Sigma level/);
    expect(validateRule({ ...good, tests: [], attack: [] }).warnings.join()).toMatch(/no tests.*no ATT&CK|no ATT&CK.*no tests/);
    expect(validateRule({ ...sprayRule, groupBy: ["NotAField"] }).errors.join()).toMatch(/groupBy\[0\]/);
    expect(validateRule({ ...sprayRule, regularity: { maxCoefficientOfVariation: 0.2 }, threshold: 2 }).errors.join()).toMatch(/regularity/);
    expect(
      validateRule({
        kind: "sequence",
        id: "v-seq",
        name: "Seq",
        version: 1,
        severity: "low",
        by: ["identity.principal"],
        windowSeconds: 60,
        steps: [
          { name: "a", filter: { detection: { s: { outcome: "success" } }, condition: "s" }, constraints: [{ type: "field_differs", field: "identity.sourceIp" }] },
          { name: "b", filter: { detection: { s: { outcome: "success" } }, condition: "s" } },
        ],
      }).errors.join(),
    ).toMatch(/steps\[0\].constraints/);
    expect(validateRule(null).valid).toBe(false);
  });

  it("runRuleTests reports per-test results", () => {
    const rep = runRuleTests(good);
    expect(rep.passed).toBe(true);
    expect(rep.results.map((r) => [r.name, r.passed, r.matches])).toEqual([
      ["hit", true, 1],
      ["miss", true, 0],
    ]);
    const failing = runRuleTests({ ...good, tests: [{ name: "wrong", expect: "match", events: [{ category: "process", process: { path: "C:\\calc.exe" } }] }] });
    expect(failing.passed).toBe(false);
    const badEvent = runRuleTests({ ...good, tests: [{ name: "bad", expect: "match", events: [{ category: "nonsense" }] }] });
    expect(badEvent.results[0]!.error).toMatch(/invalid test event/);
    expect(runRuleTests({ id: "x" }).validation.valid).toBe(false);
  });

  it("registry enforces tested, monotonic versions with rollback, enable/disable and integrity-checked snapshots", () => {
    const clock = new ManualClock("2026-03-01T00:00:00Z");
    const reg = new RuleRegistry({ clock });
    expect(reg.deploy(good, { by: "eng" })).toMatchObject({ ok: true, unchanged: false });
    expect(reg.deploy(good, { by: "eng" })).toMatchObject({ ok: true, unchanged: true });
    expect(reg.deploy({ ...good, name: "Changed" }, { by: "eng" })).toMatchObject({ ok: false });
    const failingTests = { ...good, version: 2, tests: [{ name: "wrong", expect: "no_match" as const, events: [{ category: "process", process: { path: "C:\\cmd.exe" } }] }] };
    const rejected = reg.deploy(failingTests, { by: "eng" });
    expect(rejected.ok).toBe(false);
    expect(!rejected.ok && rejected.errors[0]).toMatch(/test "wrong" failed/);
    expect(reg.deploy({ ...good, version: 2, name: "Good rule v2" }, { by: "eng", comment: "tighten" }).ok).toBe(true);
    expect(reg.deploy({ ...good, version: 1, name: "older" }, { by: "eng" }).ok).toBe(false);
    expect(reg.get("v-good")!.version).toBe(2);
    expect(reg.rollback("v-good", { by: "lead" })).toMatchObject({ ok: true });
    expect(reg.get("v-good")!.version).toBe(1);
    expect(reg.rollback("v-good", { by: "lead" })).toMatchObject({ ok: false });
    expect(reg.rollback("nope", { by: "lead" })).toMatchObject({ ok: false });
    expect(reg.setEnabled("v-good", false, { by: "lead" })).toBe(true);
    expect(reg.active()[0]!.enabled).toBe(false);
    expect(reg.history("v-good").map((h) => h.action)).toEqual(["deploy", "deploy", "rollback", "disable"]);
    const restored = RuleRegistry.restore(JSON.parse(JSON.stringify(reg.snapshot())));
    expect(restored.get("v-good")).toEqual(reg.get("v-good"));
    const tampered = reg.snapshot();
    tampered.rules[0]!.revisions[0]!.rule.name = "evil";
    expect(() => RuleRegistry.restore(tampered)).toThrow(/integrity/);
    expect(new RuleRegistry({ requireTests: true }).deploy({ ...good, tests: [] }, { by: "x" }).ok).toBe(false);
    // active rules load straight into the engine
    expect(new DetectionEngine().loadRules(reg.active()).loaded).toEqual(["v-good"]);
  });
});
