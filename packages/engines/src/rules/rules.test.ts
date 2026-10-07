import { describe, expect, it } from "vitest";
import { Correlator } from "../correlation/correlator.js";
import { DetectionEngine } from "../detection/engine.js";
import { IndicatorSet } from "../detection/indicators.js";
import { runRuleTests } from "../detection/test-runner.js";
import { validateRule } from "../detection/validate.js";
import { InMemoryGraphStore } from "../graph/memory-store.js";
import { SecurityGraph } from "../graph/security-graph.js";
import { automationEventFor, BufferingSink } from "../notifications.js";
import { narrateIncident } from "../reporting/narrative.js";
import { makeEvent, ORG_1, TENANT_A } from "../test-support/fixtures.js";
import { ManualClock } from "../util/clock.js";
import { BUILTIN_RULE_DEFINITIONS, BUILTIN_RULES } from "./index.js";

describe("built-in rule pack", () => {
  it("covers the required detection scenarios with unique ids", () => {
    const ids = BUILTIN_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toEqual(
      expect.arrayContaining([
        "bloody-edr-encoded-powershell",
        "bloody-edr-lsass-credential-access",
        "bloody-edr-office-spawns-shell",
        "bloody-itdr-password-spray",
        "bloody-itdr-impossible-travel",
        "bloody-itdr-bruteforce-success",
        "bloody-ndr-dns-beaconing",
        "bloody-edr-ransomware-mass-rename",
        "bloody-itdr-new-admin-account",
        "bloody-ndr-suricata-high-severity",
        "bloody-cti-indicator-match",
      ]),
    );
    expect(new Set(BUILTIN_RULES.map((r) => r.kind))).toEqual(new Set(["sigma", "threshold", "sequence", "ioc"]));
  });

  it.each(BUILTIN_RULE_DEFINITIONS.map((r) => [r.id, r] as const))("%s validates and passes its positive and negative tests", (_id, rule) => {
    const v = validateRule(rule);
    expect(v.errors).toEqual([]);
    expect(v.warnings.filter((w) => !w.startsWith("attack:"))).toEqual([]);
    const report = runRuleTests(rule);
    expect(report.results.filter((r) => !r.passed)).toEqual([]);
    expect(report.passed).toBe(true);
    expect(report.results.some((r) => r.expect === "match")).toBe(true);
    expect(report.results.some((r) => r.expect === "no_match")).toBe(true);
  });

  it("all load into one engine", () => {
    const engine = new DetectionEngine({ rules: BUILTIN_RULES });
    expect(engine.rules()).toHaveLength(BUILTIN_RULES.length);
  });
});

describe("end to end: telemetry → detections → incident → graph → narrative", () => {
  it("turns a phishing-to-credential-theft story into one critical, explained incident", async () => {
    const clock = new ManualClock();
    const sink = new BufferingSink();
    const intel = new IndicatorSet({ clock });
    intel.add({ tenantId: TENANT_A, organizationId: null, type: "domain", value: "c2.badcdn.example", confidence: 85, severity: "high", source: "opencti", threatActor: "TA-Example" });
    const engine = new DetectionEngine({ rules: BUILTIN_RULES, clock, indicators: intel, sink });
    const correlator = new Correlator({ clock, sink, context: { assetCriticality: () => "high" } });
    const graph = new SecurityGraph({ store: new InMemoryGraphStore({ tenantId: TENANT_A }), sink });

    const host = { hostname: "WS-042", os: "Windows 11", ip: ["10.0.0.42"] };
    const events = [
      makeEvent({
        offsetSeconds: 0,
        category: "process",
        asset: host,
        user: { name: "bob", domain: "CORP" },
        process: {
          pid: 4100,
          path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          commandLine: "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi",
          parent: { pid: 3000, path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" },
        },
      }),
      makeEvent({ offsetSeconds: 120, category: "process", asset: host, process: { pid: 4200, path: "C:\\Windows\\System32\\rundll32.exe", commandLine: "rundll32 C:\\Windows\\System32\\comsvcs.dll, MiniDump 640 C:\\Temp\\d.bin full" } }),
      ...Array.from({ length: 12 }, (_, i) => makeEvent({ offsetSeconds: 300 + i * 300, category: "dns", source: { kind: "network", product: "zeek" }, asset: host, network: { dnsQuery: "c2.badcdn.example" } })),
    ];
    const matches = [];
    for (const e of events) {
      clock.set(e.timestamp);
      matches.push(...engine.process(e));
      await graph.ingestEvent(e);
    }
    const fired = new Set(matches.map((m) => m.rule.id));
    expect(fired).toEqual(new Set(["bloody-edr-office-spawns-shell", "bloody-edr-encoded-powershell", "bloody-edr-lsass-credential-access", "bloody-cti-indicator-match", "bloody-ndr-dns-beaconing"]));

    const results = correlator.addMany(matches);
    const incidents = correlator.list({ promotedOnly: true });
    expect(incidents).toHaveLength(1);
    const inc = incidents[0]!;
    expect(results.at(-1)!.incident.id).toBe(inc.id);
    expect(inc.severity).toBe("critical");
    expect(inc.assetKeys).toEqual(["ws-042"]);
    expect(inc.attack.map((t) => t.id)).toEqual(expect.arrayContaining(["T1003.001", "T1059.001", "T1204.002", "T1071.004"]));
    expect(inc.title).toBe("Credential Access and Command and Control on WS-042");

    // persist into the graph and pivot
    await graph.linkIncident({ incidentId: inc.id, organizationId: ORG_1, title: inc.title, severity: inc.severity, entities: matches.flatMap((m) => m.entities), techniques: inc.attack });
    const seen = await graph.whereObserved({ type: "domain", value: "c2.badcdn.example" });
    expect(seen.map((o) => o.node.key)).toEqual(["ws-042"]);

    // automation & reporting outputs
    const automation = sink.items.map(automationEventFor).filter((x) => x !== null);
    expect(automation).toEqual(expect.arrayContaining(["indicator.matched", "incident.created"]));
    for (const audience of ["executive", "customer", "analyst", "mssp"] as const) {
      const n = narrateIncident(inc, { audience, organizationName: "Contoso" });
      expect(n.headline.length).toBeGreaterThan(10);
    }
  });
});
