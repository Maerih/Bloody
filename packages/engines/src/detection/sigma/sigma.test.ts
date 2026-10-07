import { describe, expect, it } from "vitest";
import { makeEvent } from "../../test-support/fixtures.js";
import { resolveField } from "../field-mapping.js";
import { buildStringMatcher, compileDetection } from "./compiler.js";
import { ConditionError, evaluateCondition, parseCondition } from "./condition.js";
import { attackFromTags, compileSigma, parseSigma, sigmaToRule } from "./sigma.js";

const proc = (process: Record<string, unknown>, extra: Record<string, unknown> = {}) => makeEvent({ category: "process", asset: { hostname: "ws-1", os: "Windows 11" }, process, ...extra });

function det(detection: Record<string, unknown>, condition: string | string[] = "sel") {
  const r = compileDetection(detection, condition);
  if (!r.compiled) throw new Error(r.errors.join("; "));
  return r.compiled;
}

describe("condition grammar", () => {
  const names = ["sel_a", "sel_b", "filter", "_internal"];
  const evalWith = (cond: string, truth: Record<string, boolean>) => evaluateCondition(parseCondition(cond, names), (n) => truth[n] ?? false);

  it("applies precedence not > and > or, and parentheses", () => {
    expect(evalWith("sel_a or sel_b and filter", { sel_a: true })).toBe(true);
    expect(evalWith("(sel_a or sel_b) and filter", { sel_a: true })).toBe(false);
    expect(evalWith("sel_a and not filter", { sel_a: true, filter: true })).toBe(false);
    expect(evalWith("not not sel_a", { sel_a: true })).toBe(true);
    expect(evalWith("SEL_A".toLowerCase() + " AND NOT filter", { sel_a: true })).toBe(true);
  });

  it("supports quantifiers over wildcard patterns and them", () => {
    expect(evalWith("1 of sel_*", { sel_b: true })).toBe(true);
    expect(evalWith("all of sel_*", { sel_b: true })).toBe(false);
    expect(evalWith("all of sel_*", { sel_a: true, sel_b: true })).toBe(true);
    expect(evalWith("2 of them", { sel_a: true, filter: true })).toBe(true);
    // "them" ignores underscore-prefixed selections
    expect(evalWith("all of them", { sel_a: true, sel_b: true, filter: true })).toBe(true);
    expect(evalWith("any of sel_* and not filter", { sel_a: true, filter: true })).toBe(false);
  });

  it("rejects malformed conditions with precise errors", () => {
    expect(() => parseCondition("sel_a and", names)).toThrow(ConditionError);
    expect(() => parseCondition("(sel_a", names)).toThrow(/Missing "\)"/);
    expect(() => parseCondition("sel_a)", names)).toThrow(/Unexpected "\)"/);
    expect(() => parseCondition("unknown", names)).toThrow(/unknown selection "unknown"/);
    expect(() => parseCondition("1 of nothing*", names)).toThrow(/matches no selection/);
    expect(() => parseCondition("sel_* and filter", names)).toThrow(/only valid after/);
    expect(() => parseCondition("sel_a | count() > 5", names)).toThrow(/threshold rule/);
    expect(() => parseCondition("5 of sel_*", names)).toThrow(/requires more selections/);
    expect(() => parseCondition("", names)).toThrow(/empty/);
  });
});

describe("selection compilation & modifiers", () => {
  it("maps are AND, lists of maps are OR, value lists are OR", () => {
    const d = det({ sel: { "process.name": ["cmd.exe", "powershell.exe"], "process.pid": 4 } });
    expect(d.evaluate(proc({ name: "CMD.EXE", pid: 4 })).matched).toBe(true); // case-insensitive
    expect(d.evaluate(proc({ name: "cmd.exe", pid: 5 })).matched).toBe(false);
    const or = det({ sel: [{ "process.name": "a.exe" }, { "process.pid": 9 }] });
    expect(or.evaluate(proc({ name: "x.exe", pid: 9 })).matched).toBe(true);
    expect(or.evaluate(proc({ name: "x.exe", pid: 1 })).matched).toBe(false);
  });

  it("contains / startswith / endswith / all / cased", () => {
    const e = proc({ commandLine: "C:\\Tools\\Mimikatz.exe sekurlsa::logonpasswords exit" });
    expect(det({ sel: { "CommandLine|contains": "SEKURLSA" } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { "CommandLine|contains|cased": "SEKURLSA" } }).evaluate(e).matched).toBe(false);
    expect(det({ sel: { "CommandLine|startswith": "c:\\tools\\" } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { "CommandLine|endswith": "EXIT" } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { "CommandLine|contains|all": ["sekurlsa", "logonpasswords"] } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { "CommandLine|contains|all": ["sekurlsa", "lsadump"] } }).evaluate(e).matched).toBe(false);
  });

  it("wildcards in plain values and escapes", () => {
    const e = proc({ path: "C:\\Windows\\System32\\rundll32.exe", commandLine: "a*b" });
    expect(det({ sel: { Image: "*\\rundll32.exe" } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { Image: "c:\\windows\\system3?\\rundll32.exe" } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { Image: "rundll32.exe" } }).evaluate(e).matched).toBe(false); // equality is exact
    expect(det({ sel: { CommandLine: "a\\*b" } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { CommandLine: "a\\*c" } }).evaluate(e).matched).toBe(false);
    const m = buildStringMatcher("foo*bar", "contains", false);
    expect(typeof m === "function" && m("xxFOOzzzBARyy")).toBe(true);
  });

  it("re (case-sensitive by default, i flag), cidr, numeric comparisons", () => {
    const e = proc({ commandLine: "Invoke-WebRequest http://x", pid: 4242 }, { network: { dstIp: "10.20.30.40", dstPort: 8443 } });
    expect(det({ sel: { "CommandLine|re": "^Invoke-\\w+" } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { "CommandLine|re": "^invoke-" } }).evaluate(e).matched).toBe(false);
    expect(det({ sel: { "CommandLine|re|i": "^invoke-" } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { "DestinationIp|cidr": ["192.168.0.0/16", "10.0.0.0/8"] } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { "DestinationIp|cidr": "172.16.0.0/12" } }).evaluate(e).matched).toBe(false);
    expect(det({ sel: { "DestinationPort|gt": 8000 } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { "DestinationPort|gte": 8443 } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { "DestinationPort|lt": 8443 } }).evaluate(e).matched).toBe(false);
    expect(det({ sel: { "DestinationPort|lte": 8443, "ProcessId|gt": "4000" } }).evaluate(e).matched).toBe(true);
  });

  it("exists, null, numeric/boolean equality and array fields", () => {
    const e = makeEvent({ category: "identity", eventType: "role_assigned", identity: { principal: "x", privileged: true }, asset: { ip: ["10.0.0.5", "192.0.2.1"] }, labels: { eventId: "4732" } });
    expect(det({ sel: { "identity.principal|exists": true } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { "process.path|exists": false } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { "process.path": null } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { "identity.principal": null } }).evaluate(e).matched).toBe(false);
    expect(det({ sel: { EventID: 4732 } }).evaluate(e).matched).toBe(true); // number vs string label
    expect(det({ sel: { "identity.privileged": true } }).evaluate(e).matched).toBe(true);
    expect(det({ sel: { "asset.ip|cidr": "192.0.2.0/24" } }).evaluate(e).matched).toBe(true);
  });

  it("keyword selections search message and command-line style fields", () => {
    const d = det({ keywords: ["mimikatz", "sekurlsa::*"] }, "keywords");
    expect(d.evaluate(proc({ commandLine: "run SEKURLSA::logonpasswords" })).matched).toBe(true);
    expect(d.evaluate(makeEvent({ message: "Detected MimiKatz in memory" })).matched).toBe(true);
    expect(d.evaluate(proc({ commandLine: "notepad.exe" })).matched).toBe(false);
  });

  it("reports matched selections for explanations", () => {
    const d = det({ sel_a: { "process.name": "a.exe" }, sel_b: { "process.pid": 1 }, filter: { "process.user": "system" } }, "1 of sel_* and not filter");
    const r = d.evaluate(proc({ name: "a.exe", pid: 1 }));
    expect(r.matched).toBe(true);
    expect(r.matchedSelections.sort()).toEqual(["sel_a"]); // quantifier short-circuits after the first hit
    expect(d.selections.get("sel_a")!.description).toBe('process.name "a.exe"');
  });

  it("rejects invalid definitions with actionable errors", () => {
    const bad = (detection: Record<string, unknown>, condition = "sel") => compileDetection(detection, condition).errors.join(" | ");
    expect(bad({ sel: { "CommandLine|base64": "x" } })).toMatch(/not supported/);
    expect(bad({ sel: { "CommandLine|frobnicate": "x" } })).toMatch(/unknown modifier/);
    expect(bad({ sel: { "CommandLine|contains|startswith": "x" } })).toMatch(/cannot be combined/);
    expect(bad({ sel: { "CommandLine|re": "(" } })).toMatch(/invalid regular expression/);
    expect(bad({ sel: { "DestinationIp|cidr": "10.0.0.0/99" } })).toMatch(/invalid CIDR/);
    expect(bad({ sel: { "DestinationPort|gt": "abc" } })).toMatch(/numeric/);
    expect(bad({ sel: { NoSuchSigmaField: "x" } })).toMatch(/no mapping/);
    expect(bad({ sel: { "process.name|exists": "yes" } })).toMatch(/boolean/);
    expect(bad({ sel: { "process.name": [] } })).toMatch(/empty value list/);
    expect(bad({ sel: [] })).toMatch(/empty list/);
    expect(bad({ sel: [{ a: 1 }, "x"] })).toMatch(/only maps or only keyword/);
    expect(bad({ sel: { "process.name": "x" } }, "other")).toMatch(/unknown selection/);
    expect(bad({})).toMatch(/no selections/);
    expect(compileDetection({ sel: { "process.name": "x" }, unused: { "process.pid": 1 } }, "sel").warnings.join()).toMatch(/never used/);
    // non-strict mode degrades unmapped fields to never-matching with a warning
    const lax = compileDetection({ sel: { NoSuchSigmaField: "x" } }, "sel", { strictFields: false });
    expect(lax.compiled).not.toBeNull();
    expect(lax.warnings.join()).toMatch(/unmapped/);
  });
});

describe("field mapping", () => {
  it("maps Sigma names to BCE paths, passes BCE paths through, honours overrides", () => {
    expect(resolveField("Image")).toEqual({ path: "process.path", mapped: true });
    expect(resolveField("commandline").path).toBe("process.commandLine");
    expect(resolveField("ParentImage").path).toBe("process.parent.path");
    expect(resolveField("TargetFilename").path).toBe("file.path");
    expect(resolveField("DestinationIp").path).toBe("network.dstIp");
    expect(resolveField("QueryName").path).toBe("network.dnsQuery");
    expect(resolveField("User").path).toBe("user.name");
    expect(resolveField("network.ja3")).toEqual({ path: "network.ja3", mapped: false });
    expect(resolveField("category")).toEqual({ path: "category", mapped: false });
    expect(resolveField("bogus.path").path).toBeNull();
    expect(resolveField("CustomField", { customfield: "labels.custom" }).path).toBe("labels.custom");
  });
});

describe("Sigma YAML", () => {
  const rule = String.raw`
title: Test rule
id: 11111111-2222-4333-8444-555555555555
status: experimental
description: test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains:
      - 'urlcache'
      - 'verifyctl'
  condition: selection
level: high
tags:
  - attack.command-and-control
  - attack.t1105
falsepositives:
  - admins
`;

  it("parses metadata, level, ATT&CK tags and compiles with logsource filtering", () => {
    const parsed = parseSigma(rule);
    expect(parsed.errors).toEqual([]);
    expect(parsed.value).toMatchObject({ title: "Test rule", level: "high", attack: [{ id: "T1105", tactic: "command-and-control" }], falsePositives: ["admins"] });
    const c = compileSigma(rule);
    expect(c.value).not.toBeNull();
    const hit = proc({ path: "C:\\Windows\\System32\\certutil.exe", commandLine: "certutil -urlcache -f http://x/a.exe a.exe" });
    expect(c.value!.evaluate(hit).matched).toBe(true);
    // logsource: wrong category, and wrong OS when the OS is known
    expect(c.value!.evaluate({ ...hit, category: "network" }).matched).toBe(false);
    expect(c.value!.evaluate({ ...hit, asset: { hostname: "l", os: "Ubuntu 22.04" } }).matched).toBe(false);
    // unknown OS is not dropped
    expect(c.value!.evaluate({ ...hit, asset: { hostname: "l" } }).matched).toBe(true);
  });

  it("rejects invalid YAML, multi-document collections, missing parts and unknown levels", () => {
    expect(parseSigma("title: [unclosed").errors.join()).toMatch(/YAML/);
    expect(parseSigma(`${rule}\n---\n${rule}`).errors.join()).toMatch(/exactly one YAML document/);
    expect(parseSigma("title: x\ndetection:\n  sel:\n    a: 1\n").errors.join()).toMatch(/condition/);
    expect(parseSigma("detection:\n  sel:\n    a: 1\n  condition: sel\n").errors.join()).toMatch(/title/);
    expect(parseSigma(rule.replace("level: high", "level: severe")).errors.join()).toMatch(/unknown level/);
    expect(parseSigma("- a\n- b\n").errors.join()).toMatch(/mapping/);
    expect(parseSigma(rule.replace("  condition: selection", "  condition: selection\n  timeframe: 5m")).warnings.join()).toMatch(/timeframe/);
    expect(compileSigma(rule.replace("category: process_creation", "category: quantum_flux")).warnings.join()).toMatch(/not mapped/);
  });

  it("attackFromTags only assigns a tactic when unambiguous", () => {
    expect(attackFromTags(["attack.t1059.001", "attack.execution"])).toEqual([{ id: "T1059.001", tactic: "execution" }]);
    expect(attackFromTags(["attack.t1059", "attack.execution", "attack.persistence"])).toEqual([{ id: "T1059" }]);
    expect(attackFromTags(["attack.g0016", "cve.2021-44228"])).toEqual([]);
  });

  it("sigmaToRule wraps a Sigma document as a Bloody rule definition", () => {
    const r = sigmaToRule(rule);
    expect(r.value).toMatchObject({ kind: "sigma", id: "sigma-11111111-2222-4333-8444-555555555555", name: "Test rule", severity: "high", version: 1 });
    expect(sigmaToRule(rule.replace(/^id: .*$/m, "")).errors.join()).toMatch(/id/);
    expect(sigmaToRule(rule.replace(/^id: .*$/m, ""), { id: "custom-rule" }).value!.id).toBe("custom-rule");
  });
});
