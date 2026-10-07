import type { AttackTechnique, Severity } from "@bloody/contracts";
import { describe, expect, it } from "vitest";
import type { DetectionMatch } from "../detection/types.js";
import type { EntityRef } from "../entities/keys.js";
import { BufferingSink } from "../notifications.js";
import { at, ORG_1, ORG_2, TENANT_A } from "../test-support/fixtures.js";
import { ManualClock } from "../util/clock.js";
import { stableId } from "../util/uuid.js";
import { Correlator } from "./correlator.js";

let seq = 0;
function match(p: { rule?: string; name?: string; severity?: Severity; confidence?: number; t?: number; entities: EntityRef[]; attack?: AttackTechnique[]; org?: string; indicators?: DetectionMatch["indicators"] }): DetectionMatch {
  const id = stableId("m", ++seq);
  const ts = at(p.t ?? 0);
  return {
    id,
    tenantId: TENANT_A,
    organizationId: p.org ?? ORG_1,
    rule: { id: p.rule ?? "r1", name: p.name ?? "Rule one", version: 1, kind: "sigma" },
    title: p.name ?? "Rule one",
    severity: p.severity ?? "medium",
    confidence: p.confidence ?? 0.7,
    attack: p.attack ?? [],
    events: [],
    entities: p.entities,
    explanation: [],
    ...(p.indicators ? { indicators: p.indicators } : {}),
    firstSeenAt: ts,
    lastSeenAt: ts,
    detectedAt: ts,
  };
}
const host = (key: string): EntityRef => ({ kind: "endpoint", key, label: key.toUpperCase() });
const user = (key: string): EntityRef => ({ kind: "user", key, label: key });
const ip = (key: string): EntityRef => ({ kind: "ip", key, label: key });

describe("Correlator grouping", () => {
  it("groups detections sharing an asset within the window, keeps others apart", () => {
    const c = new Correlator();
    const a = c.add(match({ entities: [host("ws-1")], t: 0 }));
    const b = c.add(match({ rule: "r2", name: "Rule two", entities: [host("ws-1"), user("corp\\bob")], t: 600 }));
    const other = c.add(match({ entities: [host("ws-9")], t: 700 }));
    expect(a.created).toBe(true);
    expect(b.created).toBe(false);
    expect(b.incident.id).toBe(a.incident.id);
    expect(b.incident.alertIds).toHaveLength(2);
    expect(b.incident.assetKeys).toEqual(["ws-1"]);
    expect(b.incident.identityKeys).toEqual(["corp\\bob"]);
    expect(b.incident.correlationKeys).toEqual(["endpoint:ws-1", "user:corp\\bob"]);
    expect(other.incident.id).not.toBe(a.incident.id);
    expect(c.list()).toHaveLength(2);
  });

  it("respects the time window", () => {
    const c = new Correlator({ windowSeconds: 3600 });
    const a = c.add(match({ entities: [host("ws-1")], t: 0 }));
    const late = c.add(match({ entities: [host("ws-1")], t: 4 * 3600 }));
    expect(late.incident.id).not.toBe(a.incident.id);
  });

  it("never correlates across organizations", () => {
    const c = new Correlator();
    const a = c.add(match({ entities: [host("ws-1")], org: ORG_1 }));
    const b = c.add(match({ entities: [host("ws-1")], org: ORG_2 }));
    expect(b.incident.id).not.toBe(a.incident.id);
    expect(c.list({ organizationId: ORG_2 })).toHaveLength(1);
  });

  it("merges clusters bridged by a detection touching both", () => {
    const c = new Correlator();
    const a = c.add(match({ entities: [host("ws-1")], t: 0 }));
    const b = c.add(match({ entities: [host("srv-2")], t: 10 }));
    const bridge = c.add(match({ rule: "lateral", name: "Lateral movement", entities: [host("ws-1"), host("srv-2")], t: 20 }));
    expect(bridge.incident.id).toBe(a.incident.id);
    expect(bridge.mergedIncidentIds).toEqual([b.incident.id]);
    expect(bridge.incident.alertIds).toHaveLength(3);
    expect(c.get(b.incident.id)).toBeNull();
    expect(c.list()).toHaveLength(1);
    expect(bridge.incident.title).toMatch(/on WS-1 \(\+1 asset\)/);
  });

  it("ignores noise principals and private addresses, joins on public infrastructure", () => {
    const c = new Correlator();
    const a = c.add(match({ entities: [host("ws-1"), user("nt authority\\system"), ip("10.0.0.5")] }));
    const b = c.add(match({ entities: [host("ws-2"), user("nt authority\\system"), ip("10.0.0.5")] }));
    expect(b.incident.id).not.toBe(a.incident.id);
    const d = c.add(match({ entities: [host("ws-3"), ip("198.51.100.23")] }));
    const e = c.add(match({ entities: [host("ws-4"), ip("198.51.100.23")] }));
    expect(e.incident.id).toBe(d.incident.id);
    expect(e.incident.identityKeys).toEqual([]);
  });

  it("supports explicit ignore lists and a super-node guard", () => {
    const ignoring = new Correlator({ ignoreEntities: ["endpoint:jump-01"] });
    const a = ignoring.add(match({ entities: [host("jump-01")] }));
    expect(ignoring.add(match({ entities: [host("jump-01")] })).incident.id).not.toBe(a.incident.id);
    const guarded = new Correlator({ maxEntityFanout: 0 });
    const b = guarded.add(match({ entities: [host("ws-1")] }));
    expect(guarded.add(match({ entities: [host("ws-1")] })).incident.id).not.toBe(b.incident.id);
  });

  it("is idempotent per match and uses caller-supplied alert ids", () => {
    const c = new Correlator();
    const m = match({ entities: [host("ws-1")] });
    c.add(m, { alertId: "00000000-0000-4000-8000-0000000000aa" });
    const again = c.add(m, { alertId: "00000000-0000-4000-8000-0000000000aa" });
    expect(again.incident.alertIds).toEqual(["00000000-0000-4000-8000-0000000000aa"]);
    expect(again.incident.revision).toBe(2);
  });
});

describe("Correlator severity, promotion and explanation", () => {
  it("escalates via risk (crown-jewel asset, privileged identity, kill-chain) and explains why", () => {
    const c = new Correlator({ context: { assetCriticality: (_org, key) => (key === "dc-01" ? "crown_jewel" : "medium"), identityPrivileged: (_o, k) => k === "corp\\da-admin" } });
    c.add(match({ rule: "office", name: "Office spawned shell", severity: "medium", confidence: 0.8, entities: [host("dc-01")], attack: [{ id: "T1204.002", tactic: "execution" }] }));
    const r = c.add(
      match({ rule: "lsass", name: "LSASS access", severity: "high", confidence: 0.85, t: 60, entities: [host("dc-01"), user("corp\\da-admin")], attack: [{ id: "T1003.001", tactic: "credential-access" }] }),
    );
    expect(r.incident.severity).toBe("critical");
    expect(r.incident.escalationReasons[0]).toMatch(/Escalated from high to critical: correlated risk score/);
    expect(r.incident.riskScore).toBeGreaterThanOrEqual(90);
    expect(Math.abs(r.incident.risk.factors.reduce((s, f) => s + f.contribution, 0) - r.incident.riskScore)).toBeLessThan(1e-6);
    expect(r.incident.title).toBe("Execution and Credential Access on DC-01");
    expect(r.incident.attack.map((t) => t.id)).toEqual(["T1003.001", "T1204.002"]);
    expect(r.incident.summary).toMatch(/2 detection\(s\) from 2 rule\(s\)/);
    expect(r.incident.summary).toMatch(/ATT&CK: T1003.001 \(credential-access\), T1204.002 \(execution\)/);
    expect(r.incident.promote).toBe(true);
  });

  it("never de-escalates below the strongest detection", () => {
    const c = new Correlator();
    const r = c.add(match({ severity: "critical", confidence: 0.1, entities: [host("lab-1")] }));
    expect(r.incident.severity).toBe("critical");
    expect(r.incident.escalationReasons).toEqual([]);
  });

  it("promotes only meaningful clusters", () => {
    const c = new Correlator();
    expect(c.add(match({ severity: "low", entities: [host("a")] })).incident.promote).toBe(false);
    expect(c.add(match({ severity: "high", entities: [host("b")] })).incident).toMatchObject({ promote: true, promoteReason: "Severity high ≥ high." });
    const intel = c.add(match({ severity: "medium", entities: [host("c"), { kind: "indicator", key: "ip:198.51.100.1", label: "198.51.100.1" }], indicators: [{ type: "ip", value: "198.51.100.1", observed: "198.51.100.1", field: "network.dstIp", source: "misp", confidence: 90, severity: "medium" }] }));
    expect(intel.incident.promote).toBe(true);
    expect(intel.incident.indicatorKeys).toEqual(["ip:198.51.100.1"]);
    const strict = new Correlator({ promoteSeverity: "critical", promoteRiskScore: 101 });
    expect(strict.add(match({ severity: "high", entities: [host("d")] })).incident.promote).toBe(false);
  });

  it("notifies automation once on creation, then on escalation / update", () => {
    const sink = new BufferingSink();
    const c = new Correlator({ sink, context: { assetCriticality: (_o, k) => (k === "db-01" ? "crown_jewel" : "low") } });
    c.add(match({ severity: "low", entities: [host("db-01")] })); // not promoted yet → silent
    expect(sink.items).toHaveLength(0);
    c.add(match({ rule: "r2", severity: "high", entities: [host("db-01")], t: 30 }));
    expect(sink.items.map((n) => n.type)).toEqual(["incident.created"]);
    c.add(match({ rule: "r3", severity: "critical", entities: [host("db-01")], t: 60, attack: [{ id: "T1486", tactic: "impact" }] }));
    expect(sink.items.map((n) => n.type)).toEqual(["incident.created", "incident.severity_changed"]);
    c.add(match({ rule: "r3", severity: "critical", entities: [host("db-01")], t: 90 }));
    expect(sink.items.at(-1)!.type).toBe("incident.updated");
  });

  it("expires idle clusters and returns their final drafts", () => {
    const clock = new ManualClock(at(0));
    const c = new Correlator({ windowSeconds: 600, clock });
    c.add(match({ entities: [host("ws-1")], t: 0 }));
    clock.set(at(300));
    expect(c.expire()).toHaveLength(0);
    clock.set(at(1200));
    const done = c.expire();
    expect(done).toHaveLength(1);
    expect(c.list()).toHaveLength(0);
    expect(c.add(match({ entities: [host("ws-1")], t: 1300 })).created).toBe(true);
  });
});
