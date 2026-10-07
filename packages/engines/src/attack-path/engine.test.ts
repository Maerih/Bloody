import { AttackPath as AttackPathSchema, type GraphEdge, type GraphNode, type NodeKind, type Subgraph } from "@bloody/contracts";
import { describe, expect, it } from "vitest";
import { InMemoryGraphStore } from "../graph/memory-store.js";
import { SecurityGraph } from "../graph/security-graph.js";
import { BufferingSink } from "../notifications.js";
import { ORG_1, TENANT_A } from "../test-support/fixtures.js";
import { AttackPathEngine } from "./engine.js";

const node = (id: string, kind: NodeKind, props: Record<string, unknown> = {}): GraphNode => ({ id, kind, key: id, label: id, organizationId: ORG_1, props });
const edge = (from: string, kind: GraphEdge["kind"], to: string, props: Record<string, unknown> = {}): GraphEdge => ({ id: `${from}-${kind}-${to}`, kind, from, to, props });
const vuln = (id: string, props: Record<string, unknown>) => node(id, "vulnerability", { cve: id, ...props });

/**
 * I → A(KEV) ─┐
 *             ├→ H(vuln) → T1(crown) / T2(crown)
 * I → B(EPSS) ┘        B → T2 directly
 */
function hubGraph(extra: { nodes?: GraphNode[]; edges?: GraphEdge[]; hubProps?: Record<string, unknown> } = {}): Subgraph {
  const nodes = [
    node("I", "internet"),
    node("A", "server", { internetFacing: true }),
    node("B", "server", { internetFacing: true }),
    node("H", "server", { criticality: "medium", ...extra.hubProps }),
    node("T1", "data_store", { criticality: "crown_jewel" }),
    node("T2", "data_store", { criticality: "crown_jewel" }),
    vuln("CVE-A", { cvss: 9.8, epss: 0.9, knownExploited: true }),
    vuln("CVE-B", { cvss: 8.1, epss: 0.8 }),
    vuln("CVE-H", { cvss: 8.8, epss: 0.7 }),
    vuln("CVE-T1", { cvss: 7.5, epss: 0.6 }),
    vuln("CVE-T2", { cvss: 7.5, epss: 0.6 }),
    ...(extra.nodes ?? []),
  ];
  const edges = [
    edge("I", "exposes", "A"),
    edge("I", "exposes", "B"),
    edge("A", "can_reach", "H"),
    edge("B", "can_reach", "H"),
    edge("H", "can_reach", "T1"),
    edge("H", "can_reach", "T2"),
    edge("B", "can_reach", "T2"),
    edge("A", "has_vulnerability", "CVE-A", { status: "open", patchAvailable: true }),
    edge("B", "has_vulnerability", "CVE-B", { status: "open" }),
    edge("H", "has_vulnerability", "CVE-H", { status: "open" }),
    edge("T1", "has_vulnerability", "CVE-T1", { status: "open" }),
    edge("T2", "has_vulnerability", "CVE-T2", { status: "open" }),
    ...(extra.edges ?? []),
  ];
  return { nodes, edges };
}

const chain = (p: { nodes: GraphNode[]; steps: Array<{ to: string }>; entry: GraphNode }) => [p.entry.id, ...p.steps.map((s) => s.to)].join(">");

describe("AttackPathEngine — discovery", () => {
  const engine = new AttackPathEngine();

  it("finds every exploitable route from the internet to crown jewels", () => {
    const r = engine.analyze(hubGraph());
    expect(r.paths.map(chain).sort()).toEqual(["I>A>H>T1", "I>A>H>T2", "I>B>H>T1", "I>B>H>T2", "I>B>T2"].sort());
    expect(r.summary).toMatchObject({ totalPaths: 5, targetsAtRisk: 2, entryPoints: 2, shortestPathLength: 2, truncated: false });
    for (const p of r.paths) {
      expect(AttackPathSchema.safeParse(p).success).toBe(true);
      expect(p.target.props.criticality).toBe("crown_jewel");
      expect(p.entry.kind).toBe("internet");
      // exploited vulnerabilities are part of the path with their has_vulnerability edge
      expect(p.nodes.filter((n) => n.kind === "vulnerability").length).toBe(p.steps.filter((s) => s.exploited).length);
      expect(Math.abs(p.risk.factors.reduce((s, f) => s + f.contribution, 0) - p.risk.score)).toBeLessThan(1e-6);
    }
    // ordered by risk
    for (let i = 1; i < r.paths.length; i++) expect(r.paths[i - 1]!.risk.score).toBeGreaterThanOrEqual(r.paths[i]!.risk.score);
  });

  it("scores paths with all required factors and explains the exploited CVEs", () => {
    const r = engine.analyze(hubGraph());
    const viaA = r.paths.find((p) => chain(p) === "I>A>H>T1")!;
    const keys = viaA.risk.factors.map((f) => f.key);
    expect(keys).toEqual(expect.arrayContaining(["exploitability", "known_exploitation", "exposure", "lateral_movement", "asset_criticality", "blast_radius", "path_complexity"]));
    expect(viaA.risk.factors.find((f) => f.key === "exploitability")!.explanation).toContain("CVE-A");
    expect(viaA.steps[0]!.technique).toMatch(/T1190/);
    expect(viaA.steps[1]!.technique).toMatch(/T1210/);
    expect(viaA.chainProbability).toBeGreaterThan(0);
    expect(viaA.chainProbability).toBeLessThan(1);
    // the KEV route outranks the equivalent non-KEV route
    const viaB = r.paths.find((p) => chain(p) === "I>B>H>T1")!;
    expect(viaA.risk.score).toBeGreaterThan(viaB.risk.score);
  });

  it("gates network steps on exploitability (has_vulnerability → exploit)", () => {
    const g = hubGraph();
    const patched = { nodes: g.nodes, edges: g.edges.map((e) => (e.kind === "has_vulnerability" && (e.from === "A" || e.from === "B") ? { ...e, props: { status: "resolved" } } : e)) };
    expect(engine.analyze(patched).paths).toHaveLength(0);
    const explicit = { nodes: patched.nodes.map((n) => (n.id === "B" ? { ...n, props: { ...n.props, exploitability: 0.9 } } : n)), edges: patched.edges };
    expect(engine.analyze(explicit).paths.map(chain).sort()).toEqual(["I>B>H>T1", "I>B>H>T2", "I>B>T2"].sort());
    expect(engine.analyze(hubGraph(), { exploitabilityThreshold: 0.99 }).paths).toHaveLength(0);
  });

  it("protects against cycles and honours max depth / k / budgets", () => {
    const cyclic = hubGraph({ edges: [edge("H", "can_reach", "A"), edge("T1", "can_reach", "H"), edge("H", "can_reach", "B")] });
    const r = engine.analyze(cyclic);
    for (const p of r.paths) {
      const ids = [p.entry.id, ...p.steps.map((s) => s.to)];
      expect(new Set(ids).size).toBe(ids.length);
    }
    expect(r.paths.length).toBeGreaterThanOrEqual(5);
    expect(engine.analyze(hubGraph(), { maxDepth: 2 }).paths.map(chain)).toEqual(["I>B>T2"]);
    const k1 = engine.analyze(hubGraph(), { k: 1 });
    expect(k1.paths.length).toBe(2); // best path per target
    expect(k1.paths.find((p) => p.target.id === "T2")!.length).toBe(2); // shortest/likeliest to T2 is direct
    const budget = engine.analyze(hubGraph(), { maxExpansions: 3 });
    expect(budget.summary.truncated).toBe(true);
    expect(engine.analyze(hubGraph(), { maxPaths: 2 }).paths).toHaveLength(2);
  });

  it("traverses identity edges: credential theft, privileged sessions, admin rights", () => {
    const g: Subgraph = {
      nodes: [
        node("I", "internet"),
        node("vpn", "server", { internetFacing: true }),
        vuln("CVE-VPN", { cvss: 10, epss: 0.95, knownExploited: true }),
        node("svc", "identity", { privileged: false }),
        node("jump", "server"),
        node("da", "identity", { privileged: true, mfa: false }),
        node("dc", "server", { assetKind: "domain_controller", criticality: "high" }),
        node("db", "data_store", { criticality: "crown_jewel" }),
      ],
      edges: [
        edge("I", "exposes", "vpn"),
        edge("vpn", "has_vulnerability", "CVE-VPN"),
        edge("vpn", "stores_credential_for", "svc"),
        edge("svc", "admin_of", "jump"),
        edge("da", "logged_into", "jump"),
        edge("da", "admin_of", "dc"),
        edge("dc", "contains", "db"),
      ],
    };
    const r = engine.analyze(g);
    expect(r.paths).toHaveLength(1);
    const p = r.paths[0]!;
    expect(chain(p)).toBe("I>vpn>svc>jump>da>dc>db");
    expect(p.steps.map((s) => `${s.edgeKind}:${s.direction}`)).toEqual(["exposes:forward", "stores_credential_for:forward", "admin_of:forward", "logged_into:reverse", "admin_of:forward", "contains:forward"]);
    expect(p.nodes.map((n) => n.id)).toEqual(["I", "vpn", "CVE-VPN", "svc", "jump", "da", "dc", "db"]);
    expect(p.risk.factors.find((f) => f.key === "identity_privilege")!.explanation).toContain("da");
    expect(p.risk.factors.find((f) => f.key === "privilege")).toBeDefined();
    expect(p.risk.severity === "high" || p.risk.severity === "critical").toBe(true);
    // MFA on the privileged identity is a compensating control on that step
    const mfa = engine.analyze({ ...g, nodes: g.nodes.map((n) => (n.id === "da" ? { ...n, props: { ...n.props, mfa: true } } : n)) });
    expect(mfa.paths[0]!.risk.score).toBeLessThan(p.risk.score);
    expect(mfa.paths[0]!.risk.factors.some((f) => f.key === "control_mfa")).toBe(true);
  });

  it("synthesizes an internet entry when the subgraph has only internet-facing flags", () => {
    const g = hubGraph();
    const noInternet = { nodes: g.nodes.filter((n) => n.kind !== "internet"), edges: g.edges.filter((e) => e.from !== "I") };
    const r = engine.analyze(noInternet);
    expect(r.paths.length).toBe(5);
    expect(r.paths[0]!.entry.props.virtual).toBe(true);
    const exposure = r.paths.flatMap((p) => p.remediations).find((x) => x.action.startsWith("Remove internet exposure of B"));
    expect(exposure?.nodeId).toBe("B");
  });

  it("is deterministic", () => {
    const a = engine.analyze(hubGraph());
    const b = engine.analyze(hubGraph());
    expect(a.paths.map((p) => p.id)).toEqual(b.paths.map((p) => p.id));
    expect(a.remediations).toEqual(b.remediations);
  });
});

describe("AttackPathEngine — remediation priorities", () => {
  const engine = new AttackPathEngine();
  it("greedy cut: the first remediation breaks the most paths and the cut breaks all of them", () => {
    const r = engine.analyze(hubGraph());
    expect(r.remediations[0]!.pathsBroken).toBe(4);
    expect(r.remediations[0]!.action).toMatch(/CVE-H/); // patching the hub breaks 4 of 5 paths
    expect(r.remediations[0]!.effort).toBe("low");
    expect(r.summary.fixesToBreakAll).toBe(2);
    expect(r.remediations[1]!.marginalPathsBroken).toBe(1);
    expect(r.remediations.reduce((s, x) => s + x.marginalPathsBroken, 0)).toBe(r.paths.length);
    expect(r.summary.topRemediation).toBe(r.remediations[0]!.action);
    // every path lists remediations, strongest (greedy rank) first
    for (const p of r.paths) {
      expect(p.remediations.length).toBeGreaterThan(0);
      expect(p.remediations.every((x) => x.pathsBroken >= 1)).toBe(true);
    }
    const viaHub = r.paths.find((p) => chain(p) === "I>A>H>T1")!;
    expect(viaHub.remediations[0]!.action).toBe(r.remediations[0]!.action);
  });

  it("compensating controls lower path risk", () => {
    const base = engine.analyze(hubGraph());
    const edr = engine.analyze(hubGraph({ hubProps: { edr: true, segmented: true } }));
    const pick = (x: typeof base) => x.paths.find((p) => chain(p) === "I>A>H>T1")!.risk.score;
    expect(pick(edr)).toBeLessThan(pick(base));
  });

  it("emits a crown-jewel exposure notification for automation", () => {
    const sink = new BufferingSink();
    new AttackPathEngine({ sink }).analyze(hubGraph(), {}, { tenantId: TENANT_A, organizationId: ORG_1 });
    expect(sink.items).toHaveLength(1);
    expect(sink.items[0]).toMatchObject({ type: "attack_path.crown_jewel_exposed", paths: 5, organizationId: ORG_1 });
  });
});

describe("AttackPathEngine × SecurityGraph (spec example: Internet → VPN → … → crown-jewel data)", () => {
  it("discovers the path end to end from an ingested graph", async () => {
    const store = new InMemoryGraphStore({ tenantId: TENANT_A });
    const g = new SecurityGraph({ store });
    const vpn = await g.ingestAsset({ organizationId: ORG_1, name: "vpn-gw", hostname: "vpn-gw", kind: "server", criticality: "high", internetFacing: true });
    await g.ingestVulnerability({ organizationId: ORG_1, asset: vpn.id, cve: "CVE-2024-3400", title: "VPN RCE", cvss: 10, epss: 0.96, knownExploited: true, patchAvailable: true });
    const svc = await g.ingestIdentity({ organizationId: ORG_1, provider: "ad", principal: "svc-vpn", kind: "service_account" });
    const da = await g.ingestIdentity({ organizationId: ORG_1, provider: "ad", principal: "da-admin", privileged: true, mfaEnabled: false });
    const dc = await g.ingestAsset({ organizationId: ORG_1, name: "dc-01", hostname: "dc-01", kind: "domain_controller", criticality: "high" });
    const db = await g.ingestAsset({ organizationId: ORG_1, name: "payments-db", hostname: "payments-db", kind: "database", criticality: "crown_jewel" });
    await g.relate(vpn.id, "stores_credential_for", svc.id);
    await g.relate(svc.id, "member_of", (await g.ingestIdentity({ organizationId: ORG_1, provider: "ad", principal: "VPN Admins", kind: "group" })).id);
    await g.relate({ organizationId: ORG_1, kind: "group", key: "ad:vpn admins" }, "admin_of", dc.id);
    await g.relate(da.id, "logged_into", dc.id);
    await g.relate(dc.id, "can_reach", db.id);
    await g.relate(da.id, "has_access_to", db.id);

    const surface = await g.loadAttackSurface(ORG_1);
    const r = new AttackPathEngine().analyze(surface);
    expect(r.paths.length).toBeGreaterThanOrEqual(1);
    const best = r.paths[0]!;
    expect(best.nodes.map((n) => n.label)).toEqual(["Internet", "vpn-gw", "CVE-2024-3400 VPN RCE", "svc-vpn", "VPN Admins", "dc-01", "da-admin", "payments-db"]);
    expect(best.target.label).toBe("payments-db");
    expect(r.remediations[0]!.pathsBroken).toBe(r.paths.length);
  });
});
