import { describe, expect, it } from "vitest";
import { ORG_1, ORG_2, TENANT_A, TENANT_B } from "../test-support/fixtures.js";
import { graphEdgeId, graphNodeId } from "./ids.js";
import { InMemoryGraphStore, InMemoryGraphStoreProvider } from "./memory-store.js";
import { edgeFromRow, escapeLikePattern, nodeFromRow, nodeToRow } from "./sql.js";
import { GraphError } from "./types.js";

describe("InMemoryGraphStore", () => {
  it("upsertNode returns a stable id for (organization, kind, key) and merges props", async () => {
    const s = new InMemoryGraphStore({ tenantId: TENANT_A });
    const a = await s.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "ws-1", props: { os: "Windows" } });
    const b = await s.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "ws-1", label: "WS-1", props: { criticality: "high", os: undefined } });
    expect(b.id).toBe(a.id);
    expect(a.id).toBe(graphNodeId(TENANT_A, ORG_1, "endpoint", "ws-1"));
    expect(b.label).toBe("WS-1");
    expect(b.props).toEqual({ os: "Windows", criticality: "high" });
    const other = await s.upsertNode({ organizationId: ORG_2, kind: "endpoint", key: "ws-1" });
    expect(other.id).not.toBe(a.id);
    const global = await s.upsertNode({ organizationId: null, kind: "technique", key: "T1003" });
    expect(global.organizationId).toBeNull();
    expect(s.size.nodes).toBe(3);
  });

  it("maintains firstSeenAt / lastSeenAt / seenCount from observations (order independent)", async () => {
    const s = new InMemoryGraphStore({ tenantId: TENANT_A });
    await s.upsertNode({ organizationId: ORG_1, kind: "ip", key: "8.8.8.8" }, { observedAt: "2026-01-02T00:00:00.000Z" });
    await s.upsertNode({ organizationId: ORG_1, kind: "ip", key: "8.8.8.8" }, { observedAt: "2026-01-01T00:00:00.000Z" });
    const n = await s.upsertNode({ organizationId: ORG_1, kind: "ip", key: "8.8.8.8", props: { seenCount: 999 } }, { observedAt: "2026-01-03T00:00:00.000Z" });
    expect(n.props).toMatchObject({ firstSeenAt: "2026-01-01T00:00:00.000Z", lastSeenAt: "2026-01-03T00:00:00.000Z", seenCount: 3 });
  });

  it("dedupes edges by (from, kind, to) and rejects dangling or cross-organization edges", async () => {
    const s = new InMemoryGraphStore({ tenantId: TENANT_A });
    const u = await s.upsertNode({ organizationId: ORG_1, kind: "user", key: "corp\\bob" });
    const h = await s.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "ws-1" });
    const e1 = await s.upsertEdge({ kind: "logged_into", from: u.id, to: h.id, props: { a: 1 } });
    const e2 = await s.upsertEdge({ kind: "logged_into", from: u.id, to: h.id, props: { b: 2 } });
    expect(e2.id).toBe(e1.id);
    expect(e2.id).toBe(graphEdgeId(TENANT_A, u.id, "logged_into", h.id));
    expect(e2.props).toEqual({ a: 1, b: 2 });
    expect(e2.organizationId).toBe(ORG_1);
    expect(s.size.edges).toBe(1);
    await expect(s.upsertEdge({ kind: "logged_into", from: u.id, to: "missing" })).rejects.toBeInstanceOf(GraphError);
    const foreign = await s.upsertNode({ organizationId: ORG_2, kind: "endpoint", key: "ws-9" });
    await expect(s.upsertEdge({ kind: "logged_into", from: u.id, to: foreign.id })).rejects.toThrow(/Cross-organization/);
    await expect(s.upsertEdge({ kind: "logged_into", from: u.id, to: h.id, organizationId: ORG_2 })).rejects.toThrow(/does not match/);
    // tenant-global node may connect to any organization
    const t = await s.upsertNode({ organizationId: null, kind: "technique", key: "T1078" });
    expect((await s.upsertEdge({ kind: "observed_on", from: t.id, to: foreign.id })).organizationId).toBe(ORG_2);
  });

  it("validates node input", async () => {
    const s = new InMemoryGraphStore({ tenantId: TENANT_A });
    await expect(s.upsertNode({ organizationId: ORG_1, kind: "nope" as never, key: "x" })).rejects.toThrow(/Unknown node kind/);
    await expect(s.upsertNode({ organizationId: ORG_1, kind: "ip", key: "" })).rejects.toThrow(/non-empty/);
    expect(() => new InMemoryGraphStore({ tenantId: "" })).toThrow();
  });

  it("findNodes filters by organization, kind(s), key, prefix, label and props", async () => {
    const s = new InMemoryGraphStore({ tenantId: TENANT_A });
    await s.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "ws-1", label: "Finance laptop", props: { internetFacing: false } });
    await s.upsertNode({ organizationId: ORG_1, kind: "server", key: "web-1", label: "Web server", props: { internetFacing: true } });
    await s.upsertNode({ organizationId: ORG_2, kind: "endpoint", key: "ws-2", label: "HR laptop" });
    await s.upsertNode({ organizationId: null, kind: "technique", key: "T1003" });
    expect((await s.findNodes({ kind: "endpoint" })).map((n) => n.key)).toEqual(["ws-1", "ws-2"]);
    expect((await s.findNodes({ organizationId: ORG_1, kind: ["endpoint", "server"] })).length).toBe(2);
    expect((await s.findNodes({ organizationId: null })).map((n) => n.key)).toEqual(["T1003"]);
    expect((await s.findNodes({ keyPrefix: "ws-" })).length).toBe(2);
    expect((await s.findNodes({ labelContains: "LAPTOP" })).length).toBe(2);
    expect((await s.findNodes({ propEquals: { internetFacing: true } })).map((n) => n.key)).toEqual(["web-1"]);
    expect((await s.findNodes({ organizationId: ORG_1, kind: "endpoint", key: "ws-1" })).length).toBe(1);
    expect((await s.findNodes({ limit: 1 })).length).toBe(1);
    expect(await s.countNodes({ kind: "endpoint" })).toBe(2);
  });

  it("neighbors traverses by direction, edge kinds, node kinds and depth with limits", async () => {
    const s = new InMemoryGraphStore({ tenantId: TENANT_A });
    const n = async (kind: "user" | "endpoint" | "process" | "ip", key: string) => s.upsertNode({ organizationId: ORG_1, kind, key });
    const u = await n("user", "bob");
    const h = await n("endpoint", "ws-1");
    const p = await n("process", "ws-1|1|cmd.exe");
    const ip = await n("ip", "8.8.8.8");
    await s.upsertEdge({ kind: "logged_into", from: u.id, to: h.id });
    await s.upsertEdge({ kind: "runs_on", from: p.id, to: h.id });
    await s.upsertEdge({ kind: "connected_to", from: p.id, to: ip.id });

    const out1 = await s.neighbors(u.id, { direction: "out" });
    expect(out1.nodes.map((x) => x.node.key)).toEqual(["ws-1"]);
    const both2 = await s.neighbors(u.id, { direction: "both", depth: 2 });
    expect(both2.nodes.map((x) => [x.node.key, x.depth])).toEqual([
      ["ws-1", 1],
      ["ws-1|1|cmd.exe", 2],
    ]);
    const both3 = await s.neighbors(u.id, { depth: 3 });
    expect(both3.nodes.find((x) => x.node.key === "8.8.8.8")?.depth).toBe(3);
    expect(both3.edges.length).toBe(3);
    const onlyLogon = await s.neighbors(h.id, { direction: "in", edgeKinds: ["logged_into"] });
    expect(onlyLogon.nodes.map((x) => x.node.key)).toEqual(["bob"]);
    const kinds = await s.neighbors(h.id, { depth: 3, nodeKinds: ["process", "ip"] });
    expect(kinds.nodes.map((x) => x.node.kind).sort()).toEqual(["ip", "process"]);
    const limited = await s.neighbors(h.id, { depth: 3, limit: 1 });
    expect(limited.nodes.length).toBe(1);
    expect(limited.truncated).toBe(true);
    await expect(s.neighbors("missing")).rejects.toThrow(/not found/);
  });

  it("subgraph returns induced edges; deleteNode cascades edges", async () => {
    const s = new InMemoryGraphStore({ tenantId: TENANT_A });
    const a = await s.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "a" });
    const b = await s.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "b" });
    const c = await s.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "c" });
    await s.upsertEdge({ kind: "can_reach", from: a.id, to: b.id });
    await s.upsertEdge({ kind: "can_reach", from: b.id, to: c.id });
    const sub = await s.subgraph([a.id, b.id, "unknown"]);
    expect(sub.nodes.length).toBe(2);
    expect(sub.edges.length).toBe(1);
    expect(await s.deleteNode(b.id)).toBe(true);
    expect(s.size).toEqual({ nodes: 2, edges: 0 });
    expect(await s.edgesOf([a.id], { direction: "both" })).toEqual([]);
    expect(await s.deleteNode(b.id)).toBe(false);
  });

  it("isolates tenants: one store per tenant, no shared ids", async () => {
    const provider = new InMemoryGraphStoreProvider();
    const a = provider.forTenant(TENANT_A);
    const b = provider.forTenant(TENANT_B);
    expect(provider.forTenant(TENANT_A)).toBe(a);
    const na = await a.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "shared-name" });
    const nb = await b.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "shared-name" });
    expect(na.id).not.toBe(nb.id);
    expect(await b.getNode(na.id)).toBeNull();
    await expect(b.upsertEdge({ kind: "can_reach", from: nb.id, to: na.id })).rejects.toThrow(/does not exist in tenant/);
    expect(provider.dropTenant(TENANT_B)).toBe(true);
  });

  it("returns defensive copies", async () => {
    const s = new InMemoryGraphStore({ tenantId: TENANT_A });
    const n = await s.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "a", props: { tags: ["x"] } });
    (n.props.tags as string[]).push("mutated");
    expect((await s.getNode(n.id))!.props.tags).toEqual(["x"]);
  });
});

describe("SQL row mapping", () => {
  it("round-trips nodes and enforces tenant on read", async () => {
    const s = new InMemoryGraphStore({ tenantId: TENANT_A });
    const n = await s.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "a", props: { x: 1 } });
    const row = nodeToRow(n, TENANT_A);
    expect(nodeFromRow({ ...row, props: JSON.stringify(row.props) }, TENANT_A)).toEqual(n);
    expect(() => nodeFromRow(row, TENANT_B)).toThrow(/another tenant/);
    expect(() => nodeFromRow({ ...row, kind: "bogus" }, TENANT_A)).toThrow(/unknown node kind/);
    expect(() => edgeFromRow({ id: "e", tenant_id: TENANT_A, organization_id: ORG_1, kind: "bogus", from_id: "a", to_id: "b", props: null }, TENANT_A)).toThrow();
    expect(edgeFromRow({ id: "e", tenant_id: TENANT_A, organization_id: ORG_1, kind: "can_reach", from_id: "a", to_id: "b", props: null }, TENANT_A).props).toEqual({});
    expect(escapeLikePattern("50%_off\\")).toBe("50\\%\\_off\\\\");
  });
});

describe("GRAPH_SCHEMA_SQL", () => {
  it("documents both tables with tenant isolation and the dedupe keys", async () => {
    const { GRAPH_SCHEMA_SQL } = await import("./sql.js");
    expect(GRAPH_SCHEMA_SQL).toMatch(/create table if not exists graph_nodes/);
    expect(GRAPH_SCHEMA_SQL).toMatch(/unique \(tenant_id, from_id, kind, to_id\)/);
    expect(GRAPH_SCHEMA_SQL).toMatch(/row level security/);
  });
});
