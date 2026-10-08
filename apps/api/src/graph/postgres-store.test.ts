import { CanonicalEvent, type GraphNode } from "@bloody/contracts";
import { GraphError, InMemoryGraphStore, SecurityGraph, type GraphEdgeRecord, type GraphStore } from "@bloody/engines";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTenant, createTestApp, credentialTheftChain, dnsEvent, minutesAgo, type TestApp, type TestTenant } from "../test/harness.js";
import { PostgresGraphStore } from "./postgres-store.js";

/**
 * Differential tests: the Postgres store must behave exactly like the engines' reference
 * InMemoryGraphStore. Every scenario runs against both and the observable results must match.
 */
let t: TestApp;
let tenant: TestTenant;
let ORG_1: string;
let ORG_2: string;

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 2 });
  [ORG_1, ORG_2] = tenant.orgIds as [string, string];
});
afterAll(async () => {
  await t?.close();
});

const byId = <T extends { id: string }>(xs: T[]): T[] => [...xs].sort((a, b) => a.id.localeCompare(b.id));
const errorOf = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "resolved";
  } catch (err) {
    return err instanceof GraphError ? `GraphError:${err.code}` : `Error:${(err as Error).message}`;
  }
};

/** Run the same operations against both stores (Postgres inside a rolled-back tenant transaction). */
async function differential<T>(scenario: (store: GraphStore) => Promise<T>): Promise<{ memory: T; postgres: T }> {
  const memory = await scenario(new InMemoryGraphStore({ tenantId: tenant.tenantId }));
  const client = await t.db.app.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenant.tenantId]);
    const postgres = await scenario(new PostgresGraphStore(client, tenant.tenantId));
    return { memory, postgres };
  } finally {
    await client.query("ROLLBACK");
    client.release();
  }
}

describe("PostgresGraphStore ≡ InMemoryGraphStore", () => {
  it("upserts nodes with stable ids, merged props and observation bookkeeping", async () => {
    const r = await differential(async (s) => {
      const a = await s.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "ws-1", props: { os: "Windows" } }, { observedAt: "2026-01-02T00:00:00.000Z" });
      const b = await s.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "ws-1", label: "WS-1", props: { criticality: "high", os: undefined } }, { observedAt: "2026-01-01T00:00:00.000Z" });
      const c = await s.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "ws-1", props: { seenCount: 999 } }, { observedAt: "2026-01-03T00:00:00.000Z" });
      const other = await s.upsertNode({ organizationId: ORG_2, kind: "endpoint", key: "ws-1" });
      const global = await s.upsertNode({ organizationId: null, kind: "technique", key: "T1003" });
      return { a, b, c, other, global, byKey: await s.getNodeByKey(ORG_1, "endpoint", "ws-1"), missing: await s.getNode("00000000-0000-4000-8000-000000000000"), bad: await errorOf(s.upsertNode({ organizationId: ORG_1, kind: "ip", key: "" })) };
    });
    expect(r.postgres).toEqual(r.memory);
    expect(r.postgres.c.props).toMatchObject({ firstSeenAt: "2026-01-01T00:00:00.000Z", lastSeenAt: "2026-01-03T00:00:00.000Z", seenCount: 3, os: "Windows", criticality: "high" });
  });

  it("dedupes edges and enforces referential and organization integrity", async () => {
    const r = await differential(async (s) => {
      const u = await s.upsertNode({ organizationId: ORG_1, kind: "user", key: "corp\\bob" });
      const h = await s.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "ws-1" });
      const e1 = await s.upsertEdge({ kind: "logged_into", from: u.id, to: h.id, props: { a: 1 } });
      const e2 = await s.upsertEdge({ kind: "logged_into", from: u.id, to: h.id, props: { b: 2 } });
      const foreign = await s.upsertNode({ organizationId: ORG_2, kind: "endpoint", key: "ws-9" });
      const tech = await s.upsertNode({ organizationId: null, kind: "technique", key: "T1078" });
      const crossGlobal = await s.upsertEdge({ kind: "observed_on", from: tech.id, to: foreign.id });
      return {
        e1,
        e2,
        crossGlobal,
        dangling: await errorOf(s.upsertEdge({ kind: "logged_into", from: u.id, to: "00000000-0000-4000-8000-000000000000" })),
        crossOrg: await errorOf(s.upsertEdge({ kind: "logged_into", from: u.id, to: foreign.id })),
        wrongOrg: await errorOf(s.upsertEdge({ kind: "logged_into", from: u.id, to: h.id, organizationId: ORG_2 })),
        badKind: await errorOf(s.upsertEdge({ kind: "nope" as never, from: u.id, to: h.id })),
        edge: await s.getEdge(e1.id),
      };
    });
    expect(r.postgres).toEqual(r.memory);
    expect(r.postgres.e2.props).toEqual({ a: 1, b: 2 });
    expect(r.postgres.crossGlobal.organizationId).toBe(ORG_2);
    expect(r.postgres.dangling).toBe("GraphError:integrity");
  });

  it("finds, counts, traverses and deletes identically", async () => {
    const r = await differential(async (s) => {
      await s.upsertNode({ organizationId: ORG_1, kind: "endpoint", key: "ws-1", label: "Finance laptop", props: { internetFacing: false } });
      await s.upsertNode({ organizationId: ORG_1, kind: "server", key: "web-1", label: "Web server", props: { internetFacing: true } });
      await s.upsertNode({ organizationId: ORG_2, kind: "endpoint", key: "ws-2", label: "HR laptop" });
      await s.upsertNode({ organizationId: null, kind: "technique", key: "T1003" });
      await s.upsertNode({ organizationId: ORG_1, kind: "domain", key: "50%_off.example", label: "50%_off.example" });
      const find = {
        endpoints: await s.findNodes({ kind: "endpoint" }),
        org1: await s.findNodes({ organizationId: ORG_1, kind: ["endpoint", "server"] }),
        global: await s.findNodes({ organizationId: null }),
        prefix: await s.findNodes({ keyPrefix: "ws-" }),
        likeEscaping: await s.findNodes({ keyPrefix: "50%_" }),
        label: await s.findNodes({ labelContains: "LAPTOP" }),
        props: await s.findNodes({ propEquals: { internetFacing: true } }),
        limited: await s.findNodes({ limit: 1 }),
        all: await s.findNodes({}),
        count: await s.countNodes({ kind: "endpoint" }),
      };

      const n = (kind: "user" | "endpoint" | "process" | "ip", key: string) => s.upsertNode({ organizationId: ORG_1, kind, key });
      const u = await n("user", "bob");
      const h = await n("endpoint", "ws-1");
      const p = await n("process", "ws-1|1|cmd.exe");
      const ip = await n("ip", "8.8.8.8");
      await s.upsertEdge({ kind: "logged_into", from: u.id, to: h.id });
      await s.upsertEdge({ kind: "runs_on", from: p.id, to: h.id });
      await s.upsertEdge({ kind: "connected_to", from: p.id, to: ip.id });
      const hood = (x: Awaited<ReturnType<GraphStore["neighbors"]>>) => ({ root: x.root.id, nodes: x.nodes.map((y) => [y.node.key, y.depth]).sort(), edges: byId(x.edges), truncated: x.truncated });
      const traverse = {
        out1: hood(await s.neighbors(u.id, { direction: "out" })),
        both2: hood(await s.neighbors(u.id, { direction: "both", depth: 2 })),
        both3: hood(await s.neighbors(u.id, { depth: 3 })),
        logon: hood(await s.neighbors(h.id, { direction: "in", edgeKinds: ["logged_into"] })),
        kinds: hood(await s.neighbors(h.id, { depth: 3, nodeKinds: ["process", "ip"] })),
        limited: (await s.neighbors(h.id, { depth: 3, limit: 1 })).truncated,
        edgesOut: byId(await s.edgesOf([p.id], { direction: "out" })),
        edgesIn: byId(await s.edgesOf([h.id], { direction: "in", edgeKinds: ["runs_on"] })),
        sub: await s.subgraph([u.id, h.id, "unknown"]).then((g) => ({ nodes: byId(g.nodes), edges: byId(g.edges) })),
      };
      const deleted = { first: await s.deleteNode(h.id), again: await s.deleteNode(h.id), dangling: await s.edgesOf([u.id, p.id], { direction: "both" }) };
      return { find, traverse, deleted };
    });
    expect(r.postgres).toEqual(r.memory);
    expect(r.postgres.find.endpoints.map((x: GraphNode) => x.key)).toEqual(["ws-1", "ws-2"]);
    expect(r.postgres.find.likeEscaping.map((x: GraphNode) => x.key)).toEqual(["50%_off.example"]);
    expect(r.postgres.deleted.dangling.map((e: GraphEdgeRecord) => e.kind)).toEqual(["connected_to"]);
  });

  it("produces the same Security Graph from canonical events", async () => {
    const now = Date.parse("2026-10-07T12:00:00.000Z");
    const events = [...credentialTheftChain("kb-ws-fin07", now), dnsEvent("kb-ws-fin07", minutesAgo(25, now), "10.10.20.47", "cdn-telemetry.update-check.example")].map((e) =>
      CanonicalEvent.parse({ ...e, tenantId: tenant.tenantId, organizationId: ORG_1 }),
    );
    const clock = { now: () => now };
    const r = await differential(async (store) => {
      const graph = new SecurityGraph({ store, clock });
      for (const e of events) await graph.ingestEvent(e);
      await graph.ingestAsset({ id: "6a7f6c8e-6a11-4f0a-9a37-1f5a7d1f0001", organizationId: ORG_1, kind: "endpoint", name: "Finance WS 07", hostname: "kb-ws-fin07", criticality: "high", internetFacing: false });
      const nodes = await store.findNodes({ limit: 1000 });
      const edges = await store.edgesOf(nodes.map((n) => n.id), { direction: "both", limit: 5000 });
      return { nodes: byId(nodes), edges: byId(edges), blast: (await graph.blastRadius({ organizationId: ORG_1, kind: "endpoint", key: "kb-ws-fin07" })).nodes?.length ?? null };
    });
    expect(r.postgres.nodes.length).toBeGreaterThan(8);
    expect(r.postgres.edges.length).toBeGreaterThan(8);
    expect(r.postgres).toEqual(r.memory);
  });
});
