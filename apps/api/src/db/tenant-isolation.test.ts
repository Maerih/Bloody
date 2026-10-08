import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PostgresGraphStore } from "../graph/postgres-store.js";
import { api, createApiKey, createTenant, createTestApp, credentialTheftChain, login, uniq, type Json, type TestApp, type TestTenant } from "../test/harness.js";

/**
 * Tenant isolation is enforced twice: every handler derives the tenant from the authenticated
 * principal, and Postgres row-level security (FORCE RLS, runtime role without BYPASSRLS) hides
 * every other tenant's rows even from a query that forgets its tenant predicate.
 */
let t: TestApp;
let A: TestTenant;
let B: TestTenant;
let a: ReturnType<typeof api>;
let b: ReturnType<typeof api>;
const fx = {} as {
  aIncident: Json;
  bIncident: Json;
  bAsset: Json;
  bAssetName: string;
  bInvestigation: Json;
  bEscalationId: string;
  bKey: string;
  bGraphNodeId: string;
};

beforeAll(async () => {
  t = await createTestApp();
  A = await createTenant(t, { orgs: 2 });
  B = await createTenant(t, { orgs: 1 });
  a = api(t.app, { token: (await login(t.app, A.admin.email)).token });
  b = api(t.app, { token: (await login(t.app, B.admin.email)).token });

  fx.bAssetName = uniq("b-secret-server");
  const bAsset = await b.post("/assets", { organizationId: B.orgIds[0], kind: "server", name: fx.bAssetName, hostname: `${fx.bAssetName}.corp`, ipAddresses: ["10.66.0.5"], criticality: "crown_jewel" });
  expect(bAsset.status).toBe(201);
  fx.bAsset = bAsset.body;
  const aAsset = await a.post("/assets", { organizationId: A.orgIds[0], kind: "endpoint", name: "a-laptop", hostname: "a-laptop" });
  expect(aAsset.status).toBe(201);

  const bInc = await b.post("/incidents", { organizationId: B.orgIds[0], title: "B: ransomware on the file server", severity: "critical", assetIds: [fx.bAsset.id] });
  expect(bInc.status).toBe(201);
  fx.bIncident = bInc.body;
  fx.bEscalationId = bInc.body.escalations[0]?.id ?? (await b.get(`/escalations?incidentId=${bInc.body.id}`)).body.items[0].id;
  const aInc = await a.post("/incidents", { organizationId: A.orgIds[0], title: "A: suspicious sign-in", severity: "medium" });
  expect(aInc.status).toBe(201);
  fx.aIncident = aInc.body;
  fx.bInvestigation = (await b.post("/investigations", { incidentId: fx.bIncident.id, title: "B investigation" })).body;
  fx.bKey = (await createApiKey(t.app, (await login(t.app, B.admin.email)).token, { organizationId: B.orgIds[0]! })).key;

  const ingest = await api(t.app, { apiKey: fx.bKey }).post("/ingest/events", { events: credentialTheftChain("b-ws-01") });
  expect(ingest.status).toBe(202);
  await t.services.bus.drain();
  const node = await t.privileged.query<{ id: string }>("SELECT id FROM graph_nodes WHERE tenant_id = $1 AND kind = 'endpoint' AND key = 'b-ws-01'", [B.tenantId]);
  fx.bGraphNodeId = node.rows[0]!.id;
});

afterAll(async () => {
  await t?.close();
});

describe("tenant isolation through the API", () => {
  it("never returns another tenant's records, and reports them as not found", async () => {
    expect((await a.get(`/incidents/${fx.bIncident.id}`)).status).toBe(404);
    expect((await a.patch(`/incidents/${fx.bIncident.id}`, { status: "closed" })).status).toBe(404);
    expect((await a.post(`/incidents/${fx.bIncident.id}/notes`, { body: "hello" })).status).toBe(404);
    expect((await a.get(`/assets/${fx.bAsset.id}`)).status).toBe(404);
    expect((await a.get(`/organizations/${B.orgIds[0]}`)).status).toBe(404);
    expect((await a.get(`/investigations/${fx.bInvestigation.id}`)).status).toBe(404);
    expect((await a.get(`/escalations/${fx.bEscalationId}`)).status).toBe(404);
    expect((await a.post(`/escalations/${fx.bEscalationId}/acknowledge`)).status).toBe(404);
    expect((await a.get(`/users/${B.admin.id}`)).status).toBe(404);
    expect((await a.get(`/command-center/summary?organizationId=${B.orgIds[0]}`)).status).toBe(404);

    const list = await a.get("/incidents?status=all&limit=500");
    expect(list.status).toBe(200);
    const ids = list.body.items.map((i: Json) => i.id);
    expect(ids).toContain(fx.aIncident.id);
    expect(ids).not.toContain(fx.bIncident.id);
    expect(list.body.items.every((i: Json) => i.tenantId === A.tenantId)).toBe(true);

    // Explicitly asking for a foreign organization yields nothing, never B's data.
    const foreign = await a.get(`/incidents?organizationId=${B.orgIds[0]}&status=all`);
    expect(foreign.body.items).toEqual([]);
    expect((await a.get(`/alerts?organizationId=${B.orgIds[0]}`)).body.items).toEqual([]);
    expect((await a.get("/alerts")).body.items).toEqual([]);
  });

  it("keeps per-tenant incident numbering", async () => {
    expect(fx.aIncident.number).toBe(1);
    expect(fx.bIncident.number).toBe(1);
  });

  it("scopes global search, users, organizations and the audit trail", async () => {
    const search = await a.get(`/search?q=${encodeURIComponent(fx.bAssetName)}`);
    expect(search.status).toBe(200);
    expect(search.body.items).toEqual([]);
    expect((await a.get("/search?q=b-ws-01")).body.items).toEqual([]);
    expect((await b.get(`/search?q=${encodeURIComponent(fx.bAssetName)}`)).body.items.map((h: Json) => h.id)).toContain(fx.bAsset.id);

    const users = await a.get("/users?limit=500");
    expect(users.body.items.map((u: Json) => u.id)).not.toContain(B.admin.id);
    const orgs = await a.get("/organizations");
    expect(orgs.body.items.map((o: Json) => o.id).sort()).toEqual([...A.orgIds].sort());
    const audit = await a.get("/audit?limit=500");
    expect(audit.status).toBe(200);
    expect(audit.body.items.length).toBeGreaterThan(0);
    const bRows = await t.privileged.query<{ id: string }>("SELECT id FROM audit_log WHERE tenant_id = $1", [B.tenantId]);
    expect(bRows.rows.length).toBeGreaterThan(0);
    const bIds = new Set(bRows.rows.map((r) => r.id));
    expect(audit.body.items.filter((r: Json) => bIds.has(r.id))).toEqual([]);
    // A's own denied attempts against B's ids are part of A's trail (outcome failure/denied).
    const attempts = audit.body.items.filter((r: Json) => r.target?.id === fx.bIncident.id);
    expect(attempts.length).toBeGreaterThan(0);
    expect(attempts.every((r: Json) => r.outcome !== "success")).toBe(true);
  });

  it("refuses cross-tenant references and writes", async () => {
    const bad = await a.post("/incidents", { organizationId: A.orgIds[0], title: "steal B asset", severity: "low", assetIds: [fx.bAsset.id] });
    expect(bad.status).toBe(400);
    expect((await a.post("/incidents", { organizationId: B.orgIds[0], title: "write into B", severity: "low" })).status).toBe(404);
    expect((await a.post("/assets", { organizationId: B.orgIds[0], kind: "endpoint", name: "implant" })).status).toBe(404);
    expect((await a.post("/ingest/events", { organizationId: B.orgIds[0], events: credentialTheftChain("x") })).status).toBe(404);
    expect((await a.post("/investigations", { incidentId: fx.bIncident.id, title: "peek into B" })).status).toBe(404);
    expect((await api(t.app, { apiKey: fx.bKey }).post("/ingest/events", { organizationId: A.orgIds[0], events: [] })).status).toBe(403);
  });

  it("isolates analytics: B's telemetry never reaches A's dashboard or graph", async () => {
    const aSummary = await a.get("/command-center/summary");
    expect(aSummary.status).toBe(200);
    expect(aSummary.body.socActions.eventsAnalyzed).toBe(0);
    expect(aSummary.body.socActions.signalsGenerated).toBe(0);
    expect(aSummary.body.triage.every((i: Json) => A.orgIds.includes(i.organizationId))).toBe(true);
    const bSummary = await b.get("/command-center/summary");
    expect(bSummary.body.socActions.eventsAnalyzed).toBe(3);
    expect(bSummary.body.socActions.signalsGenerated).toBeGreaterThanOrEqual(3);
  });
});

describe("row-level security with the runtime role", () => {
  it("runs as a role that cannot bypass RLS, and every tenant table forces it", async () => {
    const role = await t.db.app.query<{ current_user: string; rolsuper: boolean; rolbypassrls: boolean }>(
      "SELECT current_user, r.rolsuper, r.rolbypassrls FROM pg_roles r WHERE r.rolname = current_user",
    );
    expect(role.rows[0]).toEqual({ current_user: "bloody_app", rolsuper: false, rolbypassrls: false });
    const unprotected = await t.privileged.query<{ relname: string }>(`
      SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relname <> 'auth_lookup'
        AND EXISTS (SELECT 1 FROM pg_attribute x WHERE x.attrelid = c.oid AND x.attname = 'tenant_id' AND NOT x.attisdropped)
        AND NOT (c.relrowsecurity AND c.relforcerowsecurity)`);
    expect(unprotected.rows).toEqual([]);
    const owned = await t.privileged.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tableowner = 'bloody_app'");
    expect(owned.rows).toEqual([]);
  });

  it("hides other tenants' rows even without a tenant predicate", async () => {
    await t.db.withTenant(A.tenantId, async (tx) => {
      const direct = await tx.query("SELECT * FROM incidents WHERE id = $1", [fx.bIncident.id]);
      expect(direct.rowCount).toBe(0);
      const all = await tx.query<{ tenant_id: string }>("SELECT DISTINCT tenant_id FROM incidents");
      expect(all.rows.map((r) => r.tenant_id)).toEqual([A.tenantId]);
      for (const table of ["organizations", "assets", "events", "alerts", "graph_nodes", "graph_edges", "audit_log", "users", "api_keys", "escalations", "investigations", "role_bindings"]) {
        const leaked = await tx.query(`SELECT 1 FROM ${table} WHERE tenant_id = $1 LIMIT 1`, [B.tenantId]);
        expect(leaked.rowCount, `${table} leaked tenant B rows`).toBe(0);
      }
      const accounts = await tx.query<{ id: string }>("SELECT id FROM accounts");
      expect(accounts.rows.map((r) => r.id)).toEqual([A.tenantId]);
    });
  });

  it("shows nothing at all without a tenant context", async () => {
    await t.db.withoutTenant(async (tx) => {
      for (const table of ["accounts", "organizations", "users", "incidents", "events", "audit_log", "sessions", "user_credentials"]) {
        const { rows } = await tx.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${table}`);
        expect(rows[0]!.n, table).toBe(0);
      }
    });
    const bare = await t.db.app.query<{ n: number }>("SELECT count(*)::int AS n FROM incidents");
    expect(bare.rows[0]!.n).toBe(0);
  });

  it("rejects writes that would cross the tenant boundary", async () => {
    await expect(
      t.db.withTenant(A.tenantId, (tx) =>
        tx.query("INSERT INTO incidents (tenant_id, organization_id, number, title, severity) VALUES ($1, $2, 999, 'forged into B', 'low')", [B.tenantId, B.orgIds[0]]),
      ),
    ).rejects.toMatchObject({ code: "42501" });
    const moved = await t.db.withTenant(A.tenantId, (tx) => tx.query("UPDATE incidents SET tenant_id = $2 WHERE id = $1", [fx.aIncident.id, B.tenantId]).catch((e: { code: string }) => e));
    expect((moved as { code?: string }).code).toBe("42501");
    const updated = await t.db.withTenant(A.tenantId, (tx) => tx.query("UPDATE incidents SET title = 'owned by A' WHERE id = $1", [fx.bIncident.id]));
    expect(updated.rowCount).toBe(0);
    const deleted = await t.db.withTenant(A.tenantId, (tx) => tx.query("DELETE FROM assets WHERE tenant_id = $1", [B.tenantId]));
    expect(deleted.rowCount).toBe(0);
    const still = await t.privileged.query<{ title: string }>("SELECT title FROM incidents WHERE id = $1", [fx.bIncident.id]);
    expect(still.rows[0]!.title).toBe("B: ransomware on the file server");
  });

  it("denies direct access to event partitions and write access to the auth directory", async () => {
    const partition = await t.privileged.query<{ relname: string }>("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = 'events'::regclass LIMIT 1");
    const name = partition.rows[0]!.relname;
    await expect(t.db.withTenant(A.tenantId, (tx) => tx.query(`SELECT * FROM ${name}`))).rejects.toMatchObject({ code: "42501" });
    await expect(
      t.db.withoutTenant((tx) => tx.query("INSERT INTO auth_lookup (lookup_hash, kind, tenant_id, subject_id) VALUES (repeat('a', 64), 'api_key', $1, $1)", [A.tenantId])),
    ).rejects.toMatchObject({ code: "42501" });
  });

  it("keeps the Security Graph store tenant-bound", async () => {
    await t.db.withTenant(A.tenantId, async (tx) => {
      const store = new PostgresGraphStore(tx, A.tenantId);
      expect(await store.getNode(fx.bGraphNodeId)).toBeNull();
      expect(await store.findNodes({ key: "b-ws-01" })).toEqual([]);
      // A store bound to B inside A's transaction still sees nothing (RLS), and cannot write.
      const spoofed = new PostgresGraphStore(tx, B.tenantId);
      expect(await spoofed.getNode(fx.bGraphNodeId)).toBeNull();
    });
    await expect(
      t.db.withTenant(A.tenantId, (tx) => new PostgresGraphStore(tx, B.tenantId).upsertNode({ organizationId: null, kind: "ip", key: "203.0.113.7" })),
    ).rejects.toMatchObject({ code: "42501" });
    await t.db.withTenant(B.tenantId, async (tx) => {
      expect((await new PostgresGraphStore(tx, B.tenantId).getNode(fx.bGraphNodeId))?.key).toBe("b-ws-01");
    });
  });
});
