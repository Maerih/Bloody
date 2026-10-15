import { randomUUID } from "node:crypto";
import type { IngestEvent } from "@bloody/contracts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, credentialTheftChain, dnsEvent, login, minutesAgo, type TestApp, type TestTenant } from "../test/harness.js";
import { backfillSearchIndex } from "../db/search-backfill.js";
import { EventSearchService, QuerySyntaxError, type EventFilter, type EventSearchInput } from "./event-search.js";
import { OpenSearchEventIndex, scopedQuery, UnsupportedSearch } from "./opensearch-events.js";

const TENANT = "00000000-0000-4000-8000-000000000001";
const RANGE = { from: "2026-01-01T00:00:00.000Z", to: "2026-12-31T00:00:00.000Z" };

describe("OpenSearch query compilation", () => {
  it("always scopes to the tenant, organizations and time range", () => {
    const q = JSON.stringify(scopedQuery(TENANT, ["00000000-0000-4000-8000-0000000000a1"], { ...RANGE, q: "host:ws-01 OR -outcome:success" }));
    expect(q).toContain(`{"term":{"tenant_id":"${TENANT}"}}`);
    expect(q).toContain('{"terms":{"organization_id":["00000000-0000-4000-8000-0000000000a1"]}}');
    expect(q).toContain('"range":{"timestamp"');
  });

  it("hands regex and numeric comparison on document paths back to Postgres", () => {
    const unsupported: EventFilter[] = [
      { field: "process.name", op: "regex", value: "^power" },
      { field: "network.dstPort", op: "gt", value: 50 },
      { field: "message", op: "cidr", value: "10.0.0.0/8" },
    ];
    for (const f of unsupported) expect(() => scopedQuery(TENANT, null, { ...RANGE, filters: [f] })).toThrow(UnsupportedSearch);
  });

  it("reports query syntax errors exactly like the Postgres compiler", () => {
    expect(() => scopedQuery(TENANT, null, { ...RANGE, filters: [{ field: "id", op: "eq", value: "nope" }] })).toThrow(QuerySyntaxError);
    expect(() => scopedQuery(TENANT, null, { ...RANGE, q: "bad..field:x" })).toThrow(QuerySyntaxError);
  });
});

// ─── Live parity against a real OpenSearch ──────────────────────────────────

const OS_URL = process.env.TEST_OPENSEARCH_URL ?? "http://127.0.0.1:9200";
let available = false;
let t: TestApp;
let a: TestTenant;
let b: TestTenant;
let index: OpenSearchEventIndex;
let viaOs: EventSearchService;
let viaPg: EventSearchService;
const fallbacks: string[] = [];
const prefix = `bloody-test-${randomUUID().slice(0, 8)}`;

function richEvents(host: string, now: number): IngestEvent[] {
  const base = { provenance: { adapter: "bloody-tests", adapterVersion: "1", receivedAt: new Date(now).toISOString() } };
  return [
    ...credentialTheftChain(host, now).map((e, i) => ({ ...e, message: i === 2 ? "MiniDump of LSASS via comsvcs" : "PowerShell launched", attack: [{ id: i === 2 ? "T1003.001" : "T1059.001" }], severity: i === 2 ? ("critical" as const) : ("high" as const), risk: 40 + i * 25 })),
    dnsEvent(host, minutesAgo(15, now), "192.168.10.7", "c2.evil.example"),
    dnsEvent(host, minutesAgo(14, now), "10.20.0.9", "intranet.corp"),
    {
      ...base,
      id: randomUUID(),
      timestamp: minutesAgo(10, now),
      source: { kind: "network", product: "suricata", sensorId: "ids-1" },
      category: "network",
      eventType: "alert",
      outcome: "failure",
      severity: "medium",
      message: "ET TROJAN beacon to 203.0.113.5",
      asset: { hostname: host },
      network: { srcIp: "10.20.0.9", dstIp: "203.0.113.5", dstPort: 443, protocol: "tcp" },
      indicators: [{ type: "ip", value: "203.0.113.5" }],
      labels: { env: "Prod", "k8s.ns": "payments" },
    },
    {
      ...base,
      id: randomUUID(),
      timestamp: minutesAgo(5, now),
      source: { kind: "identity", product: "keycloak" },
      category: "authentication",
      eventType: "login",
      outcome: "success",
      severity: "low",
      message: "User jdoe logged in",
      identity: { principal: "jdoe@corp.example", outcome: "success", sourceIp: "198.51.100.77" },
      user: { name: "jdoe", domain: "CORP" },
    },
  ] as IngestEvent[];
}

beforeAll(async () => {
  available = await fetch(OS_URL, { signal: AbortSignal.timeout(1500) }).then(
    (r) => r.ok,
    () => false,
  );
  if (!available) return;
  index = new OpenSearchEventIndex({ url: OS_URL, indexPrefix: prefix, refresh: "wait_for" });
  t = await createTestApp({ deps: { searchIndex: index } });
  a = await createTenant(t, { orgs: 2, plan: "mssp" });
  b = await createTenant(t, { orgs: 1, plan: "mssp" });
  const now = Date.now();
  for (const [tenant, org, host] of [
    [a, a.orgIds[0]!, "ws-alpha-01"],
    [a, a.orgIds[1]!, "srv-beta-02"],
    [b, b.orgIds[0]!, "ws-alpha-01"],
  ] as const) {
    const admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
    const res = await admin.post("/ingest/events", { organizationId: org, events: richEvents(host, now) });
    expect(res.status).toBeLessThan(300);
  }
  await t.services.bus.drain();
  viaOs = new EventSearchService(t.db, () => Date.now(), index, { onFallback: (reason) => fallbacks.push(reason) });
  viaPg = new EventSearchService(t.db, () => Date.now());
}, 60_000);

afterAll(async () => {
  if (!available) return;
  await t?.close();
  await fetch(`${OS_URL}/${prefix}-*`, { method: "DELETE" }).catch(() => undefined);
  await fetch(`${OS_URL}/${prefix}bf-*`, { method: "DELETE" }).catch(() => undefined);
  for (const tpl of [prefix, `${prefix}bf`]) await fetch(`${OS_URL}/_index_template/${tpl}`, { method: "DELETE" }).catch(() => undefined);
});

const window = (): Pick<EventSearchInput, "from" | "to"> => ({ from: new Date(Date.now() - 3_600_000).toISOString(), to: new Date(Date.now() + 60_000).toISOString() });
const ids = (r: { items: Array<{ id: string }> }) => r.items.map((e) => e.id);

const QUERIES = [
  "",
  "host:ws-alpha-01",
  "process.name:powershell*",
  "process.name:POWERSHELL.EXE",
  "-outcome:success",
  "network.dstIp:10.0.0.0/8",
  "src:10.20.*",
  "ip:203.0.113.5",
  "risk:>=60",
  "severity:>=high",
  "severity:critical",
  "category:dns OR category:authentication",
  "_exists_:file.sha256",
  "_exists_:user.name AND -category:process",
  "process.commandLine:*comsvcs*",
  "labels.env:prod",
  "labels.k8s.ns:payments",
  "technique:T1059.001",
  "technique:T1003*",
  "ioc:203.0.113.5",
  "dns:*.example",
  "network.dstPort:443",
  "principal:JDOE@corp.example",
  "MiniDump",
  '"logged in"',
  "(host:srv-beta-02 AND category:dns) OR severity:medium",
];

describe("OpenSearch event search (live, parity with Postgres)", () => {
  it("answers every query exactly like Postgres", async (ctx) => {
    if (!available) ctx.skip();
    const before = fallbacks.length;
    for (const q of QUERIES) {
      const input = { ...window(), q, limit: 100 };
      const [os, pg] = await Promise.all([viaOs.search(a.tenantId, null, input, { count: true }), viaPg.search(a.tenantId, null, input, { count: true })]);
      expect({ q, ids: ids(os), total: os.total }).toEqual({ q, ids: ids(pg), total: pg.total });
    }
    expect(fallbacks.length).toBe(before); // all answered by OpenSearch
    // Sanity: the fixtures actually exercise the queries.
    expect((await viaOs.search(a.tenantId, null, { ...window(), q: "labels.env:prod", limit: 10 })).items).toHaveLength(2);
  });

  it("keeps tenants and organization scopes apart", async (ctx) => {
    if (!available) ctx.skip();
    const all = await viaOs.search(b.tenantId, null, { ...window(), limit: 100 }, { count: true });
    expect(all.total).toBe(7);
    expect(all.items.every((e) => e.organizationId === b.orgIds[0])).toBe(true);
    const org = await viaOs.search(a.tenantId, [a.orgIds[1]!], { ...window(), limit: 100 });
    expect(org.items).toHaveLength(7);
    expect(org.items.every((e) => e.organizationId === a.orgIds[1] && (e.asset?.hostname ?? "srv-beta-02") === "srv-beta-02")).toBe(true);
  });

  it("paginates with the same cursor format and order", async (ctx) => {
    if (!available) ctx.skip();
    for (const order of ["desc", "asc"] as const) {
      const walk = async (svc: EventSearchService) => {
        const seen: string[] = [];
        let cursor: string | undefined;
        do {
          const page = await svc.search(a.tenantId, null, { ...window(), limit: 3, order, cursor });
          seen.push(...ids(page));
          cursor = page.nextCursor ?? undefined;
        } while (cursor);
        return seen;
      };
      const [os, pg] = await Promise.all([walk(viaOs), walk(viaPg)]);
      expect(os).toHaveLength(14);
      expect(os).toEqual(pg);
    }
  });

  it("aggregates hunting pivots like Postgres", async (ctx) => {
    if (!available) ctx.skip();
    const fields = ["asset.hostname", "process.name", "attack.id", "severity", "category"];
    const [os, pg] = await Promise.all([viaOs.aggregate(a.tenantId, null, window(), fields), viaPg.aggregate(a.tenantId, null, window(), fields)]);
    expect(os).toEqual(pg);
  });

  it("falls back to Postgres for what OpenSearch cannot answer identically, and when it is down", async (ctx) => {
    if (!available) ctx.skip();
    const before = fallbacks.length;
    const filters: EventFilter[] = [{ field: "process.name", op: "regex", value: "^power" }];
    const [os, pg] = await Promise.all([viaOs.search(a.tenantId, null, { ...window(), filters, limit: 50 }), viaPg.search(a.tenantId, null, { ...window(), filters, limit: 50 })]);
    expect(ids(os)).toEqual(ids(pg));
    expect(ids(os).length).toBeGreaterThan(0);
    expect(fallbacks.slice(before)).toEqual(["unsupported"]);

    const down = new EventSearchService(t.db, () => Date.now(), new OpenSearchEventIndex({ url: "http://127.0.0.1:1", indexPrefix: prefix, timeoutMs: 500 }), { onFallback: (r) => fallbacks.push(r) });
    expect((await down.search(a.tenantId, null, { ...window(), limit: 100 })).items).toHaveLength(14);
    expect(fallbacks.at(-1)).toBe("error");
  });

  it("backfills events stored before the index existed", async (ctx) => {
    if (!available) ctx.skip();
    const fresh = new OpenSearchEventIndex({ url: OS_URL, indexPrefix: `${prefix}bf`, refresh: "wait_for" });
    const { indexed } = await backfillSearchIndex({ pool: t.privileged, index: fresh, since: window().from, batch: 500 });
    expect(indexed).toBeGreaterThanOrEqual(21);
    const svc = new EventSearchService(t.db, () => Date.now(), fresh, { onFallback: (r) => fallbacks.push(r) });
    const [os, pg] = await Promise.all([svc.search(a.tenantId, null, { ...window(), limit: 100 }), viaPg.search(a.tenantId, null, { ...window(), limit: 100 })]);
    expect(ids(os)).toEqual(ids(pg));
    expect(ids(os)).toHaveLength(14);
  });

  it("serves GET /events/search from the wired index", async (ctx) => {
    if (!available) ctx.skip();
    const admin = api(t.app, { token: (await login(t.app, a.admin.email)).token });
    const res = await admin.get(`/events/search?q=${encodeURIComponent("labels.env:prod")}&range=1h&count=true`);
    expect(res.status).toBe(200);
    expect(res.body.total).toBe(2);
    expect(await t.services.metrics.registry.getSingleMetricAsString("bloody_event_search_queries_total")).toMatch(/engine="opensearch"[^}]*} [1-9]/);
  });
});
