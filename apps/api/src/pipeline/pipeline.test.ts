import { randomUUID } from "node:crypto";
import { RiskAssessment } from "@bloody/contracts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  POWERSHELL,
  api,
  call,
  createApiKey,
  createTenant,
  createTestApp,
  createUser,
  credentialTheftChain,
  dnsEvent,
  login,
  minutesAgo,
  processEvent,
  uniq,
  type Json,
  type TestApp,
  type TestTenant,
} from "../test/harness.js";

/**
 * Ingest → data fabric → analytics pipeline, end to end, with nothing mocked: the built-in
 * detection pack, the correlator, the risk engine and the Postgres-backed Security Graph all
 * run exactly as in production.
 */
const C2_DOMAIN = "cdn-telemetry.update-check.example";

let t: TestApp;
let tenant: TestTenant;
let org: string;
let admin: ReturnType<typeof api>;
let ingestKey: string;
let host: string;
let assetId: string;
let firstBatch: Json[];

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 2 });
  org = tenant.orgIds[0]!;
  const session = await login(t.app, tenant.admin.email);
  admin = api(t.app, { token: session.token });
  host = uniq("fin-ws").toLowerCase();
  const asset = await admin.post("/assets", { organizationId: org, kind: "endpoint", name: "Finance workstation", hostname: host, ipAddresses: ["10.10.20.47"], criticality: "high" });
  expect(asset.status).toBe(201);
  assetId = asset.body.id;
  await t.db.withTenant(tenant.tenantId, (tx) =>
    t.services.inventory.upsertIndicator(tx, tenant.tenantId, { organizationId: null, type: "domain", value: C2_DOMAIN, confidence: 90, severity: "high", source: "misp", threatActor: "TA-TEST-01", malware: "Cobalt Strike", campaign: "Operation Test" }),
  );
  ingestKey = (await createApiKey(t.app, session.token, { organizationId: org, name: "wazuh-manager" })).key;
});

afterAll(async () => {
  await t?.close();
});

async function ingest(events: Json[], auth: Parameters<typeof api>[1] = { apiKey: ingestKey }, query = "") {
  const res = await call(t.app, "POST", `/ingest/events${query}`, { auth, body: { events } });
  await t.services.bus.drain();
  return res;
}

describe("ingest → detection → correlation → incident", () => {
  it("accepts a canonical batch and assigns tenancy server-side", async () => {
    firstBatch = [...credentialTheftChain(host), dnsEvent(host, minutesAgo(25), "10.10.20.47", C2_DOMAIN)];
    // A forged tenant/org in the body is ignored: tenancy comes from the API key.
    const forged = firstBatch.map((e) => ({ ...e, tenantId: randomUUID(), organizationId: tenant.orgIds[1] }));
    const res = await ingest(forged);
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ organizationId: org, received: 4, accepted: 4, duplicates: 0, rejectedCount: 0 });
    const stored = await t.privileged.query<{ tenant_id: string; organization_id: string; n: number }>(
      "SELECT tenant_id, organization_id, count(*)::int AS n FROM events WHERE id = ANY($1::uuid[]) GROUP BY 1, 2",
      [res.body.eventIds],
    );
    expect(stored.rows).toEqual([{ tenant_id: tenant.tenantId, organization_id: org, n: 4 }]);
    const doc = await t.privileged.query<{ doc: Json; asset_hostname: string; process_name: string | null }>("SELECT doc, asset_hostname, process_name FROM events WHERE id = $1", [firstBatch[1].id]);
    expect(doc.rows[0]!.doc).toMatchObject({ schemaVersion: "1.0", tenantId: tenant.tenantId, organizationId: org, category: "process" });
    expect(doc.rows[0]).toMatchObject({ asset_hostname: host, process_name: "powershell.exe" });
  });

  it("produces explainable alerts from the built-in detection pack", async () => {
    const alerts = await admin.get(`/alerts?organizationId=${org}&limit=100`);
    expect(alerts.status).toBe(200);
    const byRule = new Map<string, Json>(alerts.body.items.map((a: Json) => [a.ruleId, a]));
    expect([...byRule.keys()]).toEqual(
      expect.arrayContaining(["bloody-edr-office-spawns-shell", "bloody-edr-encoded-powershell", "bloody-edr-lsass-credential-access", "bloody-cti-indicator-match"]),
    );
    const lsass = byRule.get("bloody-edr-lsass-credential-access")!;
    expect(lsass).toMatchObject({ severity: "critical", assetId, status: "promoted", source: "wazuh" });
    expect(lsass.attack.map((a: Json) => a.id)).toContain("T1003.001");
    expect(lsass.explanation.length).toBeGreaterThan(1);
    expect(lsass.riskScore).toBeGreaterThan(0);
    const detail = await admin.get(`/alerts/${lsass.id}`);
    expect(detail.body.events.map((e: Json) => e.id)).toEqual([firstBatch[2].id]);
    const ioc = byRule.get("bloody-cti-indicator-match")!;
    expect(JSON.stringify(ioc.indicators)).toContain(C2_DOMAIN);
  });

  it("correlates the detections into one critical incident with an escalation", async () => {
    const list = await admin.get(`/incidents?organizationId=${org}&status=all`);
    expect(list.body.items).toHaveLength(1);
    const incident = (await admin.get(`/incidents/${list.body.items[0].id}`)).body;
    expect(incident).toMatchObject({ number: 1, severity: "critical", status: "new", source: "correlation", organizationId: org });
    expect(incident.alertCount).toBeGreaterThanOrEqual(4);
    expect(incident.assetIds).toEqual([assetId]);
    expect(incident.attack.map((a: Json) => a.id)).toEqual(expect.arrayContaining(["T1003.001", "T1059.001"]));
    expect(incident.alerts.map((a: Json) => a.incidentId)).toEqual(incident.alerts.map(() => incident.id));
    expect(Date.parse(incident.firstSeenAt)).toBe(Date.parse(firstBatch[0].timestamp));
    // Every score is explained.
    const risk = RiskAssessment.parse(incident.risk);
    expect(risk.factors.length).toBeGreaterThan(0);
    expect(risk.score).toBe(incident.riskScore);

    expect(incident.escalations).toHaveLength(1);
    const esc = incident.escalations[0];
    expect(esc).toMatchObject({ status: "open", severity: "critical", overdue: false });
    expect(Date.parse(esc.dueAt) - Date.now()).toBeLessThanOrEqual(15 * 60_000);

    const audit = await t.privileged.query("SELECT actor_kind, actor_id FROM audit_log WHERE tenant_id = $1 AND action = 'incident.created' AND target_id = $2", [tenant.tenantId, incident.id]);
    expect(audit.rows).toEqual([{ actor_kind: "system", actor_id: "pipeline" }]);
  });

  it("records IOC matches, re-scores the asset and builds the Security Graph", async () => {
    const matches = await t.privileged.query<{ observed_value: string; asset_id: string }>("SELECT observed_value, asset_id FROM indicator_matches WHERE tenant_id = $1", [tenant.tenantId]);
    expect(matches.rows).toEqual([expect.objectContaining({ observed_value: C2_DOMAIN, asset_id: assetId })]);

    const asset = (await admin.get(`/assets/${assetId}`)).body;
    expect(asset.riskScore).toBeGreaterThan(0);
    const assessment = RiskAssessment.parse(asset.risk);
    expect(assessment.factors.some((f) => f.contribution > 0)).toBe(true);
    expect(asset.alerts.length).toBeGreaterThanOrEqual(4);
    expect(asset.incidents).toHaveLength(1);

    const nodes = await t.privileged.query<{ kind: string; n: number }>("SELECT kind, count(*)::int AS n FROM graph_nodes WHERE tenant_id = $1 GROUP BY kind", [tenant.tenantId]);
    const kinds = Object.fromEntries(nodes.rows.map((r) => [r.kind, r.n]));
    expect(kinds).toMatchObject({ endpoint: expect.any(Number), process: expect.any(Number), domain: expect.any(Number), incident: 1, technique: expect.any(Number) });
    const involves = await t.privileged.query(
      `SELECT 1 FROM graph_edges e JOIN graph_nodes i ON i.id = e.from_id AND i.kind = 'incident' JOIN graph_nodes h ON h.id = e.to_id AND h.kind = 'endpoint' AND h.key = $2
       WHERE e.tenant_id = $1 AND e.kind = 'involves'`,
      [tenant.tenantId, host],
    );
    expect(involves.rowCount).toBe(1);
  });

  it("is idempotent under redelivery", async () => {
    const before = await t.privileged.query<{ alerts: number; incidents: number; matches: number }>(
      "SELECT (SELECT count(*)::int FROM alerts WHERE tenant_id = $1) AS alerts, (SELECT count(*)::int FROM incidents WHERE tenant_id = $1) AS incidents, (SELECT count(*)::int FROM indicator_matches WHERE tenant_id = $1) AS matches",
      [tenant.tenantId],
    );
    const res = await ingest(firstBatch);
    expect(res.body).toMatchObject({ accepted: 0, duplicates: 4 });
    // Even a direct re-run of the pipeline over the same events creates nothing new.
    const events = (await t.privileged.query<{ doc: Json }>("SELECT doc FROM events WHERE id = ANY($1::uuid[])", [firstBatch.map((e) => e.id)])).rows.map((r) => r.doc);
    const rerun = await t.services.pipeline.process({ batchId: randomUUID(), tenantId: tenant.tenantId, organizationId: org, source: "test", receivedAt: new Date().toISOString(), events });
    expect(rerun.alertsCreated).toEqual([]);
    expect(rerun.incidentsCreated).toEqual([]);
    const after = await t.privileged.query(
      "SELECT (SELECT count(*)::int FROM alerts WHERE tenant_id = $1) AS alerts, (SELECT count(*)::int FROM incidents WHERE tenant_id = $1) AS incidents, (SELECT count(*)::int FROM indicator_matches WHERE tenant_id = $1) AS matches",
      [tenant.tenantId],
    );
    expect(after.rows[0]).toEqual(before.rows[0]);
  });

  it("folds later activity on the same host into the open incident", async () => {
    const follow = processEvent(host, minutesAgo(5), { path: POWERSHELL, cmd: "powershell.exe -nop -EncodedCommand ZQBjAGgAbwAgACIAcwB0AGEAZwBlADIAIgA7AHMAbABlAGUAcAAgADMAMAA=", user: "jdoe" });
    const res = await ingest([follow]);
    expect(res.body.accepted).toBe(1);
    const list = await admin.get(`/incidents?organizationId=${org}&status=all`);
    expect(list.body.items).toHaveLength(1);
    const alerts = await admin.get(`/alerts?incidentId=${list.body.items[0].id}&limit=100`);
    expect(alerts.body.items.some((a: Json) => a.eventIds.includes(follow.id))).toBe(true);
    expect(list.body.items[0].alertCount).toBe(alerts.body.items.length);
  });

  it("exports pipeline metrics", async () => {
    const metrics = await call(t.app, "GET", "/metrics");
    expect(metrics.text).toMatch(/bloody_pipeline_detections_total\{[^}]*severity="critical"[^}]*\} [1-9]/);
    expect(metrics.text).toMatch(/bloody_ingest_events_total\{[^}]*result="accepted"[^}]*\} [1-9]/);
    expect(metrics.text).toMatch(/bloody_pipeline_incidents_total\{[^}]*kind="created"[^}]*\} 1/);
  });
});

describe("ingest validation and authorization", () => {
  it("rejects invalid records individually and keeps the rest", async () => {
    const good = processEvent(host, minutesAgo(3), { path: "C:\\Windows\\explorer.exe", cmd: "explorer.exe" });
    const future = { ...processEvent(host, new Date(Date.now() + 3_600_000).toISOString(), { path: "C:\\x.exe", cmd: "x" }) };
    const res = await ingest([good, { timestamp: "not a date", category: "process" }, future]);
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ received: 3, accepted: 1, rejectedCount: 2 });
    expect(res.body.rejected.map((r: Json) => r.index)).toEqual([1, 2]);
    expect(res.body.rejected[1].errors[0]).toMatchObject({ path: "timestamp", message: "timestamp is in the future" });
  });

  it("bounds batch size and requires an organization the caller may ingest into", async () => {
    const tooMany = await call(t.app, "POST", "/ingest/events", { auth: { apiKey: ingestKey }, body: Array.from({ length: t.config.ingest.maxBatch + 1 }, () => ({})) });
    expect(tooMany.status).toBe(413);
    expect(tooMany.body.error.code).toBe("batch_too_large");
    expect((await call(t.app, "POST", "/ingest/events", { auth: { apiKey: ingestKey }, body: [] })).status).toBe(400);

    const session = { token: (await login(t.app, tenant.admin.email)).token };
    expect((await call(t.app, "POST", "/ingest/events", { auth: session, body: { events: [processEvent(host, minutesAgo(1), { path: "C:\\a.exe", cmd: "a" })] } })).status).toBe(400);
    const explicit = await call(t.app, "POST", "/ingest/events", { auth: session, body: { organizationId: org, events: [processEvent(host, minutesAgo(1), { path: "C:\\a.exe", cmd: "a" })] } });
    expect(explicit.status).toBe(202);
    expect(explicit.body.accepted).toBe(1);

    const analyst = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t2", organizationId: null }] });
    const denied = await call(t.app, "POST", "/ingest/events", { auth: { token: (await login(t.app, analyst.email)).token }, body: { organizationId: org, events: [] } });
    expect(denied.status).toBe(403);
    await t.services.bus.drain();
  });

  it("normalizes raw engine payloads through the adapter registry", async () => {
    const eve = {
      timestamp: new Date(Date.now() - 60_000).toISOString(),
      event_type: "alert",
      src_ip: "203.0.113.200",
      src_port: 51515,
      dest_ip: "10.10.20.47",
      dest_port: 443,
      proto: "TCP",
      host: "ids-sensor-01",
      alert: { action: "allowed", signature_id: 2036984, signature: "ET EXPLOIT Atlassian Confluence OGNL Injection (CVE-2022-26134)", category: "Attempted Administrator Privilege Gain", severity: 1, metadata: { signature_severity: ["Critical"] } },
    };
    const res = await call(t.app, "POST", "/ingest/suricata", { auth: { apiKey: ingestKey }, body: `${JSON.stringify(eve)}\n${JSON.stringify({ event_type: "stats", timestamp: eve.timestamp })}\n`, headers: { "content-type": "application/x-ndjson" } });
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ adapter: "suricata", normalization: { records: 2, events: 1, skipped: 1, rejected: 0 }, ingest: { accepted: 1 } });
    await t.services.bus.drain();
    const alerts = await admin.get(`/alerts?organizationId=${org}&ruleId=bloody-ndr-suricata-high-severity`);
    expect(alerts.body.items).toHaveLength(1);
    expect(alerts.body.items[0].severity).toBe("critical");

    const unknown = await call(t.app, "POST", "/ingest/not_an_engine", { auth: { apiKey: ingestKey }, body: { a: 1 } });
    expect(unknown.status).toBe(404);
    expect(unknown.body.error.code).toBe("unknown_adapter");
  });

  it("meters ingested events per organization and day", async () => {
    const { rows } = await t.privileged.query<{ value: number }>("SELECT value::int FROM usage_counters WHERE tenant_id = $1 AND organization_id = $2 AND metric = 'events_ingested'", [tenant.tenantId, org]);
    const stored = await t.privileged.query<{ n: number }>("SELECT count(*)::int AS n FROM events WHERE tenant_id = $1 AND organization_id = $2", [tenant.tenantId, org]);
    expect(rows.reduce((s, r) => s + r.value, 0)).toBe(stored.rows[0]!.n);
  });
});
