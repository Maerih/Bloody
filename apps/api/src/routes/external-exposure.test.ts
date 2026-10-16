import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let other: TestTenant;
let admin: ReturnType<typeof api>;
let analyst: ReturnType<typeof api>;
let otherAdmin: ReturnType<typeof api>;
let org: string;
let accountKey: string;

/** What the fake internet looks like: "ip|port" pairs that accept connections. */
const listening = new Set<string>();
const probed: string[] = [];

const enroll = async (hostname: string) =>
  (await t.app.inject({ method: "POST", url: "/api/v1/agent/enroll", headers: { "content-type": "application/json" }, payload: JSON.stringify({ accountKey, organizationKey: "org-1", hostname, platform: "windows", version: "1.1.0" }) })).json().token as string;
const heartbeat = (token: string, hostname: string, remoteAddress: string) =>
  t.app.inject({ method: "POST", url: "/api/v1/agent/heartbeat", remoteAddress, headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, payload: JSON.stringify({ hostname, version: "1.1.0" }) });
const inAYear = () => new Date(Date.now() + 300 * 86_400_000).toISOString();
const overview = async () => (await admin.get(`/exposure/overview?organizationId=${org}`)).body;
const waitForScan = async () => {
  for (let i = 0; i < 100; i++) {
    const o = await overview();
    if (o.scans[0] && o.scans[0].status !== "running") return o;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error("scan did not finish");
};

beforeAll(async () => {
  t = await createTestApp({
    deps: {
      hostResolver: false,
      portProbe: async (ip, port) => {
        probed.push(`${ip}|${port}`);
        return listening.has(`${ip}|${port}`);
      },
    },
  });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  other = await createTenant(t, { orgs: 1, plan: "mssp" });
  org = tenant.orgIds[0]!;
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  otherAdmin = api(t.app, { token: (await login(t.app, other.admin.email)).token });
  const a = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: null }] });
  analyst = api(t.app, { token: (await login(t.app, a.email)).token });
  accountKey = (await admin.get("/agents/enrollment")).body.accountKey;
});
afterAll(async () => {
  await t?.close();
});

describe("External Exposure", () => {
  it("learns public addresses from agent check-ins, never private ones", async () => {
    const a = await enroll("kb-ws-01");
    const b = await enroll("kb-ws-02");
    expect((await heartbeat(a, "kb-ws-01", "41.90.64.10")).statusCode).toBe(200);
    expect((await heartbeat(b, "kb-ws-02", "::ffff:41.90.64.10")).statusCode).toBe(200);
    await heartbeat(b, "kb-ws-02", "192.168.1.20");
    await heartbeat(b, "kb-ws-02", "100.64.3.3");
    const o = await overview();
    expect(o.targets).toHaveLength(1);
    expect(o.targets[0]).toMatchObject({ ip: "41.90.64.10", source: "agent", status: "discovered", hostnames: ["kb-ws-01", "kb-ws-02"] });
    expect(o.authorization).toBeNull();
    expect(o.portsChecked.find((p: { port: number }) => p.port === 3389)).toMatchObject({ service: "Remote Desktop (RDP)" });
    expect((await analyst.get(`/exposure/overview?organizationId=${org}`)).status).toBe(200);
    expect((await otherAdmin.get(`/exposure/overview?organizationId=${org}`)).status).toBe(404);
  });

  it("refuses to scan without an authorization and a confirmed address", async () => {
    expect((await admin.post("/exposure/scans", { organizationId: org })).body.error.code).toBe("not_authorized");
    const bad = { reference: "MSA-2026-014 §4 external testing", expiresAt: inAYear() };
    expect((await admin.put(`/exposure/authorization/${org}`, bad)).status).toBe(400); // no attestation
    expect((await admin.put(`/exposure/authorization/${org}`, { ...bad, attest: true, expiresAt: new Date(Date.now() + 400 * 86_400_000).toISOString() })).status).toBe(400);
    expect((await analyst.put(`/exposure/authorization/${org}`, { ...bad, attest: true })).status).toBe(403);
    expect((await otherAdmin.put(`/exposure/authorization/${org}`, { ...bad, attest: true })).status).toBe(404);
    const ok = await admin.put(`/exposure/authorization/${org}`, { ...bad, attest: true });
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ reference: "MSA-2026-014 §4 external testing", valid: true });
    // Discovered addresses are not scanned until someone confirms them.
    expect((await admin.post("/exposure/scans", { organizationId: org })).body.error.code).toBe("no_addresses");
    expect(probed).toEqual([]);
  });

  it("adds and confirms addresses; private and documentation ranges are refused", async () => {
    expect((await admin.post("/exposure/targets", { organizationId: org, ip: "10.1.2.3" })).body.error.code).toBe("not_public_address");
    expect((await admin.post("/exposure/targets", { organizationId: org, ip: "203.0.113.5" })).status).toBe(400);
    expect((await analyst.post("/exposure/targets", { organizationId: org, ip: "102.68.1.7" })).status).toBe(403);
    expect((await admin.post("/exposure/targets", { organizationId: org, ip: "102.68.1.7", note: "Nairobi office fibre" })).status).toBe(201);
    const discovered = (await overview()).targets.find((x: { ip: string }) => x.ip === "41.90.64.10");
    expect((await analyst.patch(`/exposure/targets/${discovered.id}`, { status: "confirmed" })).status).toBe(403);
    expect((await otherAdmin.patch(`/exposure/targets/${discovered.id}`, { status: "confirmed" })).status).toBe(404);
    expect((await admin.patch(`/exposure/targets/${discovered.id}`, { status: "confirmed" })).status).toBe(200);
    const targets = (await overview()).targets;
    expect(targets.map((x: { ip: string; status: string; source: string }) => [x.ip, x.status, x.source])).toEqual([
      ["102.68.1.7", "confirmed", "manual"],
      ["41.90.64.10", "confirmed", "agent"],
    ]);
  });

  it("scans confirmed addresses, reports risky open ports and alerts once per new exposure", async () => {
    const seen: Array<{ subject: { label: string }; severity: string; data: { exposure: { hostnames: string } } }> = [];
    const off = t.services.domainEvents.subscribe("test-exposure", async (e) => {
      if (e.event === "exposure.port_open") seen.push(e as never);
    });
    listening.add("41.90.64.10|3389");
    listening.add("41.90.64.10|22");
    listening.add("102.68.1.7|443"); // not a port we check
    const started = await admin.post("/exposure/scans", { organizationId: org });
    expect(started.status).toBe(202);
    expect(started.body).toMatchObject({ status: "running", trigger: "manual", addresses: 2 });
    let o = await waitForScan();
    expect(o.scans[0]).toMatchObject({ status: "finished", openPorts: 2 });
    expect(o.findings.map((f: { ip: string; port: number; severity: string }) => [f.ip, f.port, f.severity])).toEqual([
      ["41.90.64.10", 3389, "critical"],
      ["41.90.64.10", 22, "medium"],
    ]);
    expect(o.findings[0]).toMatchObject({ service: "Remote Desktop (RDP)", hostnames: ["kb-ws-01", "kb-ws-02"] });
    expect(o.targets.find((x: { ip: string }) => x.ip === "41.90.64.10")).toMatchObject({ openPorts: 2 });
    expect(probed.some((p) => p.startsWith("102.68.1.7|"))).toBe(true);
    expect(probed.every((p) => p.startsWith("41.90.64.10|") || p.startsWith("102.68.1.7|"))).toBe(true);

    // RDP gets closed, SSH stays: the closed one leaves the list, and only new exposures alert.
    listening.delete("41.90.64.10|3389");
    expect((await admin.post("/exposure/scans", { organizationId: org })).status).toBe(202);
    o = await waitForScan();
    expect(o.findings.map((f: { port: number }) => f.port)).toEqual([22]);
    await new Promise((r) => setTimeout(r, 50));
    expect(seen.map((e) => e.subject.label).sort()).toEqual(["Remote Desktop (RDP) on 41.90.64.10:3389", "SSH on 41.90.64.10:22"]);
    expect(seen.find((e) => e.subject.label.startsWith("Remote"))).toMatchObject({ severity: "critical", data: { exposure: { hostnames: "kb-ws-01, kb-ws-02" } } });
    off();

    const audit = await t.privileged.query("SELECT action FROM audit_log WHERE tenant_id = $1 AND action LIKE 'exposure.%' ORDER BY seq", [tenant.tenantId]);
    expect(audit.rows.map((r) => r.action)).toEqual(["exposure.authorized", "exposure.address_added", "exposure.address_confirmed", "exposure.scan_started", "exposure.scan_started"]);
  });

  it("ignoring an address drops its findings; revoking the authorization stops scans", async () => {
    const target = (await overview()).targets.find((x: { ip: string }) => x.ip === "41.90.64.10");
    expect((await admin.patch(`/exposure/targets/${target.id}`, { status: "ignored" })).status).toBe(200);
    expect((await overview()).findings).toEqual([]);
    expect((await admin.delete(`/exposure/authorization/${org}`)).status).toBe(200);
    expect((await admin.post("/exposure/scans", { organizationId: org })).body.error.code).toBe("not_authorized");
    expect(await t.services.exposure.scanDue(tenant.tenantId)).toBe(0);
  });
});
