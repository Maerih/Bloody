import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, type TestApp, type TestTenant } from "../test/harness.js";
import { login } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let other: TestTenant;
let admin: ReturnType<typeof api>;
let otherAdmin: ReturnType<typeof api>;
let org: string;
const tokens: Record<string, { token: string; agentId: string }> = {};
const seen: Array<{ subject: { label: string }; data: { patch: { reasons: string; os: string } } }> = [];

const today = () => new Date().toISOString();
const report = (patches: object | null) => ({ software: [], services: [], users: [], processes: [], ports: [], antivirus: [], patches });
const inventory = (host: string, patches: object | null) =>
  t.app.inject({ method: "POST", url: "/api/v1/agent/inventory", headers: { "content-type": "application/json", authorization: `Bearer ${tokens[host]!.token}` }, payload: JSON.stringify(report(patches)) });
const heartbeat = (host: string, os: string) =>
  t.app.inject({ method: "POST", url: "/api/v1/agent/heartbeat", headers: { "content-type": "application/json", authorization: `Bearer ${tokens[host]!.token}` }, payload: JSON.stringify({ hostname: host, version: "1.5.0", os }) });
const overview = async () => (await admin.get(`/patching/overview?organizationId=${org}`)).body;
const settle = () => new Promise((r) => setTimeout(r, 50));
const openssl = { title: "openssl", id: "openssl", version: "3.0.13-0ubuntu3.5", security: true };

beforeAll(async () => {
  t = await createTestApp({ deps: { hostResolver: false } });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  other = await createTenant(t, { orgs: 1, plan: "mssp" });
  org = tenant.orgIds[0]!;
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  otherAdmin = api(t.app, { token: (await login(t.app, other.admin.email)).token });
  const key = (await admin.get("/agents/enrollment")).body.accountKey;
  for (const [host, platform, os] of [
    ["kb-lnx-01", "linux", "Ubuntu 24.04.1 LTS"],
    ["kb-ws-10", "windows", "Microsoft Windows 10 Pro 10.0.19045"],
    ["kb-ws-11", "windows", "Microsoft Windows 11 Enterprise 10.0.26100"],
  ] as const) {
    const res = await t.app.inject({ method: "POST", url: "/api/v1/agent/enroll", headers: { "content-type": "application/json" }, payload: JSON.stringify({ accountKey: key, organizationKey: "org-1", hostname: host, platform, version: "1.5.0" }) });
    tokens[host] = { token: res.json().token, agentId: res.json().agentId };
    await heartbeat(host, os);
  }
  t.services.domainEvents.subscribe("test-patching", async (e) => {
    if (e.event === "patch.sla_breached") seen.push(e as never);
  });
});
afterAll(async () => {
  await t?.close();
});

describe("Patch Compliance", () => {
  it("lists every computer, unknown until it reports, with its OS support status", async () => {
    const o = await overview();
    expect(o.summary).toMatchObject({ endpoints: 3, reporting: 0, unknown: 2, breached: 1, unsupportedOs: 1, compliance: 0 });
    expect(o.endpoints[0]).toMatchObject({ hostname: "kb-ws-10", osSupport: { product: "Windows 10", status: "ended" }, grade: { state: "breached" } });
    expect(o.endpoints.find((e: { hostname: string }) => e.hostname === "kb-ws-11").osSupport).toMatchObject({ product: "Windows 11 24H2 Enterprise / Education", status: "supported" });
  });

  it("grades reported update status and starts the clock on security updates", async () => {
    expect((await inventory("kb-lnx-01", { source: "apt", pending: [openssl, { title: "vim", id: "vim", security: false }], rebootRequired: false, lastCheckedAt: today() })).statusCode).toBe(200);
    expect((await inventory("kb-ws-11", { source: "windows_update", pending: [], rebootRequired: true, lastInstalledAt: "2026-10-01T00:00:00Z", lastCheckedAt: today() })).statusCode).toBe(200);
    const o = await overview();
    const lnx = o.endpoints.find((e: { hostname: string }) => e.hostname === "kb-lnx-01");
    expect(lnx).toMatchObject({ source: "apt", pendingCount: 2, securityCount: 1, grade: { state: "behind", reasons: ["1 security update waiting"] }, securityPendingSince: expect.any(String) });
    expect(o.endpoints.find((e: { hostname: string }) => e.hostname === "kb-ws-11").grade).toEqual({ state: "behind", reasons: ["Restart needed to finish installing updates"] });
    expect(o.missing[0]).toMatchObject({ title: "openssl", security: true, endpoints: 1 });
    expect(o.summary).toMatchObject({ reporting: 2, behind: 2, securityUpdates: 1, rebootPending: 1 });
    // The clock keeps running across reports.
    const first = lnx.securityPendingSince;
    await inventory("kb-lnx-01", { source: "apt", pending: [openssl], rebootRequired: false, lastCheckedAt: today() });
    expect((await overview()).endpoints.find((e: { hostname: string }) => e.hostname === "kb-lnx-01").securityPendingSince).toBe(first);
  });

  it("alerts once when a computer breaches the SLA, and clears when patched", async () => {
    await t.privileged.query("UPDATE agents SET security_pending_since = now() - interval '40 days' WHERE id = $1", [tokens["kb-lnx-01"]!.agentId]);
    await inventory("kb-lnx-01", { source: "apt", pending: [openssl], rebootRequired: false, lastCheckedAt: today() });
    await inventory("kb-lnx-01", { source: "apt", pending: [openssl], rebootRequired: false, lastCheckedAt: today() });
    await settle();
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ subject: { label: "kb-lnx-01" }, data: { patch: { os: "Ubuntu 24.04.1 LTS" } } });
    expect(seen[0]!.data.patch.reasons).toMatch(/1 security update outstanding for 40 days \(SLA 30\)/);
    expect((await overview()).endpoints[0]).toMatchObject({ hostname: "kb-lnx-01", grade: { state: "breached" } });
    // Patched: the clock stops and the computer is current.
    await inventory("kb-lnx-01", { source: "apt", pending: [], rebootRequired: false, lastCheckedAt: today() });
    const lnx = (await overview()).endpoints.find((e: { hostname: string }) => e.hostname === "kb-lnx-01");
    expect(lnx).toMatchObject({ securityPendingSince: null, grade: { state: "current" } });
  });

  it("alerts for an unsupported OS once it reports, and keeps tenants apart", async () => {
    await inventory("kb-ws-10", { source: "windows_update", pending: [], rebootRequired: false, lastCheckedAt: today() });
    await settle();
    expect(seen.at(-1)).toMatchObject({ subject: { label: "kb-ws-10" } });
    expect(seen.at(-1)!.data.patch.reasons).toContain("Windows 10 no longer gets security updates");
    // Older agents (no patch status) leave the last report in place.
    await inventory("kb-ws-11", null);
    expect((await overview()).endpoints.find((e: { hostname: string }) => e.hostname === "kb-ws-11").source).toBe("windows_update");
    expect((await otherAdmin.get(`/patching/overview?organizationId=${org}`)).status).toBe(404);
    expect((await admin.get(`/patching/overview?organizationId=not-a-uuid`)).status).toBe(400);
  });
});

describe("endpoint security posture report", () => {
  it("reports patching, unsupported systems, antivirus and persistence from agent data", async () => {
    await inventory("kb-lnx-01", { source: "apt", pending: [openssl], rebootRequired: true, lastCheckedAt: today() });
    await t.app.inject({
      method: "POST",
      url: "/api/v1/agent/inventory",
      headers: { "content-type": "application/json", authorization: `Bearer ${tokens["kb-ws-11"]!.token}` },
      payload: JSON.stringify({
        ...report({ source: "windows_update", pending: [], rebootRequired: false, lastCheckedAt: today() }),
        antivirus: [{ name: "Microsoft Defender Antivirus", enabled: false, realTimeProtection: false }],
        autoruns: [{ kind: "scheduled_task", location: "\\Updater", name: "Updater", command: "powershell.exe -nop -w hidden -enc SQBFAFgA", user: "SYSTEM" }],
      }),
    });
    const res = await admin.post("/reports/generate", { type: "endpoint_posture", format: "json", periodDays: 30, organizationId: org });
    expect(res.status).toBe(200);
    const r = res.body;
    expect(r.title).toBe("Endpoint security posture");
    const kpi = (k: string) => r.summary.kpis.find((x: { key: string }) => x.key === k);
    expect(kpi("unsupported_os").value).toBe(1);
    expect(kpi("footholds").value).toBe(1);
    const unsupported = r.sections.find((s: { id: string }) => s.id === "patching").blocks.find((b: { table?: { id: string } }) => b.table?.id === "unsupported-os").table.rows;
    expect(unsupported).toEqual([expect.objectContaining({ hostname: "kb-ws-10", endsOn: "2025-10-14" })]);
    const attention = r.sections.find((s: { id: string }) => s.id === "attention").blocks[0].table.rows;
    const ws11 = attention.find((a: { hostname: string }) => a.hostname === "kb-ws-11");
    expect(ws11.issues).toContain("Antivirus off or out of date");
    expect(ws11.issues).toContain("Suspicious persistence: Updater");
    expect(attention.find((a: { hostname: string }) => a.hostname === "kb-ws-10").issues).toContain("Windows 10 no longer gets security updates (since 2025-10-14)");
    // PDF renders too, and other accounts cannot report on this organization.
    expect((await admin.post("/reports/generate", { type: "endpoint_posture", format: "pdf", periodDays: 30, organizationId: org })).status).toBe(200);
    expect((await otherAdmin.post("/reports/generate", { type: "endpoint_posture", format: "json", periodDays: 30, organizationId: org })).status).toBeGreaterThanOrEqual(400);
  });
});
