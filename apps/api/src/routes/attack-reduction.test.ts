import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let other: TestTenant;
let admin: ReturnType<typeof api>;
let analyst: ReturnType<typeof api>;
let otherAdmin: ReturnType<typeof api>;
let org: string;
let token: string;

const good = {
  smb1_enabled: false,
  llmnr_disabled: true,
  netbios_enabled_adapters: 0,
  wdigest_use_logon_credential: null,
  lsa_run_as_ppl: 1,
  rdp_enabled: false,
  uac_enabled: true,
  uac_admin_prompt: 5,
  bitlocker_os_protected: true,
};
const report = (hardening: Record<string, unknown>) => ({
  software: [],
  services: [],
  users: [{ name: "it-admin", admin: true, enabled: true }],
  processes: [],
  ports: [],
  antivirus: [],
  firewall: { enabled: true, detail: null },
  hardening,
});
const inventory = (body: object) =>
  t.app.inject({ method: "POST", url: "/api/v1/agent/inventory", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, payload: JSON.stringify(body) });
const overview = async () => (await admin.get(`/attack-reduction/overview?organizationId=${org}`)).body;
const result = (o: { endpoints: Array<{ results: Array<{ key: string; status: string; detail: string | null }> }> }, key: string) => o.endpoints[0]!.results.find((r) => r.key === key)!;

beforeAll(async () => {
  t = await createTestApp({ deps: { hostResolver: false } });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  other = await createTenant(t, { orgs: 1, plan: "mssp" });
  org = tenant.orgIds[0]!;
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  otherAdmin = api(t.app, { token: (await login(t.app, other.admin.email)).token });
  const a = await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: null }] });
  analyst = api(t.app, { token: (await login(t.app, a.email)).token });
  const key = (await admin.get("/agents/enrollment")).body.accountKey;
  const enrolled = await t.app.inject({ method: "POST", url: "/api/v1/agent/enroll", headers: { "content-type": "application/json" }, payload: JSON.stringify({ accountKey: key, organizationKey: "org-1", hostname: "kb-ws-31", platform: "windows", version: "1.2.0" }) });
  token = enrolled.json().token;
});
afterAll(async () => {
  await t?.close();
});

describe("Attack Reduction", () => {
  it("grades an endpoint from the hardening facts its agent reports", async () => {
    expect((await overview())).toMatchObject({ score: null, endpoints: [], checks: [] });
    expect((await inventory(report(good))).statusCode).toBe(200);
    const o = await overview();
    expect(o.catalog.length).toBeGreaterThan(25);
    expect(o.endpoints).toHaveLength(1);
    expect(o.endpoints[0]).toMatchObject({ hostname: "kb-ws-31", platform: "windows", score: 100 });
    expect(result(o, "win_smb1").status).toBe("pass");
    expect(result(o, "win_rdp_nla")).toMatchObject({ status: "pass", detail: "Remote Desktop is off" });
    expect(result(o, "win_asr_standard").status).toBe("unknown");
    // Only Windows checks apply to a Windows computer.
    expect(o.endpoints[0].results.some((r: { key: string }) => r.key.startsWith("mac_") || r.key.startsWith("linux_"))).toBe(false);
    expect(o.checks.find((c: { key: string }) => c.key === "win_smb1")).toMatchObject({ passing: 1, failing: 0, exception: null });
    expect((await analyst.get(`/attack-reduction/overview?organizationId=${org}`)).status).toBe(200);
    expect((await otherAdmin.get(`/attack-reduction/overview?organizationId=${org}`)).status).toBe(404);
  });

  it("alerts once when a setting that was in place is switched off", async () => {
    const seen: Array<{ subject: { label: string }; data: { hardening: { checks: string; keys: string[] } } }> = [];
    const off = t.services.domainEvents.subscribe("test-hardening", async (e) => {
      if (e.event === "hardening.regressed") seen.push(e as never);
    });
    const weakened = { ...good, wdigest_use_logon_credential: 1, smb1_enabled: true };
    await inventory(report(weakened));
    await inventory(report(weakened));
    await new Promise((r) => setTimeout(r, 50));
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ subject: { label: "kb-ws-31" }, data: { hardening: { keys: ["win_smb1", "win_wdigest"] } } });
    expect(seen[0]!.data.hardening.checks).toContain("WDigest does not keep clear-text passwords (UseLogonCredential = 1");
    const o = await overview();
    expect(o.endpoints[0].score).toBeLessThan(100);
    expect(o.checks.find((c: { key: string }) => c.key === "win_smb1")).toMatchObject({ failing: 1, passing: 0 });
    off();
  });

  it("accepts a gap with a reason (out of the score), and only admins may", async () => {
    const before = (await overview()).endpoints[0].score;
    expect((await analyst.put(`/attack-reduction/exceptions/${org}/win_smb1`, { reason: "Legacy scanner needs SMBv1 until March" })).status).toBe(403);
    expect((await otherAdmin.put(`/attack-reduction/exceptions/${org}/win_smb1`, { reason: "Legacy scanner needs SMBv1 until March" })).status).toBe(404);
    expect((await admin.put(`/attack-reduction/exceptions/${org}/win_smb1`, { reason: "short" })).status).toBe(400);
    expect((await admin.put(`/attack-reduction/exceptions/${org}/not_a_check`, { reason: "Legacy scanner needs SMBv1 until March" })).status).toBe(400);
    expect((await admin.put(`/attack-reduction/exceptions/${org}/win_smb1`, { reason: "Legacy scanner needs SMBv1 until March" })).status).toBe(200);
    const o = await overview();
    expect(o.endpoints[0].score).toBeGreaterThan(before);
    expect(o.checks.find((c: { key: string }) => c.key === "win_smb1").exception).toMatchObject({ reason: "Legacy scanner needs SMBv1 until March" });
    expect((await admin.delete(`/attack-reduction/exceptions/${org}/win_smb1`)).status).toBe(200);
    expect((await admin.delete(`/attack-reduction/exceptions/${org}/win_smb1`)).status).toBe(404);
    const audit = await t.privileged.query("SELECT action FROM audit_log WHERE tenant_id = $1 AND action LIKE 'attack_reduction.%' ORDER BY seq", [tenant.tenantId]);
    expect(audit.rows.map((r) => r.action)).toEqual(["attack_reduction.exception_set", "attack_reduction.exception_removed"]);
  });

  it("refuses malformed hardening facts", async () => {
    expect((await inventory(report({ "Not A Key": true }))).statusCode).toBe(400);
  });
});
