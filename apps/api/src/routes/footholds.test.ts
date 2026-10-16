import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { footholdFingerprint } from "@bloody/contracts";
import { api, createTenant, createTestApp, createUser, login, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let other: TestTenant;
let admin: ReturnType<typeof api>;
let analyst: ReturnType<typeof api>;
let otherAdmin: ReturnType<typeof api>;
let org: string;
const tokens: Record<string, string> = {};

const RUN = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const teams = { kind: "run_key", location: "HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", name: "Teams", command: "C:\\Users\\amina\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart Teams.exe", user: "amina", signed: true, signer: "Microsoft Corporation" };
const defender = { kind: "run_key", location: RUN, name: "SecurityHealth", command: "%windir%\\system32\\SecurityHealthSystray.exe", signed: true };
const evil = { kind: "scheduled_task", location: "\\Microsoft\\Windows\\UpdateCheck", name: "UpdateCheck", command: "powershell.exe -nop -w hidden -enc SQBFAFgA", user: "SYSTEM" };
const report = (autoruns: object[]) => ({ software: [], services: [], users: [], processes: [], ports: [], antivirus: [], autoruns });
const inventory = (host: string, autoruns: object[]) =>
  t.app.inject({ method: "POST", url: "/api/v1/agent/inventory", headers: { "content-type": "application/json", authorization: `Bearer ${tokens[host]}` }, payload: JSON.stringify(report(autoruns)) });
const overview = async () => (await admin.get(`/footholds/overview?organizationId=${org}`)).body;
const seen: Array<{ severity: string; subject: { label: string }; data: { foothold: Record<string, string> } }> = [];

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
  for (const host of ["kb-ws-01", "kb-ws-02"]) {
    const res = await t.app.inject({ method: "POST", url: "/api/v1/agent/enroll", headers: { "content-type": "application/json" }, payload: JSON.stringify({ accountKey: key, organizationKey: "org-1", hostname: host, platform: "windows", version: "1.4.0" }) });
    tokens[host] = res.json().token;
  }
  t.services.domainEvents.subscribe("test-footholds", async (e) => {
    if (e.event === "foothold.suspicious_detected") seen.push(e as never);
  });
});
afterAll(async () => {
  await t?.close();
});

const settle = () => new Promise((r) => setTimeout(r, 50));

describe("Persistent Footholds", () => {
  it("takes the first report as the computer's baseline, without alerting", async () => {
    expect((await overview())).toMatchObject({ footholds: [], summary: { entries: 0, endpointsReporting: 0 } });
    expect((await inventory("kb-ws-01", [teams, defender, evil])).statusCode).toBe(200);
    await settle();
    expect(seen).toHaveLength(0);
    const o = await overview();
    expect(o.summary).toMatchObject({ entries: 3, suspicious: 1, malicious: 0, newLast7Days: 0, endpointsReporting: 1 });
    // Riskiest first, with the reasons.
    expect(o.footholds[0]).toMatchObject({ name: "UpdateCheck", kind: "scheduled_task", isNew: false, endpointCount: 1, assessment: { level: "high" } });
    expect(o.footholds[0].assessment.reasons[0].text).toBe("Encoded or obfuscated PowerShell");
    expect(o.footholds[0].endpoints[0]).toMatchObject({ hostname: "kb-ws-01", user: "SYSTEM", baseline: true });
  });

  it("groups the same entry across computers and users", async () => {
    await inventory("kb-ws-02", [{ ...teams, location: "HKU\\S-1-5-21-1-2-3-1002\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", command: "C:\\Users\\joseph\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart Teams.exe", user: "joseph" }, defender]);
    const o = await overview();
    const t1 = o.footholds.find((f: { name: string }) => f.name === "Teams");
    expect(t1.endpointCount).toBe(2);
    expect(t1.endpoints.map((e: { user: string }) => e.user).sort()).toEqual(["amina", "joseph"]);
    expect(o.summary.endpointsReporting).toBe(2);
  });

  it("alerts when a suspicious entry appears later, once", async () => {
    const dropper = { kind: "run_key", location: "HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", name: "OneDrive Sync", command: "C:\\Users\\amina\\AppData\\Local\\Temp\\svchost.exe", user: "amina", signed: false };
    const harmless = { kind: "run_key", location: RUN, name: "Zoom", command: "\"C:\\Program Files\\Zoom\\bin\\Zoom.exe\" /background", signed: true, signer: "Zoom Video Communications" };
    await inventory("kb-ws-01", [teams, defender, evil, dropper, harmless]);
    await inventory("kb-ws-01", [teams, defender, evil, dropper, harmless]);
    await settle();
    expect(seen).toHaveLength(1); // the harmless new entry does not alert; the repeat report does not either
    expect(seen[0]).toMatchObject({ severity: "high", subject: { label: "kb-ws-01" }, data: { foothold: { kind: "Run key", name: "OneDrive Sync", level: "high" } } });
    expect(seen[0]!.data.foothold.reasons).toContain("Runs from a temporary or user-writable folder");
    const o = await overview();
    expect(o.footholds.find((f: { name: string }) => f.name === "OneDrive Sync")).toMatchObject({ isNew: true });
    expect(o.footholds.find((f: { name: string }) => f.name === "Zoom")).toMatchObject({ isNew: true, assessment: { level: "low" } });
    expect(o.summary.newLast7Days).toBe(2);
  });

  it("drops entries that are removed, and alerts again if they come back", async () => {
    await inventory("kb-ws-01", [teams, defender, evil]);
    let o = await overview();
    expect(o.footholds.find((f: { name: string }) => f.name === "OneDrive Sync")).toBeUndefined();
    await inventory("kb-ws-01", [teams, defender, evil, { kind: "run_key", location: "HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", name: "OneDrive Sync", command: "C:\\Users\\amina\\AppData\\Local\\Temp\\svchost.exe", user: "amina", signed: false }]);
    await settle();
    expect(seen).toHaveLength(2);
    o = await overview();
    expect(o.footholds.find((f: { name: string }) => f.name === "OneDrive Sync")).toBeDefined();
  });

  it("verdicts are per organization, need asset:write, are audited and steer alerts", async () => {
    const fp = footholdFingerprint({ kind: "scheduled_task", location: evil.location, name: evil.name, command: evil.command });
    const put = (who: ReturnType<typeof api>, body: object) => who.put("/footholds/verdicts", { organizationId: org, fingerprints: [fp], ...body });
    expect((await put(analyst, { verdict: "expected" })).status).toBe(403);
    expect((await put(otherAdmin, { verdict: "expected" })).status).toBe(404);
    expect((await put(admin, { verdict: "bogus" })).status).toBe(400);
    expect((await put(admin, { verdict: "malicious", note: "Cobalt Strike stager, IR-2026-41" })).body).toEqual({ changed: 1 });
    let o = await overview();
    expect(o.footholds[0]).toMatchObject({ name: "UpdateCheck", verdict: { verdict: "malicious", note: "Cobalt Strike stager, IR-2026-41" } });
    expect(o.summary).toMatchObject({ malicious: 1 });
    expect(o.footholds[0].verdict.by).not.toMatch(/^user:/); // shown as the person, not an internal id
    // The malicious entry turning up on another computer alerts even though that is its first report… after baseline.
    await inventory("kb-ws-02", [teams, defender, evil]);
    await settle();
    expect(seen.at(-1)).toMatchObject({ severity: "high", data: { foothold: { name: "UpdateCheck", level: "malicious (marked by an analyst)" } } });
    // Expected entries go to the bottom and stop counting as suspicious.
    await put(admin, { verdict: "expected" });
    o = await overview();
    expect(o.footholds.at(-1).name).toBe("UpdateCheck");
    expect(o.summary.malicious).toBe(0);
    expect((await put(admin, { verdict: null })).body).toEqual({ changed: 1 });
    const audit = await t.privileged.query("SELECT details FROM audit_log WHERE tenant_id = $1 AND action = 'footholds.verdict_changed' ORDER BY created_at", [tenant.tenantId]);
    expect(audit.rows.map((r) => r.details.verdict)).toEqual(["malicious", "expected", null]);
    expect((await analyst.get(`/footholds/overview?organizationId=${org}`)).status).toBe(200);
    expect((await otherAdmin.get(`/footholds/overview?organizationId=${org}`)).status).toBe(404);
  });

  it("ignores reports from agents that do not collect autoruns", async () => {
    const before = (await overview()).summary.entries;
    expect((await inventory("kb-ws-01", [])).statusCode).toBe(200);
    expect((await overview()).summary.entries).toBe(before);
  });
});
