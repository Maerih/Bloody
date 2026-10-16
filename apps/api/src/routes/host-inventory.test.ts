import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, login, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let tenant: TestTenant;
let other: TestTenant;
let admin: ReturnType<typeof api>;
let otherAdmin: ReturnType<typeof api>;
let token: string;
let assetId: string;

const post = (url: string, body: object, tok?: string) =>
  t.app.inject({ method: "POST", url: `/api/v1${url}`, headers: { "content-type": "application/json", ...(tok ? { authorization: `Bearer ${tok}` } : {}) }, payload: JSON.stringify(body) });

const defender = { name: "Microsoft Defender Antivirus", enabled: true, upToDate: true, realTimeProtection: true, tamperProtection: true, signatureAgeDays: 0 };
const report = (av = [defender]) => ({
  software: [{ name: "Google Chrome", version: "129.0.6668.90", publisher: "Google LLC" }, { name: "AnyDesk", version: "8.0.14", publisher: "AnyDesk Software GmbH" }],
  services: [{ name: "WinDefend", displayName: "Microsoft Defender Antivirus Service", state: "Running", startMode: "Auto", account: "LocalSystem" }],
  users: [{ name: "amina", fullName: "Amina Mushi", admin: true, enabled: true, loggedIn: true }],
  processes: [{ pid: 4120, name: "chrome.exe", path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", user: "amina" }],
  ports: [{ protocol: "tcp", address: "0.0.0.0", port: 3389, process: "svchost.exe" }],
  antivirus: av,
  firewall: { enabled: true, detail: "Domain, Private, Public" },
});

beforeAll(async () => {
  t = await createTestApp({ deps: { hostResolver: false } });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  other = await createTenant(t, { orgs: 1, plan: "mssp" });
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  otherAdmin = api(t.app, { token: (await login(t.app, other.admin.email)).token });
  const key = (await admin.get("/agents/enrollment")).body.accountKey;
  token = (await post("/agent/enroll", { accountKey: key, organizationKey: "org-1", hostname: "kb-ws-07", platform: "windows", version: "1.1.0" })).json().token;
  assetId = (await t.privileged.query("SELECT asset_id FROM agents WHERE hostname = 'kb-ws-07'")).rows[0].asset_id;
});
afterAll(async () => {
  await t?.close();
});

describe("host inventory", () => {
  it("stores what the agent reports and shows it on the asset", async () => {
    expect((await admin.get(`/assets/${assetId}/inventory`)).body.inventory).toBeNull();
    const res = await post("/agent/inventory", report(), token);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ antivirusStatus: "protected" });
    const inv = (await admin.get(`/assets/${assetId}/inventory`)).body.inventory;
    expect(inv).toMatchObject({ hostname: "kb-ws-07", platform: "windows", antivirusStatus: "protected", antivirusIssues: [], firewall: { enabled: true } });
    expect(inv.software.map((s: { name: string }) => s.name)).toEqual(["Google Chrome", "AnyDesk"]);
    expect(inv.services[0]).toMatchObject({ name: "WinDefend", state: "running", startMode: "auto" });
    expect(inv.users[0]).toMatchObject({ name: "amina", admin: true, loggedIn: true });
    expect(inv.ports[0]).toMatchObject({ port: 3389 });
    const agent = (await t.privileged.query("SELECT antivirus_status, firewall_enabled FROM agents WHERE hostname = 'kb-ws-07'")).rows[0];
    expect(agent).toEqual({ antivirus_status: "protected", firewall_enabled: true });
    // Other accounts cannot read it.
    expect((await otherAdmin.get(`/assets/${assetId}/inventory`)).status).toBe(404);
  });

  it("flags tampering: antivirus turned unhealthy raises a notification once", async () => {
    const seen: unknown[] = [];
    const off = t.services.domainEvents.subscribe("test-av", async (e) => {
      if (e.event === "antivirus.unhealthy") seen.push(e);
    });
    const tampered = [{ ...defender, realTimeProtection: false, tamperProtection: false }];
    expect((await post("/agent/inventory", report(tampered), token)).json()).toMatchObject({ antivirusStatus: "unhealthy" });
    await post("/agent/inventory", report(tampered), token);
    await new Promise((r) => setTimeout(r, 50));
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ subject: { kind: "agent", label: "kb-ws-07" }, data: { antivirus: { issues: expect.stringContaining("real-time protection is off") } } });
    const av = (await admin.get("/agents/antivirus")).body.items;
    expect(av[0]).toMatchObject({ products: ["Microsoft Defender Antivirus"], issues: expect.arrayContaining(["Microsoft Defender Antivirus: tamper protection is off"]) });
    off();
  });

  it("refuses bad tokens and malformed reports", async () => {
    expect((await post("/agent/inventory", report(), "sat_bogus")).statusCode).toBe(401);
    expect((await post("/agent/inventory", { ...report(), unknown: true }, token)).statusCode).toBe(400);
  });
});
