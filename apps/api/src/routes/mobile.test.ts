import { generateKeyPairSync } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, type Json, type TestApp, type TestTenant } from "../test/harness.js";

const pem = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const KEY = JSON.stringify({ type: "service_account", project_id: "sciat-mdm-01", client_email: "mdm@sciat-mdm-01.iam.gserviceaccount.com", private_key: pem });
const ENT = "enterprises/LC04xkq1";
const recent = new Date(Date.now() - 3_600_000).toISOString();

/** Fake Google: OAuth token endpoint + the Android Management API calls SCIAT makes. */
const google: { calls: Array<{ method: string; path: string; query: Record<string, string>; body: Json }>; devices: Json[]; failToken: boolean } = { calls: [], devices: [], failToken: false };
const fakeGoogle = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(String(input instanceof Request ? input.url : input));
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  if (url.host === "oauth2.googleapis.com") return google.failToken ? json(400, { error: "invalid_grant", error_description: "Invalid JWT Signature." }) : json(200, { access_token: "ya29.fake", expires_in: 3600 });
  const path = url.pathname.replace(/^\/v1\//, "");
  const method = init?.method ?? "GET";
  google.calls.push({ method, path, query: Object.fromEntries(url.searchParams), body: init?.body ? JSON.parse(String(init.body)) : null });
  if (method === "POST" && path === "signupUrls") return json(200, { name: "signupUrls/C9a8b7c6d5", url: "https://enterprise.google.com/signup/android/email?token=abc" });
  if (method === "POST" && path === "enterprises") return url.searchParams.get("enterpriseToken") === "good-token" ? json(200, { name: ENT, enterpriseDisplayName: "Kilimanjaro Bank" }) : json(400, { error: { status: "INVALID_ARGUMENT", message: "Invalid enterprise token" } });
  if (method === "GET" && path === ENT) return json(200, { name: ENT, enterpriseDisplayName: "Kilimanjaro Bank" });
  if (method === "GET" && path === "enterprises/LC99other") return json(404, { error: { status: "NOT_FOUND", message: "Enterprise not found" } });
  if (method === "PATCH" && path === `${ENT}/policies/sciat-baseline`) return json(200, {});
  if (method === "POST" && path === `${ENT}/enrollmentTokens`) return json(200, { name: `${ENT}/enrollmentTokens/tok1`, value: "ABCDEFGHIJ", qrCode: '{"android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME":"com.google.android.apps.work.clouddpc/.receivers.CloudDeviceAdminReceiver"}', expirationTimestamp: "2026-12-01T00:00:00Z" });
  if (method === "DELETE" && path === `${ENT}/enrollmentTokens/tok1`) return json(200, {});
  if (method === "GET" && path === `${ENT}/devices`) return json(200, { devices: google.devices });
  if (method === "POST" && path.endsWith(":issueCommand")) return json(200, { name: `${path}/operations/1` });
  if (method === "DELETE" && path.startsWith(`${ENT}/devices/`)) return json(200, {});
  return json(404, { error: { status: "NOT_FOUND", message: `unexpected ${method} ${path}` } });
}) as typeof fetch;

let t: TestApp;
let tenant: TestTenant;
let org: string;
let admin: ReturnType<typeof api>;
let analyst: ReturnType<typeof api>;
let responder: ReturnType<typeof api>;
let other: ReturnType<typeof api>;

beforeAll(async () => {
  t = await createTestApp({ deps: { fetch: fakeGoogle } });
  tenant = await createTenant(t, { orgs: 1, plan: "mssp" });
  org = tenant.orgIds[0]!;
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  analyst = api(t.app, { token: (await login(t.app, (await createUser(t, tenant.tenantId, { roles: [{ role: "soc_analyst_t1", organizationId: null }] })).email)).token });
  responder = api(t.app, { token: (await login(t.app, (await createUser(t, tenant.tenantId, { roles: [{ role: "incident_responder", organizationId: null }] })).email)).token });
  other = api(t.app, { token: (await login(t.app, (await createTenant(t, { orgs: 1, plan: "mssp" })).admin.email)).token });
});
afterAll(async () => {
  await t?.close();
});

const phone = (id: string, extra: Json = {}) => ({
  name: `${ENT}/devices/${id}`,
  state: "ACTIVE",
  managementMode: "DEVICE_OWNER",
  ownership: "COMPANY_OWNED",
  policyCompliant: true,
  enrollmentTime: "2026-10-01T09:00:00Z",
  lastStatusReportTime: recent,
  enrollmentTokenData: "",
  hardwareInfo: { manufacturer: "Samsung", model: "SM-A546E", serialNumber: `R58N${id}XYZ123` },
  softwareInfo: { androidVersion: "14", securityPatchLevel: new Date(Date.now() - 20 * 86_400_000).toISOString().slice(0, 10) },
  deviceSettings: { isEncrypted: true, isDeviceSecure: true, unknownSourcesEnabled: false, verifyAppsEnabled: true, adbEnabled: false },
  securityPosture: { devicePosture: "SECURE" },
  ...extra,
});

describe("Mobile device management — Android Enterprise", () => {
  it("starts unconfigured and explains the order of steps", async () => {
    const o = (await admin.get(`/mobile/overview?organizationId=${org}`)).body;
    expect(o).toMatchObject({ account: { configured: false }, enterprise: null, devices: [], counts: { total: 0 } });
    const r = await admin.post("/mobile/android/enterprise/signup", { organizationId: org });
    expect(r.status).toBe(409);
    expect(r.body.error.code).toBe("android_not_configured");
  });

  it("checks the Google key before storing it, and never returns it", async () => {
    expect((await admin.put("/mobile/android/account", { serviceAccountJson: '{"type":"authorized_user","client_id":"x","refresh_token":"y-long-enough-to-pass"}' })).status).toBe(400);
    google.failToken = true;
    const bad = await admin.put("/mobile/android/account", { serviceAccountJson: KEY });
    expect(bad.status).toBe(400);
    expect(bad.body.error.message).toMatch(/Invalid JWT Signature/);
    google.failToken = false;
    expect((await analyst.put("/mobile/android/account", { serviceAccountJson: KEY })).status).toBe(403);
    const ok = await admin.put("/mobile/android/account", { serviceAccountJson: KEY });
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ configured: true, projectId: "sciat-mdm-01", clientEmail: "mdm@sciat-mdm-01.iam.gserviceaccount.com", status: "ok" });
    expect(JSON.stringify((await admin.get("/mobile/android/account")).body)).not.toContain("PRIVATE KEY");
    const stored = await t.privileged.query("SELECT count(*)::int AS n FROM secrets WHERE tenant_id = $1 AND purpose = 'android.service_account'", [tenant.tenantId]);
    expect(stored.rows[0].n).toBe(1);
  });

  it("creates the customer's Android Enterprise through Google's sign-up and applies the baseline", async () => {
    const r = await admin.post("/mobile/android/enterprise/signup", { organizationId: org, adminEmail: "it@kilimanjaro.example" });
    expect(r.status).toBe(200);
    expect(r.body.url).toBe("https://enterprise.google.com/signup/android/email?token=abc");
    const call = google.calls.find((c) => c.path === "signupUrls")!;
    expect(call.query).toMatchObject({ projectId: "sciat-mdm-01", adminEmail: "it@kilimanjaro.example" });
    const callback = new URL(call.query.callbackUrl!);
    expect(callback.pathname).toBe("/api/v1/mobile/android/signup-callback");
    const state = callback.searchParams.get("state")!;

    // A forged / wrong state or a bad token never creates anything.
    const forged = await t.app.inject({ method: "GET", url: `/api/v1/mobile/android/signup-callback?state=${tenant.tenantId}.${"x".repeat(40)}&enterpriseToken=good-token` });
    expect(forged.headers.location).toMatch(/android=error/);
    const back = await t.app.inject({ method: "GET", url: `/api/v1/mobile/android/signup-callback?state=${encodeURIComponent(state)}&enterpriseToken=good-token` });
    expect(back.statusCode).toBe(302);
    expect(back.headers.location).toMatch(new RegExp(`/mdm\\?organizationId=${org}&android=connected$`));
    const again = await t.app.inject({ method: "GET", url: `/api/v1/mobile/android/signup-callback?state=${encodeURIComponent(state)}&enterpriseToken=good-token` });
    expect(again.headers.location).toMatch(/android=error/); // single use

    const o = (await admin.get(`/mobile/overview?organizationId=${org}`)).body;
    expect(o.enterprise).toMatchObject({ status: "active", enterpriseName: ENT, displayName: "Kilimanjaro Bank", policy: { password: "medium", maxPatchAgeDays: 90 } });
    expect(o.enterprise.policySyncedAt).not.toBeNull();
    const policy = google.calls.find((c) => c.method === "PATCH")!.body;
    expect(policy).toMatchObject({ passwordPolicies: [{ passwordQuality: "COMPLEXITY_MEDIUM" }], advancedSecurityOverrides: { untrustedAppsPolicy: "DISALLOW_INSTALL" } });
  });

  it("issues enrollment QR codes and revokes them", async () => {
    expect((await analyst.post("/mobile/android/enrollment-tokens", { organizationId: org, ownership: "company", validDays: 7 })).status).toBe(403);
    const r = await admin.post("/mobile/android/enrollment-tokens", { organizationId: org, ownership: "company", validDays: 7, assignee: "Amina Mushi" });
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ ownership: "company", assignee: "Amina Mushi", value: "ABCDEFGHIJ", expiresAt: "2026-12-01T00:00:00.000Z" });
    expect(JSON.parse(r.body.qrCode)).toHaveProperty("android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME");
    const sent = google.calls.filter((c) => c.path === `${ENT}/enrollmentTokens`).at(-1)!.body;
    expect(sent).toMatchObject({ policyName: `${ENT}/policies/sciat-baseline`, duration: "604800s", allowPersonalUsage: "PERSONAL_USAGE_DISALLOWED" });
    expect(JSON.parse(sent.additionalData).sciatToken).toBe(r.body.id);
    expect((await admin.get(`/mobile/overview?organizationId=${org}`)).body.tokens).toHaveLength(1);

    // The phone enrolled with that code: its record carries the assignee.
    google.devices = [phone("d1", { enrollmentTokenData: sent.additionalData }), phone("d2", { deviceSettings: { isEncrypted: true, isDeviceSecure: false, unknownSourcesEnabled: true, verifyAppsEnabled: true } }), phone("d3", { securityPosture: { devicePosture: "POTENTIALLY_COMPROMISED", postureDetails: [{ securityRisk: "COMPROMISED_OS" }] } })];

    expect((await other.delete(`/mobile/android/enrollment-tokens/${r.body.id}`)).status).toBe(404);
    expect((await admin.delete(`/mobile/android/enrollment-tokens/${r.body.id}`)).status).toBe(204);
    expect((await admin.get(`/mobile/overview?organizationId=${org}`)).body.tokens).toHaveLength(0);
  });

  it("syncs phones from Google, grades them and lists them as assets", async () => {
    const r = await analyst.post("/mobile/android/sync", { organizationId: org });
    expect(r.body).toEqual({ devices: 3, removed: 0 });
    const o = (await admin.get(`/mobile/overview?organizationId=${org}`)).body;
    expect(o.counts).toMatchObject({ total: 3, compliant: 1, non_compliant: 1, at_risk: 1 });
    expect(o.devices.map((d: Json) => d.compliance)).toEqual(["at_risk", "non_compliant", "compliant"]);
    const good = o.devices.find((d: Json) => d.compliance === "compliant");
    expect(good).toMatchObject({ manufacturer: "Samsung", model: "SM-A546E", osVersion: "14", ownership: "company", assignee: "Amina Mushi" });
    expect(o.devices.find((d: Json) => d.compliance === "non_compliant").findings.map((f: Json) => f.key)).toEqual(["no_screen_lock", "unknown_sources"]);
    const assets = await t.privileged.query("SELECT kind, os, owner, source FROM assets WHERE tenant_id = $1 AND external_source = 'android' ORDER BY name", [tenant.tenantId]);
    expect(assets.rows).toHaveLength(3);
    expect(assets.rows[0]).toMatchObject({ kind: "mobile_device", os: "Android 14", source: "integration" });

    // A phone removed in Google disappears here; the scheduler re-syncs on its own.
    google.devices = google.devices.slice(0, 2);
    await t.privileged.query("UPDATE android_enterprises SET last_sync_at = now() - interval '1 hour' WHERE tenant_id = $1", [tenant.tenantId]);
    expect(await t.services.android.syncDue(tenant.tenantId)).toBe(1);
    expect(await t.services.android.syncDue(tenant.tenantId)).toBe(0);
    expect((await admin.get(`/mobile/overview?organizationId=${org}`)).body.counts.total).toBe(2);
    expect((await other.get(`/mobile/overview?organizationId=${org}`)).status).toBe(404);
  });

  it("tightening the policy re-grades phones at once", async () => {
    const o = (await admin.get(`/mobile/overview?organizationId=${org}`)).body;
    const r = await admin.put("/mobile/android/policy", { organizationId: org, settings: { ...o.enterprise.policy, maxPatchAgeDays: 14 } });
    expect(r.status).toBe(200);
    const after = (await admin.get(`/mobile/overview?organizationId=${org}`)).body;
    expect(after.counts.compliant).toBe(0);
    expect(after.devices.find((d: Json) => d.assignee === "Amina Mushi").findings[0]).toMatchObject({ key: "patch_old", title: expect.stringMatching(/^Security patch is 2\d days old$/) });
    expect((await admin.put("/mobile/android/policy", { organizationId: org, settings: { ...o.enterprise.policy, maxPatchAgeDays: 1 } })).status).toBe(400);
  });

  it("locks a phone and wipes one only after a second person approves", async () => {
    const o = (await admin.get(`/mobile/overview?organizationId=${org}`)).body;
    const device = o.devices.find((d: Json) => d.assignee === "Amina Mushi");
    const target = { kind: "asset", id: device.assetId, label: device.name };
    const lock = await responder.post("/response/actions", { action: "lock_device", organizationId: org, target, reason: "Phone reported lost at the airport" });
    expect(lock.status).toBe(201);
    expect(lock.body).toMatchObject({ status: "succeeded", executor: "mdm:android" });
    expect(google.calls.at(-1)).toMatchObject({ method: "POST", path: `${ENT}/devices/d1:issueCommand`, body: { type: "LOCK" } });

    const wipe = await responder.post("/response/actions", { action: "wipe_device", organizationId: org, target, reason: "Lost phone with customer data, not recovered" });
    expect(wipe.body.status).toBe("pending_approval");
    expect(google.calls.some((c) => c.method === "DELETE" && c.path === `${ENT}/devices/d1`)).toBe(false);
    const approved = await admin.post(`/response/actions/${wipe.body.id}/approve`, { comment: "confirmed with the customer" });
    expect(approved.status).toBe(200);
    const done = (await admin.get(`/response/actions/${wipe.body.id}`)).body;
    expect(done.status).toBe("succeeded");
    const del = google.calls.find((c) => c.method === "DELETE" && c.path === `${ENT}/devices/d1`)!;
    expect(del.query.wipeReasonMessage).toBe("Lost phone with customer data, not recovered");
    expect((await admin.get(`/mobile/overview?organizationId=${org}`)).body.counts.total).toBe(1);

    // Only enrolled phones can be targeted.
    const pc = await admin.post("/assets", { organizationId: org, kind: "endpoint", name: "ws-01", hostname: "ws-01" });
    const bad = await responder.post("/response/actions", { action: "lock_device", organizationId: org, target: { kind: "asset", id: pc.body.id }, reason: "Not a phone at all, should be refused" });
    expect(bad.status).toBe(400);
    const audit = await t.privileged.query("SELECT action FROM audit_log WHERE tenant_id = $1 AND (action LIKE 'mobile.%' OR action LIKE 'response.%_device')", [tenant.tenantId]);
    expect(audit.rows.map((r) => r.action)).toEqual(expect.arrayContaining(["mobile.google_account_connected", "mobile.enterprise_signup_started", "mobile.enterprise_created", "mobile.enrollment_code_created", "mobile.policy_changed", "response.lock_device", "response.wipe_device"]));
  });

  it("links an existing enterprise only once, and unlinks", async () => {
    const second = (await t.privileged.query("INSERT INTO organizations (tenant_id, name, slug) VALUES ($1, 'Nile Health', 'nile-health-mdm') RETURNING id", [tenant.tenantId])).rows[0].id as string;
    expect((await admin.post("/mobile/android/enterprise/link", { organizationId: second, enterpriseName: ENT })).status).toBe(409);
    expect((await admin.post("/mobile/android/enterprise/link", { organizationId: second, enterpriseName: "enterprises/LC99other" })).status).toBe(502);
    expect((await admin.post("/mobile/android/enterprise/link", { organizationId: second, enterpriseName: "https://evil" })).status).toBe(400);
    expect((await admin.delete(`/mobile/android/enterprise?organizationId=${org}`)).status).toBe(204);
    const o = (await admin.get(`/mobile/overview?organizationId=${org}`)).body;
    expect(o).toMatchObject({ enterprise: null, devices: [] });
    expect((await admin.post("/mobile/android/enterprise/link", { organizationId: second, enterpriseName: ENT })).status).toBe(200);
  });
});
