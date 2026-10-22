import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { encodePlist, parsePlist, parsePlistDict, type ApnsPush, type PlistValue } from "@bloody/adapters";
import { api, createTenant, createTestApp, createUser, login, type Json, type TestApp, type TestTenant } from "../test/harness.js";
import { APNS_CERT_PEM, APNS_KEY_PEM, APNS_TOPIC } from "../test/apple-mdm-fixtures.js";

const pushes: ApnsPush[] = [];

let t: TestApp;
let tenant: TestTenant;
let org: string;
let admin: ReturnType<typeof api>;
let analyst: ReturnType<typeof api>;
let responder: ReturnType<typeof api>;
let other: ReturnType<typeof api>;

beforeAll(async () => {
  t = await createTestApp({ deps: { appleApnsTransport: () => async (p) => void pushes.push(p) } });
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

const UDID = "00008030-001A2B3C4D5E";

/** A simulated iPhone: posts plists to the public MDM endpoints. */
async function mdm(kind: "checkin" | "connect", token: string, message: Record<string, PlistValue>): Promise<{ status: number; body: Record<string, PlistValue> | null }> {
  const res = await t.app.inject({ method: "PUT", url: `/api/v1/mdm/apple/${kind}/${token}`, headers: { "content-type": "application/x-apple-aspen-mdm" }, payload: encodePlist(message) });
  const body = res.payload ? (parsePlist(res.payload) as Record<string, PlistValue>) : null;
  return { status: res.statusCode, body };
}

describe("Apple (iOS / iPadOS) device management", () => {
  let enrollToken: string;

  it("needs the push certificate before anything, and checks it", async () => {
    expect((await admin.get(`/mobile/apple/overview?organizationId=${org}`)).body).toMatchObject({ certificate: { configured: false }, devices: [], counts: { total: 0 } });
    expect((await admin.post("/mobile/apple/enrollments", { organizationId: org, ownership: "company", validDays: 30 })).status).toBe(409);
    expect((await admin.put("/mobile/apple/certificate", { certificatePem: "not a cert", privateKeyPem: APNS_KEY_PEM })).status).toBe(400);
    expect((await analyst.put("/mobile/apple/certificate", { certificatePem: APNS_CERT_PEM, privateKeyPem: APNS_KEY_PEM })).status).toBe(403);
    const ok = await admin.put("/mobile/apple/certificate", { certificatePem: APNS_CERT_PEM, privateKeyPem: APNS_KEY_PEM });
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ configured: true, topic: APNS_TOPIC, status: "ok" });
    expect(JSON.stringify((await admin.get("/mobile/apple/certificate")).body)).not.toContain("PRIVATE KEY");
  });

  it("hands out an enrollment profile that points the device back at this server", async () => {
    expect((await analyst.post("/mobile/apple/enrollments", { organizationId: org, ownership: "company", validDays: 30 })).status).toBe(403);
    const r = await admin.post("/mobile/apple/enrollments", { organizationId: org, ownership: "company", validDays: 30, assignee: "Amina Mushi" });
    expect(r.status).toBe(201);
    enrollToken = r.body.token;
    expect(r.body.enrollUrl).toContain(`/api/v1/mdm/apple/enroll/${enrollToken}`);

    const profileRes = await t.app.inject({ method: "GET", url: `/api/v1/mdm/apple/enroll/${enrollToken}` });
    expect(profileRes.statusCode).toBe(200);
    expect(profileRes.headers["content-type"]).toContain("application/x-apple-aspen-config");
    const mdmPayload = (parsePlistDict(profileRes.payload).PayloadContent as Record<string, PlistValue>[])[0]!;
    expect(mdmPayload.PayloadType).toBe("com.apple.mdm");
    expect(mdmPayload.Topic).toBe(APNS_TOPIC);
    expect(mdmPayload.CheckInURL).toContain(`/mdm/apple/checkin/${enrollToken}`);
  });

  it("enrolls a device, applies the baseline and learns about it", async () => {
    // Authenticate, then TokenUpdate (completes enrollment → queues InstallProfile + queries + pushes).
    expect((await mdm("checkin", enrollToken, { MessageType: "Authenticate", UDID, Topic: APNS_TOPIC, DeviceName: "Amina's iPhone" })).status).toBe(200);
    expect((await mdm("checkin", enrollToken, { MessageType: "TokenUpdate", UDID, Topic: APNS_TOPIC, Token: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]), PushMagic: "MAGIC-1" })).status).toBe(200);
    expect(pushes.at(-1)).toEqual({ pushToken: "aabbccdd", pushMagic: "MAGIC-1", topic: APNS_TOPIC });

    // The device polls; first it gets the security baseline to install.
    const first = await mdm("connect", enrollToken, { UDID, Status: "Idle" });
    expect((first.body!.Command as Record<string, PlistValue>).RequestType).toBe("InstallProfile");
    const installUuid = first.body!.CommandUUID as string;

    // Acknowledge the install; next it is asked about itself.
    const info = await mdm("connect", enrollToken, { UDID, Status: "Acknowledged", CommandUUID: installUuid });
    expect((info.body!.Command as Record<string, PlistValue>).RequestType).toBe("DeviceInformation");
    const infoUuid = info.body!.CommandUUID as string;

    const sec = await mdm("connect", enrollToken, {
      UDID,
      Status: "Acknowledged",
      CommandUUID: infoUuid,
      QueryResponses: { DeviceName: "Amina's iPhone", OSVersion: "17.6.1", ModelName: "iPhone 15", SerialNumber: "F2LXYZ123", IsSupervised: true },
    });
    const secUuid = sec.body!.CommandUUID as string;
    expect((sec.body!.Command as Record<string, PlistValue>).RequestType).toBe("SecurityInfo");

    // Report a passcode is set → compliant; then the queue is empty.
    const empty = await mdm("connect", enrollToken, { UDID, Status: "Acknowledged", CommandUUID: secUuid, SecurityInfo: { PasscodePresent: true, PasscodeCompliant: true, FDE_Enabled: true } });
    expect(empty.body).toBeNull();

    const o = (await admin.get(`/mobile/apple/overview?organizationId=${org}`)).body;
    expect(o.counts).toMatchObject({ total: 1, compliant: 1 });
    expect(o.devices[0]).toMatchObject({ platform: "ios", name: "Amina's iPhone", osVersion: "17.6.1", model: "iPhone 15", ownership: "company", assignee: "Amina Mushi", compliance: "compliant" });
    const assets = await t.privileged.query("SELECT kind, os FROM assets WHERE tenant_id = $1 AND external_source = 'apple'", [tenant.tenantId]);
    expect(assets.rows[0]).toMatchObject({ kind: "mobile_device", os: "iOS 17.6.1" });
    expect((await other.get(`/mobile/apple/overview?organizationId=${org}`)).status).toBe(404);
  });

  it("tightening the baseline re-grades and flags a device below the minimum OS", async () => {
    const r = await admin.put("/mobile/apple/policy", { organizationId: org, settings: { requirePasscode: true, minPasscodeLength: 6, blockCamera: true, blockScreenshot: false, blockAppInstall: false, forceEncryptedBackup: true, minOsVersion: 18 } });
    expect(r.status).toBe(200);
    const o = (await admin.get(`/mobile/apple/overview?organizationId=${org}`)).body;
    expect(o.devices[0].compliance).toBe("non_compliant");
    expect(o.devices[0].findings.map((f: Json) => f.key)).toContain("os_old");
    // The new baseline was queued to the device as an InstallProfile and a push was sent.
    const queued = await t.privileged.query("SELECT request_type FROM apple_commands WHERE tenant_id = $1 AND status = 'queued' AND request_type = 'InstallProfile'", [tenant.tenantId]);
    expect(queued.rowCount).toBeGreaterThanOrEqual(1);
  });

  it("locks the iPhone, and erases it only after a second person approves", async () => {
    const device = (await admin.get(`/mobile/apple/overview?organizationId=${org}`)).body.devices[0];
    const target = { kind: "asset", id: device.assetId, label: device.name };
    const lock = await responder.post("/response/actions", { action: "lock_device", organizationId: org, target, reason: "iPhone reported lost at the airport" });
    expect(lock.status).toBe(201);
    expect(lock.body).toMatchObject({ status: "succeeded", executor: "mdm:apple" });
    expect((await t.privileged.query("SELECT 1 FROM apple_commands WHERE tenant_id = $1 AND request_type = 'DeviceLock'", [tenant.tenantId])).rowCount).toBe(1);

    const wipe = await responder.post("/response/actions", { action: "wipe_device", organizationId: org, target, reason: "Lost iPhone with customer data, not recovered" });
    expect(wipe.body.status).toBe("pending_approval");
    expect((await t.privileged.query("SELECT 1 FROM apple_commands WHERE tenant_id = $1 AND request_type = 'EraseDevice'", [tenant.tenantId])).rowCount).toBe(0);
    expect((await admin.post(`/response/actions/${wipe.body.id}/approve`, { comment: "confirmed with the customer" })).status).toBe(200);
    expect((await admin.get(`/response/actions/${wipe.body.id}`)).body.status).toBe("succeeded");
    expect((await t.privileged.query("SELECT 1 FROM apple_commands WHERE tenant_id = $1 AND request_type = 'EraseDevice'", [tenant.tenantId])).rowCount).toBe(1);

    // The device works through its queue on its next connection: baseline update, lock, erase.
    const handed: string[] = [];
    let reply = await mdm("connect", enrollToken, { UDID, Status: "Idle" });
    while (reply.body) {
      handed.push(String((reply.body.Command as Record<string, PlistValue>).RequestType));
      reply = await mdm("connect", enrollToken, { UDID, Status: "Acknowledged", CommandUUID: reply.body.CommandUUID as string });
    }
    expect(handed).toEqual(expect.arrayContaining(["DeviceLock", "EraseDevice"]));
    expect(handed.indexOf("DeviceLock")).toBeLessThan(handed.indexOf("EraseDevice"));
  });

  it("un-enrolls when the user removes the profile", async () => {
    expect((await mdm("checkin", enrollToken, { MessageType: "CheckOut", UDID })).status).toBe(200);
    expect((await admin.get(`/mobile/apple/overview?organizationId=${org}`)).body.counts.total).toBe(0);
    // A later poll from a removed device is rejected.
    expect((await mdm("connect", enrollToken, { UDID, Status: "Idle" })).status).toBe(410);
    const audit = await t.privileged.query("SELECT action FROM audit_log WHERE tenant_id = $1 AND action LIKE 'mobile.apple_%'", [tenant.tenantId]);
    expect(audit.rows.map((r) => r.action)).toEqual(expect.arrayContaining(["mobile.apple_certificate_uploaded", "mobile.apple_enrollment_created", "mobile.apple_policy_changed"]));
  });
});
