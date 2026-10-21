import { createVerify, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { DEFAULT_ANDROID_POLICY } from "@bloody/contracts";
import { AmapiError, createAmapiClient, parseServiceAccountKey, serviceAccountAssertion } from "./amapi.js";
import { buildAndroidPolicy, evaluateAndroidDevice } from "./policy.js";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const keyJson = JSON.stringify({ type: "service_account", project_id: "sciat-mdm-01", client_email: "mdm@sciat-mdm-01.iam.gserviceaccount.com", private_key: pem, token_uri: "https://evil.example/token" });
const NOW = Date.parse("2026-10-21T12:00:00Z");

describe("service account key", () => {
  it("accepts a Google key file and rejects anything else", () => {
    expect(parseServiceAccountKey(keyJson)).toMatchObject({ projectId: "sciat-mdm-01", clientEmail: "mdm@sciat-mdm-01.iam.gserviceaccount.com" });
    expect(() => parseServiceAccountKey("{nope")).toThrow(/not valid JSON/);
    expect(() => parseServiceAccountKey(JSON.stringify({ type: "authorized_user" }))).toThrow(/service account/);
    expect(() => parseServiceAccountKey(JSON.stringify({ type: "service_account", project_id: "sciat-mdm-01", client_email: "x@gmail.com", private_key: pem }))).toThrow(/client_email/);
  });

  it("signs an RS256 JWT for Google's token endpoint", () => {
    const jwt = serviceAccountAssertion(parseServiceAccountKey(keyJson), NOW);
    const [h, c, sig] = jwt.split(".");
    expect(JSON.parse(Buffer.from(h!, "base64url").toString())).toEqual({ alg: "RS256", typ: "JWT" });
    const claims = JSON.parse(Buffer.from(c!, "base64url").toString());
    expect(claims).toMatchObject({ iss: "mdm@sciat-mdm-01.iam.gserviceaccount.com", aud: "https://oauth2.googleapis.com/token", scope: "https://www.googleapis.com/auth/androidmanagement" });
    expect(claims.exp - claims.iat).toBe(3600);
    expect(createVerify("RSA-SHA256").update(`${h}.${c}`).verify(publicKey, Buffer.from(sig!, "base64url"))).toBe(true);
  });
});

describe("Android Management API client", () => {
  const calls: Array<{ method: string; url: string; body: unknown }> = [];
  const fake = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push({ method: init?.method ?? "GET", url, body: init?.body ? (String(init.body).startsWith("{") ? JSON.parse(String(init.body)) : String(init.body)) : undefined });
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url === "https://oauth2.googleapis.com/token") return json(200, { access_token: "ya29.t", expires_in: 3600 });
    if (url.includes("/devices?") && !url.includes("pageToken")) return json(200, { devices: [{ name: "enterprises/LC01abcd/devices/d1" }], nextPageToken: "p2" });
    if (url.includes("pageToken=p2")) return json(200, { devices: [{ name: "enterprises/LC01abcd/devices/d2" }] });
    if (url.includes(":issueCommand")) return json(200, { name: "enterprises/LC01abcd/devices/d1/operations/1" });
    if (url.includes("/policies/")) return json(403, { error: { status: "PERMISSION_DENIED", message: "The caller does not have permission" } });
    return json(200, {});
  }) as typeof fetch;
  const client = createAmapiClient({ key: parseServiceAccountKey(keyJson), fetch: fake, now: () => NOW });

  it("signs in once, pages devices and never uses the key file's token URI", async () => {
    const devices = await client.listDevices("enterprises/LC01abcd");
    expect(devices.map((d) => d.name)).toEqual(["enterprises/LC01abcd/devices/d1", "enterprises/LC01abcd/devices/d2"]);
    await client.issueCommand("enterprises/LC01abcd/devices/d1", "LOCK");
    expect(calls.filter((c) => c.url.includes("oauth2")).length).toBe(1);
    expect(calls.some((c) => c.url.includes("evil.example"))).toBe(false);
    expect(calls.at(-1)).toMatchObject({ method: "POST", url: "https://androidmanagement.googleapis.com/v1/enterprises/LC01abcd/devices/d1:issueCommand", body: { type: "LOCK" } });
  });

  it("rejects resource names that would leave the enterprise, and reports Google errors", async () => {
    await expect(client.issueCommand("enterprises/LC01abcd/../../x", "LOCK")).rejects.toThrow(/Invalid/);
    await expect(client.listDevices("https://evil.example")).rejects.toThrow(/Invalid enterprise/);
    const err = await client.patchPolicy("enterprises/LC01abcd", "sciat-baseline", {}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AmapiError);
    expect((err as AmapiError).isPermission).toBe(true);
    expect((err as Error).message).toMatch(/does not have permission/);
  });
});

describe("SCIAT baseline policy", () => {
  it("maps the settings onto Android Management API fields", () => {
    const p = buildAndroidPolicy(DEFAULT_ANDROID_POLICY);
    expect(p).toMatchObject({
      passwordPolicies: [{ passwordScope: "SCOPE_DEVICE", passwordQuality: "COMPLEXITY_MEDIUM" }],
      maximumTimeToLock: "300000",
      minimumApiLevel: 29,
      systemUpdate: { type: "AUTOMATIC" },
      cameraAccess: "CAMERA_ACCESS_USER_CHOICE",
      advancedSecurityOverrides: { untrustedAppsPolicy: "DISALLOW_INSTALL", developerSettings: "DEVELOPER_SETTINGS_DISABLED", googlePlayProtectVerifyApps: "VERIFY_APPS_ENFORCED" },
    });
    const loose = buildAndroidPolicy({ ...DEFAULT_ANDROID_POLICY, password: "none", screenLockMinutes: 0, minAndroidVersion: 0, autoSystemUpdates: false, blockCamera: true });
    expect(loose).not.toHaveProperty("passwordPolicies");
    expect(loose).not.toHaveProperty("maximumTimeToLock");
    expect(loose).not.toHaveProperty("minimumApiLevel");
    expect(loose.cameraAccess).toBe("CAMERA_ACCESS_DISABLED");
  });
});

describe("device compliance", () => {
  const healthy = {
    name: "enterprises/LC01abcd/devices/d1",
    state: "ACTIVE",
    policyCompliant: true,
    lastStatusReportTime: "2026-10-21T08:00:00Z",
    softwareInfo: { androidVersion: "14", securityPatchLevel: "2026-09-05" },
    deviceSettings: { isEncrypted: true, isDeviceSecure: true, unknownSourcesEnabled: false, verifyAppsEnabled: true, adbEnabled: false },
    securityPosture: { devicePosture: "SECURE" },
  };

  it("a patched, locked, encrypted phone is compliant", () => {
    expect(evaluateAndroidDevice(healthy, DEFAULT_ANDROID_POLICY, NOW)).toEqual({ compliance: "compliant", findings: [] });
  });

  it("explains what is wrong", () => {
    const r = evaluateAndroidDevice(
      { ...healthy, policyCompliant: false, softwareInfo: { androidVersion: "9", securityPatchLevel: "2026-01-01" }, deviceSettings: { ...healthy.deviceSettings, isDeviceSecure: false, unknownSourcesEnabled: true }, nonComplianceDetails: [{ settingName: "passwordPolicies", nonComplianceReason: "USER_ACTION" }] },
      DEFAULT_ANDROID_POLICY,
      NOW,
    );
    expect(r.compliance).toBe("non_compliant");
    expect(r.findings.map((f) => f.key)).toEqual(["no_screen_lock", "unknown_sources", "patch_old", "os_old", "policy:passwordPolicies"]);
    expect(r.findings.find((f) => f.key === "patch_old")).toMatchObject({ severity: "high", title: "Security patch is 293 days old" });
  });

  it("rooted is at risk; silent for a week is stale; still enrolling is pending", () => {
    expect(evaluateAndroidDevice({ ...healthy, securityPosture: { devicePosture: "POTENTIALLY_COMPROMISED", postureDetails: [{ securityRisk: "COMPROMISED_OS" }] } }, DEFAULT_ANDROID_POLICY, NOW)).toMatchObject({
      compliance: "at_risk",
      findings: [{ key: "compromised", severity: "critical", detail: "COMPROMISED_OS" }],
    });
    expect(evaluateAndroidDevice({ ...healthy, lastStatusReportTime: "2026-10-01T00:00:00Z" }, DEFAULT_ANDROID_POLICY, NOW).compliance).toBe("stale");
    expect(evaluateAndroidDevice({ ...healthy, state: "PROVISIONING" }, DEFAULT_ANDROID_POLICY, NOW).compliance).toBe("pending");
  });
});
