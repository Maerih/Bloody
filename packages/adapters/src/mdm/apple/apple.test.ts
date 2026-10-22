import { describe, expect, it } from "vitest";
import { ApnsError, createApnsClient, topicFromSubject, type ApnsPush } from "./apns.js";
import {
  DEFAULT_APPLE_POLICY,
  buildCommand,
  buildEnrollmentProfile,
  buildRestrictionsProfile,
  encodeCommand,
  eraseCommand,
  evaluateAppleDevice,
  installProfileCommand,
  lockCommand,
  parseDeviceInformation,
  parseSecurityInfo,
} from "./mdm.js";
import { parsePlistDict } from "./plist.js";

const NOW = Date.parse("2026-10-21T12:00:00Z");

describe("enrollment profile", () => {
  it("points the device at the per-enrollment check-in and command URLs", () => {
    const xml = buildEnrollmentProfile({ baseUrl: "https://soc.example/", enrollToken: "tok123", topic: "com.apple.mgmt.External.abc", organizationName: "Kilimanjaro Bank", vendor: "SCIAT AFRICA" });
    const profile = parsePlistDict(xml);
    const mdm = (profile.PayloadContent as Record<string, unknown>[])[0]!;
    expect(mdm.PayloadType).toBe("com.apple.mdm");
    expect(mdm.ServerURL).toBe("https://soc.example/api/v1/mdm/apple/connect/tok123");
    expect(mdm.CheckInURL).toBe("https://soc.example/api/v1/mdm/apple/checkin/tok123");
    expect(mdm.Topic).toBe("com.apple.mgmt.External.abc");
    expect(mdm.CheckOutWhenRemoved).toBe(true);
  });
});

describe("restrictions profile", () => {
  it("turns the baseline into application-access and passcode payloads", () => {
    const { xml } = buildRestrictionsProfile({ ...DEFAULT_APPLE_POLICY, blockCamera: true, minPasscodeLength: 8 }, "SCIAT AFRICA");
    const content = parsePlistDict(xml).PayloadContent as Record<string, unknown>[];
    const access = content.find((c) => c.PayloadType === "com.apple.applicationaccess")!;
    expect(access.allowCamera).toBe(false);
    expect(access.allowScreenShot).toBe(true);
    const passcode = content.find((c) => c.PayloadType === "com.apple.mobiledevice.passwordpolicy")!;
    expect(passcode).toMatchObject({ forcePIN: true, minLength: 8 });
  });

  it("omits the passcode payload when a passcode is not required", () => {
    const { xml } = buildRestrictionsProfile({ ...DEFAULT_APPLE_POLICY, requirePasscode: false }, "SCIAT AFRICA");
    const content = parsePlistDict(xml).PayloadContent as Record<string, unknown>[];
    expect(content.some((c) => c.PayloadType === "com.apple.mobiledevice.passwordpolicy")).toBe(false);
  });
});

describe("commands", () => {
  it("builds a DeviceInformation query and a round-trippable plist", () => {
    const cmd = buildCommand("DeviceInformation");
    expect(cmd.uuid).toMatch(/^[0-9A-F-]{36}$/);
    const d = parsePlistDict(encodeCommand(cmd));
    expect(d.CommandUUID).toBe(cmd.uuid);
    const command = d.Command as Record<string, unknown>;
    expect(command.RequestType).toBe("DeviceInformation");
    expect((command.Queries as string[])).toContain("SerialNumber");
  });

  it("builds lock, erase and install-profile commands", () => {
    expect((parsePlistDict(encodeCommand(lockCommand("Lost device"))).Command as Record<string, unknown>)).toMatchObject({ RequestType: "DeviceLock", Message: "Lost device" });
    expect((parsePlistDict(encodeCommand(eraseCommand())).Command as Record<string, unknown>).RequestType).toBe("EraseDevice");
    const install = parsePlistDict(encodeCommand(installProfileCommand("<plist/>"))).Command as Record<string, unknown>;
    expect(install.RequestType).toBe("InstallProfile");
    expect(Buffer.from(install.Payload as Uint8Array).toString("utf8")).toBe("<plist/>");
  });
});

describe("device replies", () => {
  it("reads DeviceInformation and SecurityInfo query responses", () => {
    const info = parseDeviceInformation({ QueryResponses: { DeviceName: "Amina's iPhone", OSVersion: "17.6.1", ModelName: "iPhone 15", SerialNumber: "F2LABC123", IsSupervised: true, IsActivationLockEnabled: false, BatteryLevel: 0.82 } });
    expect(info).toMatchObject({ deviceName: "Amina's iPhone", osVersion: "17.6.1", modelName: "iPhone 15", supervised: true, batteryLevel: 0.82 });
    expect(parseSecurityInfo({ SecurityInfo: { PasscodePresent: true, PasscodeCompliant: true, FDE_Enabled: true } })).toMatchObject({ passcodePresent: true, passcodeCompliant: true });
  });
});

describe("compliance", () => {
  const info = { deviceName: "iPhone", osVersion: "17.6.1", buildVersion: null, model: "iPhone15,2", modelName: "iPhone 15", productName: null, serialNumber: "F2L", supervised: true, activationLockEnabled: false, batteryLevel: 0.9 };

  it("a passcode-protected, current device is compliant", () => {
    expect(evaluateAppleDevice(info, { passcodePresent: true, passcodeCompliant: true, fdeEnabled: true, hardwareEncryptionCaps: 3 }, DEFAULT_APPLE_POLICY, { lastSeenMs: NOW, nowMs: NOW })).toEqual({ compliance: "compliant", findings: [] });
  });

  it("flags a missing passcode and an old OS", () => {
    const r = evaluateAppleDevice({ ...info, osVersion: "15.7" }, { passcodePresent: false, passcodeCompliant: null, fdeEnabled: false, hardwareEncryptionCaps: 0 }, DEFAULT_APPLE_POLICY, { lastSeenMs: NOW, nowMs: NOW });
    expect(r.compliance).toBe("non_compliant");
    expect(r.findings.map((f) => f.key)).toEqual(["no_passcode", "os_old"]);
  });

  it("marks a device silent for a week as stale", () => {
    expect(evaluateAppleDevice(info, { passcodePresent: true, passcodeCompliant: true, fdeEnabled: true, hardwareEncryptionCaps: 3 }, DEFAULT_APPLE_POLICY, { lastSeenMs: NOW - 9 * 86_400_000, nowMs: NOW }).compliance).toBe("stale");
  });
});

describe("APNs client", () => {
  it("pushes the PushMagic to the device token and reports a dead token", async () => {
    const sent: ApnsPush[] = [];
    const client = createApnsClient({ cert: "", key: "", transport: async (p) => void sent.push(p) });
    await client.push({ pushToken: "aabbccdd", pushMagic: "MAGIC-1", topic: "com.apple.mgmt.External.abc" });
    expect(sent).toEqual([{ pushToken: "aabbccdd", pushMagic: "MAGIC-1", topic: "com.apple.mgmt.External.abc" }]);
    await expect(client.push({ pushToken: "not hex!", pushMagic: "m", topic: "com.apple.mgmt.External.abc" })).rejects.toThrow(ApnsError);

    const gone = createApnsClient({ cert: "", key: "", transport: async () => { throw new ApnsError(410, "Unregistered"); } });
    const err = await gone.push({ pushToken: "aabbccdd", pushMagic: "m", topic: "com.apple.mgmt.External.abc" }).catch((e: unknown) => e);
    expect((err as ApnsError).deviceGone).toBe(true);
  });

  it("reads the topic from the push certificate subject", () => {
    expect(topicFromSubject("UID=com.apple.mgmt.External.12345, CN=APSP:abc, C=US")).toBe("com.apple.mgmt.External.12345");
    expect(topicFromSubject("CN=example, C=US")).toBeNull();
  });
});
