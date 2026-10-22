import { randomUUID } from "node:crypto";
import type { MobileCompliance, MobileFinding } from "@bloody/contracts";
import { encodePlist, type PlistValue } from "./plist.js";

/**
 * Apple MDM protocol helpers (proprietary): enrollment profile, device-facing command plists,
 * parsing of the device's DeviceInformation/SecurityInfo replies, and compliance grading.
 * The server talks to the device directly (check-in + command endpoints); APNs only wakes it.
 */

export interface AppleMdmPolicySettings {
  requirePasscode: boolean;
  minPasscodeLength: number;
  blockCamera: boolean;
  blockScreenshot: boolean;
  blockAppInstall: boolean;
  forceEncryptedBackup: boolean;
  /** Lowest iOS/iPadOS major version allowed (0 = any). */
  minOsVersion: number;
}

export const DEFAULT_APPLE_POLICY: AppleMdmPolicySettings = {
  requirePasscode: true,
  minPasscodeLength: 6,
  blockCamera: false,
  blockScreenshot: false,
  blockAppInstall: false,
  forceEncryptedBackup: true,
  minOsVersion: 16,
};

/** The MDM access rights SCIAT requests (query device, manage settings, lock/erase). */
const MDM_ACCESS_RIGHTS = 8191; // all rights

export interface EnrollmentProfileInput {
  /** Base URL of the SCIAT platform, e.g. https://soc.example.com */
  baseUrl: string;
  /** Per-enrollment secret embedded in the check-in / server URLs. */
  enrollToken: string;
  /** APNs topic from the push certificate subject (com.apple.mgmt.External.<uuid>). */
  topic: string;
  organizationName: string;
  /** Shown to the device owner on the install screen. */
  vendor: string;
}

const uuid = () => randomUUID().toUpperCase();

/** Build the .mobileconfig the device downloads to enroll (unsigned preview; see note in service). */
export function buildEnrollmentProfile(input: EnrollmentProfileInput): string {
  const base = input.baseUrl.replace(/\/+$/, "");
  const mdmPayload: Record<string, PlistValue> = {
    PayloadType: "com.apple.mdm",
    PayloadVersion: 1,
    PayloadIdentifier: `africa.sciat.mdm.${input.enrollToken}`,
    PayloadUUID: uuid(),
    PayloadDisplayName: `${input.vendor} Device Management`,
    PayloadDescription: `Lets ${input.organizationName}'s IT manage security settings on this device.`,
    ServerURL: `${base}/api/v1/mdm/apple/connect/${input.enrollToken}`,
    CheckInURL: `${base}/api/v1/mdm/apple/checkin/${input.enrollToken}`,
    Topic: input.topic,
    AccessRights: MDM_ACCESS_RIGHTS,
    CheckOutWhenRemoved: true,
    ServerCapabilities: ["com.apple.mdm.per-user-connections"],
  };
  const profile: Record<string, PlistValue> = {
    PayloadType: "Configuration",
    PayloadVersion: 1,
    PayloadIdentifier: `africa.sciat.enroll.${input.enrollToken}`,
    PayloadUUID: uuid(),
    PayloadDisplayName: `${input.vendor} Enrollment — ${input.organizationName}`,
    PayloadDescription: `Enrolls this iPhone or iPad with ${input.vendor} for ${input.organizationName}.`,
    PayloadOrganization: input.vendor,
    PayloadContent: [mdmPayload],
  };
  return encodePlist(profile);
}

/** Build the Restrictions configuration profile that enforces the organization's baseline. */
export function buildRestrictionsProfile(s: AppleMdmPolicySettings, vendor: string): { identifier: string; xml: string } {
  const identifier = "africa.sciat.baseline";
  const restrictions: Record<string, PlistValue> = {
    PayloadType: "com.apple.applicationaccess",
    PayloadVersion: 1,
    PayloadIdentifier: `${identifier}.restrictions`,
    PayloadUUID: uuid(),
    PayloadDisplayName: "Security Restrictions",
    allowCamera: !s.blockCamera,
    allowScreenShot: !s.blockScreenshot,
    allowAppInstallation: !s.blockAppInstall,
    forceEncryptedBackup: s.forceEncryptedBackup,
  };
  const content: PlistValue[] = [restrictions];
  if (s.requirePasscode) {
    content.push({
      PayloadType: "com.apple.mobiledevice.passwordpolicy",
      PayloadVersion: 1,
      PayloadIdentifier: `${identifier}.passcode`,
      PayloadUUID: uuid(),
      PayloadDisplayName: "Passcode Policy",
      forcePIN: true,
      minLength: s.minPasscodeLength,
    });
  }
  const profile: Record<string, PlistValue> = {
    PayloadType: "Configuration",
    PayloadVersion: 1,
    PayloadIdentifier: identifier,
    PayloadUUID: uuid(),
    PayloadDisplayName: `${vendor} Security Baseline`,
    PayloadContent: content,
  };
  return { identifier, xml: encodePlist(profile) };
}

// ─── Commands (server → device) ─────────────────────────────────────────────────────────────────

export type AppleCommandType = "DeviceInformation" | "SecurityInfo" | "InstallProfile" | "DeviceLock" | "EraseDevice" | "ProfileList" | "RemoveProfile";

const DEVICE_INFO_QUERIES = [
  "DeviceName",
  "OSVersion",
  "BuildVersion",
  "ModelName",
  "Model",
  "ProductName",
  "SerialNumber",
  "DeviceCapacity",
  "AvailableDeviceCapacity",
  "BatteryLevel",
  "IsSupervised",
  "IsDeviceLocatorServiceEnabled",
  "IsActivationLockEnabled",
  "EASDeviceIdentifier",
];

export interface AppleCommand {
  uuid: string;
  type: AppleCommandType;
  /** The full command plist to hand the device. */
  plist: Record<string, PlistValue>;
}

export function buildCommand(type: AppleCommandType, options: Record<string, PlistValue> = {}): AppleCommand {
  const commandUuid = uuid();
  const command: Record<string, PlistValue> = { RequestType: type, ...options };
  if (type === "DeviceInformation") command.Queries = DEVICE_INFO_QUERIES;
  return { uuid: commandUuid, type, plist: { CommandUUID: commandUuid, Command: command } };
}

/** DeviceLock with an optional 6-digit PIN (required to unlock a Mac; ignored by iPhones). */
export function lockCommand(message?: string): AppleCommand {
  return buildCommand("DeviceLock", message ? { Message: message.slice(0, 200) } : {});
}

/** EraseDevice: factory reset. PreserveDataPlan/DisallowProximitySetup keep defaults. */
export function eraseCommand(): AppleCommand {
  return buildCommand("EraseDevice", {});
}

export function installProfileCommand(profileXml: string): AppleCommand {
  return buildCommand("InstallProfile", { Payload: new Uint8Array(Buffer.from(profileXml, "utf8")) });
}

/** Serialize a command to the plist body the device expects. */
export function encodeCommand(command: AppleCommand): string {
  return encodePlist(command.plist);
}

// ─── Device replies ─────────────────────────────────────────────────────────────────────────────

export interface AppleDeviceInfo {
  deviceName: string | null;
  osVersion: string | null;
  buildVersion: string | null;
  model: string | null;
  modelName: string | null;
  productName: string | null;
  serialNumber: string | null;
  supervised: boolean | null;
  activationLockEnabled: boolean | null;
  batteryLevel: number | null;
}

const str = (v: PlistValue | undefined) => (typeof v === "string" ? v : null);
const bool = (v: PlistValue | undefined) => (typeof v === "boolean" ? v : null);
const num = (v: PlistValue | undefined) => (typeof v === "number" ? v : null);

/** Read the QueryResponses dict from a DeviceInformation reply. */
export function parseDeviceInformation(reply: Record<string, PlistValue>): AppleDeviceInfo {
  const q = (reply.QueryResponses as Record<string, PlistValue> | undefined) ?? {};
  return {
    deviceName: str(q.DeviceName),
    osVersion: str(q.OSVersion),
    buildVersion: str(q.BuildVersion),
    model: str(q.Model),
    modelName: str(q.ModelName) ?? str(q.ProductName),
    productName: str(q.ProductName),
    serialNumber: str(q.SerialNumber),
    supervised: bool(q.IsSupervised),
    activationLockEnabled: bool(q.IsActivationLockEnabled),
    batteryLevel: num(q.BatteryLevel),
  };
}

export interface AppleSecurityInfo {
  passcodePresent: boolean | null;
  passcodeCompliant: boolean | null;
  fdeEnabled: boolean | null;
  hardwareEncryptionCaps: number | null;
}

export function parseSecurityInfo(reply: Record<string, PlistValue>): AppleSecurityInfo {
  const s = (reply.SecurityInfo as Record<string, PlistValue> | undefined) ?? {};
  return {
    passcodePresent: bool(s.PasscodePresent),
    passcodeCompliant: bool(s.PasscodeCompliant),
    fdeEnabled: bool(s.FDE_Enabled),
    hardwareEncryptionCaps: num(s.HardwareEncryptionCaps),
  };
}

const osMajor = (v: string | null): number | null => {
  if (!v) return null;
  const n = Number.parseInt(v.split(".")[0] ?? "", 10);
  return Number.isFinite(n) ? n : null;
};

/** Grade a device against the organization's baseline from its latest reported info. */
export function evaluateAppleDevice(
  info: AppleDeviceInfo,
  security: AppleSecurityInfo | null,
  s: AppleMdmPolicySettings,
  opts: { lastSeenMs: number | null; nowMs: number },
): { compliance: MobileCompliance; findings: MobileFinding[] } {
  const findings: MobileFinding[] = [];
  const add = (key: string, severity: MobileFinding["severity"], title: string, detail: string | null = null) => findings.push({ key, severity, title, detail });

  if (s.requirePasscode && security && security.passcodePresent === false) add("no_passcode", "high", "No passcode set", "The device has no passcode, so its data is not protected");
  if (security && security.passcodeCompliant === false) add("passcode_weak", "medium", "Passcode does not meet the policy");
  const major = osMajor(info.osVersion);
  if (s.minOsVersion > 0 && major !== null && major < s.minOsVersion) add("os_old", "high", `iOS ${major} is below the minimum (iOS ${s.minOsVersion})`, info.osVersion);
  if (info.activationLockEnabled === true && info.supervised === false) add("activation_lock", "low", "Activation Lock is on (personal Apple ID)", "A lost or wiped device may not be reusable without the owner's Apple ID");

  const DAY = 86_400_000;
  const stale = opts.lastSeenMs !== null && opts.nowMs - opts.lastSeenMs > 7 * DAY;

  let compliance: MobileCompliance;
  if (findings.some((f) => f.severity === "high")) compliance = "non_compliant";
  else if (findings.length > 0) compliance = "non_compliant";
  else if (stale) compliance = "stale";
  else compliance = "compliant";
  if (stale && compliance !== "stale") add("stale", "low", `Has not checked in for ${Math.floor((opts.nowMs - opts.lastSeenMs!) / DAY)} days`);
  return { compliance, findings };
}
