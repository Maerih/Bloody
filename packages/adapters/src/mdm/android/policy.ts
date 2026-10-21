import type { AndroidPolicySettings, MobileCompliance, MobileFinding } from "@bloody/contracts";
import type { AmapiDevice } from "./amapi.js";

/** The single policy SCIAT manages in each organization's Android Enterprise. */
export const SCIAT_POLICY_ID = "sciat-baseline";

/** Android version → API level (minimumApiLevel). */
const API_LEVEL: Record<number, number> = { 8: 26, 9: 28, 10: 29, 11: 30, 12: 31, 13: 33, 14: 34, 15: 35, 16: 36 };

/** SCIAT baseline settings → Android Management API Policy resource. */
export function buildAndroidPolicy(s: AndroidPolicySettings): Record<string, unknown> {
  const policy: Record<string, unknown> = {
    // Everything SCIAT evaluates compliance from.
    statusReportingSettings: {
      softwareInfoEnabled: true,
      hardwareStatusEnabled: true,
      deviceSettingsEnabled: true,
      networkInfoEnabled: true,
      applicationReportsEnabled: true,
    },
    advancedSecurityOverrides: {
      untrustedAppsPolicy: s.blockUnknownSources ? "DISALLOW_INSTALL" : "ALLOW_INSTALL_DEVICE_WIDE",
      developerSettings: s.blockDeveloperOptions ? "DEVELOPER_SETTINGS_DISABLED" : "DEVELOPER_SETTINGS_ALLOWED",
      googlePlayProtectVerifyApps: s.enforcePlayProtect ? "VERIFY_APPS_ENFORCED" : "VERIFY_APPS_USER_CHOICE",
    },
    cameraAccess: s.blockCamera ? "CAMERA_ACCESS_DISABLED" : "CAMERA_ACCESS_USER_CHOICE",
    screenCaptureDisabled: s.blockScreenCapture,
  };
  if (s.password !== "none") {
    policy.passwordPolicies = [{ passwordScope: "SCOPE_DEVICE", passwordQuality: `COMPLEXITY_${s.password.toUpperCase()}` }];
  }
  if (s.screenLockMinutes > 0) policy.maximumTimeToLock = String(s.screenLockMinutes * 60_000);
  if (s.autoSystemUpdates) policy.systemUpdate = { type: "AUTOMATIC" };
  const level = API_LEVEL[s.minAndroidVersion];
  if (level) policy.minimumApiLevel = level;
  return policy;
}

const DAY = 86_400_000;
/** A device that has not reported for this long is "stale" (lost, off, or the app was removed). */
export const MOBILE_STALE_DAYS = 7;

const NONCOMPLIANCE_TITLES: Record<string, string> = {
  passwordPolicies: "Screen lock does not meet the password policy",
  maximumTimeToLock: "Screen lock timeout too long",
  minimumApiLevel: "Android version below the minimum",
  advancedSecurityOverrides: "Security settings not applied",
};

/** Evaluate one device against the organization's settings: compliance state plus findings. */
export function evaluateAndroidDevice(d: AmapiDevice, s: AndroidPolicySettings, nowMs: number): { compliance: MobileCompliance; findings: MobileFinding[] } {
  const findings: MobileFinding[] = [];
  const add = (key: string, severity: MobileFinding["severity"], title: string, detail: string | null = null) => findings.push({ key, severity, title, detail });

  if (d.state === "PROVISIONING") return { compliance: "pending", findings };
  const posture = d.securityPosture?.devicePosture;
  if (posture === "POTENTIALLY_COMPROMISED") {
    const risks = (d.securityPosture?.postureDetails ?? []).map((p) => p.securityRisk).filter(Boolean);
    add("compromised", "critical", "Device may be compromised (rooted or modified Android)", risks.join(", ") || null);
  } else if (posture === "AT_RISK") {
    add("at_risk", "high", "Google reports this device at risk", (d.securityPosture?.postureDetails ?? []).map((p) => p.securityRisk).filter(Boolean).join(", ") || null);
  }
  const ds = d.deviceSettings ?? {};
  if (ds.isEncrypted === false) add("not_encrypted", "high", "Storage is not encrypted");
  if (ds.isDeviceSecure === false) add("no_screen_lock", "high", "No screen lock (PIN, pattern or password)");
  if (ds.unknownSourcesEnabled) add("unknown_sources", "medium", "Apps can be installed from unknown sources");
  if (ds.verifyAppsEnabled === false) add("play_protect_off", "medium", "Google Play Protect is turned off");
  if (ds.adbEnabled || ds.developmentSettingsEnabled) add("developer_options", "low", "Developer options or USB debugging are on");

  const patch = d.softwareInfo?.securityPatchLevel;
  if (patch) {
    const age = Math.floor((nowMs - Date.parse(patch)) / DAY);
    if (Number.isFinite(age) && age > s.maxPatchAgeDays) add("patch_old", age > s.maxPatchAgeDays * 2 ? "high" : "medium", `Security patch is ${age} days old`, `Patch level ${patch}; the limit is ${s.maxPatchAgeDays} days`);
  }
  const major = Number.parseInt(d.softwareInfo?.androidVersion ?? "", 10);
  if (s.minAndroidVersion > 0 && Number.isFinite(major) && major < s.minAndroidVersion) add("os_old", "high", `Android ${major} is below the minimum (Android ${s.minAndroidVersion})`);

  for (const n of d.nonComplianceDetails ?? []) {
    const setting = n.settingName ?? "policy";
    if (findings.some((f) => f.key === `policy:${setting}`)) continue;
    add(`policy:${setting}`, "medium", NONCOMPLIANCE_TITLES[setting] ?? `Policy setting not applied: ${setting}`, n.nonComplianceReason ?? null);
  }

  const last = d.lastStatusReportTime ? Date.parse(d.lastStatusReportTime) : NaN;
  const stale = Number.isFinite(last) && nowMs - last > MOBILE_STALE_DAYS * DAY;
  let compliance: MobileCompliance;
  if (findings.some((f) => f.severity === "critical") || posture === "AT_RISK") compliance = "at_risk";
  else if (findings.length > 0 || d.policyCompliant === false) compliance = "non_compliant";
  else if (stale) compliance = "stale";
  else compliance = "compliant";
  if (stale && compliance !== "stale") add("stale", "low", `Has not reported for ${Math.floor((nowMs - last) / DAY)} days`);
  return { compliance, findings };
}
