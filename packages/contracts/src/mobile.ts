import { z } from "zod";
import { Uuid } from "./common.js";

/**
 * Mobile device management. Android through Google's Android Management API: one Google Cloud
 * service account per account (MSSP), one Android Enterprise per organization (customer). Devices
 * enroll with a QR code / token and run Google's Android Device Policy app — there is no SCIAT APK.
 */

export const ANDROID_PASSWORD_LEVELS = ["none", "low", "medium", "high"] as const;
export type AndroidPasswordLevel = (typeof ANDROID_PASSWORD_LEVELS)[number];

export const ANDROID_PASSWORD_LABELS: Record<AndroidPasswordLevel, string> = {
  none: "Not required",
  low: "Any screen lock (pattern or PIN)",
  medium: "PIN of 4+ digits without repeats, or a password",
  high: "PIN of 8+ digits, or a password of 6+ characters",
};

/** SCIAT's mobile baseline, turned into an Android Management API policy for the organization. */
export const AndroidPolicySettings = z.object({
  password: z.enum(ANDROID_PASSWORD_LEVELS),
  /** Lock the screen after this many idle minutes (0 = the user decides). */
  screenLockMinutes: z.number().int().min(0).max(60),
  blockUnknownSources: z.boolean(),
  blockDeveloperOptions: z.boolean(),
  enforcePlayProtect: z.boolean(),
  blockCamera: z.boolean(),
  blockScreenCapture: z.boolean(),
  autoSystemUpdates: z.boolean(),
  /** Lowest Android version allowed to enroll (0 = any). */
  minAndroidVersion: z.number().int().min(0).max(30),
  /** A device whose security patch is older than this is reported as non-compliant. */
  maxPatchAgeDays: z.number().int().min(7).max(730),
});
export type AndroidPolicySettings = z.infer<typeof AndroidPolicySettings>;

export const DEFAULT_ANDROID_POLICY: AndroidPolicySettings = {
  password: "medium",
  screenLockMinutes: 5,
  blockUnknownSources: true,
  blockDeveloperOptions: true,
  enforcePlayProtect: true,
  blockCamera: false,
  blockScreenCapture: false,
  autoSystemUpdates: true,
  minAndroidVersion: 10,
  maxPatchAgeDays: 90,
};

export const AndroidServiceAccountInput = z.object({
  /** The JSON key file downloaded from Google Cloud (IAM → Service accounts → Keys). */
  serviceAccountJson: z.string().min(50).max(20_000),
});

export const AndroidEnterpriseSignupInput = z.object({
  organizationId: Uuid,
  /** Optional: the customer administrator's Google account, pre-filled on Google's sign-up page. */
  adminEmail: z.string().email().max(254).optional(),
});

export const AndroidEnterpriseLinkInput = z.object({
  organizationId: Uuid,
  enterpriseName: z.string().regex(/^enterprises\/[A-Za-z0-9_-]{4,64}$/, "Expected enterprises/<id>"),
});

export const AndroidPolicyInput = z.object({ organizationId: Uuid, settings: AndroidPolicySettings });

export const MobileEnrollmentTokenInput = z.object({
  organizationId: Uuid,
  /** company: a fully managed company phone (factory reset first); personal: a work profile on the user's own phone. */
  ownership: z.enum(["company", "personal"]),
  validDays: z.number().int().min(1).max(90),
  /** Who the phone is for (shown on the device record). */
  assignee: z.string().trim().max(120).optional(),
});

export interface AndroidAccountSettings {
  configured: boolean;
  projectId: string | null;
  clientEmail: string | null;
  status: "ok" | "error" | null;
  lastError: string | null;
  updatedAt: string | null;
}

export interface AndroidEnterprise {
  id: string;
  organizationId: string;
  status: "pending_signup" | "active" | "error";
  enterpriseName: string | null;
  displayName: string | null;
  policy: AndroidPolicySettings;
  policySyncedAt: string | null;
  lastSyncAt: string | null;
  lastError: string | null;
  createdAt: string;
}

export interface MobileEnrollmentToken {
  id: string;
  ownership: "company" | "personal";
  assignee: string | null;
  /** The code typed on the phone (or "afw#setup" flows); the QR payload is `qrCode`. */
  value: string;
  qrCode: string;
  expiresAt: string;
  createdBy: string | null;
  createdAt: string;
}

export const MOBILE_COMPLIANCE = ["compliant", "non_compliant", "at_risk", "stale", "pending"] as const;
export type MobileCompliance = (typeof MOBILE_COMPLIANCE)[number];

export interface MobileFinding {
  key: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  detail: string | null;
}

export interface MobileDevice {
  id: string;
  organizationId: string;
  assetId: string | null;
  platform: "android" | "ios";
  name: string;
  manufacturer: string | null;
  model: string | null;
  serialNumber: string | null;
  osVersion: string | null;
  securityPatchLevel: string | null;
  ownership: "company" | "personal" | null;
  managementMode: string | null;
  assignee: string | null;
  userName: string | null;
  state: string;
  compliance: MobileCompliance;
  findings: MobileFinding[];
  enrolledAt: string | null;
  lastStatusAt: string | null;
  lastSyncAt: string;
}

export interface MobileOverview {
  organizationId: string;
  account: AndroidAccountSettings;
  enterprise: AndroidEnterprise | null;
  tokens: MobileEnrollmentToken[];
  devices: MobileDevice[];
  counts: Record<MobileCompliance, number> & { total: number };
}

// ─── Apple (iOS / iPadOS) MDM ─────────────────────────────────────────────────────────────────

/**
 * Apple device management. The SCIAT server is itself the MDM server: devices install an enrollment
 * profile (.mobileconfig) and talk to the server directly; Apple Push wakes them for commands.
 * The account uploads one APNs MDM push certificate (from the Apple Push Certificates Portal).
 */

export const AppleMdmPolicySettings = z.object({
  requirePasscode: z.boolean(),
  minPasscodeLength: z.number().int().min(4).max(16),
  blockCamera: z.boolean(),
  blockScreenshot: z.boolean(),
  blockAppInstall: z.boolean(),
  forceEncryptedBackup: z.boolean(),
  /** Lowest iOS/iPadOS major version allowed to be compliant (0 = any). */
  minOsVersion: z.number().int().min(0).max(30),
});
export type AppleMdmPolicySettings = z.infer<typeof AppleMdmPolicySettings>;

export const DEFAULT_APPLE_MDM_POLICY: AppleMdmPolicySettings = {
  requirePasscode: true,
  minPasscodeLength: 6,
  blockCamera: false,
  blockScreenshot: false,
  blockAppInstall: false,
  forceEncryptedBackup: true,
  minOsVersion: 16,
};

/** The MDM push certificate is uploaded as a PEM bundle (certificate + private key). */
export const ApplePushCertificateInput = z.object({
  /** PEM-encoded MDM push certificate from the Apple Push Certificates Portal. */
  certificatePem: z.string().min(50).max(50_000),
  /** PEM-encoded private key that matches the certificate. */
  privateKeyPem: z.string().min(50).max(50_000),
});

export const AppleMdmPolicyInput = z.object({ organizationId: Uuid, settings: AppleMdmPolicySettings });

export interface ApplePushCertificateSettings {
  configured: boolean;
  /** APNs topic (com.apple.mgmt.External.<uuid>) read from the certificate subject. */
  topic: string | null;
  subject: string | null;
  expiresAt: string | null;
  status: "ok" | "expired" | "error" | null;
  lastError: string | null;
  updatedAt: string | null;
}

export interface AppleEnrollmentProfile {
  id: string;
  organizationId: string;
  token: string;
  assignee: string | null;
  ownership: "company" | "personal";
  /** Where the device downloads the .mobileconfig. */
  enrollUrl: string;
  expiresAt: string;
  createdBy: string | null;
  createdAt: string;
}

export const AppleEnrollmentInput = z.object({
  organizationId: Uuid,
  ownership: z.enum(["company", "personal"]),
  validDays: z.number().int().min(1).max(90),
  assignee: z.string().trim().max(120).optional(),
});

export interface AppleMdmOverview {
  organizationId: string;
  certificate: ApplePushCertificateSettings;
  policy: AppleMdmPolicySettings;
  enrollments: AppleEnrollmentProfile[];
  devices: MobileDevice[];
  counts: Record<MobileCompliance, number> & { total: number };
}
