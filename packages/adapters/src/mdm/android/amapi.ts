import { createSign } from "node:crypto";

/**
 * Minimal Android Management API client (proprietary).
 * Signs in with a Google Cloud service account (OAuth 2.0 JWT bearer grant, RS256) and only ever
 * contacts the fixed Google endpoints below — the token URI inside the key file is ignored, and
 * paging stays on the same collection.
 */

export const AMAPI_BASE = "https://androidmanagement.googleapis.com/v1";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const SCOPE = "https://www.googleapis.com/auth/androidmanagement";

export class AmapiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
  get isPermission(): boolean {
    return this.status === 401 || this.status === 403;
  }
}

export interface ServiceAccountKey {
  projectId: string;
  clientEmail: string;
  privateKey: string;
}

const PROJECT_RE = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const EMAIL_RE = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.iam\.gserviceaccount\.com$/i;
const ENTERPRISE_RE = /^enterprises\/[A-Za-z0-9_-]{4,64}$/;
const CHILD_RE = /^enterprises\/[A-Za-z0-9_-]{4,64}\/(devices|enrollmentTokens|policies)\/[A-Za-z0-9_-]{1,128}$/;

/** Parse and check a Google Cloud service account JSON key file. Throws a readable error. */
export function parseServiceAccountKey(json: string): ServiceAccountKey {
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(json) as Record<string, unknown>;
  } catch {
    throw new AmapiError(400, "invalid_key", "The key file is not valid JSON — upload the .json key downloaded from Google Cloud");
  }
  if (raw.type !== "service_account") throw new AmapiError(400, "invalid_key", 'The key file is not a service account key (expected "type": "service_account")');
  const projectId = String(raw.project_id ?? "");
  const clientEmail = String(raw.client_email ?? "");
  const privateKey = String(raw.private_key ?? "");
  if (!PROJECT_RE.test(projectId)) throw new AmapiError(400, "invalid_key", "The key file has no valid project_id");
  if (!EMAIL_RE.test(clientEmail)) throw new AmapiError(400, "invalid_key", "The key file has no valid service account client_email");
  if (!privateKey.includes("BEGIN PRIVATE KEY")) throw new AmapiError(400, "invalid_key", "The key file has no private_key");
  return { projectId, clientEmail, privateKey };
}

const b64url = (v: Buffer | string) => Buffer.from(v).toString("base64url");

/** RS256-signed JWT assertion for the OAuth 2.0 JWT bearer grant. */
export function serviceAccountAssertion(key: ServiceAccountKey, nowMs: number): string {
  const iat = Math.floor(nowMs / 1000);
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = b64url(JSON.stringify({ iss: key.clientEmail, scope: SCOPE, aud: TOKEN_URL, iat, exp: iat + 3600 }));
  let signature: Buffer;
  try {
    signature = createSign("RSA-SHA256").update(`${header}.${claims}`).sign(key.privateKey);
  } catch {
    throw new AmapiError(400, "invalid_key", "The private key in the key file could not be used to sign");
  }
  return `${header}.${claims}.${b64url(signature)}`;
}

// ─── Resource shapes (the fields SCIAT reads) ───────────────────────────────────────────────────

export interface AmapiEnterprise {
  name: string;
  enterpriseDisplayName?: string;
}

export interface AmapiEnrollmentToken {
  name: string;
  value: string;
  qrCode?: string;
  expirationTimestamp?: string;
  policyName?: string;
}

export interface AmapiDevice {
  name: string;
  userName?: string;
  managementMode?: "DEVICE_OWNER" | "PROFILE_OWNER" | string;
  ownership?: "COMPANY_OWNED" | "PERSONALLY_OWNED" | string;
  state?: string;
  appliedState?: string;
  policyCompliant?: boolean;
  nonComplianceDetails?: Array<{ settingName?: string; nonComplianceReason?: string }>;
  enrollmentTime?: string;
  lastStatusReportTime?: string;
  enrollmentTokenData?: string;
  hardwareInfo?: { brand?: string; manufacturer?: string; model?: string; serialNumber?: string };
  softwareInfo?: { androidVersion?: string; securityPatchLevel?: string; androidBuildNumber?: string };
  deviceSettings?: {
    isDeviceSecure?: boolean;
    unknownSourcesEnabled?: boolean;
    developmentSettingsEnabled?: boolean;
    adbEnabled?: boolean;
    isEncrypted?: boolean;
    verifyAppsEnabled?: boolean;
  };
  securityPosture?: { devicePosture?: string; postureDetails?: Array<{ securityRisk?: string }> };
  networkInfo?: { imei?: string };
}

export type AmapiCommand = "LOCK" | "REBOOT" | "START_LOST_MODE" | "STOP_LOST_MODE";

export interface AmapiClientOptions {
  key: ServiceAccountKey;
  fetch?: typeof fetch;
  now?: () => number;
  timeoutMs?: number;
}

export interface AmapiClient {
  readonly projectId: string;
  /** Check the credentials work (gets an access token). */
  verify(): Promise<void>;
  createSignupUrl(callbackUrl: string, adminEmail?: string): Promise<{ name: string; url: string }>;
  createEnterprise(signupUrlName: string, enterpriseToken: string): Promise<AmapiEnterprise>;
  getEnterprise(name: string): Promise<AmapiEnterprise>;
  patchPolicy(enterprise: string, policyId: string, policy: Record<string, unknown>): Promise<void>;
  createEnrollmentToken(enterprise: string, body: { policyName: string; duration: string; allowPersonalUsage: string; additionalData?: string; oneTimeOnly?: boolean }): Promise<AmapiEnrollmentToken>;
  deleteEnrollmentToken(name: string): Promise<void>;
  listDevices(enterprise: string, max?: number): Promise<AmapiDevice[]>;
  issueCommand(device: string, type: AmapiCommand): Promise<{ name?: string }>;
  /** Factory reset a company phone, or remove the work profile from a personal one. */
  wipeDevice(device: string, reason: string): Promise<void>;
}

export function createAmapiClient(opts: AmapiClientOptions): AmapiClient {
  const doFetch = opts.fetch ?? fetch;
  const now = opts.now ?? Date.now;
  const timeoutMs = opts.timeoutMs ?? 20_000;
  let token: { value: string; expiresAt: number } | null = null;

  const timed = async (url: string, init: RequestInit): Promise<Response> => {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      return await doFetch(url, { ...init, signal: ctl.signal, redirect: "error" });
    } finally {
      clearTimeout(t);
    }
  };

  const accessToken = async (): Promise<string> => {
    if (token && token.expiresAt - 60_000 > now()) return token.value;
    const body = new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: serviceAccountAssertion(opts.key, now()) });
    const res = await timed(TOKEN_URL, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: body.toString() });
    const json = (await res.json().catch(() => ({}))) as { access_token?: string; expires_in?: number; error?: string; error_description?: string };
    if (!res.ok || !json.access_token) {
      throw new AmapiError(401, json.error ?? "token_failed", `Sign-in to Google failed: ${json.error ?? res.status}${json.error_description ? ` — ${json.error_description}` : ""}`);
    }
    token = { value: json.access_token, expiresAt: now() + (json.expires_in ?? 3600) * 1000 };
    return token.value;
  };

  const call = async <T>(method: string, path: string, query: Record<string, string> = {}, body?: unknown): Promise<T> => {
    const qs = new URLSearchParams(query).toString();
    const res = await timed(`${AMAPI_BASE}/${path}${qs ? `?${qs}` : ""}`, {
      method,
      headers: { authorization: `Bearer ${await accessToken()}`, accept: "application/json", ...(body === undefined ? {} : { "content-type": "application/json" }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!res.ok) {
      const json = (await res.json().catch(() => ({}))) as { error?: { status?: string; message?: string } };
      throw new AmapiError(res.status, json.error?.status ?? `http_${res.status}`, `Android Management API: ${json.error?.message ?? `HTTP ${res.status}`}`);
    }
    const text = await res.text();
    return (text ? JSON.parse(text) : {}) as T;
  };

  const enterprise = (name: string) => {
    if (!ENTERPRISE_RE.test(name)) throw new AmapiError(400, "invalid_name", "Invalid enterprise name");
    return name;
  };
  const child = (name: string) => {
    if (!CHILD_RE.test(name)) throw new AmapiError(400, "invalid_name", "Invalid Android Management resource name");
    return name;
  };

  return {
    projectId: opts.key.projectId,
    async verify() {
      await accessToken();
    },
    createSignupUrl: async (callbackUrl, adminEmail) =>
      call("POST", "signupUrls", { projectId: opts.key.projectId, callbackUrl, ...(adminEmail ? { adminEmail } : {}) }),
    createEnterprise: async (signupUrlName, enterpriseToken) => {
      if (!/^signupUrls\/[A-Za-z0-9_-]{4,128}$/.test(signupUrlName)) throw new AmapiError(400, "invalid_name", "Invalid sign-up URL name");
      return call("POST", "enterprises", { projectId: opts.key.projectId, signupUrlName, enterpriseToken }, {});
    },
    getEnterprise: async (name) => call("GET", enterprise(name)),
    async patchPolicy(e, policyId, policy) {
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(policyId)) throw new AmapiError(400, "invalid_name", "Invalid policy id");
      await call("PATCH", `${enterprise(e)}/policies/${policyId}`, {}, policy);
    },
    createEnrollmentToken: async (e, body) => call("POST", `${enterprise(e)}/enrollmentTokens`, {}, body),
    async deleteEnrollmentToken(name) {
      await call("DELETE", child(name));
    },
    async listDevices(e, max = 10_000) {
      const out: AmapiDevice[] = [];
      let pageToken: string | undefined;
      do {
        const page: { devices?: AmapiDevice[]; nextPageToken?: string } = await call("GET", `${enterprise(e)}/devices`, { pageSize: "100", ...(pageToken ? { pageToken } : {}) });
        out.push(...(page.devices ?? []));
        pageToken = page.nextPageToken;
      } while (pageToken && out.length < max);
      return out.slice(0, max);
    },
    issueCommand: async (device, type) => call("POST", `${child(device)}:issueCommand`, {}, { type }),
    async wipeDevice(device, reason) {
      await call("DELETE", child(device), { wipeReasonMessage: reason.slice(0, 200) });
    },
  };
}
