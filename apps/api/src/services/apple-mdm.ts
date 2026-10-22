import { X509Certificate, randomBytes } from "node:crypto";
import {
  ApnsError,
  buildCommand,
  buildEnrollmentProfile,
  buildRestrictionsProfile,
  createApnsClient,
  encodeCommand,
  eraseCommand,
  evaluateAppleDevice,
  http2ApnsTransport,
  installProfileCommand,
  lockCommand,
  parseDeviceInformation,
  parsePlistDict,
  parseSecurityInfo,
  topicFromSubject,
  type ApnsTransport,
  type AppleCommand,
  type AppleDeviceInfo,
  type AppleSecurityInfo,
  type PlistValue,
} from "@bloody/adapters";
import {
  AppleMdmPolicySettings,
  DEFAULT_APPLE_MDM_POLICY,
  type AppleEnrollmentProfile,
  type AppleMdmOverview,
  type ApplePushCertificateSettings,
  type MobileCompliance,
  type MobileDevice,
  type MobileFinding,
} from "@bloody/contracts";
import { toMobileDevice } from "./android.js";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError, badRequest, notFound } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";
import type { SecretStore } from "./secret-store.js";

const iso = (v: unknown) => (v ? new Date(String(v)).toISOString() : null);
const hex = (v: PlistValue | undefined) => (v instanceof Uint8Array ? Buffer.from(v).toString("hex") : null);
const tokenFor = (tenantId: string) => `${tenantId.replace(/-/g, "")}_${randomBytes(18).toString("hex")}`;
/** The enrollment / device token carries its tenant, so device endpoints resolve it without a global read. */
export function tenantFromToken(token: string): string | null {
  const m = /^([0-9a-f]{32})_[0-9a-f]{36}$/.exec(token);
  if (!m) return null;
  const h = m[1]!;
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export const APPLE_SYNC_MINUTES = 60;
export const APPLE_VENDOR = "SCIAT AFRICA";

/** The plist body a device returns for a command; MDM status words. */
const MOBILE_COMPLIANCE_ORDER = "ARRAY['at_risk', 'non_compliant', 'stale', 'pending', 'compliant']";

interface CertFacts {
  topic: string;
  subject: string;
  expiresAt: string | null;
  expired: boolean;
}

function readCertificate(pem: string, nowMs: number): CertFacts {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(pem);
  } catch {
    throw badRequest("The certificate is not valid PEM — download the .pem from the Apple Push Certificates Portal");
  }
  const topic = topicFromSubject(cert.subject);
  if (!topic) throw badRequest("This is not an Apple MDM push certificate (no com.apple.mgmt topic in the subject)");
  const expiresAt = cert.validTo ? new Date(cert.validTo).toISOString() : null;
  return { topic, subject: cert.subject.replace(/\n/g, ", "), expiresAt, expired: expiresAt !== null && Date.parse(expiresAt) < nowMs };
}

/**
 * Apple (iOS / iPadOS) device management. SCIAT is the MDM server: devices install an enrollment
 * profile and talk to the server directly (check-in + command endpoints); Apple Push only wakes
 * them. One APNs push certificate per account; one SCIAT baseline per organization.
 *
 * Preview: the enrollment profile is unsigned and authenticates the device by a per-enrollment URL
 * secret. Production hardening (a signed profile and a SCEP device identity certificate) is layered
 * on later; the protocol below is unchanged by it.
 */
export class AppleMdmService {
  private readonly apnsTransport: (cert: string, key: string) => ApnsTransport;

  constructor(
    private readonly deps: { db: Database; secrets: SecretStore; publicUrl: string; now: () => number; apnsTransport?: (cert: string, key: string) => ApnsTransport },
  ) {
    this.apnsTransport = deps.apnsTransport ?? ((cert, key) => http2ApnsTransport({ cert, key }));
  }

  // ─── Account: APNs push certificate ───────────────────────────────────────────────────────────

  async settings(tx: Queryable): Promise<ApplePushCertificateSettings> {
    const r = (await tx.query<Row>("SELECT * FROM apple_mdm_settings")).rows[0];
    if (!r) return { configured: false, topic: null, subject: null, expiresAt: null, status: null, lastError: null, updatedAt: null };
    const expiresAt = iso(r.expires_at);
    const status = expiresAt && Date.parse(expiresAt) < this.deps.now() ? "expired" : (r.status as "ok" | "expired" | "error");
    return { configured: true, topic: String(r.topic), subject: (r.subject as string | null) ?? null, expiresAt, status, lastError: (r.last_error as string | null) ?? null, updatedAt: iso(r.updated_at) };
  }

  async saveCertificate(tenantId: string, certificatePem: string, privateKeyPem: string, actor: string): Promise<ApplePushCertificateSettings> {
    const facts = readCertificate(certificatePem, this.deps.now());
    if (facts.expired) throw badRequest("This push certificate has expired — renew it in the Apple Push Certificates Portal");
    if (!/BEGIN (RSA |EC )?PRIVATE KEY/.test(privateKeyPem)) throw badRequest("The private key is not valid PEM");
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const previous = (await tx.query<Row>("SELECT credential_ref FROM apple_mdm_settings")).rows[0]?.credential_ref as string | undefined;
      const secret = await this.deps.secrets.put(tx, tenantId, { value: JSON.stringify({ cert: certificatePem, key: privateKeyPem }), name: "Apple MDM push certificate", purpose: "apple.push_certificate", createdBy: actor });
      await tx.query(
        `INSERT INTO apple_mdm_settings (tenant_id, topic, subject, credential_ref, expires_at, status, updated_by)
         VALUES ($1, $2, $3, $4, $5, 'ok', $6)
         ON CONFLICT (tenant_id) DO UPDATE SET topic = EXCLUDED.topic, subject = EXCLUDED.subject, credential_ref = EXCLUDED.credential_ref,
           expires_at = EXCLUDED.expires_at, status = 'ok', last_error = NULL, updated_by = EXCLUDED.updated_by, updated_at = now()`,
        [tenantId, facts.topic, facts.subject, secret.ref, facts.expiresAt, actor],
      );
      if (previous && previous !== secret.ref) await this.deps.secrets.delete(tx, previous);
      return this.settings(tx);
    });
  }

  async removeCertificate(tx: Queryable): Promise<void> {
    const r = (await tx.query<Row>("DELETE FROM apple_mdm_settings RETURNING credential_ref")).rows[0];
    if (r) await this.deps.secrets.delete(tx, String(r.credential_ref));
  }

  private async apnsCredential(tenantId: string): Promise<{ cert: string; key: string; topic: string } | null> {
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const r = (await tx.query<Row>("SELECT topic, credential_ref FROM apple_mdm_settings")).rows[0];
      if (!r) return null;
      const raw = await this.deps.secrets.resolve(tx, tenantId, String(r.credential_ref));
      if (!raw) return null;
      const { cert, key } = JSON.parse(raw) as { cert: string; key: string };
      return { cert, key, topic: String(r.topic) };
    });
  }

  // ─── Policy ───────────────────────────────────────────────────────────────────────────────────

  async policy(tx: Queryable, organizationId: string): Promise<AppleMdmPolicySettings> {
    const r = (await tx.query<Row>("SELECT settings FROM apple_mdm_policies WHERE organization_id = $1", [organizationId])).rows[0];
    const parsed = r ? AppleMdmPolicySettings.safeParse(r.settings) : null;
    return parsed?.success ? parsed.data : DEFAULT_APPLE_MDM_POLICY;
  }

  async savePolicy(tenantId: string, organizationId: string, settings: AppleMdmPolicySettings): Promise<AppleMdmPolicySettings> {
    await this.deps.db.withTenant(tenantId, (tx) =>
      tx.query(
        `INSERT INTO apple_mdm_policies (tenant_id, organization_id, settings) VALUES ($1, $2, $3::jsonb)
         ON CONFLICT (tenant_id, organization_id) DO UPDATE SET settings = EXCLUDED.settings, updated_at = now()`,
        [tenantId, organizationId, JSON.stringify(settings)],
      ),
    );
    // Push the new baseline to every enrolled device and re-grade from the last known state.
    await this.pushBaselineToOrg(tenantId, organizationId);
    await this.deps.db.withTenant(tenantId, (tx) => this.reevaluate(tx, organizationId, settings));
    return settings;
  }

  // ─── Enrollment ───────────────────────────────────────────────────────────────────────────────

  private enrollUrl(t: string): string {
    return `${this.deps.publicUrl.replace(/\/+$/, "")}/api/v1/mdm/apple/enroll/${t}`;
  }

  private toEnrollment(r: Row): AppleEnrollmentProfile {
    return {
      id: String(r.id),
      organizationId: String(r.organization_id),
      token: String(r.token),
      assignee: (r.assignee as string | null) ?? null,
      ownership: r.ownership as "company" | "personal",
      enrollUrl: this.enrollUrl(String(r.token)),
      expiresAt: iso(r.expires_at)!,
      createdBy: (r.created_by as string | null) ?? null,
      createdAt: iso(r.created_at)!,
    };
  }

  async enrollments(tx: Queryable, organizationId: string): Promise<AppleEnrollmentProfile[]> {
    const { rows } = await tx.query<Row>("SELECT * FROM apple_enrollments WHERE organization_id = $1 AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC LIMIT 50", [organizationId]);
    return rows.map((r) => this.toEnrollment(r));
  }

  async createEnrollment(tenantId: string, input: { organizationId: string; ownership: "company" | "personal"; validDays: number; assignee?: string | undefined }, actor: string): Promise<AppleEnrollmentProfile> {
    const cert = await this.deps.db.withTenant(tenantId, (tx) => tx.query("SELECT 1 FROM apple_mdm_settings"));
    if ((cert.rowCount ?? 0) === 0) throw new HttpError(409, "apple_not_configured", "Upload your Apple MDM push certificate first (Mobile Devices → Apple setup)");
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(
        `INSERT INTO apple_enrollments (tenant_id, organization_id, token, ownership, assignee, expires_at, created_by)
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(days => $6), $7) RETURNING *`,
        [tenantId, input.organizationId, tokenFor(tenantId), input.ownership, input.assignee || null, input.validDays, actor],
      );
      return this.toEnrollment(rows[0]!);
    });
  }

  async revokeEnrollment(tenantId: string, id: string): Promise<{ organizationId: string }> {
    const row = await this.deps.db.withTenant(tenantId, async (tx) => (await tx.query<Row>("UPDATE apple_enrollments SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL RETURNING organization_id", [id])).rows[0]);
    if (!row) throw notFound("Enrollment profile");
    return { organizationId: String(row.organization_id) };
  }

  /** Serve the .mobileconfig for an enrollment token (public; the device downloads it). */
  async enrollmentProfile(enrollToken: string): Promise<{ xml: string; organizationName: string } | null> {
    // No tenant scope in the URL: look it up across tenants via the account directory.
    const tenantId = this.tenantForToken(enrollToken);
    if (!tenantId) return null;
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const r = (await tx.query<Row>("SELECT * FROM apple_enrollments WHERE token = $1 AND revoked_at IS NULL AND expires_at > now()", [enrollToken])).rows[0];
      if (!r) return null;
      const settings = (await tx.query<Row>("SELECT topic FROM apple_mdm_settings")).rows[0];
      if (!settings) return null;
      const org = (await tx.query<Row>("SELECT name FROM organizations WHERE id = $1", [r.organization_id])).rows[0];
      const organizationName = (org?.name as string | null) ?? "your organization";
      const xml = buildEnrollmentProfile({ baseUrl: this.deps.publicUrl, enrollToken, topic: String(settings.topic), organizationName, vendor: APPLE_VENDOR });
      return { xml, organizationName };
    });
  }

  /** Resolve which tenant an enrollment / device token belongs to (encoded in the token). */
  private tenantForToken(enrollToken: string): string | null {
    return tenantFromToken(enrollToken);
  }

  // ─── Device-facing protocol ───────────────────────────────────────────────────────────────────

  /** Check-in endpoint: Authenticate, TokenUpdate, CheckOut. Returns the plist body (or empty). */
  async handleCheckin(enrollToken: string, bodyXml: string): Promise<{ status: number; body: string | null }> {
    const tenantId = this.tenantForToken(enrollToken);
    if (!tenantId) return { status: 401, body: null };
    let msg: Record<string, PlistValue>;
    try {
      msg = parsePlistDict(bodyXml);
    } catch {
      return { status: 400, body: null };
    }
    const udid = typeof msg.UDID === "string" ? msg.UDID : null;
    if (!udid || !/^[0-9A-Za-z-]{8,64}$/.test(udid)) return { status: 400, body: null };
    const type = msg.MessageType;
    let wake = false;
    const result = await this.deps.db.withTenant(tenantId, async (tx): Promise<{ status: number; body: string | null }> => {
      const enroll = (await tx.query<Row>("SELECT id, organization_id FROM apple_enrollments WHERE token = $1", [enrollToken])).rows[0];
      if (!enroll) return { status: 401, body: null };
      const org = String(enroll.organization_id);
      if (type === "Authenticate") {
        const topicV = typeof msg.Topic === "string" ? msg.Topic : null;
        await tx.query(
          `INSERT INTO apple_devices (tenant_id, udid, organization_id, enrollment_id, topic, enrolled_at)
           VALUES ($1, $2, $3, $4, $5, now())
           ON CONFLICT (tenant_id, udid) DO UPDATE SET organization_id = EXCLUDED.organization_id, enrollment_id = EXCLUDED.enrollment_id, topic = EXCLUDED.topic, unenrolled_at = NULL`,
          [tenantId, udid, org, enroll.id, topicV],
        );
        await this.upsertIosDevice(tx, tenantId, org, udid, {}, null, "awaiting_configuration");
        return { status: 200, body: null };
      }
      if (type === "TokenUpdate") {
        const first = (await tx.query<Row>("SELECT push_token FROM apple_devices WHERE udid = $1", [udid])).rows[0];
        await tx.query(
          `UPDATE apple_devices SET push_token = coalesce($2, push_token), push_magic = coalesce($3, push_magic), topic = coalesce($4, topic),
             unlock_token = coalesce($5, unlock_token), last_seen_at = now(), unenrolled_at = NULL WHERE udid = $1`,
          [udid, hex(msg.Token), typeof msg.PushMagic === "string" ? msg.PushMagic : null, typeof msg.Topic === "string" ? msg.Topic : null, msg.UnlockToken instanceof Uint8Array ? Buffer.from(msg.UnlockToken) : null],
        );
        // First TokenUpdate completes enrollment: apply the baseline and ask the device about itself.
        if (!first?.push_token) {
          await tx.query("UPDATE mobile_devices SET state = 'enrolled' WHERE external_id = $1 AND platform = 'ios'", [udid]);
          const settings = await this.policy(tx, org);
          await this.queueCommand(tx, tenantId, udid, installProfileCommand(buildRestrictionsProfile(settings, APPLE_VENDOR).xml));
          await this.queueCommand(tx, tenantId, udid, buildCommand("DeviceInformation"));
          await this.queueCommand(tx, tenantId, udid, buildCommand("SecurityInfo"));
          wake = true;
        }
        return { status: 200, body: null };
      }
      if (type === "CheckOut") {
        await tx.query("UPDATE apple_devices SET unenrolled_at = now() WHERE udid = $1", [udid]);
        await tx.query("UPDATE mobile_devices SET removed_at = now(), state = 'unenrolled' WHERE external_id = $1 AND platform = 'ios' AND removed_at IS NULL", [udid]);
        return { status: 200, body: null };
      }
      return { status: 200, body: null };
    });
    // Wake the device so it picks up the baseline and queries right away.
    if (wake) await this.pushDevice(tenantId, udid);
    return result;
  }

  /** Command endpoint (ServerURL): the device reports status and we hand it the next command. */
  async handleConnect(enrollToken: string, bodyXml: string): Promise<{ status: number; body: string | null }> {
    const tenantId = this.tenantForToken(enrollToken);
    if (!tenantId) return { status: 401, body: null };
    let msg: Record<string, PlistValue>;
    try {
      msg = parsePlistDict(bodyXml);
    } catch {
      return { status: 400, body: null };
    }
    const udid = typeof msg.UDID === "string" ? msg.UDID : null;
    if (!udid) return { status: 400, body: null };
    const statusWord = typeof msg.Status === "string" ? msg.Status : "Idle";
    const commandUuid = typeof msg.CommandUUID === "string" ? msg.CommandUUID : null;
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const device = (await tx.query<Row>("SELECT organization_id FROM apple_devices WHERE udid = $1 AND unenrolled_at IS NULL", [udid])).rows[0];
      if (!device) return { status: 410, body: null };
      await tx.query("UPDATE apple_devices SET last_seen_at = now() WHERE udid = $1", [udid]);

      if (statusWord !== "Idle" && commandUuid) {
        await this.recordResult(tx, tenantId, String(device.organization_id), udid, commandUuid, statusWord, msg);
      }
      if (statusWord === "NotNow") return { status: 200, body: null };

      // Hand over the next queued command (oldest first).
      const next = (await tx.query<Row>("SELECT * FROM apple_commands WHERE udid = $1 AND status = 'queued' ORDER BY created_at LIMIT 1", [udid])).rows[0];
      if (!next) return { status: 200, body: null };
      await tx.query("UPDATE apple_commands SET status = 'sent', sent_at = now() WHERE id = $1", [next.id]);
      return { status: 200, body: String(next.payload) };
    });
  }

  private async recordResult(tx: Queryable, tenantId: string, organizationId: string, udid: string, commandUuid: string, statusWord: string, msg: Record<string, PlistValue>): Promise<void> {
    const cmd = (await tx.query<Row>("SELECT id, request_type FROM apple_commands WHERE command_uuid = $1 AND udid = $2", [commandUuid, udid])).rows[0];
    if (!cmd) return;
    if (statusWord === "Acknowledged") {
      await tx.query("UPDATE apple_commands SET status = 'acknowledged', result = $2::jsonb, completed_at = now() WHERE id = $1", [cmd.id, JSON.stringify({ ok: true })]);
      if (cmd.request_type === "DeviceInformation") await this.applyDeviceInformation(tx, tenantId, organizationId, udid, parseDeviceInformation(msg));
      if (cmd.request_type === "SecurityInfo") await this.applySecurityInfo(tx, organizationId, udid, parseSecurityInfo(msg));
    } else if (statusWord === "Error" || statusWord === "CommandFormatError") {
      const chain = (msg.ErrorChain as Array<{ LocalizedDescription?: string }> | undefined)?.[0]?.LocalizedDescription ?? statusWord;
      await tx.query("UPDATE apple_commands SET status = 'error', error = $2, completed_at = now() WHERE id = $1", [cmd.id, String(chain).slice(0, 1000)]);
    }
  }

  private async queueCommand(tx: Queryable, tenantId: string, udid: string, command: AppleCommand): Promise<void> {
    await tx.query(
      "INSERT INTO apple_commands (tenant_id, udid, command_uuid, request_type, payload) VALUES ($1, $2, $3, $4, $5)",
      [tenantId, udid, command.uuid, command.type, encodeCommand(command)],
    );
  }

  // ─── Device records / grading ─────────────────────────────────────────────────────────────────

  private async upsertIosDevice(tx: Queryable, tenantId: string, organizationId: string, udid: string, info: Partial<AppleDeviceInfo>, ev: { compliance: MobileCompliance; findings: MobileFinding[] } | null, state: string): Promise<void> {
    const name = (info.deviceName || info.modelName || "iPhone").slice(0, 300);
    const os = info.osVersion ? `iOS ${info.osVersion}` : "iOS";
    const asset = await tx.query<Row>(
      `INSERT INTO assets (tenant_id, organization_id, kind, name, os, criticality, source, external_source, external_ref, tags, last_seen_at)
       VALUES ($1, $2, 'mobile_device', $3, $4, 'medium', 'integration', 'apple', $5, ARRAY['mobile', 'ios'], now())
       ON CONFLICT (tenant_id, external_source, external_ref) WHERE external_ref IS NOT NULL
       DO UPDATE SET name = EXCLUDED.name, os = EXCLUDED.os, last_seen_at = now(), updated_at = now()
       RETURNING id`,
      [tenantId, organizationId, name, os, udid],
    );
    const assetId = asset.rows[0]!.id;
    // Ownership and the assignee come from the enrollment profile the device installed.
    const enroll = (await tx.query<Row>("SELECT e.ownership, e.assignee FROM apple_devices d JOIN apple_enrollments e ON e.id = d.enrollment_id WHERE d.udid = $1", [udid])).rows[0];
    const r = await tx.query<Row>(
      `INSERT INTO mobile_devices (tenant_id, organization_id, asset_id, platform, external_id, name, manufacturer, model, serial_number, os_version,
         ownership, assignee, management_mode, state, compliance, findings, enrolled_at, last_status_at, last_sync_at)
       VALUES ($1, $2, $3, 'ios', $4, $5, 'Apple', $6, $7, $8, $9, $14, 'mdm', $10, $11, $12::jsonb, now(), $13, now())
       ON CONFLICT (tenant_id, external_id) DO UPDATE SET organization_id = EXCLUDED.organization_id, asset_id = EXCLUDED.asset_id, name = EXCLUDED.name,
         model = coalesce(EXCLUDED.model, mobile_devices.model), serial_number = coalesce(EXCLUDED.serial_number, mobile_devices.serial_number),
         os_version = coalesce(EXCLUDED.os_version, mobile_devices.os_version), ownership = coalesce(EXCLUDED.ownership, mobile_devices.ownership),
         assignee = coalesce(EXCLUDED.assignee, mobile_devices.assignee), state = EXCLUDED.state,
         compliance = EXCLUDED.compliance, findings = EXCLUDED.findings, last_status_at = EXCLUDED.last_status_at, last_sync_at = now(), removed_at = NULL
       RETURNING id`,
      [
        tenantId,
        organizationId,
        assetId,
        udid,
        name,
        info.modelName ?? null,
        info.serialNumber ?? null,
        info.osVersion ?? null,
        (enroll?.ownership as string | undefined) ?? (info.supervised === true ? "company" : info.supervised === false ? "personal" : null),
        state,
        ev?.compliance ?? "pending",
        JSON.stringify(ev?.findings ?? []),
        ev ? new Date(this.deps.now()).toISOString() : null,
        (enroll?.assignee as string | null | undefined) ?? null,
      ],
    );
    await tx.query("UPDATE apple_devices SET mobile_device_id = $2 WHERE udid = $1", [udid, r.rows[0]!.id]);
  }

  private async applyDeviceInformation(tx: Queryable, tenantId: string, organizationId: string, udid: string, info: AppleDeviceInfo): Promise<void> {
    const settings = await this.policy(tx, organizationId);
    // Passcode facts arrive separately (SecurityInfo), which re-grades; here security is unknown.
    const ev = evaluateAppleDevice(info, null, settings, { lastSeenMs: this.deps.now(), nowMs: this.deps.now() });
    await this.upsertIosDevice(tx, tenantId, organizationId, udid, info, ev, "enrolled");
  }

  private async applySecurityInfo(tx: Queryable, organizationId: string, udid: string, security: AppleSecurityInfo): Promise<void> {
    // Re-grade with the new security facts against the last known device info.
    const dev = (await tx.query<Row>("SELECT os_version, model, serial_number, name, ownership FROM mobile_devices WHERE external_id = $1 AND platform = 'ios'", [udid])).rows[0];
    if (!dev) return;
    const settings = await this.policy(tx, organizationId);
    const info: AppleDeviceInfo = {
      deviceName: String(dev.name ?? ""),
      osVersion: (dev.os_version as string | null) ?? null,
      buildVersion: null,
      model: (dev.model as string | null) ?? null,
      modelName: (dev.model as string | null) ?? null,
      productName: null,
      serialNumber: (dev.serial_number as string | null) ?? null,
      supervised: dev.ownership === "company" ? true : dev.ownership === "personal" ? false : null,
      activationLockEnabled: null,
      batteryLevel: null,
    };
    const ev = evaluateAppleDevice(info, security, settings, { lastSeenMs: this.deps.now(), nowMs: this.deps.now() });
    await tx.query("UPDATE mobile_devices SET compliance = $2, findings = $3::jsonb, last_status_at = now() WHERE external_id = $1 AND platform = 'ios'", [udid, ev.compliance, JSON.stringify(ev.findings)]);
  }

  private async reevaluate(tx: Queryable, organizationId: string, settings: AppleMdmPolicySettings): Promise<void> {
    const { rows } = await tx.query<Row>("SELECT external_id, os_version, name, model, serial_number, ownership, last_status_at FROM mobile_devices WHERE organization_id = $1 AND platform = 'ios' AND removed_at IS NULL", [organizationId]);
    for (const d of rows) {
      const info: AppleDeviceInfo = {
        deviceName: String(d.name ?? ""),
        osVersion: (d.os_version as string | null) ?? null,
        buildVersion: null,
        model: (d.model as string | null) ?? null,
        modelName: (d.model as string | null) ?? null,
        productName: null,
        serialNumber: (d.serial_number as string | null) ?? null,
        supervised: d.ownership === "company" ? true : d.ownership === "personal" ? false : null,
        activationLockEnabled: null,
        batteryLevel: null,
      };
      const ev = evaluateAppleDevice(info, null, settings, { lastSeenMs: d.last_status_at ? Date.parse(String(d.last_status_at)) : null, nowMs: this.deps.now() });
      await tx.query("UPDATE mobile_devices SET compliance = $2, findings = $3::jsonb WHERE external_id = $1 AND platform = 'ios'", [d.external_id, ev.compliance, JSON.stringify(ev.findings)]);
    }
  }

  // ─── Overview / devices ───────────────────────────────────────────────────────────────────────

  async devices(tx: Queryable, organizationId: string): Promise<MobileDevice[]> {
    const { rows } = await tx.query<Row>(
      `SELECT * FROM mobile_devices WHERE organization_id = $1 AND platform = 'ios' AND removed_at IS NULL
       ORDER BY array_position(${MOBILE_COMPLIANCE_ORDER}, compliance), name`,
      [organizationId],
    );
    return rows.map(toMobileDevice);
  }

  async overview(tx: Queryable, organizationId: string): Promise<AppleMdmOverview> {
    const devices = await this.devices(tx, organizationId);
    const counts = { compliant: 0, non_compliant: 0, at_risk: 0, stale: 0, pending: 0, total: devices.length } as AppleMdmOverview["counts"];
    for (const d of devices) counts[d.compliance] += 1;
    return { organizationId, certificate: await this.settings(tx), policy: await this.policy(tx, organizationId), enrollments: await this.enrollments(tx, organizationId), devices, counts };
  }

  // ─── Push / sync ──────────────────────────────────────────────────────────────────────────────

  private async pushDevice(tenantId: string, udid: string): Promise<void> {
    const cred = await this.apnsCredential(tenantId);
    if (!cred) return;
    const d = await this.deps.db.withTenant(tenantId, async (tx) => (await tx.query<Row>("SELECT push_token, push_magic, topic FROM apple_devices WHERE udid = $1 AND unenrolled_at IS NULL", [udid])).rows[0]);
    if (!d?.push_token || !d.push_magic) return;
    const client = createApnsClient({ cert: cred.cert, key: cred.key, transport: this.apnsTransport(cred.cert, cred.key) });
    try {
      await client.push({ pushToken: String(d.push_token), pushMagic: String(d.push_magic), topic: String(d.topic ?? cred.topic) });
    } catch (err) {
      if (err instanceof ApnsError && err.deviceGone) {
        await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE apple_devices SET unenrolled_at = now() WHERE udid = $1", [udid]));
      }
      // Other push errors are transient; the scheduled sync retries.
    }
  }

  private async pushBaselineToOrg(tenantId: string, organizationId: string): Promise<void> {
    const settings = await this.deps.db.withTenant(tenantId, (tx) => this.policy(tx, organizationId));
    const profile = buildRestrictionsProfile(settings, APPLE_VENDOR);
    const udids = await this.deps.db.withTenant(tenantId, async (tx) => {
      const rows = (await tx.query<Row>("SELECT udid FROM apple_devices WHERE organization_id = $1 AND unenrolled_at IS NULL", [organizationId])).rows;
      for (const r of rows) await this.queueCommand(tx, tenantId, String(r.udid), installProfileCommand(profile.xml));
      return rows.map((r) => String(r.udid));
    });
    for (const udid of udids) await this.pushDevice(tenantId, udid);
  }

  /** Query every device for fresh info (queue DeviceInformation + SecurityInfo, then push). */
  async sync(tenantId: string, organizationId: string): Promise<{ devices: number }> {
    const udids = await this.deps.db.withTenant(tenantId, async (tx) => {
      const rows = (await tx.query<Row>("SELECT udid FROM apple_devices WHERE organization_id = $1 AND unenrolled_at IS NULL", [organizationId])).rows;
      for (const r of rows) {
        await this.queueCommand(tx, tenantId, String(r.udid), buildCommand("DeviceInformation"));
        await this.queueCommand(tx, tenantId, String(r.udid), buildCommand("SecurityInfo"));
      }
      return rows.map((r) => String(r.udid));
    });
    for (const udid of udids) await this.pushDevice(tenantId, udid);
    return { devices: udids.length };
  }

  async syncDue(tenantId: string): Promise<number> {
    const orgs = await this.deps.db.withTenant(tenantId, async (tx) =>
      (await tx.query<Row>("SELECT DISTINCT organization_id FROM apple_devices WHERE unenrolled_at IS NULL AND (last_seen_at IS NULL OR last_seen_at < now() - make_interval(mins => $1))", [APPLE_SYNC_MINUTES])).rows,
    );
    let n = 0;
    for (const r of orgs) {
      try {
        await this.sync(tenantId, String(r.organization_id));
        n++;
      } catch {
        /* transient; next tick retries */
      }
    }
    return n;
  }

  // ─── Commands run by response actions (lock_device / wipe_device) ─────────────────────────────

  async deviceForAsset(tx: Queryable, assetId: string): Promise<(MobileDevice & { udid: string }) | null> {
    const r = (await tx.query<Row>("SELECT * FROM mobile_devices WHERE asset_id = $1 AND platform = 'ios' AND removed_at IS NULL", [assetId])).rows[0];
    return r ? { ...toMobileDevice(r), udid: String(r.external_id) } : null;
  }

  async lock(tenantId: string, assetId: string): Promise<string> {
    const d = await this.requireDevice(tenantId, assetId);
    await this.deps.db.withTenant(tenantId, (tx) => this.queueCommand(tx, tenantId, d.udid, lockCommand("Locked by your IT/security team")));
    await this.pushDevice(tenantId, d.udid);
    return `Lock sent to ${d.name}; it locks as soon as it connects`;
  }

  async wipe(tenantId: string, assetId: string, _reason: string): Promise<string> {
    const d = await this.requireDevice(tenantId, assetId);
    await this.deps.db.withTenant(tenantId, (tx) => this.queueCommand(tx, tenantId, d.udid, eraseCommand()));
    await this.pushDevice(tenantId, d.udid);
    await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE mobile_devices SET state = 'erase_pending' WHERE asset_id = $1", [assetId]));
    return `Erase (factory reset) sent to ${d.name}; it wipes as soon as it connects`;
  }

  private async requireDevice(tenantId: string, assetId: string): Promise<MobileDevice & { udid: string }> {
    const d = await this.deps.db.withTenant(tenantId, (tx) => this.deviceForAsset(tx, assetId));
    if (!d) throw new HttpError(409, "not_a_managed_phone", "This asset is not an enrolled Apple device");
    return d;
  }
}
