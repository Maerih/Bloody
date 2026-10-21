import { createHash, randomBytes, randomUUID } from "node:crypto";
import { AmapiError, SCIAT_POLICY_ID, buildAndroidPolicy, createAmapiClient, evaluateAndroidDevice, parseServiceAccountKey, type AmapiClient, type AmapiDevice } from "@bloody/adapters";
import {
  AndroidPolicySettings,
  DEFAULT_ANDROID_POLICY,
  MOBILE_COMPLIANCE,
  type AndroidAccountSettings,
  type AndroidEnterprise,
  type MobileDevice,
  type MobileEnrollmentToken,
  type MobileFinding,
  type MobileOverview,
} from "@bloody/contracts";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError, badRequest, notFound } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";
import type { SecretStore } from "./secret-store.js";

const iso = (v: unknown) => (v ? new Date(String(v)).toISOString() : null);
const sha256 = (v: string) => createHash("sha256").update(v).digest("hex");
/** Devices are re-read from Google this often (and on demand). */
export const ANDROID_SYNC_MINUTES = 30;
const SIGNUP_TTL_MINUTES = 60;

function toEnterprise(r: Row): AndroidEnterprise {
  const parsed = AndroidPolicySettings.safeParse(r.policy);
  return {
    id: String(r.id),
    organizationId: String(r.organization_id),
    status: r.status as AndroidEnterprise["status"],
    enterpriseName: (r.enterprise_name as string | null) ?? null,
    displayName: (r.display_name as string | null) ?? null,
    policy: parsed.success ? parsed.data : DEFAULT_ANDROID_POLICY,
    policySyncedAt: iso(r.policy_synced_at),
    lastSyncAt: iso(r.last_sync_at),
    lastError: (r.last_error as string | null) ?? null,
    createdAt: iso(r.created_at)!,
  };
}

function toToken(r: Row): MobileEnrollmentToken {
  return {
    id: String(r.id),
    ownership: r.ownership as MobileEnrollmentToken["ownership"],
    assignee: (r.assignee as string | null) ?? null,
    value: String(r.value),
    qrCode: String(r.qr_code),
    expiresAt: iso(r.expires_at)!,
    createdBy: (r.created_by as string | null) ?? null,
    createdAt: iso(r.created_at)!,
  };
}

export function toMobileDevice(r: Row): MobileDevice {
  return {
    id: String(r.id),
    organizationId: String(r.organization_id),
    assetId: (r.asset_id as string | null) ?? null,
    platform: r.platform as MobileDevice["platform"],
    name: String(r.name),
    manufacturer: (r.manufacturer as string | null) ?? null,
    model: (r.model as string | null) ?? null,
    serialNumber: (r.serial_number as string | null) ?? null,
    osVersion: (r.os_version as string | null) ?? null,
    securityPatchLevel: (r.security_patch_level as string | null) ?? null,
    ownership: (r.ownership as MobileDevice["ownership"]) ?? null,
    managementMode: (r.management_mode as string | null) ?? null,
    assignee: (r.assignee as string | null) ?? null,
    userName: (r.user_name as string | null) ?? null,
    state: String(r.state),
    compliance: r.compliance as MobileDevice["compliance"],
    findings: (r.findings as MobileFinding[]) ?? [],
    enrolledAt: iso(r.enrolled_at),
    lastStatusAt: iso(r.last_status_at),
    lastSyncAt: iso(r.last_sync_at)!,
  };
}

/** Google's message, or a readable one, for an error from the Android Management API. */
function googleError(err: unknown): HttpError {
  if (err instanceof HttpError) return err;
  const message = err instanceof Error ? err.message : String(err);
  if (err instanceof AmapiError) return new HttpError(err.status === 400 ? 400 : err.isPermission ? 400 : 502, "android_api_error", message);
  return new HttpError(502, "android_api_error", message);
}

/**
 * Android Enterprise management through Google's Android Management API.
 * The account's Google Cloud service account is the only credential; each organization gets its own
 * Android Enterprise (created through Google's sign-up flow, or linked), SCIAT's baseline policy,
 * enrollment QR codes and the devices — mirrored into inventory as `mobile_device` assets.
 */
export class AndroidService {
  constructor(
    private readonly deps: { db: Database; secrets: SecretStore; fetch: typeof fetch; publicUrl: string; now: () => number },
  ) {}

  // ─── Account: Google Cloud service account ────────────────────────────────────────────────────

  async settings(tx: Queryable): Promise<AndroidAccountSettings> {
    const r = (await tx.query<Row>("SELECT * FROM android_settings")).rows[0];
    if (!r) return { configured: false, projectId: null, clientEmail: null, status: null, lastError: null, updatedAt: null };
    return { configured: true, projectId: String(r.project_id), clientEmail: String(r.client_email), status: r.status as "ok" | "error", lastError: (r.last_error as string | null) ?? null, updatedAt: iso(r.updated_at) };
  }

  /** Check the key signs in to Google, then store it sealed (replacing any previous key). */
  async saveServiceAccount(tenantId: string, json: string, actor: string): Promise<AndroidAccountSettings> {
    let key;
    try {
      key = parseServiceAccountKey(json);
      await createAmapiClient({ key, fetch: this.deps.fetch, now: this.deps.now }).verify();
    } catch (err) {
      throw googleError(err);
    }
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const previous = (await tx.query<Row>("SELECT credential_ref FROM android_settings")).rows[0]?.credential_ref as string | undefined;
      const secret = await this.deps.secrets.put(tx, tenantId, { value: json, name: "Google service account (Android Management)", purpose: "android.service_account", createdBy: actor });
      await tx.query(
        `INSERT INTO android_settings (tenant_id, project_id, client_email, credential_ref, status, updated_by)
         VALUES ($1, $2, $3, $4, 'ok', $5)
         ON CONFLICT (tenant_id) DO UPDATE SET project_id = EXCLUDED.project_id, client_email = EXCLUDED.client_email, credential_ref = EXCLUDED.credential_ref,
           status = 'ok', last_error = NULL, updated_by = EXCLUDED.updated_by, updated_at = now()`,
        [tenantId, key.projectId, key.clientEmail, secret.ref, actor],
      );
      if (previous && previous !== secret.ref) await this.deps.secrets.delete(tx, previous);
      return this.settings(tx);
    });
  }

  async removeServiceAccount(tx: Queryable): Promise<void> {
    const r = (await tx.query<Row>("DELETE FROM android_settings RETURNING credential_ref")).rows[0];
    if (r) await this.deps.secrets.delete(tx, String(r.credential_ref));
  }

  private async client(tenantId: string): Promise<AmapiClient> {
    const json = await this.deps.db.withTenant(tenantId, async (tx) => {
      const r = (await tx.query<Row>("SELECT credential_ref FROM android_settings")).rows[0];
      if (!r) throw new HttpError(409, "android_not_configured", "Connect your Google Cloud service account first (Mobile Devices → Google account)");
      return this.deps.secrets.resolve(tx, tenantId, String(r.credential_ref));
    });
    if (!json) throw new HttpError(409, "credential_missing", "The Google service account key is missing — upload it again");
    return createAmapiClient({ key: parseServiceAccountKey(json), fetch: this.deps.fetch, now: this.deps.now });
  }

  // ─── Organization: Android Enterprise ─────────────────────────────────────────────────────────

  async enterprise(tx: Queryable, organizationId: string): Promise<AndroidEnterprise | null> {
    const r = (await tx.query<Row>("SELECT * FROM android_enterprises WHERE organization_id = $1", [organizationId])).rows[0];
    return r ? toEnterprise(r) : null;
  }

  private async activeEnterprise(tx: Queryable, organizationId: string): Promise<{ id: string; name: string; policy: AndroidPolicySettings }> {
    const e = await this.enterprise(tx, organizationId);
    if (!e || e.status !== "active" || !e.enterpriseName) throw new HttpError(409, "android_enterprise_missing", "This organization has no Android Enterprise yet — create one first");
    return { id: e.id, name: e.enterpriseName, policy: e.policy };
  }

  /** Google's sign-up page for the customer's Android Enterprise; Google returns to our callback. */
  async startSignup(tenantId: string, organizationId: string, actor: string, adminEmail?: string): Promise<{ url: string }> {
    const existing = await this.deps.db.withTenant(tenantId, (tx) => this.enterprise(tx, organizationId));
    if (existing?.status === "active") throw new HttpError(409, "android_enterprise_exists", "This organization already has an Android Enterprise");
    const client = await this.client(tenantId);
    const state = `${tenantId}.${randomBytes(24).toString("base64url")}`;
    const callback = `${this.deps.publicUrl.replace(/\/+$/, "")}/api/v1/mobile/android/signup-callback?state=${encodeURIComponent(state)}`;
    let signup;
    try {
      signup = await client.createSignupUrl(callback, adminEmail);
    } catch (err) {
      throw googleError(err);
    }
    await this.deps.db.withTenant(tenantId, (tx) =>
      tx.query(
        `INSERT INTO android_enterprises (tenant_id, organization_id, status, signup_url_name, signup_state_hash, signup_expires_at, policy, created_by)
         VALUES ($1, $2, 'pending_signup', $3, $4, now() + make_interval(mins => $5), $6::jsonb, $7)
         ON CONFLICT (organization_id) DO UPDATE SET status = 'pending_signup', signup_url_name = EXCLUDED.signup_url_name,
           signup_state_hash = EXCLUDED.signup_state_hash, signup_expires_at = EXCLUDED.signup_expires_at, last_error = NULL`,
        [tenantId, organizationId, signup.name, sha256(state), SIGNUP_TTL_MINUTES, JSON.stringify(DEFAULT_ANDROID_POLICY), actor],
      ),
    );
    return { url: signup.url };
  }

  /** Google redirected back after sign-up: create the enterprise and apply the baseline policy. */
  async completeSignup(state: string, enterpriseToken: string): Promise<{ tenantId: string; organizationId: string }> {
    const tenantId = state.split(".")[0] ?? "";
    if (!/^[0-9a-f-]{36}$/i.test(tenantId)) throw badRequest("Invalid sign-up state");
    const row = await this.deps.db.withTenant(tenantId, async (tx) =>
      (await tx.query<Row>("SELECT * FROM android_enterprises WHERE signup_state_hash = $1 AND status = 'pending_signup' AND signup_expires_at > now()", [sha256(state)])).rows[0],
    );
    if (!row) throw badRequest("This sign-up link has expired or was already used — start again from Mobile Devices");
    const organizationId = String(row.organization_id);
    const client = await this.client(tenantId);
    try {
      const e = await client.createEnterprise(String(row.signup_url_name), enterpriseToken);
      await this.activate(tenantId, organizationId, e.name, e.enterpriseDisplayName ?? null);
    } catch (err) {
      const message = (err instanceof Error ? err.message : String(err)).slice(0, 1000);
      await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE android_enterprises SET status = 'error', last_error = $2, signup_state_hash = NULL WHERE id = $1", [row.id, message]));
      throw googleError(err);
    }
    await this.pushPolicy(tenantId, organizationId).catch(() => undefined); // recorded on the enterprise
    return { tenantId, organizationId };
  }

  /** Bind an Android Enterprise that already exists under the account's Google Cloud project. */
  async link(tenantId: string, organizationId: string, enterpriseName: string, actor: string): Promise<AndroidEnterprise> {
    const client = await this.client(tenantId);
    let e;
    try {
      e = await client.getEnterprise(enterpriseName);
    } catch (err) {
      throw googleError(err);
    }
    const taken = await this.deps.db.withTenant(tenantId, async (tx) => (await tx.query<Row>("SELECT organization_id FROM android_enterprises WHERE enterprise_name = $1", [e.name])).rows[0]);
    if (taken && String(taken.organization_id) !== organizationId) throw new HttpError(409, "android_enterprise_in_use", "That Android Enterprise is already linked to another organization");
    await this.deps.db.withTenant(tenantId, (tx) =>
      tx.query(
        `INSERT INTO android_enterprises (tenant_id, organization_id, status, policy, created_by) VALUES ($1, $2, 'pending_signup', $3::jsonb, $4)
         ON CONFLICT (organization_id) DO NOTHING`,
        [tenantId, organizationId, JSON.stringify(DEFAULT_ANDROID_POLICY), actor],
      ),
    );
    await this.activate(tenantId, organizationId, e.name, e.enterpriseDisplayName ?? null);
    await this.pushPolicy(tenantId, organizationId).catch(() => undefined);
    return this.deps.db.withTenant(tenantId, async (tx) => (await this.enterprise(tx, organizationId))!);
  }

  private async activate(tenantId: string, organizationId: string, name: string, displayName: string | null): Promise<void> {
    await this.deps.db.withTenant(tenantId, (tx) =>
      tx.query(
        `UPDATE android_enterprises SET status = 'active', enterprise_name = $2, display_name = $3, signup_url_name = NULL, signup_state_hash = NULL, signup_expires_at = NULL, last_error = NULL
         WHERE organization_id = $1`,
        [organizationId, name, displayName],
      ),
    );
  }

  /** Forget the organization's enterprise here (it stays in Google; devices stay enrolled there). */
  async unlink(tx: Queryable, organizationId: string): Promise<AndroidEnterprise> {
    const r = (await tx.query<Row>("DELETE FROM android_enterprises WHERE organization_id = $1 RETURNING *", [organizationId])).rows[0];
    if (!r) throw notFound("Android Enterprise");
    await tx.query("UPDATE mobile_devices SET removed_at = now() WHERE organization_id = $1 AND platform = 'android' AND removed_at IS NULL", [organizationId]);
    return toEnterprise(r);
  }

  // ─── Policy ───────────────────────────────────────────────────────────────────────────────────

  async savePolicy(tenantId: string, organizationId: string, settings: AndroidPolicySettings): Promise<AndroidEnterprise> {
    await this.deps.db.withTenant(tenantId, async (tx) => {
      await this.activeEnterprise(tx, organizationId);
      await tx.query("UPDATE android_enterprises SET policy = $2::jsonb WHERE organization_id = $1", [organizationId, JSON.stringify(settings)]);
    });
    await this.pushPolicy(tenantId, organizationId);
    // Compliance limits (patch age, Android version) apply at once to the last known state.
    await this.deps.db.withTenant(tenantId, (tx) => this.reevaluate(tx, organizationId, settings));
    return this.deps.db.withTenant(tenantId, async (tx) => (await this.enterprise(tx, organizationId))!);
  }

  private async pushPolicy(tenantId: string, organizationId: string): Promise<void> {
    const e = await this.deps.db.withTenant(tenantId, (tx) => this.activeEnterprise(tx, organizationId));
    const client = await this.client(tenantId);
    try {
      await client.patchPolicy(e.name, SCIAT_POLICY_ID, buildAndroidPolicy(e.policy));
      await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE android_enterprises SET policy_synced_at = now(), last_error = NULL WHERE id = $1", [e.id]));
    } catch (err) {
      await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE android_enterprises SET last_error = $2 WHERE id = $1", [e.id, (err instanceof Error ? err.message : String(err)).slice(0, 1000)]));
      throw googleError(err);
    }
  }

  // ─── Enrollment ───────────────────────────────────────────────────────────────────────────────

  async tokens(tx: Queryable, organizationId: string): Promise<MobileEnrollmentToken[]> {
    const { rows } = await tx.query<Row>("SELECT * FROM mobile_enrollment_tokens WHERE organization_id = $1 AND expires_at > now() AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 50", [organizationId]);
    return rows.map(toToken);
  }

  async createToken(tenantId: string, input: { organizationId: string; ownership: "company" | "personal"; validDays: number; assignee?: string | undefined }, actor: string): Promise<MobileEnrollmentToken> {
    const e = await this.deps.db.withTenant(tenantId, (tx) => this.activeEnterprise(tx, input.organizationId));
    const client = await this.client(tenantId);
    const id = randomUUID();
    let t;
    try {
      t = await client.createEnrollmentToken(e.name, {
        policyName: `${e.name}/policies/${SCIAT_POLICY_ID}`,
        duration: `${input.validDays * 86_400}s`,
        // Company phones are fully managed; personal phones get a separate work profile.
        allowPersonalUsage: input.ownership === "company" ? "PERSONAL_USAGE_DISALLOWED" : "PERSONAL_USAGE_ALLOWED",
        additionalData: JSON.stringify({ sciatToken: id }),
      });
    } catch (err) {
      throw googleError(err);
    }
    const expires = t.expirationTimestamp ?? new Date(this.deps.now() + input.validDays * 86_400_000).toISOString();
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>(
        `INSERT INTO mobile_enrollment_tokens (id, tenant_id, organization_id, enterprise_id, token_name, value, qr_code, ownership, assignee, expires_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
        [id, tenantId, input.organizationId, e.id, t.name, t.value, t.qrCode ?? "", input.ownership, input.assignee || null, expires, actor],
      );
      return toToken(rows[0]!);
    });
  }

  /** Revoke at Google and here. Returns the organization (for authorization / audit). */
  async revokeToken(tenantId: string, id: string): Promise<{ organizationId: string }> {
    const row = await this.deps.db.withTenant(tenantId, async (tx) => (await tx.query<Row>("SELECT * FROM mobile_enrollment_tokens WHERE id = $1 AND revoked_at IS NULL", [id])).rows[0]);
    if (!row) throw notFound("Enrollment code");
    const client = await this.client(tenantId);
    try {
      await client.deleteEnrollmentToken(String(row.token_name));
    } catch (err) {
      if (!(err instanceof AmapiError && err.status === 404)) throw googleError(err);
    }
    await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE mobile_enrollment_tokens SET revoked_at = now() WHERE id = $1", [id]));
    return { organizationId: String(row.organization_id) };
  }

  // ─── Devices ──────────────────────────────────────────────────────────────────────────────────

  async devices(tx: Queryable, organizationId: string): Promise<MobileDevice[]> {
    const { rows } = await tx.query<Row>(
      `SELECT * FROM mobile_devices WHERE organization_id = $1 AND removed_at IS NULL
       ORDER BY array_position(ARRAY['at_risk', 'non_compliant', 'stale', 'pending', 'compliant'], compliance), name`,
      [organizationId],
    );
    return rows.map(toMobileDevice);
  }

  async overview(tx: Queryable, organizationId: string): Promise<MobileOverview> {
    const devices = await this.devices(tx, organizationId);
    const counts = Object.fromEntries(MOBILE_COMPLIANCE.map((c) => [c, devices.filter((d) => d.compliance === c).length])) as MobileOverview["counts"];
    counts.total = devices.length;
    return { organizationId, account: await this.settings(tx), enterprise: await this.enterprise(tx, organizationId), tokens: await this.tokens(tx, organizationId), devices, counts };
  }

  /** Read every device of the organization's enterprise from Google into SCIAT. */
  async sync(tenantId: string, organizationId: string): Promise<{ devices: number; removed: number }> {
    const e = await this.deps.db.withTenant(tenantId, (tx) => this.activeEnterprise(tx, organizationId));
    const client = await this.client(tenantId);
    let list: AmapiDevice[];
    try {
      list = await client.listDevices(e.name);
    } catch (err) {
      await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE android_enterprises SET last_error = $2, last_sync_at = now() WHERE id = $1", [e.id, (err instanceof Error ? err.message : String(err)).slice(0, 1000)]));
      throw googleError(err);
    }
    const now = this.deps.now();
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const seen: string[] = [];
      for (const d of list) {
        if (d.state === "DELETED") continue;
        seen.push(d.name);
        await this.upsertDevice(tx, tenantId, organizationId, d, evaluateAndroidDevice(d, e.policy, now));
      }
      const removed = await tx.query(
        "UPDATE mobile_devices SET removed_at = now() WHERE organization_id = $1 AND platform = 'android' AND removed_at IS NULL AND NOT (external_id = ANY($2::text[]))",
        [organizationId, seen],
      );
      await tx.query("UPDATE android_enterprises SET last_sync_at = now(), last_error = NULL WHERE id = $1", [e.id]);
      return { devices: seen.length, removed: removed.rowCount ?? 0 };
    });
  }

  private async upsertDevice(tx: Queryable, tenantId: string, organizationId: string, d: AmapiDevice, ev: { compliance: string; findings: MobileFinding[] }): Promise<void> {
    const hw = d.hardwareInfo ?? {};
    const sw = d.softwareInfo ?? {};
    const brand = hw.manufacturer || hw.brand || "Android";
    const name = `${brand} ${hw.model ?? "device"}${hw.serialNumber ? ` (${hw.serialNumber.slice(-6)})` : ""}`.trim().slice(0, 300);
    let assignee: string | null = null;
    let ownership: "company" | "personal" | null = d.ownership === "COMPANY_OWNED" ? "company" : d.ownership === "PERSONALLY_OWNED" ? "personal" : null;
    try {
      const tokenId = (JSON.parse(d.enrollmentTokenData ?? "{}") as { sciatToken?: string }).sciatToken;
      if (tokenId && /^[0-9a-f-]{36}$/i.test(tokenId)) {
        const t = (await tx.query<Row>("SELECT assignee, ownership FROM mobile_enrollment_tokens WHERE id = $1", [tokenId])).rows[0];
        assignee = (t?.assignee as string | null) ?? null;
        ownership ??= (t?.ownership as "company" | "personal" | undefined) ?? null;
      }
    } catch {
      /* not one of our tokens */
    }
    const os = sw.androidVersion ? `Android ${sw.androidVersion}` : "Android";
    const asset = await tx.query<Row>(
      `INSERT INTO assets (tenant_id, organization_id, kind, name, os, criticality, owner, source, external_source, external_ref, tags, last_seen_at)
       VALUES ($1, $2, 'mobile_device', $3, $4, 'medium', $5, 'integration', 'android', $6, ARRAY['mobile', 'android'], $7)
       ON CONFLICT (tenant_id, external_source, external_ref) WHERE external_ref IS NOT NULL
       DO UPDATE SET name = EXCLUDED.name, os = EXCLUDED.os, owner = coalesce(EXCLUDED.owner, assets.owner), last_seen_at = coalesce(EXCLUDED.last_seen_at, assets.last_seen_at), updated_at = now()
       RETURNING id`,
      [tenantId, organizationId, name, os, assignee ?? d.userName ?? null, d.name, d.lastStatusReportTime ?? null],
    );
    await tx.query(
      `INSERT INTO mobile_devices (tenant_id, organization_id, asset_id, platform, external_id, name, manufacturer, model, serial_number, os_version, security_patch_level,
         ownership, management_mode, assignee, user_name, state, compliance, findings, enrolled_at, last_status_at, last_sync_at)
       VALUES ($1, $2, $3, 'android', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::jsonb, $18, $19, now())
       ON CONFLICT (tenant_id, external_id) DO UPDATE SET organization_id = EXCLUDED.organization_id, asset_id = EXCLUDED.asset_id, name = EXCLUDED.name,
         manufacturer = EXCLUDED.manufacturer, model = EXCLUDED.model, serial_number = EXCLUDED.serial_number, os_version = EXCLUDED.os_version,
         security_patch_level = EXCLUDED.security_patch_level, ownership = EXCLUDED.ownership, management_mode = EXCLUDED.management_mode,
         assignee = coalesce(EXCLUDED.assignee, mobile_devices.assignee), user_name = EXCLUDED.user_name, state = EXCLUDED.state, compliance = EXCLUDED.compliance,
         findings = EXCLUDED.findings, enrolled_at = EXCLUDED.enrolled_at, last_status_at = EXCLUDED.last_status_at, last_sync_at = now(), removed_at = NULL`,
      [
        tenantId,
        organizationId,
        asset.rows[0]!.id,
        d.name,
        name,
        hw.manufacturer ?? hw.brand ?? null,
        hw.model ?? null,
        hw.serialNumber ?? null,
        sw.androidVersion ?? null,
        sw.securityPatchLevel ?? null,
        ownership,
        d.managementMode ?? null,
        assignee,
        d.userName ?? null,
        d.state ?? "ACTIVE",
        ev.compliance,
        JSON.stringify(ev.findings),
        d.enrollmentTime ?? null,
        d.lastStatusReportTime ?? null,
      ],
    );
  }

  /** Re-grade the stored devices after a settings change (no call to Google). */
  private async reevaluate(tx: Queryable, organizationId: string, settings: AndroidPolicySettings): Promise<void> {
    const { rows } = await tx.query<Row>("SELECT id, findings, os_version, security_patch_level, state, last_status_at FROM mobile_devices WHERE organization_id = $1 AND platform = 'android' AND removed_at IS NULL", [organizationId]);
    for (const r of rows) {
      // Rebuild the inputs the stored findings came from (device settings / posture / policy findings are kept).
      const kept = ((r.findings as MobileFinding[]) ?? []).filter((f) => f.key !== "patch_old" && f.key !== "os_old" && f.key !== "stale");
      const probe = evaluateAndroidDevice(
        { name: "x", state: String(r.state), softwareInfo: { androidVersion: (r.os_version as string | null) ?? undefined, securityPatchLevel: (r.security_patch_level as string | null) ?? undefined }, lastStatusReportTime: iso(r.last_status_at) ?? undefined },
        settings,
        this.deps.now(),
      );
      const findings = [...kept, ...probe.findings];
      const atRisk = findings.some((f) => f.severity === "critical" || f.key === "at_risk");
      const compliance = probe.compliance === "pending" ? "pending" : atRisk ? "at_risk" : findings.some((f) => f.key !== "stale") ? "non_compliant" : findings.length ? "stale" : "compliant";
      await tx.query("UPDATE mobile_devices SET findings = $2::jsonb, compliance = $3 WHERE id = $1", [r.id, JSON.stringify(findings), compliance]);
    }
  }

  /** Scheduler: re-read devices of enterprises not synced recently. */
  async syncDue(tenantId: string): Promise<number> {
    const due = await this.deps.db.withTenant(tenantId, async (tx) =>
      (await tx.query<Row>(
        `SELECT e.organization_id FROM android_enterprises e, android_settings s
         WHERE e.status = 'active' AND (e.last_sync_at IS NULL OR e.last_sync_at < now() - make_interval(mins => $1))`,
        [ANDROID_SYNC_MINUTES],
      )).rows,
    );
    let n = 0;
    for (const r of due) {
      try {
        await this.sync(tenantId, String(r.organization_id));
        n++;
      } catch {
        // Recorded on the enterprise (last_error); the next tick tries again.
      }
    }
    return n;
  }

  // ─── Commands (run by response actions: lock_device / wipe_device) ────────────────────────────

  /** The managed phone behind an asset, or null when the asset is not an enrolled Android device. */
  async deviceForAsset(tx: Queryable, assetId: string): Promise<MobileDevice & { externalId: string } | null> {
    const r = (await tx.query<Row>("SELECT * FROM mobile_devices WHERE asset_id = $1 AND platform = 'android' AND removed_at IS NULL", [assetId])).rows[0];
    return r ? { ...toMobileDevice(r), externalId: String(r.external_id) } : null;
  }

  async lock(tenantId: string, assetId: string): Promise<string> {
    const d = await this.requireDevice(tenantId, assetId);
    const client = await this.client(tenantId);
    try {
      await client.issueCommand(d.externalId, "LOCK");
    } catch (err) {
      throw googleError(err);
    }
    return `Lock sent to ${d.name}; it locks as soon as it is online`;
  }

  async wipe(tenantId: string, assetId: string, reason: string): Promise<string> {
    const d = await this.requireDevice(tenantId, assetId);
    const client = await this.client(tenantId);
    try {
      await client.wipeDevice(d.externalId, reason);
    } catch (err) {
      throw googleError(err);
    }
    await this.deps.db.withTenant(tenantId, (tx) => tx.query("UPDATE mobile_devices SET state = 'DELETED', removed_at = now() WHERE asset_id = $1", [assetId]));
    return d.ownership === "personal" ? `Work profile removed from ${d.name} (personal data untouched)` : `Factory reset sent to ${d.name}`;
  }

  private async requireDevice(tenantId: string, assetId: string) {
    const d = await this.deps.db.withTenant(tenantId, (tx) => this.deviceForAsset(tx, assetId));
    if (!d) throw new HttpError(409, "not_a_managed_phone", "This asset is not an enrolled Android device");
    return d;
  }
}
