import { randomUUID } from "node:crypto";
import type { Database, Queryable } from "../db/pool.js";
import type { SecretBox } from "../security/crypto.js";

/**
 * Tenant secret store over the `secrets` table (AI provider keys, integration credentials,
 * webhook signing secrets…). Plaintext never leaves this service except to the server-side
 * component that needs it; records elsewhere hold only the opaque `ref` (`credentialRef`).
 *
 *  - AES-256-GCM via {@link SecretBox}, with the tenant, ref and purpose bound as additional
 *    authenticated data: a ciphertext copied to another tenant, record or purpose fails to open.
 *  - Key versioning: reads transparently re-encrypt values sealed with a retired key, and
 *    {@link SecretStore.rotateAll} re-seals a tenant's secrets after a key rotation.
 *  - Every call runs inside the caller's `withTenant` transaction, so RLS applies as well.
 */
export interface SecretMetadata {
  ref: string;
  organizationId: string | null;
  name: string;
  purpose: string;
  keyVersion: number;
  createdBy: string | null;
  createdAt: string;
  rotatedAt: string | null;
}

export class SecretNotFoundError extends Error {
  constructor(ref: string) {
    super(`Secret ${ref} not found`);
    this.name = "SecretNotFoundError";
  }
}

const REF_RE = /^sec_[0-9a-f]{32}$/;
const PURPOSE_RE = /^[a-z0-9_.:-]{1,64}$/;

interface SecretRow {
  ref: string;
  organization_id: string | null;
  name: string;
  purpose: string;
  key_version: number;
  ciphertext: string;
  created_by: string | null;
  created_at: string;
  rotated_at: string | null;
}

export class SecretStore {
  constructor(
    private readonly box: SecretBox,
    private readonly db?: Database,
  ) {}

  static isRef(value: unknown): value is string {
    return typeof value === "string" && REF_RE.test(value);
  }

  private context(tenantId: string, ref: string, purpose: string): string {
    return `${tenantId}:secret:${ref}:${purpose}`;
  }

  /** Seal a new secret and return its opaque reference. */
  async put(
    tx: Queryable,
    tenantId: string,
    input: { value: string; name: string; purpose?: string; organizationId?: string | null; createdBy?: string | null },
  ): Promise<SecretMetadata> {
    const purpose = input.purpose ?? "generic";
    if (!PURPOSE_RE.test(purpose)) throw new Error("Invalid secret purpose");
    if (input.value.length === 0 || input.value.length > 64 * 1024) throw new Error("Secret value must be 1 byte to 64 KiB");
    const ref = `sec_${randomUUID().replace(/-/g, "")}`;
    const ciphertext = this.box.encrypt(input.value, this.context(tenantId, ref, purpose));
    const { rows } = await tx.query<SecretRow>(
      `INSERT INTO secrets (tenant_id, organization_id, ref, name, purpose, key_version, ciphertext, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING ref, organization_id, name, purpose, key_version, ciphertext, created_by, created_at, rotated_at`,
      [tenantId, input.organizationId ?? null, ref, input.name.slice(0, 200), purpose, this.box.activeVersion, ciphertext, input.createdBy ?? null],
    );
    return toMetadata(rows[0]!);
  }

  /** Decrypt a secret (null when unknown). Values sealed with a retired key are re-sealed. */
  async resolve(tx: Queryable, tenantId: string, ref: string): Promise<string | null> {
    if (!SecretStore.isRef(ref)) return null;
    const { rows } = await tx.query<SecretRow>("SELECT ref, purpose, key_version, ciphertext FROM secrets WHERE ref = $1 FOR UPDATE", [ref]);
    const row = rows[0];
    if (!row) return null;
    const ctx = this.context(tenantId, ref, row.purpose);
    const value = this.box.decrypt(row.ciphertext, ctx);
    if (this.box.needsRotation(row.ciphertext)) {
      await tx.query("UPDATE secrets SET ciphertext = $2, key_version = $3, rotated_at = now() WHERE ref = $1", [ref, this.box.encrypt(value, ctx), this.box.activeVersion]);
    }
    return value;
  }

  async describe(tx: Queryable, ref: string): Promise<SecretMetadata | null> {
    if (!SecretStore.isRef(ref)) return null;
    const { rows } = await tx.query<SecretRow>("SELECT ref, organization_id, name, purpose, key_version, created_by, created_at, rotated_at FROM secrets WHERE ref = $1", [ref]);
    return rows[0] ? toMetadata(rows[0]) : null;
  }

  /** Replace the value behind an existing reference (credential rotation by the customer). */
  async replace(tx: Queryable, tenantId: string, ref: string, value: string): Promise<SecretMetadata> {
    const current = await this.describe(tx, ref);
    if (!current) throw new SecretNotFoundError(ref);
    const ciphertext = this.box.encrypt(value, this.context(tenantId, ref, current.purpose));
    const { rows } = await tx.query<SecretRow>(
      `UPDATE secrets SET ciphertext = $2, key_version = $3, rotated_at = now() WHERE ref = $1
       RETURNING ref, organization_id, name, purpose, key_version, ciphertext, created_by, created_at, rotated_at`,
      [ref, ciphertext, this.box.activeVersion],
    );
    return toMetadata(rows[0]!);
  }

  async delete(tx: Queryable, ref: string): Promise<boolean> {
    if (!SecretStore.isRef(ref)) return false;
    const res = await tx.query("DELETE FROM secrets WHERE ref = $1", [ref]);
    return (res.rowCount ?? 0) > 0;
  }

  /** Re-seal every secret of the tenant still encrypted with a retired key. Returns the count. */
  async rotateAll(tx: Queryable, tenantId: string): Promise<number> {
    const { rows } = await tx.query<SecretRow>("SELECT ref, purpose, ciphertext FROM secrets WHERE key_version <> $1 FOR UPDATE", [this.box.activeVersion]);
    for (const row of rows) {
      const next = this.box.rotate(row.ciphertext, this.context(tenantId, row.ref, row.purpose));
      await tx.query("UPDATE secrets SET ciphertext = $2, key_version = $3, rotated_at = now() WHERE ref = $1", [row.ref, next, this.box.activeVersion]);
    }
    return rows.length;
  }

  private requireDb(): Database {
    if (!this.db) throw new Error("SecretStore was constructed without a Database; resolvers need one");
    return this.db;
  }

  /** `AiSecretResolver` (@bloody/ai): null when the reference is unknown. */
  aiResolver(): { resolve(tenantId: string, credentialRef: string): Promise<string | null> } {
    const db = this.requireDb();
    return { resolve: (tenantId, ref) => db.withTenant(tenantId, (tx) => this.resolve(tx, tenantId, ref)) };
  }

  /** `SecretResolver` (@bloody/automation): throws when the reference is unknown. */
  strictResolver(): { resolve(tenantId: string, ref: string): Promise<string> } {
    const db = this.requireDb();
    return {
      resolve: async (tenantId, ref) => {
        const value = await db.withTenant(tenantId, (tx) => this.resolve(tx, tenantId, ref));
        if (value === null) throw new SecretNotFoundError(ref);
        return value;
      },
    };
  }
}

function toMetadata(r: SecretRow): SecretMetadata {
  return {
    ref: r.ref,
    organizationId: r.organization_id,
    name: r.name,
    purpose: r.purpose,
    keyVersion: Number(r.key_version),
    createdBy: r.created_by,
    createdAt: String(r.created_at),
    rotatedAt: r.rotated_at,
  };
}
