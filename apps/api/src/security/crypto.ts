import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export function hmacSha256(key: Uint8Array | string, data: string): string {
  return createHmac("sha256", key).update(data, "utf8").digest("base64url");
}

/** URL-safe random token with `bytes` bytes of entropy. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

/** Lower-case alphanumeric random string (for API-key prefixes). */
export function randomAlnum(length: number): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  const out: string[] = [];
  // Rejection sampling avoids modulo bias.
  while (out.length < length) {
    for (const b of randomBytes(length * 2)) {
      if (b < 252) out.push(alphabet[b % 36]!);
      if (out.length === length) break;
    }
  }
  return out.join("");
}

/** Constant-time string comparison (false on length mismatch without early exit on content). */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) {
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
}

export class SecretStoreError extends Error {
  constructor(
    readonly code: "unknown_key_version" | "malformed" | "authentication_failed",
    message: string,
  ) {
    super(message);
    this.name = "SecretStoreError";
  }
}

/**
 * AES-256-GCM envelope with key versioning.
 *
 * Ciphertext format: `v<version>.<iv>.<tag>.<ciphertext>` (base64url parts, 96-bit random IV,
 * 128-bit tag). The caller-supplied `context` (e.g. `tenantId:purpose:ref`) is bound as
 * additional authenticated data, so a ciphertext copied to another tenant or record fails to
 * decrypt. Old key versions stay available for decryption; `needsRotation()` tells callers to
 * re-encrypt with the active key.
 */
export class SecretBox {
  constructor(
    private readonly keys: ReadonlyMap<number, Buffer>,
    readonly activeVersion: number,
  ) {
    const active = keys.get(activeVersion);
    if (!active || active.length !== 32) throw new SecretStoreError("unknown_key_version", `Active encryption key v${activeVersion} must be 32 bytes`);
    for (const [v, k] of keys) if (k.length !== 32) throw new SecretStoreError("malformed", `Encryption key v${v} must be 32 bytes`);
  }

  encrypt(plaintext: string, context: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.keys.get(this.activeVersion)!, iv);
    cipher.setAAD(Buffer.from(context, "utf8"));
    const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `v${this.activeVersion}.${iv.toString("base64url")}.${tag.toString("base64url")}.${ct.toString("base64url")}`;
  }

  decrypt(envelope: string, context: string): string {
    const parts = envelope.split(".");
    if (parts.length !== 4 || !/^v\d+$/.test(parts[0]!)) throw new SecretStoreError("malformed", "Malformed ciphertext envelope");
    const version = Number(parts[0]!.slice(1));
    const key = this.keys.get(version);
    if (!key) throw new SecretStoreError("unknown_key_version", `No encryption key v${version} is configured`);
    const iv = Buffer.from(parts[1]!, "base64url");
    const tag = Buffer.from(parts[2]!, "base64url");
    const ct = Buffer.from(parts[3]!, "base64url");
    if (iv.length !== 12 || tag.length !== 16) throw new SecretStoreError("malformed", "Malformed ciphertext envelope");
    try {
      const decipher = createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAAD(Buffer.from(context, "utf8"));
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
    } catch {
      throw new SecretStoreError("authentication_failed", "Ciphertext failed authentication (wrong key, context or tampered data)");
    }
  }

  versionOf(envelope: string): number | null {
    const m = /^v(\d+)\./.exec(envelope);
    return m ? Number(m[1]) : null;
  }

  needsRotation(envelope: string): boolean {
    return this.versionOf(envelope) !== this.activeVersion;
  }

  /** Re-encrypt with the active key (no-op when already current). */
  rotate(envelope: string, context: string): string {
    return this.needsRotation(envelope) ? this.encrypt(this.decrypt(envelope, context), context) : envelope;
  }
}
