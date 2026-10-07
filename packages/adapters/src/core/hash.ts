import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export function hmacSha256Hex(secret: string | Uint8Array, data: string): string {
  return createHmac("sha256", secret).update(data, "utf8").digest("hex");
}

/** Constant-time comparison of two hex digests. */
export function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length || !/^[0-9a-f]*$/i.test(a) || !/^[0-9a-f]*$/i.test(b)) return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}

/**
 * RFC 4122 §4.3 name-based UUID (version 5, SHA-1). Used for deterministic event ids
 * scoped by a caller-supplied namespace (the tenant id), so replaying the same engine
 * output converges on the same canonical event ids without cross-tenant collisions.
 */
export function uuidV5(name: string, namespace: string): string {
  if (!isUuid(namespace)) throw new Error("uuidV5 namespace must be a UUID");
  const ns = Buffer.from(namespace.replace(/-/g, ""), "hex");
  const digest = createHash("sha1").update(ns).update(name, "utf8").digest();
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x50;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Canonical JSON (sorted keys) for stable digests of structured payloads. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v)).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}
