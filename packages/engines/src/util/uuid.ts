import { createHash } from "node:crypto";

/**
 * Bloody's private UUID namespace. Every deterministic identifier produced by the engines
 * (graph nodes/edges, detection matches, incident drafts, attack paths) is a RFC 4122
 * version-5 UUID derived from this namespace and a canonical name string.
 *
 * Deterministic ids make every engine write idempotent: replaying the same event stream
 * (at-least-once delivery from the data fabric) converges on the same rows instead of
 * creating duplicates, and the in-memory and Postgres graph stores agree on ids.
 */
export const BLOODY_UUID_NAMESPACE = "8d4f6f3e-2b1a-4c7e-9a55-b100d5ec0c0e";

const namespaceBytes = Buffer.from(BLOODY_UUID_NAMESPACE.replace(/-/g, ""), "hex");

/** RFC 4122 §4.3 name-based UUID (SHA-1, version 5). */
export function uuidV5(name: string, namespace: Buffer = namespaceBytes): string {
  const digest = createHash("sha1").update(namespace).update(name, "utf8").digest();
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x50;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Deterministic id from ordered parts. Parts are joined with an unambiguous separator. */
export function stableId(...parts: Array<string | number | null | undefined>): string {
  return uuidV5(parts.map((p) => (p === null || p === undefined ? "∅" : String(p).replace(/␟/g, ""))).join("␟"));
}

/** Short stable content hash (hex) — used for rule content fingerprints. */
export function contentHash(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

/** JSON with sorted object keys so semantically equal values hash identically. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortKeys(v);
    }
    return out;
  }
  return value;
}
