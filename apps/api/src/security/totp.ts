import { createHmac, randomBytes } from "node:crypto";
import { safeEqual } from "./crypto.js";

/**
 * RFC 6238 TOTP (HMAC-SHA1, 30-second steps, 6 digits) — compatible with every authenticator
 * app. Verification accepts ±`window` steps for clock drift and returns the matched step so
 * the caller can store it and reject replays (a step at or below the last used one fails).
 */

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32.indexOf(ch);
    if (idx < 0) throw new Error("Invalid base32 character");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export interface TotpOptions {
  stepSeconds?: number;
  digits?: number;
  algorithm?: "sha1" | "sha256" | "sha512";
}

export function generateTotpSecret(bytes = 20): string {
  return base32Encode(randomBytes(bytes));
}

export function hotp(secret: Buffer, counter: number, digits = 6, algorithm: TotpOptions["algorithm"] = "sha1"): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac(algorithm ?? "sha1", secret).update(msg).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const code = ((mac[offset]! & 0x7f) << 24) | ((mac[offset + 1]! & 0xff) << 16) | ((mac[offset + 2]! & 0xff) << 8) | (mac[offset + 3]! & 0xff);
  return String(code % 10 ** digits).padStart(digits, "0");
}

export function totpStep(atMs: number, stepSeconds = 30): number {
  return Math.floor(atMs / 1000 / stepSeconds);
}

export function totp(secretBase32: string, atMs: number, opts: TotpOptions = {}): string {
  return hotp(base32Decode(secretBase32), totpStep(atMs, opts.stepSeconds ?? 30), opts.digits ?? 6, opts.algorithm ?? "sha1");
}

/** Returns the matched time step, or null. Steps ≤ `lastUsedStep` are rejected (replay). */
export function verifyTotp(secretBase32: string, code: string, atMs: number, opts: TotpOptions & { window?: number; lastUsedStep?: number } = {}): number | null {
  const digits = opts.digits ?? 6;
  if (!new RegExp(`^\\d{${digits}}$`).test(code)) return null;
  const secret = base32Decode(secretBase32);
  const current = totpStep(atMs, opts.stepSeconds ?? 30);
  const window = opts.window ?? 1;
  let matched: number | null = null;
  // Check every candidate (no early exit) to keep timing independent of which step matched.
  for (let delta = -window; delta <= window; delta++) {
    const step = current + delta;
    if (step < 0) continue;
    if (safeEqual(hotp(secret, step, digits, opts.algorithm ?? "sha1"), code) && matched === null) matched = step;
  }
  if (matched === null) return null;
  if (opts.lastUsedStep !== undefined && matched <= opts.lastUsedStep) return null;
  return matched;
}

export function otpauthUri(params: { secret: string; account: string; issuer: string }): string {
  const label = encodeURIComponent(`${params.issuer}:${params.account}`);
  const q = new URLSearchParams({ secret: params.secret, issuer: params.issuer, algorithm: "SHA1", digits: "6", period: "30" });
  return `otpauth://totp/${label}?${q.toString()}`;
}
