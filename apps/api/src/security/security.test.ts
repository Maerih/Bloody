import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { SecretBox, SecretStoreError, randomAlnum, safeEqual } from "./crypto.js";
import { hashPassword, needsRehash, passwordPolicyErrors, verifyPassword } from "./passwords.js";
import { TokenError, signAccessToken, signState, verifyAccessToken, verifyState } from "./tokens.js";
import { base32Decode, base32Encode, hotp, totp, verifyTotp } from "./totp.js";

describe("SecretBox (AES-256-GCM with key versioning)", () => {
  const k1 = randomBytes(32);
  const k2 = randomBytes(32);

  it("round-trips and binds ciphertexts to their context", () => {
    const box = new SecretBox(new Map([[1, k1]]), 1);
    const ct = box.encrypt("s3cr3t-api-key", "tenant-a:ai_provider:ref-1");
    expect(ct).toMatch(/^v1\.[\w-]{16}\.[\w-]{22}\.[\w-]+$/);
    expect(ct).not.toContain("s3cr3t");
    expect(box.decrypt(ct, "tenant-a:ai_provider:ref-1")).toBe("s3cr3t-api-key");
    expect(box.encrypt("same", "ctx")).not.toBe(box.encrypt("same", "ctx")); // random IV
    expect(() => box.decrypt(ct, "tenant-b:ai_provider:ref-1")).toThrow(SecretStoreError);
    const [v, iv, tag, body] = ct.split(".");
    const flipped = `${v}.${iv}.${tag}.${body!.slice(0, -2)}${body!.endsWith("AA") ? "BB" : "AA"}`;
    expect(() => box.decrypt(flipped, "tenant-a:ai_provider:ref-1")).toThrow(/authentication/);
    expect(() => box.decrypt("garbage", "x")).toThrow(/Malformed/);
  });

  it("decrypts with retired keys and rotates to the active key", () => {
    const old = new SecretBox(new Map([[1, k1]]), 1);
    const ct = old.encrypt("rotate me", "ctx");
    const current = new SecretBox(
      new Map([
        [1, k1],
        [2, k2],
      ]),
      2,
    );
    expect(current.decrypt(ct, "ctx")).toBe("rotate me");
    expect(current.needsRotation(ct)).toBe(true);
    const rotated = current.rotate(ct, "ctx");
    expect(rotated.startsWith("v2.")).toBe(true);
    expect(current.needsRotation(rotated)).toBe(false);
    expect(new SecretBox(new Map([[2, k2]]), 2).decrypt(rotated, "ctx")).toBe("rotate me");
    expect(() => new SecretBox(new Map([[2, k2]]), 2).decrypt(ct, "ctx")).toThrow(/No encryption key v1/);
    expect(() => new SecretBox(new Map([[1, randomBytes(16)]]), 1)).toThrow();
  });

  it("compares in constant time and generates unbiased prefixes", () => {
    expect(safeEqual("abc", "abc")).toBe(true);
    expect(safeEqual("abc", "abd")).toBe(false);
    expect(safeEqual("abc", "abcd")).toBe(false);
    const p = randomAlnum(12);
    expect(p).toMatch(/^[a-z0-9]{12}$/);
  });
});

describe("TOTP (RFC 6238)", () => {
  // RFC 6238 Appendix B, SHA-1 secret "12345678901234567890", 8 digits.
  const secret = base32Encode(Buffer.from("12345678901234567890", "ascii"));
  it.each([
    [59, "94287082"],
    [1111111109, "07081804"],
    [1111111111, "14050471"],
    [1234567890, "89005924"],
    [2000000000, "69279037"],
    [20000000000, "65353130"],
  ])("t=%i → %s", (seconds, expected) => {
    expect(totp(secret, seconds * 1000, { digits: 8 })).toBe(expected);
  });

  it("base32 round-trips and HOTP matches RFC 4226", () => {
    expect(base32Decode(secret).toString("ascii")).toBe("12345678901234567890");
    expect(hotp(Buffer.from("12345678901234567890"), 0)).toBe("755224");
    expect(hotp(Buffer.from("12345678901234567890"), 9)).toBe("520489");
  });

  it("accepts ±1 step of drift and rejects replays", () => {
    const at = 1_800_000_000_000;
    const step = Math.floor(at / 30_000);
    expect(verifyTotp(secret, totp(secret, at - 30_000), at)).toBe(step - 1);
    expect(verifyTotp(secret, totp(secret, at + 30_000), at)).toBe(step + 1);
    expect(verifyTotp(secret, totp(secret, at - 60_000), at)).toBeNull();
    expect(verifyTotp(secret, totp(secret, at), at, { lastUsedStep: step })).toBeNull();
    expect(verifyTotp(secret, "12a456", at)).toBeNull();
  });
});

describe("access tokens", () => {
  const settings = { secret: new TextEncoder().encode("x".repeat(48)), issuer: "bloody-api", audience: "bloody", ttlSeconds: 900 };
  const claims = { sub: "6f4e1b8a-1d2c-4e7f-9a0b-1c2d3e4f5a6b", tid: "7a5f2c9d-3e4b-4c1a-8d7e-2f3a4b5c6d7e", sid: "8b6a3d0e-4f5c-4d2b-9e8f-3a4b5c6d7e8f", kind: "user" as const };

  it("signs short-lived HS256 tokens and verifies issuer/audience/expiry", async () => {
    const now = Date.now();
    const { token, expiresAt } = await signAccessToken(claims, settings, now);
    expect(Date.parse(expiresAt) - now).toBeLessThanOrEqual(900_000);
    expect(await verifyAccessToken(token, settings)).toEqual(claims);
    await expect(verifyAccessToken(token, { ...settings, audience: "other" })).rejects.toMatchObject({ code: "invalid" });
    await expect(verifyAccessToken(token, { ...settings, secret: new TextEncoder().encode("y".repeat(48)) })).rejects.toBeInstanceOf(TokenError);
    const expired = await signAccessToken(claims, settings, now - 3_600_000);
    await expect(verifyAccessToken(expired.token, settings)).rejects.toMatchObject({ code: "expired" });
    const [h, , s] = token.split(".");
    const forgedPayload = Buffer.from(JSON.stringify({ ...claims, sub: "attacker" })).toString("base64url");
    await expect(verifyAccessToken(`${h}.${forgedPayload}.${s}`, settings)).rejects.toMatchObject({ code: "invalid" });
  });

  it("signs OIDC state that cannot be replayed as an access token", async () => {
    const state = await signState({ state: "abc", nonce: "n" }, settings, 60);
    expect(await verifyState(state, settings)).toMatchObject({ state: "abc", nonce: "n" });
    await expect(verifyAccessToken(state, settings)).rejects.toBeInstanceOf(TokenError);
  });
});

describe("passwords (Argon2id)", () => {
  it("hashes with argon2id, verifies and flags weaker parameters", async () => {
    const hash = await hashPassword("Correct-Horse-9");
    expect(hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    expect(await verifyPassword(hash, "Correct-Horse-9")).toBe(true);
    expect(await verifyPassword(hash, "correct-horse-9")).toBe(false);
    expect(await verifyPassword("not-a-hash", "x")).toBe(false);
    expect(needsRehash(hash)).toBe(false);
    expect(needsRehash("$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHQ$aGFzaA")).toBe(true);
    expect(needsRehash("$2b$10$bcrypt")).toBe(true);
  });

  it("enforces the password policy", () => {
    expect(passwordPolicyErrors("Str0ng-Passw0rd!")).toEqual([]);
    expect(passwordPolicyErrors("short1A")).toContain("must be at least 10 characters");
    expect(passwordPolicyErrors("alllowercaseletters")).toHaveLength(1);
    expect(passwordPolicyErrors("Jonathan-2026!", "jonathan@example.test")).toContain("must not contain the e-mail name");
  });
});
