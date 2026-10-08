import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SecretBox } from "../security/crypto.js";
import { createTenant, createTestApp, type TestApp, type TestTenant } from "../test/harness.js";
import { SecretNotFoundError, SecretStore } from "./secret-store.js";

let t: TestApp;
let A: TestTenant;
let B: TestTenant;
const k1 = randomBytes(32);
const k2 = randomBytes(32);

beforeAll(async () => {
  t = await createTestApp();
  A = await createTenant(t, { orgs: 1 });
  B = await createTenant(t, { orgs: 1 });
});
afterAll(async () => {
  await t?.close();
});

describe("SecretStore", () => {
  it("seals secrets, never stores plaintext and resolves by opaque reference", async () => {
    const store = new SecretStore(new SecretBox(new Map([[1, k1]]), 1), t.db);
    const meta = await t.db.withTenant(A.tenantId, (tx) => store.put(tx, A.tenantId, { value: "sk-live-0123456789", name: "OpenAI key", purpose: "ai_provider", organizationId: A.orgIds[0], createdBy: "user:x" }));
    expect(meta).toMatchObject({ name: "OpenAI key", purpose: "ai_provider", keyVersion: 1, organizationId: A.orgIds[0] });
    expect(SecretStore.isRef(meta.ref)).toBe(true);
    const raw = await t.privileged.query<{ ciphertext: string }>("SELECT ciphertext FROM secrets WHERE ref = $1", [meta.ref]);
    expect(raw.rows[0]!.ciphertext).not.toContain("sk-live");
    expect(await t.db.withTenant(A.tenantId, (tx) => store.resolve(tx, A.tenantId, meta.ref))).toBe("sk-live-0123456789");
    expect(await store.aiResolver().resolve(A.tenantId, meta.ref)).toBe("sk-live-0123456789");
    // Another tenant cannot see the row (RLS) — and the ciphertext would not open there anyway.
    expect(await store.aiResolver().resolve(B.tenantId, meta.ref)).toBeNull();
    await expect(store.strictResolver().resolve(B.tenantId, meta.ref)).rejects.toBeInstanceOf(SecretNotFoundError);
    await t.privileged.query("INSERT INTO secrets (tenant_id, ref, name, purpose, key_version, ciphertext) SELECT $1, ref, name, purpose, key_version, ciphertext FROM secrets WHERE ref = $2", [B.tenantId, meta.ref]);
    await expect(store.aiResolver().resolve(B.tenantId, meta.ref)).rejects.toThrow(/authentication/);

    const replaced = await t.db.withTenant(A.tenantId, (tx) => store.replace(tx, A.tenantId, meta.ref, "sk-live-rotated"));
    expect(replaced.rotatedAt).not.toBeNull();
    expect(await store.strictResolver().resolve(A.tenantId, meta.ref)).toBe("sk-live-rotated");
    expect(await t.db.withTenant(A.tenantId, (tx) => store.delete(tx, meta.ref))).toBe(true);
    expect(await store.aiResolver().resolve(A.tenantId, meta.ref)).toBeNull();
    expect(await store.aiResolver().resolve(A.tenantId, "not-a-ref")).toBeNull();
  });

  it("re-seals values under the active key after a key rotation", async () => {
    const v1 = new SecretStore(new SecretBox(new Map([[1, k1]]), 1), t.db);
    const a = await t.db.withTenant(A.tenantId, (tx) => v1.put(tx, A.tenantId, { value: "webhook-secret-a", name: "Slack webhook", purpose: "notification_channel" }));
    const b = await t.db.withTenant(A.tenantId, (tx) => v1.put(tx, A.tenantId, { value: "webhook-secret-b", name: "Teams webhook", purpose: "notification_channel" }));
    const v2 = new SecretStore(
      new SecretBox(
        new Map([
          [1, k1],
          [2, k2],
        ]),
        2,
      ),
      t.db,
    );
    // Lazy: reading re-seals with v2.
    expect(await v2.aiResolver().resolve(A.tenantId, a.ref)).toBe("webhook-secret-a");
    expect((await t.db.withTenant(A.tenantId, (tx) => v2.describe(tx, a.ref)))!.keyVersion).toBe(2);
    // Bulk: rotateAll re-seals the rest.
    expect(await t.db.withTenant(A.tenantId, (tx) => v2.rotateAll(tx, A.tenantId))).toBe(1);
    const v2only = new SecretStore(new SecretBox(new Map([[2, k2]]), 2), t.db);
    expect(await v2only.aiResolver().resolve(A.tenantId, b.ref)).toBe("webhook-secret-b");
  });
});
