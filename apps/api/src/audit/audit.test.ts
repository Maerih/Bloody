import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { api, createTenant, createTestApp, createUser, login, uniq, type Json, type TestApp, type TestTenant } from "../test/harness.js";
import { boundedDetails, redactDetails } from "./audit.js";

let t: TestApp;
let tenant: TestTenant;
let admin: ReturnType<typeof api>;
let orgId: string;

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 1 });
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
  const res = await admin.post("/organizations", { name: "Audited Customer", slug: uniq("audited") }, { "x-request-id": "req-audit-0001" });
  expect(res.status).toBe(201);
  orgId = res.body.id;
});

afterAll(async () => {
  await t?.close();
});

describe("audit trail", () => {
  it("records every mutation with actor, request id and outcome", async () => {
    const { rows } = await t.privileged.query("SELECT * FROM audit_log WHERE tenant_id = $1 AND request_id = 'req-audit-0001'", [tenant.tenantId]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "organization.created",
      actor_kind: "user",
      actor_id: tenant.admin.id,
      actor_label: tenant.admin.email,
      organization_id: orgId,
      target_kind: "organization",
      target_id: orgId,
      outcome: "success",
      user_agent: "bloody-api-tests",
    });
    expect(rows[0].ip).toBeTruthy();

    const dup = await admin.post("/organizations", { name: "Duplicate", slug: "org-1" }, { "x-request-id": "req-audit-0002" });
    expect(dup.status).toBe(409);
    expect(dup.body.error.code).toBe("conflict");
    const failed = await t.privileged.query("SELECT action, outcome, details FROM audit_log WHERE request_id = 'req-audit-0002'");
    expect(failed.rows).toEqual([{ action: "post /api/v1/organizations", outcome: "failure", details: { status: 409 } }]);
  });

  it("lists, filters and pages the trail", async () => {
    const page1 = await admin.get("/audit?limit=2");
    expect(page1.status).toBe(200);
    expect(page1.body.items).toHaveLength(2);
    expect(page1.body.nextCursor).toBeTruthy();
    expect(page1.body.items[0].seq).toBeGreaterThan(page1.body.items[1].seq);
    const page2 = await admin.get(`/audit?limit=2&cursor=${page1.body.nextCursor}`);
    expect(page2.body.items[0].seq).toBeLessThan(page1.body.items[1].seq);

    const created = await admin.get("/audit?action=organization.*");
    expect(created.body.items.map((r: Json) => r.action)).toEqual(["organization.created"]);
    expect(created.body.items[0]).toMatchObject({ actor: { kind: "user", id: tenant.admin.id }, target: { kind: "organization", id: orgId }, requestId: "req-audit-0001" });
    const failures = await admin.get("/audit?outcome=failure,denied");
    expect(failures.body.items.every((r: Json) => r.outcome !== "success")).toBe(true);
    expect((await admin.get("/audit?cursor=garbage")).status).toBe(400);
  });

  it("limits organization-scoped auditors to their organization's records", async () => {
    const ciso = await createUser(t, tenant.tenantId, { organizationId: orgId, roles: [{ role: "ciso", organizationId: orgId }] });
    const client = api(t.app, { token: (await login(t.app, ciso.email)).token });
    const res = await client.get("/audit?limit=500");
    expect(res.status).toBe(200);
    expect(res.body.items.length).toBeGreaterThan(0);
    expect(res.body.items.every((r: Json) => r.organizationId === orgId)).toBe(true);
    expect((await client.get(`/audit?organizationId=${tenant.orgIds[0]}`)).status).toBe(403);
    expect((await client.get("/audit/verify")).status).toBe(403);
  });

  it("hash-chains rows per tenant and verifies the chain", async () => {
    const { rows } = await t.privileged.query<{ seq: number; hash: string; prev_hash: string | null }>("SELECT seq, hash, prev_hash FROM audit_log WHERE tenant_id = $1 ORDER BY seq", [tenant.tenantId]);
    expect(rows.length).toBeGreaterThan(3);
    expect(rows[0]!.prev_hash).toBeNull();
    for (let i = 1; i < rows.length; i++) expect(rows[i]!.prev_hash).toBe(rows[i - 1]!.hash);
    const verify = await admin.get("/audit/verify");
    expect(verify.status).toBe(200);
    expect(verify.body).toMatchObject({ intact: true, firstBrokenSeq: null, records: rows.length, headHash: rows.at(-1)!.hash });
  });

  it("detects tampering even by someone able to bypass the triggers", async () => {
    const client = await t.privileged.connect();
    try {
      await client.query("BEGIN");
      await client.query("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update");
      const target = await client.query<{ seq: number }>("SELECT seq FROM audit_log WHERE tenant_id = $1 AND action = 'organization.created'", [tenant.tenantId]);
      await client.query("UPDATE audit_log SET details = '{\"name\": \"rewritten\"}' WHERE tenant_id = $1 AND seq = $2", [tenant.tenantId, target.rows[0]!.seq]);
      const broken = await client.query<{ seq: number | null }>("SELECT audit_log_verify($1) AS seq", [tenant.tenantId]);
      expect(Number(broken.rows[0]!.seq)).toBe(Number(target.rows[0]!.seq));
    } finally {
      await client.query("ROLLBACK");
      client.release();
    }
    expect((await admin.get("/audit/verify")).body.intact).toBe(true);
  });
});

describe("audit_log is append-only", () => {
  it("denies UPDATE, DELETE and TRUNCATE to the runtime role", async () => {
    for (const sql of ["UPDATE audit_log SET action = 'x'", "DELETE FROM audit_log", "TRUNCATE audit_log"]) {
      await expect(t.db.withTenant(tenant.tenantId, (tx) => tx.query(sql)), sql).rejects.toMatchObject({ code: "42501" });
    }
    // INSERT is allowed, but only for the caller's own tenant (RLS WITH CHECK).
    await expect(
      t.db.withTenant(tenant.tenantId, (tx) => tx.query("INSERT INTO audit_log (tenant_id, actor_kind, action, outcome) VALUES ($1, 'system', 'test.forged', 'success')", [tenant.orgIds[0]])),
    ).rejects.toMatchObject({ code: "42501" });
  });

  it("refuses UPDATE, DELETE and TRUNCATE even for the schema owner", async () => {
    const before = await t.privileged.query<{ n: number }>("SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1", [tenant.tenantId]);
    await expect(t.privileged.query("UPDATE audit_log SET action = 'rewritten' WHERE tenant_id = $1", [tenant.tenantId])).rejects.toThrow(/append-only/);
    await expect(t.privileged.query("DELETE FROM audit_log WHERE tenant_id = $1", [tenant.tenantId])).rejects.toThrow(/append-only/);
    await expect(t.privileged.query("TRUNCATE audit_log")).rejects.toThrow(/append-only/);
    const after = await t.privileged.query<{ n: number }>("SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1", [tenant.tenantId]);
    expect(after.rows[0]!.n).toBe(before.rows[0]!.n);
  });
});

describe("audit details", () => {
  it("redacts credential-like fields and bounds the size", () => {
    expect(redactDetails({ password: "p", nested: { apiKey: "k", token: "t", ok: 1 }, list: [{ secret: "s" }], code: "123456" })).toEqual({
      password: "[redacted]",
      nested: { apiKey: "[redacted]", token: "[redacted]", ok: 1 },
      list: [{ secret: "[redacted]" }],
      code: "[redacted]",
    });
    const big = boundedDetails({ blob: Array.from({ length: 200 }, (_, i) => "x".repeat(900) + i) });
    expect(big).toMatchObject({ truncated: true });
    expect(JSON.stringify(big).length).toBeLessThan(8_200);
  });
});
