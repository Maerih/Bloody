import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TEST_PASSWORD, createTenant, createTestApp, type TestApp, type TestTenant } from "../test/harness.js";

let t: TestApp;
let own: TestTenant;
let demo: TestTenant;

/** A browser: keeps cookies and sends the CSRF header on unsafe requests. */
function browser() {
  const jar = new Map<string, string>();
  const store = (res: { headers: Record<string, unknown> }) => {
    const raw = res.headers["set-cookie"];
    for (const c of (Array.isArray(raw) ? raw : raw ? [raw] : []) as string[]) {
      const [pair, ...attrs] = c.split(";");
      const [name, ...rest] = pair!.split("=");
      const value = rest.join("=");
      const expired = attrs.some((a) => /expires=thu, 01 jan 1970/i.test(a.trim())) || value === "";
      if (expired) jar.delete(name!.trim());
      else jar.set(name!.trim(), value);
    }
  };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  const call = async (method: "GET" | "POST", url: string, body?: object) => {
    const res = await t.app.inject({
      method,
      url: `/api/v1${url}`,
      headers: { cookie: cookie(), ...(method === "POST" ? { "content-type": "application/json", "x-csrf-token": jar.get("bloody_csrf") ?? "", origin: "http://localhost" } : {}), host: "localhost" },
      ...(body ? { payload: JSON.stringify(body) } : method === "POST" ? { payload: "{}" } : {}),
    });
    store(res);
    return { status: res.statusCode, body: res.body ? (JSON.parse(res.body) as Record<string, any>) : {} };
  };
  return { call, jar };
}

beforeAll(async () => {
  t = await createTestApp({ deps: { hostResolver: false } });
  own = await createTenant(t, { orgs: 1, plan: "mssp", name: "Visitor MSSP" });
  demo = await createTenant(t, { orgs: 2, plan: "mssp", name: "SCIAT Demo" });
});
afterAll(async () => {
  await t?.close();
});

describe("Demo sandbox", () => {
  it("is off until the operator chooses a demo account", async () => {
    const b = browser();
    expect((await b.call("POST", "/auth/login", { email: own.admin.email, password: TEST_PASSWORD })).status).toBe(200);
    expect((await b.call("GET", "/sandbox")).body).toMatchObject({ available: false, inSandbox: false });
    expect((await b.call("POST", "/sandbox/enter")).status).toBe(404);
  });

  it("switches into the demo account read-only and back to the visitor's own session", async () => {
    (t.services.config.sandbox as { accountId: string | null }).accountId = demo.tenantId;
    const b = browser();
    await b.call("POST", "/auth/login", { email: own.admin.email, password: TEST_PASSWORD });
    expect((await b.call("GET", "/sandbox")).body).toMatchObject({ available: true, accountName: "SCIAT Demo", inSandbox: false });

    expect((await b.call("POST", "/sandbox/enter")).status).toBe(200);
    const me = (await b.call("GET", "/auth/me")).body;
    expect(me.account.name).toBe("SCIAT Demo");
    expect(me.session.method).toBe("sandbox");
    expect(me.organizations).toHaveLength(2);
    expect((await b.call("GET", "/sandbox")).body.inSandbox).toBe(true);
    // Read-only: reading works, changing anything does not.
    expect((await b.call("GET", "/incidents")).status).toBe(200);
    expect((await b.call("POST", "/organizations", { name: "Should fail", slug: "nope" })).status).toBe(403);
    expect((await b.call("POST", "/sandbox/enter")).body).toMatchObject({ alreadyInSandbox: true });

    expect((await b.call("POST", "/sandbox/exit")).body).toEqual({ restored: true });
    const back = (await b.call("GET", "/auth/me")).body;
    expect(back.account.name).toBe("Visitor MSSP");
    expect(back.session.method).toBe("password");
    expect(b.jar.has("bloody_sandbox_return")).toBe(false);
    // The sandbox session is revoked; only one demo visitor exists.
    const visitors = await t.privileged.query("SELECT count(*)::int AS n FROM users WHERE tenant_id = $1 AND email LIKE 'sandbox@%'", [demo.tenantId]);
    expect(visitors.rows[0].n).toBe(1);
    const audit = await t.privileged.query("SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1 AND action = 'sandbox.entered'", [own.tenantId]);
    expect(audit.rows[0].n).toBe(1);
  });

  it("refuses API keys / bearer tokens and exit outside the sandbox", async () => {
    const b = browser();
    await b.call("POST", "/auth/login", { email: own.admin.email, password: TEST_PASSWORD });
    expect((await b.call("POST", "/sandbox/exit")).status).toBe(400);
    const token = (await t.app.inject({ method: "POST", url: "/api/v1/auth/login", headers: { "content-type": "application/json" }, payload: JSON.stringify({ email: own.admin.email, password: TEST_PASSWORD }) })).json().token;
    const viaBearer = await t.app.inject({ method: "POST", url: "/api/v1/sandbox/enter", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, payload: "{}" });
    expect(viaBearer.statusCode).toBe(400);
  });
});
