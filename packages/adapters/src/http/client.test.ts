import { describe, expect, it } from "vitest";
import { z } from "zod";
import { classifyIp, inferDirection, isExternalIp, parseIPv6 } from "../net/ip.js";
import { mockFetch, testResolver } from "../test-support/http.js";
import { cachedTokenProvider, EngineClient, EngineError, type EngineRequestLog, type FetchLike } from "./client.js";
import { runHealthCheck } from "./health.js";
import { redactUrl, UnsafeUrlError, validateEngineUrl } from "./url-guard.js";

const noSleep = async (): Promise<void> => undefined;

function reason(fn: () => unknown): string | undefined {
  try {
    fn();
    return undefined;
  } catch (err) {
    return err instanceof UnsafeUrlError ? err.reason : `other:${(err as Error).message}`;
  }
}

describe("IP classification", () => {
  it("classifies IPv4 / IPv6 ranges including embedded IPv4 forms", () => {
    expect(classifyIp("10.1.2.3")).toBe("private");
    expect(classifyIp("100.100.100.200")).toBe("metadata");
    expect(classifyIp("169.254.169.254")).toBe("metadata");
    expect(classifyIp("169.254.10.1")).toBe("link_local");
    expect(classifyIp("127.0.0.1")).toBe("loopback");
    expect(classifyIp("8.8.8.8")).toBe("public");
    expect(classifyIp("203.0.113.9")).toBe("documentation");
    expect(classifyIp("::1")).toBe("loopback");
    expect(classifyIp("::ffff:127.0.0.1")).toBe("loopback");
    expect(classifyIp("[::ffff:a9fe:a9fe]")).toBe("metadata");
    expect(classifyIp("fd00:ec2::254")).toBe("metadata");
    expect(classifyIp("fe80::1%eth0")).toBe("link_local");
    expect(classifyIp("fc00::5")).toBe("private");
    expect(classifyIp("2606:4700::1111")).toBe("public");
    expect(classifyIp("010.0.0.1")).toBeUndefined();
    expect(classifyIp("example.com")).toBeUndefined();
    expect(parseIPv6("1:2:3:4:5:6:7:8:9")).toBeUndefined();
    expect(parseIPv6("2001:db8::1")).toEqual([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
  });

  it("derives traffic direction from the organization's perspective", () => {
    expect(inferDirection("10.0.0.1", "8.8.8.8")).toBe("outbound");
    expect(inferDirection("203.0.113.1", "192.168.1.1")).toBe("inbound");
    expect(inferDirection("10.0.0.1", "172.16.0.1")).toBe("lateral");
    expect(inferDirection(undefined, "8.8.8.8")).toBe("unknown");
    expect(isExternalIp("198.51.100.1")).toBe(true);
  });
});

describe("SSRF URL guard", () => {
  it("requires https, refuses credentials and metadata / link-local targets", () => {
    expect(reason(() => validateEngineUrl("https://wazuh.acme.example:55000"))).toBeUndefined();
    expect(reason(() => validateEngineUrl("http://wazuh.acme.example"))).toBe("scheme_not_allowed");
    expect(reason(() => validateEngineUrl("http://wazuh.acme.example", { allowHttp: true }))).toBeUndefined();
    expect(reason(() => validateEngineUrl("https://user:pw@wazuh.acme.example"))).toBe("credentials_in_url");
    expect(reason(() => validateEngineUrl("https://169.254.169.254/latest/meta-data", { allowPrivateNetworks: true, allowLoopback: true }))).toBe("metadata_host");
    expect(reason(() => validateEngineUrl("https://metadata.google.internal", { allowPrivateNetworks: true }))).toBe("metadata_host");
    expect(reason(() => validateEngineUrl("https://[fe80::1]/"))).toBe("blocked_address_class");
    expect(reason(() => validateEngineUrl("file:///etc/passwd"))).toBe("scheme_not_allowed");
    expect(reason(() => validateEngineUrl("not a url"))).toBe("invalid_url");
  });

  it("loopback and private networks only when explicitly allowed (on-prem relays)", () => {
    expect(reason(() => validateEngineUrl("https://127.0.0.1:9200"))).toBe("loopback");
    expect(reason(() => validateEngineUrl("https://2130706433/"))).toBe("loopback"); // decimal form canonicalized by URL
    expect(reason(() => validateEngineUrl("https://[::ffff:127.0.0.1]/"))).toBe("loopback");
    expect(reason(() => validateEngineUrl("https://localhost:8443"))).toBe("loopback");
    expect(reason(() => validateEngineUrl("https://127.0.0.1:9200", { allowLoopback: true }))).toBeUndefined();
    expect(reason(() => validateEngineUrl("https://10.0.0.5:55000"))).toBe("private_network");
    expect(reason(() => validateEngineUrl("https://wazuh.security.svc.cluster.local"))).toBe("private_network");
    expect(reason(() => validateEngineUrl("https://wazuh"))).toBe("private_network");
    expect(reason(() => validateEngineUrl("https://10.0.0.5:55000", { allowPrivateNetworks: true }))).toBeUndefined();
  });

  it("allow/deny lists and ports", () => {
    expect(reason(() => validateEngineUrl("https://a.evil.example", { allowedHosts: ["*.acme.example"] }))).toBe("host_not_allowed");
    expect(reason(() => validateEngineUrl("https://misp.acme.example", { allowedHosts: ["*.acme.example"] }))).toBeUndefined();
    expect(reason(() => validateEngineUrl("https://misp.acme.example:8443", { allowedPorts: [443] }))).toBe("port_not_allowed");
    expect(redactUrl("https://u:p@h.example/x?api_key=abc&page=2")).toBe("https://h.example/x?api_key=***&page=2");
  });
});

describe("EngineClient", () => {
  it("sends auth headers, encodes queries and validates responses with zod", async () => {
    const { fetch, calls } = mockFetch([{ method: "GET", path: "/api/items", json: { items: [1, 2] } }]);
    const logs: EngineRequestLog[] = [];
    const client = new EngineClient({ engine: "test", baseUrl: "https://engine.acme.example/api/", auth: { kind: "basic", username: "svc", password: "pw" }, fetch, resolveHost: testResolver, onRequest: (l) => logs.push(l) });
    const res = await client.get("/items", { query: { tag: ["a", "b"], page: 2, skip: undefined }, schema: z.object({ items: z.array(z.number()) }) });
    expect(res.data.items).toEqual([1, 2]);
    expect(calls[0]?.url.toString()).toBe("https://engine.acme.example/api/items?tag=a&tag=b&page=2");
    expect(calls[0]?.headers["authorization"]).toBe(`Basic ${Buffer.from("svc:pw").toString("base64")}`);
    expect(logs[0]).toMatchObject({ engine: "test", method: "GET", status: 200, attempt: 1 });
    expect(JSON.stringify(logs)).not.toContain("Basic");

    await expect(client.get("/items", { schema: z.object({ other: z.string() }) })).rejects.toMatchObject({ code: "schema_mismatch" });
  });

  it("api-key and bearer auth", async () => {
    const { fetch, calls } = mockFetch([{ method: "GET", path: "/x", json: {} }]);
    await new EngineClient({ engine: "t", baseUrl: "https://e.acme.example", auth: { kind: "api_key", header: "X-API-Key", value: "k1" }, fetch, resolveHost: testResolver }).get("/x");
    await new EngineClient({ engine: "t", baseUrl: "https://e.acme.example", auth: { kind: "bearer", token: "tok" }, fetch, resolveHost: testResolver }).get("/x");
    expect(calls[0]?.headers["x-api-key"]).toBe("k1");
    expect(calls[1]?.headers["authorization"]).toBe("Bearer tok");
  });

  it("refuses path traversal, origin escape, redirects and DNS names resolving to metadata", async () => {
    const { fetch } = mockFetch([{ method: "GET", path: "/r", status: 302, json: {}, headers: { location: "http://169.254.169.254/" } }]);
    const client = new EngineClient({ engine: "t", baseUrl: "https://e.acme.example", fetch, resolveHost: testResolver });
    expect(() => client.resolve("/../admin")).toThrow(EngineError);
    expect(() => client.resolve("//evil.example/x")).toThrow(EngineError);
    expect(() => client.resolve("relative")).toThrow(EngineError);
    await expect(client.get("/r")).rejects.toMatchObject({ code: "redirect_blocked" });
    const rebinding = new EngineClient({ engine: "t", baseUrl: "https://rebind.example.com", fetch, resolveHost: testResolver });
    await expect(rebinding.get("/x")).rejects.toMatchObject({ code: "unsafe_url" });
    expect(() => new EngineClient({ engine: "t", baseUrl: "http://e.acme.example", fetch })).toThrow(UnsafeUrlError);
  });

  it("times out, retries idempotent calls on 503 but never retries POST", async () => {
    const hanging: FetchLike = (_url, init) =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      });
    const slow = new EngineClient({ engine: "t", baseUrl: "https://e.acme.example", fetch: hanging, timeoutMs: 20, retries: 0, resolveHost: testResolver });
    await expect(slow.get("/x")).rejects.toMatchObject({ code: "timeout" });

    const flaky = mockFetch([
      { method: "GET", path: "/x", status: 503, json: { error: "busy" }, times: 1 },
      { method: "GET", path: "/x", json: { ok: true } },
      { method: "POST", path: "/x", status: 503, json: {} },
    ]);
    const client = new EngineClient({ engine: "t", baseUrl: "https://e.acme.example", fetch: flaky.fetch, sleep: noSleep, resolveHost: testResolver });
    expect((await client.get<{ ok: boolean }>("/x")).data.ok).toBe(true);
    expect(flaky.calls.filter((c) => c.method === "GET")).toHaveLength(2);
    await expect(client.post("/x", { json: {} })).rejects.toMatchObject({ code: "http", details: { status: 503 } });
    expect(flaky.calls.filter((c) => c.method === "POST")).toHaveLength(1);
  });

  it("refreshes a token once on 401 and redacts tokens from error messages", async () => {
    let logins = 0;
    const getToken = cachedTokenProvider(async () => ({ token: `tok-${++logins}`, expiresInSeconds: 3600 }));
    const { fetch, calls } = mockFetch([
      { method: "GET", path: "/me", status: 401, json: { detail: "expired" }, times: 1 },
      { method: "GET", path: "/me", json: { user: "svc" } },
      { method: "GET", path: "/fail", status: 400, json: { detail: "bad", authorization: "Bearer abc.def.ghi" } },
    ]);
    const client = new EngineClient({ engine: "t", baseUrl: "https://e.acme.example", auth: { kind: "token_provider", getToken }, fetch, resolveHost: testResolver });
    await client.get("/me");
    expect(logins).toBe(2);
    expect(calls.map((c) => c.headers["authorization"])).toEqual(["Bearer tok-1", "Bearer tok-2"]);
    const err = (await client.get("/fail").then(
      () => undefined,
      (e: unknown) => e,
    )) as EngineError;
    expect(err).toBeInstanceOf(EngineError);
    expect(err.message).not.toContain("abc.def.ghi");
  });

  it("enforces the response size limit", async () => {
    const { fetch } = mockFetch([{ method: "GET", path: "/big", text: "x".repeat(5000) }]);
    const client = new EngineClient({ engine: "t", baseUrl: "https://e.acme.example", fetch, maxResponseBytes: 1000, resolveHost: testResolver });
    await expect(client.get("/big", { responseType: "text" })).rejects.toMatchObject({ code: "too_large" });
  });

  it("health checks never throw", async () => {
    const h = await runHealthCheck("t", async () => {
      throw new EngineError("timeout", "timed out after 10 ms", { engine: "t", retryable: true });
    });
    expect(h).toMatchObject({ engine: "t", status: "unhealthy", ok: false, error: { code: "timeout" } });
  });
});
