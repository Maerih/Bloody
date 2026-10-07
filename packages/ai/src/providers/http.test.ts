import { describe, expect, it } from "vitest";
import { AiAbortError, AiProviderError } from "../errors.js";
import { fakeFetch } from "../test-support/fake-fetch.js";
import { noSleep } from "../test-support/fixtures.js";
import { HttpClient, parseRetryAfter } from "./http.js";

function client(fetch: ReturnType<typeof fakeFetch>["fetch"], extra: Partial<ConstructorParameters<typeof HttpClient>[0]> = {}): HttpClient {
  return new HttpClient({ fetch, providerKind: "openai", providerId: "p1", sleep: noSleep, maxRetries: 2, ...extra });
}

describe("HttpClient", () => {
  it("retries 429/5xx with backoff, honouring Retry-After", async () => {
    const delays: number[] = [];
    const { fetch, requests } = fakeFetch([{ status: 429, headers: { "retry-after": "2" }, json: { error: { message: "slow down" } } }, { status: 503, text: "busy" }, { json: { ok: true } }]);
    const http = client(fetch, { sleep: async (ms) => void delays.push(ms), retryMaxMs: 5000, random: () => 0 });
    const res = await http.json({ url: "https://api.example.com/x", method: "GET", headers: {} });
    expect(res.data).toEqual({ ok: true });
    expect(requests).toHaveLength(3);
    expect(delays[0]).toBe(2000);
    expect(delays[1]).toBe(500); // base 500 * 2^1 * (0.5 + 0)
    expect(requests[0]!.redirect).toBe("error");
  });

  it("does not retry 400 and redacts secrets in error messages", async () => {
    const { fetch, requests } = fakeFetch([{ status: 400, json: { error: { message: "bad key sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" } } }]);
    const err = await client(fetch).json({ url: "https://api.example.com/x", method: "POST", headers: {}, body: "{}" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AiProviderError);
    expect((err as AiProviderError).code).toBe("bad_request");
    expect((err as AiProviderError).message).not.toContain("ABCDEFGHIJKLMNOP");
    expect(requests).toHaveLength(1);
  });

  it("maps auth failures without retrying", async () => {
    const { fetch } = fakeFetch([{ status: 401, json: { error: { message: "invalid x-api-key" } } }]);
    await expect(client(fetch).json({ url: "https://a.example.com", method: "GET", headers: {} })).rejects.toMatchObject({ code: "auth_failed", status: 401, retryable: false });
  });

  it("times out, retries and reports a timeout error", async () => {
    const { fetch, requests } = fakeFetch([{ hang: true }]);
    const err = await client(fetch, { timeoutMs: 20, maxRetries: 1 }).json({ url: "https://a.example.com", method: "GET", headers: {} }).catch((e: unknown) => e);
    expect((err as AiProviderError).code).toBe("timeout");
    expect(requests).toHaveLength(2);
  });

  it("propagates caller aborts without retrying", async () => {
    const { fetch, requests } = fakeFetch([{ hang: true }]);
    const ctrl = new AbortController();
    const p = client(fetch, { timeoutMs: 10_000 }).json({ url: "https://a.example.com", method: "GET", headers: {}, signal: ctrl.signal });
    ctrl.abort();
    await expect(p).rejects.toBeInstanceOf(AiAbortError);
    expect(requests).toHaveLength(1);
  });

  it("enforces the response size limit", async () => {
    const { fetch } = fakeFetch([{ chunks: ["{\"a\":\"", "x".repeat(2000), "\"}"] }]);
    await expect(client(fetch, { maxResponseBytes: 1000 }).json({ url: "https://a.example.com", method: "GET", headers: {} })).rejects.toMatchObject({ code: "response_too_large" });
  });

  it("retries network errors", async () => {
    const { fetch, requests } = fakeFetch((_, i) => (i === 0 ? { error: new TypeError("fetch failed: ECONNRESET") } : { json: { ok: 1 } }));
    await expect(client(fetch).json({ url: "https://a.example.com", method: "GET", headers: {} })).resolves.toMatchObject({ data: { ok: 1 } });
    expect(requests).toHaveLength(2);
  });

  it("streams lines across chunk boundaries", async () => {
    const { fetch } = fakeFetch([{ chunks: ["data: one\n", "\ndata: t", "wo\n\n"] }]);
    const lines: string[] = [];
    await client(fetch).stream({ url: "https://a.example.com", method: "POST", headers: {}, body: "{}" }, (l) => lines.push(l));
    expect(lines).toEqual(["data: one", "", "data: two", ""]);
  });

  it("parses Retry-After variants", () => {
    const h = (o: Record<string, string>) => ({ get: (n: string) => o[n] ?? null });
    expect(parseRetryAfter(h({ "retry-after-ms": "150" }))).toBe(150);
    expect(parseRetryAfter(h({ "retry-after": "3" }))).toBe(3000);
    expect(parseRetryAfter(h({ "retry-after": new Date(10_000).toUTCString() }), 0)).toBe(10_000);
    expect(parseRetryAfter(h({}))).toBeNull();
  });
});
