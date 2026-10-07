import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, buildUrl, filenameFromDisposition, readCookie, setUnauthorizedHandler } from "./client";
import { normalizeSearchResponse } from "./hooks";
import { mockApi } from "../test/utils";

afterEach(() => {
  document.cookie = "bloody_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
  setUnauthorizedHandler(null);
});

describe("buildUrl", () => {
  it("prefixes /api/v1 and drops empty params", () => {
    expect(buildUrl("/incidents", { organizationId: null, q: "", limit: 50, severity: ["critical", "high"] })).toBe(
      "/api/v1/incidents?limit=50&severity=critical%2Chigh",
    );
    expect(buildUrl("auth/me")).toBe("/api/v1/auth/me");
  });
});

describe("api client", () => {
  it("sends credentials and the CSRF header on mutations only", async () => {
    document.cookie = "bloody_csrf=tok%20123; path=/";
    const { calls } = mockApi({ "/auth/me": { ok: true }, "POST /organizations": { id: "1" } });
    await api.get("/auth/me");
    await api.post("/organizations", { name: "x" });
    const [get, post] = calls;
    expect(get!.init.credentials).toBe("include");
    expect((get!.init.headers as Record<string, string>)["x-csrf-token"]).toBeUndefined();
    expect((post!.init.headers as Record<string, string>)["x-csrf-token"]).toBe("tok 123");
    expect((post!.init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect(post!.body).toEqual({ name: "x" });
  });

  it("parses the uniform error envelope into ApiError", async () => {
    mockApi({ "/incidents/x": { status: 403, body: { error: { code: "forbidden", message: "Nope", requestId: "req-1" } } } });
    const err = await api.get("/incidents/x").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(403);
    expect((err as ApiError).code).toBe("forbidden");
    expect((err as ApiError).requestId).toBe("req-1");
    expect((err as ApiError).isForbidden).toBe(true);
  });

  it("invokes the unauthorized handler on 401 unless skipped", async () => {
    mockApi({ "/incidents": { status: 401, body: { error: { code: "unauthorized", message: "expired" } } } });
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    await expect(api.get("/incidents")).rejects.toBeInstanceOf(ApiError);
    expect(handler).toHaveBeenCalledTimes(1);
    await expect(api.get("/incidents", { skipAuthRedirect: true })).rejects.toBeInstanceOf(ApiError);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("maps network failures to a status-0 ApiError", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    const err = (await api.get("/x").catch((e: unknown) => e)) as ApiError;
    expect(err.isNetworkError).toBe(true);
  });

  it("resolves 204 to undefined", async () => {
    mockApi({ "POST /auth/logout": { status: 204, body: null } });
    await expect(api.post("/auth/logout")).resolves.toBeUndefined();
  });
});

describe("helpers", () => {
  it("reads cookies", () => {
    expect(readCookie("b", "a=1; b=two%20words; c=3")).toBe("two words");
    expect(readCookie("z", "a=1")).toBeNull();
  });

  it("parses content-disposition filenames", () => {
    expect(filenameFromDisposition('attachment; filename="report.pdf"')).toBe("report.pdf");
    expect(filenameFromDisposition("attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf")).toBe("résumé.pdf");
    expect(filenameFromDisposition(null)).toBeNull();
  });

  it("normalizes search responses of different shapes", () => {
    expect(normalizeSearchResponse({ items: [{ kind: "incident", id: "i1", title: "Ransomware" }] })[0]).toMatchObject({
      kind: "incident",
      title: "Ransomware",
      href: "/incidents/i1",
    });
    const grouped = normalizeSearchResponse({ groups: [{ kind: "asset", items: [{ id: "a1", name: "dc01" }] }] });
    expect(grouped[0]).toMatchObject({ kind: "asset", title: "dc01", href: "/assets/a1" });
    // Unsafe external hrefs are replaced by the canonical in-app route.
    expect(normalizeSearchResponse([{ kind: "incident", id: "i2", title: "x", href: "//evil.example" }])[0]!.href).toBe("/incidents/i2");
    expect(normalizeSearchResponse("garbage")).toEqual([]);
  });
});
