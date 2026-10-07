import type { FetchLike } from "../http/client.js";

/** Minimal fetch router for tests: matches method + path (string or RegExp), records calls. */

export interface RecordedCall {
  method: string;
  url: URL;
  headers: Record<string, string>;
  body: string | null;
}

export interface Route {
  method: string;
  path: string | RegExp;
  status?: number;
  json?: unknown | ((call: RecordedCall) => unknown);
  text?: string;
  headers?: Record<string, string>;
  /** Respond only this many times (then fall through to later routes). */
  times?: number;
}

export function mockFetch(routes: Route[]): { fetch: FetchLike; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const used = new Map<Route, number>();
  const fetch: FetchLike = async (input, init) => {
    const url = new URL(input);
    const headers: Record<string, string> = {};
    const h = init.headers;
    if (h && typeof h === "object" && !Array.isArray(h) && !(h instanceof Headers)) {
      for (const [k, v] of Object.entries(h as Record<string, string>)) headers[k.toLowerCase()] = v;
    }
    const body = typeof init.body === "string" ? init.body : init.body instanceof Uint8Array ? new TextDecoder().decode(init.body) : null;
    const call: RecordedCall = { method: init.method ?? "GET", url, headers, body };
    calls.push(call);
    for (const r of routes) {
      if (r.method !== call.method) continue;
      const match = typeof r.path === "string" ? r.path === url.pathname : r.path.test(url.pathname + url.search);
      if (!match) continue;
      const n = used.get(r) ?? 0;
      if (r.times !== undefined && n >= r.times) continue;
      used.set(r, n + 1);
      const payload = typeof r.json === "function" ? (r.json as (c: RecordedCall) => unknown)(call) : r.json;
      const text = r.text ?? (payload !== undefined ? JSON.stringify(payload) : "");
      return new Response(text, { status: r.status ?? 200, headers: { "content-type": r.text !== undefined ? "text/plain" : "application/json", ...r.headers } });
    }
    return new Response(JSON.stringify({ detail: "not found" }), { status: 404, headers: { "content-type": "application/json" } });
  };
  return { fetch, calls };
}

/** Resolver used in tests: public documentation-free addresses for test host names. */
export const testResolver = async (host: string): Promise<string[]> => {
  if (host.endsWith(".internal-test")) return ["10.0.0.10"];
  if (host === "rebind.example.com") return ["169.254.169.254"];
  return ["93.184.216.34"];
};
