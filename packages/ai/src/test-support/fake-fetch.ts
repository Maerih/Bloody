import type { FetchInitLike, FetchLike, FetchResponseLike } from "../providers/types.js";

/** Test-only scripted fetch. Records every request and replays canned responses. */

export interface RecordedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  rawBody: string | undefined;
  body: unknown;
  redirect: FetchInitLike["redirect"];
}

export interface FakeResponseSpec {
  status?: number;
  json?: unknown;
  text?: string;
  headers?: Record<string, string>;
  /** Body delivered as these chunks (for streaming tests). */
  chunks?: string[];
  /** Reject the fetch with this error (network failure). */
  error?: Error;
  /** Never resolve until aborted (timeout tests). */
  hang?: boolean;
}

export type Responder = (req: RecordedRequest, index: number) => FakeResponseSpec | Promise<FakeResponseSpec>;

function makeBody(chunks: string[]): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const c of chunks) controller.enqueue(enc.encode(c));
      controller.close();
    },
  });
}

export function sseChunks(events: Array<unknown | string>, opts: { done?: boolean; eventNames?: boolean } = {}): string[] {
  const out = events.map((e) => {
    if (typeof e === "string") return `data: ${e}\n\n`;
    const name = opts.eventNames && typeof e === "object" && e !== null && "type" in e ? `event: ${(e as { type: string }).type}\n` : "";
    return `${name}data: ${JSON.stringify(e)}\n\n`;
  });
  if (opts.done) out.push("data: [DONE]\n\n");
  return out;
}

export function fakeFetch(responder: Responder | FakeResponseSpec[]): { fetch: FetchLike; requests: RecordedRequest[] } {
  const requests: RecordedRequest[] = [];
  const fetch: FetchLike = async (url, init) => {
    let body: unknown = init.body;
    if (typeof init.body === "string") {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = init.body;
      }
    }
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(init.headers)) headers[k.toLowerCase()] = v;
    const rec: RecordedRequest = { url, method: init.method, headers, rawBody: init.body, body, redirect: init.redirect };
    const index = requests.length;
    requests.push(rec);
    const spec = Array.isArray(responder) ? (responder[Math.min(index, responder.length - 1)] ?? { status: 500 }) : await responder(rec, index);
    if (spec.error) throw spec.error;
    if (spec.hang) {
      return new Promise<FetchResponseLike>((_, reject) => {
        const abort = (): void => reject(Object.assign(new Error("The operation was aborted"), { name: "AbortError" }));
        if (init.signal?.aborted) abort();
        init.signal?.addEventListener("abort", abort, { once: true });
      });
    }
    const status = spec.status ?? 200;
    const text = spec.text ?? (spec.json !== undefined ? JSON.stringify(spec.json) : "");
    const chunks = spec.chunks ?? [text];
    const hdrs = Object.fromEntries(Object.entries(spec.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    const res: FetchResponseLike = {
      status,
      ok: status >= 200 && status < 300,
      headers: { get: (name: string) => hdrs[name.toLowerCase()] ?? null },
      body: makeBody(chunks),
      text: async () => chunks.join(""),
    };
    return res;
  };
  return { fetch, requests };
}
