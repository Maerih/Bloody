import type { ZodType, ZodTypeDef } from "zod";
import { assertResolvedSafe, redactUrl, systemResolver, UnsafeUrlError, validateEngineUrl, type HostResolver, type UrlPolicy } from "./url-guard.js";

/**
 * Small HTTP client every engine connector uses (Wazuh, Velociraptor, MISP, OpenCTI,
 * CoPilot, KEV/EPSS feeds, response webhooks).
 *
 * Secure defaults:
 *  - SSRF guard on the base URL (structural + post-DNS), path traversal / origin escape refused;
 *  - redirects are never followed (a 3xx is an error) so a hostile engine cannot bounce us
 *    into the metadata service;
 *  - hard timeout per attempt, bounded response size, bounded retries (idempotent calls only);
 *  - credentials are only ever sent as headers and never appear in errors or request logs.
 *
 * TLS: certificate verification is always on — this package offers no switch to disable it.
 * Engines with a private CA are supported by trusting that CA process-wide
 * (`NODE_EXTRA_CA_CERTS`) or by passing an undici `Agent` configured with the CA as
 * `dispatcher` (forwarded to `fetch`). Self-signed engine certificates must be replaced or
 * pinned through that CA, never skipped.
 */

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export type EngineAuth =
  | { kind: "none" }
  | { kind: "basic"; username: string; password: string }
  | { kind: "bearer"; token: string }
  | { kind: "api_key"; header: string; value: string; prefix?: string }
  | {
      kind: "token_provider";
      /** Return a (cached) token; `forceRefresh` after a 401. */
      getToken: (opts: { forceRefresh: boolean }) => Promise<string>;
      /** Authorization scheme, default "Bearer". */
      scheme?: string;
    };

export interface EngineRequestLog {
  engine: string;
  method: string;
  url: string;
  status: number | null;
  durationMs: number;
  attempt: number;
  errorCode?: EngineErrorCode;
}

export interface EngineClientOptions {
  /** Engine key (for errors, logs and audit). */
  engine: string;
  baseUrl: string;
  auth?: EngineAuth;
  fetch?: FetchLike;
  /** Per-attempt timeout. Default 15 s. */
  timeoutMs?: number;
  /** Max response body. Default 25 MiB. */
  maxResponseBytes?: number;
  /** Retries for idempotent requests on 429/502/503/504/network errors. Default 2. */
  retries?: number;
  retryBaseDelayMs?: number;
  sleep?: (ms: number) => Promise<void>;
  urlPolicy?: UrlPolicy;
  /** DNS resolver for the post-resolution SSRF check; `false` disables it (egress proxy enforces). */
  resolveHost?: HostResolver | false;
  userAgent?: string;
  defaultHeaders?: Record<string, string>;
  /** undici dispatcher (custom CA / mTLS client certificate). Never used to disable verification. */
  dispatcher?: unknown;
  clock?: () => number;
  /** Request log hook for metrics/audit (URL redacted, no headers/bodies). */
  onRequest?: (log: EngineRequestLog) => void;
}

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
export type QueryValue = string | number | boolean | undefined | null | ReadonlyArray<string | number>;

export interface EngineRequest<T> {
  method: HttpMethod;
  /** Path relative to the base URL, starting with "/". */
  path: string;
  query?: Record<string, QueryValue>;
  json?: unknown;
  form?: Record<string, string>;
  body?: string | Uint8Array;
  headers?: Record<string, string>;
  timeoutMs?: number;
  responseType?: "json" | "text" | "bytes";
  schema?: ZodType<T, ZodTypeDef, unknown>;
  /** Override idempotency for retries (default: GET/PUT/DELETE retry, POST/PATCH don't). */
  retry?: boolean;
  signal?: AbortSignal;
  skipAuth?: boolean;
  /** HTTP statuses (besides 2xx) to return instead of throwing. */
  acceptStatus?: readonly number[];
}

export interface EngineResponse<T> {
  status: number;
  headers: Headers;
  data: T;
  durationMs: number;
  url: string;
}

export type EngineErrorCode =
  | "timeout"
  | "network"
  | "http"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "rate_limited"
  | "invalid_response"
  | "too_large"
  | "unsafe_url"
  | "redirect_blocked"
  | "schema_mismatch"
  | "aborted";

export class EngineError extends Error {
  constructor(
    readonly code: EngineErrorCode,
    message: string,
    readonly details: { engine: string; status?: number; url?: string; retryable: boolean },
  ) {
    super(message);
    this.name = "EngineError";
  }
}

const DEFAULT_TIMEOUT = 15_000;
const DEFAULT_MAX_BYTES = 25 * 1024 * 1024;
const RETRYABLE_STATUS = new Set([429, 502, 503, 504]);

function sanitizeSnippet(text: string): string {
  return text
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/(bearer\s+)[a-z0-9._~+/-]+=*/gi, "$1***")
    .replace(/("?(?:token|password|secret|api[_-]?key|authorization)"?\s*[:=]\s*)"[^"]*"/gi, '$1"***"')
    .slice(0, 300);
}

async function readLimited(res: Response, max: number, engine: string, url: string): Promise<Uint8Array> {
  const declared = res.headers.get("content-length");
  if (declared && Number(declared) > max) {
    throw new EngineError("too_large", `response exceeds ${max} bytes`, { engine, status: res.status, url, retryable: false });
  }
  if (!res.body) return new Uint8Array(await res.arrayBuffer());
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => undefined);
      throw new EngineError("too_large", `response exceeds ${max} bytes`, { engine, status: res.status, url, retryable: false });
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

function encodeQuery(query: Record<string, QueryValue> | undefined): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) for (const item of v) params.append(k, String(item));
    else params.append(k, String(v));
  }
  const s = params.toString();
  return s ? `?${s}` : "";
}

export class EngineClient {
  readonly engine: string;
  readonly baseUrl: URL;
  private readonly opts: EngineClientOptions;
  private readonly fetchImpl: FetchLike;
  private readonly clock: () => number;
  private resolvedOk: { host: string; at: number } | null = null;

  constructor(opts: EngineClientOptions) {
    this.opts = opts;
    this.engine = opts.engine;
    const policy = opts.urlPolicy ?? {};
    const url = validateEngineUrl(opts.baseUrl, policy);
    if (!url.pathname.endsWith("/")) url.pathname = `${url.pathname}/`;
    url.search = "";
    url.hash = "";
    this.baseUrl = url;
    const f = opts.fetch ?? (globalThis.fetch as FetchLike | undefined);
    if (!f) throw new Error("no fetch implementation available");
    this.fetchImpl = f;
    this.clock = opts.clock ?? Date.now;
  }

  /** Non-sensitive description for audit records and the integration status page. */
  describe(): { engine: string; baseUrl: string; auth: EngineAuth["kind"] } {
    return { engine: this.engine, baseUrl: redactUrl(this.baseUrl), auth: this.opts.auth?.kind ?? "none" };
  }

  /** Resolve a relative path against the base URL, refusing anything that escapes it. */
  resolve(path: string, query?: Record<string, QueryValue>): URL {
    if (!path.startsWith("/") || path.startsWith("//") || /(^|\/)\.\.?(\/|$)/.test(path) || /[\\?#\u0000-\u001f]/.test(path)) {
      throw new EngineError("unsafe_url", "request path must be an absolute, normalized path", { engine: this.engine, retryable: false });
    }
    const prefix = this.baseUrl.pathname.replace(/\/$/, "");
    const url = new URL(`${prefix}${path}${encodeQuery(query)}`, this.baseUrl.origin);
    // WHATWG URL parsing also folds "%2e%2e" segments; the result must stay under the base path.
    if (url.origin !== this.baseUrl.origin || !url.pathname.startsWith(`${prefix}/`)) {
      throw new EngineError("unsafe_url", "request escaped the engine base URL", { engine: this.engine, retryable: false });
    }
    return url;
  }

  private async ensureResolvedSafe(): Promise<void> {
    if (this.opts.resolveHost === false) return;
    const host = this.baseUrl.hostname;
    const now = this.clock();
    if (this.resolvedOk && this.resolvedOk.host === host && now - this.resolvedOk.at < 60_000) return;
    try {
      await assertResolvedSafe(this.baseUrl, this.opts.urlPolicy ?? {}, this.opts.resolveHost ?? systemResolver);
    } catch (err) {
      if (err instanceof UnsafeUrlError) throw new EngineError("unsafe_url", err.message, { engine: this.engine, retryable: false });
      throw err;
    }
    this.resolvedOk = { host, at: now };
  }

  private async authHeaders(forceRefresh: boolean): Promise<Record<string, string>> {
    const auth = this.opts.auth ?? { kind: "none" };
    switch (auth.kind) {
      case "none":
        return {};
      case "basic":
        return { authorization: `Basic ${Buffer.from(`${auth.username}:${auth.password}`, "utf8").toString("base64")}` };
      case "bearer":
        return { authorization: `Bearer ${auth.token}` };
      case "api_key":
        return { [auth.header.toLowerCase()]: auth.prefix ? `${auth.prefix} ${auth.value}` : auth.value };
      case "token_provider": {
        const token = await auth.getToken({ forceRefresh });
        return { authorization: `${auth.scheme ?? "Bearer"} ${token}` };
      }
    }
  }

  private log(entry: EngineRequestLog): void {
    try {
      this.opts.onRequest?.(entry);
    } catch {
      // observers must never break engine calls
    }
  }

  async request<T = unknown>(req: EngineRequest<T>): Promise<EngineResponse<T>> {
    const url = this.resolve(req.path, req.query);
    const safeUrl = redactUrl(url);
    await this.ensureResolvedSafe();

    const idempotent = req.retry ?? (req.method === "GET" || req.method === "PUT" || req.method === "DELETE");
    const maxAttempts = idempotent ? 1 + Math.max(0, this.opts.retries ?? 2) : 1;
    const sleep = this.opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    const baseDelay = this.opts.retryBaseDelayMs ?? 250;

    let body: string | Uint8Array | undefined;
    const headers: Record<string, string> = {
      accept: req.responseType === "text" ? "text/plain, */*" : req.responseType === "bytes" ? "*/*" : "application/json",
      "user-agent": this.opts.userAgent ?? "Bloody-Adapters/1.0",
      ...lower(this.opts.defaultHeaders),
    };
    if (req.json !== undefined) {
      body = JSON.stringify(req.json);
      headers["content-type"] = "application/json";
    } else if (req.form) {
      body = new URLSearchParams(req.form).toString();
      headers["content-type"] = "application/x-www-form-urlencoded";
    } else if (req.body !== undefined) {
      body = req.body;
    }
    Object.assign(headers, lower(req.headers));

    let refreshedAuth = false;
    let lastError: EngineError | undefined;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const started = this.clock();
      const controller = new AbortController();
      const timeoutMs = req.timeoutMs ?? this.opts.timeoutMs ?? DEFAULT_TIMEOUT;
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const onExternalAbort = (): void => controller.abort();
      req.signal?.addEventListener("abort", onExternalAbort, { once: true });
      let res: Response;
      try {
        const auth = req.skipAuth ? {} : await this.authHeaders(false);
        const init: RequestInit = {
          method: req.method,
          headers: { ...headers, ...auth },
          redirect: "manual",
          signal: controller.signal,
        };
        if (body !== undefined) init.body = body;
        // undici extension; typed loosely so callers need not depend on undici's types
        if (this.opts.dispatcher !== undefined) (init as Record<string, unknown>)["dispatcher"] = this.opts.dispatcher;
        res = await this.fetchImpl(url.toString(), init);
      } catch (err) {
        clearTimeout(timer);
        req.signal?.removeEventListener("abort", onExternalAbort);
        // Errors raised while obtaining credentials (token login, 2FA refusal) are final.
        if (err instanceof EngineError) throw err;
        const aborted = controller.signal.aborted;
        const code: EngineErrorCode = req.signal?.aborted ? "aborted" : aborted ? "timeout" : "network";
        lastError = new EngineError(code, code === "timeout" ? `timed out after ${timeoutMs} ms` : `request failed: ${sanitizeSnippet((err as Error).message ?? "")}`, {
          engine: this.engine,
          url: safeUrl,
          retryable: code !== "aborted",
        });
        this.log({ engine: this.engine, method: req.method, url: safeUrl, status: null, durationMs: this.clock() - started, attempt, errorCode: code });
        if (code === "aborted" || attempt === maxAttempts) throw lastError;
        await sleep(baseDelay * 2 ** (attempt - 1));
        continue;
      }

      try {
        const status = res.status;
        if (status >= 300 && status < 400) {
          await res.body?.cancel().catch(() => undefined);
          throw new EngineError("redirect_blocked", `engine answered with redirect ${status}; redirects are not followed`, { engine: this.engine, status, url: safeUrl, retryable: false });
        }
        if (status === 401 && !refreshedAuth && this.opts.auth?.kind === "token_provider" && !req.skipAuth) {
          refreshedAuth = true;
          await res.body?.cancel().catch(() => undefined);
          await this.opts.auth.getToken({ forceRefresh: true });
          this.log({ engine: this.engine, method: req.method, url: safeUrl, status, durationMs: this.clock() - started, attempt, errorCode: "unauthorized" });
          attempt--; // token refresh does not consume a retry
          continue;
        }
        const accepted = (status >= 200 && status < 300) || (req.acceptStatus?.includes(status) ?? false);
        if (!accepted) {
          const bytes = await readLimited(res, 64 * 1024, this.engine, safeUrl).catch(() => new Uint8Array());
          const snippet = sanitizeSnippet(new TextDecoder().decode(bytes));
          const code: EngineErrorCode =
            status === 401 ? "unauthorized" : status === 403 ? "forbidden" : status === 404 ? "not_found" : status === 429 ? "rate_limited" : "http";
          throw new EngineError(code, `HTTP ${status}${snippet ? `: ${snippet}` : ""}`, {
            engine: this.engine,
            status,
            url: safeUrl,
            retryable: RETRYABLE_STATUS.has(status),
          });
        }
        const bytes = await readLimited(res, this.opts.maxResponseBytes ?? DEFAULT_MAX_BYTES, this.engine, safeUrl);
        let data: unknown;
        const type = req.responseType ?? "json";
        if (type === "bytes") data = bytes;
        else {
          const text = new TextDecoder().decode(bytes);
          if (type === "text") data = text;
          else if (text.trim() === "") data = null;
          else {
            try {
              data = JSON.parse(text);
            } catch {
              throw new EngineError("invalid_response", `expected JSON from ${this.engine}`, { engine: this.engine, status, url: safeUrl, retryable: false });
            }
          }
        }
        if (req.schema) {
          const parsed = req.schema.safeParse(data);
          if (!parsed.success) {
            const issues = parsed.error.issues
              .slice(0, 3)
              .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
              .join("; ");
            throw new EngineError("schema_mismatch", `unexpected ${this.engine} response shape: ${issues}`, { engine: this.engine, status, url: safeUrl, retryable: false });
          }
          data = parsed.data;
        }
        const durationMs = this.clock() - started;
        this.log({ engine: this.engine, method: req.method, url: safeUrl, status, durationMs, attempt });
        return { status, headers: res.headers, data: data as T, durationMs, url: safeUrl };
      } catch (err) {
        const e =
          err instanceof EngineError
            ? err
            : new EngineError(controller.signal.aborted ? "timeout" : "network", sanitizeSnippet((err as Error).message ?? "error"), {
                engine: this.engine,
                url: safeUrl,
                retryable: true,
              });
        lastError = e;
        this.log({ engine: this.engine, method: req.method, url: safeUrl, status: e.details.status ?? null, durationMs: this.clock() - started, attempt, errorCode: e.code });
        if (!e.details.retryable || attempt === maxAttempts) throw e;
        const retryAfter = Number(res.headers.get("retry-after"));
        await sleep(Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter * 1000, 30_000) : baseDelay * 2 ** (attempt - 1));
      } finally {
        clearTimeout(timer);
        req.signal?.removeEventListener("abort", onExternalAbort);
      }
    }
    throw lastError ?? new EngineError("network", "request failed", { engine: this.engine, url: safeUrl, retryable: false });
  }

  get<T = unknown>(path: string, opts: Omit<EngineRequest<T>, "method" | "path"> = {}): Promise<EngineResponse<T>> {
    return this.request<T>({ ...opts, method: "GET", path });
  }

  post<T = unknown>(path: string, opts: Omit<EngineRequest<T>, "method" | "path"> = {}): Promise<EngineResponse<T>> {
    return this.request<T>({ ...opts, method: "POST", path });
  }

  put<T = unknown>(path: string, opts: Omit<EngineRequest<T>, "method" | "path"> = {}): Promise<EngineResponse<T>> {
    return this.request<T>({ ...opts, method: "PUT", path });
  }

  delete<T = unknown>(path: string, opts: Omit<EngineRequest<T>, "method" | "path"> = {}): Promise<EngineResponse<T>> {
    return this.request<T>({ ...opts, method: "DELETE", path });
  }
}

function lower(h: Record<string, string> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!h) return out;
  for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = v;
  return out;
}

/** Token cache helper for engines with login endpoints (Wazuh JWT, CoPilot OAuth2 password flow). */
export function cachedTokenProvider(
  login: () => Promise<{ token: string; expiresInSeconds?: number }>,
  opts: { clock?: () => number; defaultTtlSeconds?: number; refreshSkewSeconds?: number } = {},
): (o: { forceRefresh: boolean }) => Promise<string> {
  const clock = opts.clock ?? Date.now;
  let cached: { token: string; expiresAt: number } | null = null;
  let inflight: Promise<string> | null = null;
  return async ({ forceRefresh }) => {
    const now = clock();
    if (!forceRefresh && cached && now < cached.expiresAt) return cached.token;
    if (inflight) return inflight;
    inflight = (async () => {
      try {
        const r = await login();
        const ttl = r.expiresInSeconds ?? opts.defaultTtlSeconds ?? 600;
        const skew = opts.refreshSkewSeconds ?? 30;
        cached = { token: r.token, expiresAt: clock() + Math.max(1, ttl - skew) * 1000 };
        return r.token;
      } finally {
        inflight = null;
      }
    })();
    return inflight;
  };
}
