import type { AiProviderKind } from "@bloody/contracts";
import { AiAbortError, AiProviderError, type AiProviderErrorCode } from "../errors.js";
import { scrubSecrets } from "../safety/redact.js";
import { defaultSleep, type SleepFn } from "../util/ids.js";
import { asString, isRecord, safeJsonParse, truncate } from "../util/json.js";
import type { FetchLike, FetchResponseLike } from "./types.js";

export interface HttpClientOptions {
  fetch: FetchLike;
  providerKind: AiProviderKind;
  providerId?: string | null;
  /** Per-attempt timeout (connect + full body). Default 60s. */
  timeoutMs?: number;
  /** Retries for 408/425/429/5xx/529, timeouts and network errors. Default 2. */
  maxRetries?: number;
  retryBaseMs?: number;
  retryMaxMs?: number;
  /** Maximum response body size. Default 8 MiB. */
  maxResponseBytes?: number;
  sleep?: SleepFn;
  random?: () => number;
  userAgent?: string;
}

export interface HttpRequest {
  url: string;
  method: "GET" | "POST";
  headers: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
  /** Called before every attempt (e.g. SigV4 re-signing with a fresh timestamp). */
  prepareHeaders?: (headers: Record<string, string>) => Record<string, string>;
}

export interface HttpJsonResponse {
  status: number;
  headers: { get(name: string): string | null };
  data: unknown;
}

const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504, 529]);
const ERROR_BODY_LIMIT = 64 * 1024;

export function statusToCode(status: number): AiProviderErrorCode {
  if (status === 401 || status === 403) return "auth_failed";
  if (status === 404) return "not_found";
  if (status === 413) return "request_too_large";
  if (status === 429) return "rate_limited";
  if (status === 529) return "overloaded";
  if (status >= 500) return "upstream_error";
  return "bad_request";
}

/** Pull a human-readable message out of the error envelopes used by the supported providers. */
export function extractErrorMessage(body: string): string {
  const parsed = safeJsonParse(body);
  if (parsed.ok) {
    const v = parsed.value;
    if (isRecord(v)) {
      const err = v.error;
      if (typeof err === "string") return err; // ollama
      if (isRecord(err)) {
        const msg = asString(err.message) ?? asString(err.type);
        if (msg) return msg; // openai, anthropic, gemini, azure
      }
      const msg = asString(v.message) ?? asString(v.Message) ?? asString(v.detail);
      if (msg) return msg; // bedrock, vllm
    }
    if (Array.isArray(v) && v.length > 0) return extractErrorMessage(JSON.stringify(v[0])); // gemini batch errors
  }
  return body;
}

export function parseRetryAfter(headers: { get(name: string): string | null }, now = Date.now()): number | null {
  const ms = headers.get("retry-after-ms");
  if (ms && /^\d+(\.\d+)?$/.test(ms)) return Math.round(Number(ms));
  const ra = headers.get("retry-after");
  if (!ra) return null;
  if (/^\d+(\.\d+)?$/.test(ra.trim())) return Math.round(Number(ra) * 1000);
  const at = Date.parse(ra);
  return Number.isNaN(at) ? null : Math.max(0, at - now);
}

/** Read a response body up to `limit` bytes; throws `response_too_large` beyond it. */
export async function readBodyLimited(res: FetchResponseLike, limit: number, kind: AiProviderKind, providerId: string | null): Promise<string> {
  if (!res.body) {
    const text = await res.text();
    if (Buffer.byteLength(text, "utf8") > limit) throw tooLarge(kind, providerId, limit);
    return text;
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let out = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => undefined);
      throw tooLarge(kind, providerId, limit);
    }
    out += decoder.decode(value, { stream: true });
  }
  return out + decoder.decode();
}

function tooLarge(kind: AiProviderKind, providerId: string | null, limit: number): AiProviderError {
  return new AiProviderError({ code: "response_too_large", message: `Provider response exceeded ${limit} bytes`, providerKind: kind, providerId, retryable: false });
}

/**
 * HTTP transport shared by every provider: per-attempt timeout, exponential backoff with jitter
 * (honouring Retry-After), redirect refusal (SSRF), body size limits and credential-free errors.
 */
export class HttpClient {
  readonly kind: AiProviderKind;
  readonly providerId: string | null;
  private readonly fetchImpl: FetchLike;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly retryBaseMs: number;
  private readonly retryMaxMs: number;
  readonly maxResponseBytes: number;
  private readonly sleep: SleepFn;
  private readonly random: () => number;
  private readonly userAgent: string;

  constructor(opts: HttpClientOptions) {
    this.fetchImpl = opts.fetch;
    this.kind = opts.providerKind;
    this.providerId = opts.providerId ?? null;
    this.timeoutMs = opts.timeoutMs ?? 60_000;
    this.maxRetries = Math.max(0, opts.maxRetries ?? 2);
    this.retryBaseMs = opts.retryBaseMs ?? 500;
    this.retryMaxMs = opts.retryMaxMs ?? 8_000;
    this.maxResponseBytes = opts.maxResponseBytes ?? 8 * 1024 * 1024;
    this.sleep = opts.sleep ?? defaultSleep;
    this.random = opts.random ?? Math.random;
    this.userAgent = opts.userAgent ?? "Bloody-AI-SOC/1.0";
  }

  async json(req: HttpRequest): Promise<HttpJsonResponse> {
    return this.withRetries(req, async (res) => {
      const text = await readBodyLimited(res, this.maxResponseBytes, this.kind, this.providerId);
      const parsed = safeJsonParse(text);
      if (!parsed.ok) {
        throw new AiProviderError({
          code: "invalid_response",
          message: `Provider returned a non-JSON response (${truncate(scrubSecrets(text), 120)})`,
          providerKind: this.kind,
          providerId: this.providerId,
          status: res.status,
        });
      }
      return { status: res.status, headers: res.headers, data: parsed.value };
    });
  }

  /**
   * Streamed request: `onLine` receives every text line (SSE or NDJSON). Retries happen only
   * before the first line has been delivered, so callers never see duplicated deltas.
   */
  async stream(req: HttpRequest, onLine: (line: string) => void): Promise<{ status: number }> {
    let delivered = false;
    return this.withRetries(
      req,
      async (res) => {
        if (!res.body) {
          const text = await readBodyLimited(res, this.maxResponseBytes, this.kind, this.providerId);
          for (const line of text.split(/\r?\n/)) {
            delivered = true;
            onLine(line);
          }
          return { status: res.status };
        }
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let total = 0;
        let pending = "";
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            total += value.byteLength;
            if (total > this.maxResponseBytes) throw tooLarge(this.kind, this.providerId, this.maxResponseBytes);
            pending += decoder.decode(value, { stream: true });
            let nl: number;
            while ((nl = pending.indexOf("\n")) >= 0) {
              const line = pending.slice(0, nl).replace(/\r$/, "");
              pending = pending.slice(nl + 1);
              delivered = true;
              onLine(line);
            }
          }
        } catch (err) {
          await reader.cancel().catch(() => undefined);
          throw err;
        }
        pending += decoder.decode();
        if (pending.length > 0) {
          delivered = true;
          onLine(pending.replace(/\r$/, ""));
        }
        return { status: res.status };
      },
      () => !delivered,
    );
  }

  private async withRetries<T>(req: HttpRequest, onOk: (res: FetchResponseLike) => Promise<T>, canRetry: () => boolean = () => true): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      if (req.signal?.aborted) throw new AiAbortError(undefined, req.signal.reason);
      try {
        return await this.attempt(req, onOk);
      } catch (err) {
        if (err instanceof AiAbortError) throw err;
        const providerErr =
          err instanceof AiProviderError
            ? err
            : new AiProviderError({
                code: "network_error",
                message: `Network error contacting AI provider: ${scrubSecrets(err instanceof Error ? err.message : String(err))}`,
                providerKind: this.kind,
                providerId: this.providerId,
                retryable: true,
                cause: err,
              });
        if (!providerErr.retryable || attempt >= this.maxRetries || !canRetry()) throw providerErr;
        const backoff = Math.min(this.retryMaxMs, this.retryBaseMs * 2 ** attempt) * (0.5 + this.random() * 0.5);
        const delay = providerErr.retryAfterMs !== null ? Math.min(this.retryMaxMs, providerErr.retryAfterMs) : backoff;
        try {
          await this.sleep(delay, req.signal);
        } catch (sleepErr) {
          throw new AiAbortError(undefined, sleepErr);
        }
      }
    }
  }

  private async attempt<T>(req: HttpRequest, onOk: (res: FetchResponseLike) => Promise<T>): Promise<T> {
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort(new Error("timeout"));
    }, this.timeoutMs);
    const onUserAbort = (): void => controller.abort(req.signal?.reason);
    req.signal?.addEventListener("abort", onUserAbort, { once: true });
    try {
      const baseHeaders: Record<string, string> = { "user-agent": this.userAgent, ...req.headers };
      const headers = req.prepareHeaders ? req.prepareHeaders(baseHeaders) : baseHeaders;
      const res = await this.fetchImpl(req.url, {
        method: req.method,
        headers,
        ...(req.body !== undefined ? { body: req.body } : {}),
        signal: controller.signal,
        redirect: "error",
      });
      if (!res.ok) {
        let body = "";
        try {
          body = await readBodyLimited(res, ERROR_BODY_LIMIT, this.kind, this.providerId);
        } catch {
          body = "";
        }
        const message = truncate(scrubSecrets(extractErrorMessage(body) || `HTTP ${res.status}`), 500);
        throw new AiProviderError({
          code: statusToCode(res.status),
          message: `AI provider returned HTTP ${res.status}: ${message}`,
          providerKind: this.kind,
          providerId: this.providerId,
          status: res.status,
          retryable: RETRYABLE_STATUS.has(res.status),
          retryAfterMs: parseRetryAfter(res.headers),
        });
      }
      return await onOk(res);
    } catch (err) {
      if (req.signal?.aborted) throw new AiAbortError(undefined, err);
      if (timedOut) {
        throw new AiProviderError({
          code: "timeout",
          message: `AI provider did not respond within ${this.timeoutMs} ms`,
          providerKind: this.kind,
          providerId: this.providerId,
          retryable: true,
          cause: err,
        });
      }
      throw err;
    } finally {
      clearTimeout(timer);
      req.signal?.removeEventListener("abort", onUserAbort);
    }
  }
}

export function joinUrl(base: string, path: string): string {
  return `${base.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}

/** Parse SSE lines into events ({event, data}); `data` lines are joined with "\n". */
export class SseDecoder {
  private event: string | null = null;
  private data: string[] = [];

  push(line: string): { event: string | null; data: string } | null {
    if (line === "") {
      if (this.data.length === 0) {
        this.event = null;
        return null;
      }
      const out = { event: this.event, data: this.data.join("\n") };
      this.event = null;
      this.data = [];
      return out;
    }
    if (line.startsWith(":")) return null; // comment / keep-alive
    const colon = line.indexOf(":");
    const field = colon >= 0 ? line.slice(0, colon) : line;
    let value = colon >= 0 ? line.slice(colon + 1) : "";
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "event") this.event = value;
    else if (field === "data") this.data.push(value);
    return null;
  }

  flush(): { event: string | null; data: string } | null {
    return this.push("");
  }
}
