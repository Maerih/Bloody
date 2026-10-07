import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { DeliveryError, SsrfBlockedError } from "../util/errors.js";
import { assertSafeUrl, checkAddress, createGuardedLookup, type LookupFunction, type SsrfPolicy } from "./ssrf.js";

export interface HttpRequest {
  url: string;
  method: "POST";
  headers: Record<string, string>;
  body: string;
  timeoutMs?: number;
  /** Per-request SSRF policy (e.g. Slack host allow-list). */
  ssrf?: SsrfPolicy;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  /** Response body, truncated to the transport's limit. */
  body: string;
}

/** Outbound HTTP port. Tests inject a fake; production uses {@link NodeHttpTransport}. */
export interface HttpTransport {
  request(req: HttpRequest): Promise<HttpResponse>;
}

export interface NodeHttpTransportOptions {
  /** Baseline policy merged under each request's policy. */
  ssrf?: SsrfPolicy;
  timeoutMs?: number;
  maxResponseBytes?: number;
  userAgent?: string;
  /** For tests of the guard itself. */
  lookup?: LookupFunction;
}

/**
 * Hardened outbound HTTP client for webhooks: SSRF guard (static + connect-time DNS check),
 * no redirects, bounded response size, hard timeout, TLS verification always on.
 */
export class NodeHttpTransport implements HttpTransport {
  private readonly opts: Required<Omit<NodeHttpTransportOptions, "lookup" | "ssrf">> & { ssrf: SsrfPolicy; lookup?: LookupFunction };

  constructor(opts: NodeHttpTransportOptions = {}) {
    this.opts = {
      ssrf: opts.ssrf ?? {},
      timeoutMs: opts.timeoutMs ?? 10_000,
      maxResponseBytes: opts.maxResponseBytes ?? 64 * 1024,
      userAgent: opts.userAgent ?? "Bloody-Notifications/1.0",
      ...(opts.lookup ? { lookup: opts.lookup } : {}),
    };
  }

  async request(req: HttpRequest): Promise<HttpResponse> {
    const policy: SsrfPolicy = { ...this.opts.ssrf, ...req.ssrf };
    const url = assertSafeUrl(req.url, policy);
    const host = url.hostname.replace(/^\[|\]$/g, "");
    if (isIP(host)) {
      const v = checkAddress(host, policy);
      if (v.blocked) throw new SsrfBlockedError(v.reason ?? "destination blocked", { host });
    }
    const lookup = createGuardedLookup(policy, this.opts.lookup);
    const timeoutMs = Math.min(req.timeoutMs ?? this.opts.timeoutMs, 60_000);
    const body = Buffer.from(req.body, "utf8");
    const doRequest = url.protocol === "https:" ? httpsRequest : httpRequest;
    return new Promise<HttpResponse>((resolve, reject) => {
      const r = doRequest(
        url,
        {
          method: req.method,
          headers: { "User-Agent": this.opts.userAgent, ...req.headers, "Content-Length": String(body.length) },
          lookup: lookup as never,
          timeout: timeoutMs,
          rejectUnauthorized: true,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on("data", (chunk: Buffer) => {
            if (size >= this.opts.maxResponseBytes) return;
            const room = this.opts.maxResponseBytes - size;
            const piece = chunk.length > room ? chunk.subarray(0, room) : chunk;
            chunks.push(piece);
            size += piece.length;
          });
          res.on("end", () => {
            const headers: Record<string, string> = {};
            for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) headers[k] = Array.isArray(v) ? v.join(", ") : v;
            resolve({ status: res.statusCode ?? 0, headers, body: Buffer.concat(chunks).toString("utf8") });
          });
          res.on("error", (err) => reject(new DeliveryError("network_error", err.message, { retryable: true })));
        },
      );
      const deadline = setTimeout(() => r.destroy(new DeliveryError("timeout", `request timed out after ${timeoutMs} ms`, { retryable: true })), timeoutMs);
      r.on("timeout", () => r.destroy(new DeliveryError("timeout", `request timed out after ${timeoutMs} ms`, { retryable: true })));
      r.on("error", (err) => {
        clearTimeout(deadline);
        if (err instanceof DeliveryError) reject(err);
        else reject(new DeliveryError("network_error", err.message, { retryable: true }));
      });
      r.on("close", () => clearTimeout(deadline));
      r.end(body);
    });
  }
}

/** Map an HTTP response onto success / retryable / permanent failure. Redirects are never followed. */
export function assertHttpOk(res: HttpResponse, what: string): void {
  if (res.status >= 200 && res.status < 300) return;
  const retryable = res.status === 408 || res.status === 425 || res.status === 429 || res.status >= 500;
  const reason = res.status >= 300 && res.status < 400 ? "redirects are not followed" : res.body.slice(0, 300).replace(/\s+/g, " ");
  throw new DeliveryError(`http_${res.status}`, `${what} responded ${res.status}${reason ? `: ${reason}` : ""}`, { retryable, status: res.status });
}
