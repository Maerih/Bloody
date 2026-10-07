import { ApiError as ApiErrorEnvelope, API_VERSION } from "@bloody/contracts";

/**
 * Typed fetch client for the Bloody control plane (`/api/v1`).
 *
 * - Cookie session: `credentials: "include"`; the httpOnly session cookie never touches JS.
 * - CSRF: double-submit token. The API sets a readable `bloody_csrf` cookie; every mutating
 *   request echoes it in `x-csrf-token`.
 * - Errors: every non-2xx is surfaced as {@link ApiError} parsed from the uniform envelope
 *   `{ error: { code, message, requestId, details } }`.
 * - 401: the registered unauthorized handler runs (the app routes to /login and clears the
 *   query cache so no tenant data survives the session).
 */

export const API_BASE = `/api/${API_VERSION}`;
export const CSRF_COOKIE = "bloody_csrf";
export const CSRF_HEADER = "x-csrf-token";

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
type Scalar = string | number | boolean;
export type QueryValue = Scalar | null | undefined | readonly Scalar[];
export type QueryParams = Record<string, QueryValue>;

export interface RequestOptions {
  method?: HttpMethod;
  query?: QueryParams;
  body?: unknown;
  signal?: AbortSignal;
  headers?: Record<string, string>;
  /** Do not invoke the global unauthorized handler on 401 (login, session probe). */
  skipAuthRedirect?: boolean;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | undefined;
  readonly details: unknown;

  constructor(status: number, code: string, message: string, requestId?: string, details?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.details = details;
  }

  get isUnauthorized(): boolean {
    return this.status === 401;
  }
  get isForbidden(): boolean {
    return this.status === 403;
  }
  get isNotFound(): boolean {
    return this.status === 404;
  }
  get isNetworkError(): boolean {
    return this.status === 0;
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

type UnauthorizedHandler = () => void;
let unauthorizedHandler: UnauthorizedHandler | null = null;

/** Register what happens on a 401 (the router bridge navigates to /login). Returns an unsubscribe. */
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): () => void {
  unauthorizedHandler = handler;
  return () => {
    if (unauthorizedHandler === handler) unauthorizedHandler = null;
  };
}

function defaultUnauthorized(): void {
  if (typeof window === "undefined") return;
  const { pathname, search } = window.location;
  if (pathname.startsWith("/login")) return;
  window.location.assign(`/login?next=${encodeURIComponent(pathname + search)}`);
}

export function readCookie(name: string, cookieString?: string): string | null {
  const source = cookieString ?? (typeof document !== "undefined" ? document.cookie : "");
  for (const part of source.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) {
      try {
        return decodeURIComponent(part.slice(idx + 1).trim());
      } catch {
        return part.slice(idx + 1).trim();
      }
    }
  }
  return null;
}

/** Build `/api/v1{path}?query`. Null/undefined/empty values are dropped; arrays become comma lists. */
export function buildUrl(path: string, query?: QueryParams): string {
  const normalized = path.startsWith("/") ? path : `/${path}`;
  const url = normalized.startsWith(API_BASE) ? normalized : API_BASE + normalized;
  if (!query) return url;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === null || value === undefined || value === "") continue;
    if (Array.isArray(value)) {
      if (value.length > 0) params.set(key, value.map(String).join(","));
    } else {
      params.set(key, String(value));
    }
  }
  const qs = params.toString();
  return qs ? `${url}?${qs}` : url;
}

function isMutation(method: HttpMethod): boolean {
  return method !== "GET";
}

function buildInit(opts: RequestOptions): RequestInit {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json", ...opts.headers };
  let body: BodyInit | undefined;
  if (opts.body !== undefined) {
    if (opts.body instanceof FormData || opts.body instanceof Blob) {
      body = opts.body;
    } else {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.body);
    }
  }
  if (isMutation(method)) {
    const csrf = readCookie(CSRF_COOKIE);
    if (csrf) headers[CSRF_HEADER] = csrf;
  }
  const init: RequestInit = { method, headers, credentials: "include", body };
  if (opts.signal) init.signal = opts.signal;
  return init;
}

async function parseError(res: Response): Promise<ApiError> {
  const requestIdHeader = res.headers.get("x-request-id") ?? undefined;
  let payload: unknown = null;
  try {
    const type = res.headers.get("content-type") ?? "";
    payload = type.includes("json") ? await res.json() : await res.text();
  } catch {
    payload = null;
  }
  const parsed = ApiErrorEnvelope.safeParse(payload);
  if (parsed.success) {
    const e = parsed.data.error;
    return new ApiError(res.status, e.code, e.message, e.requestId ?? requestIdHeader, e.details);
  }
  return new ApiError(res.status, `http_${res.status}`, defaultMessage(res.status), requestIdHeader);
}

function defaultMessage(status: number): string {
  switch (status) {
    case 400:
      return "The request was invalid.";
    case 401:
      return "Your session has expired. Please sign in again.";
    case 403:
      return "You don't have permission to perform this action.";
    case 404:
      return "The requested resource was not found.";
    case 409:
      return "This resource was changed by someone else. Refresh and try again.";
    case 429:
      return "Too many requests. Please slow down and retry shortly.";
    default:
      return status >= 500 ? "The Bloody API is temporarily unavailable." : `Request failed (${status}).`;
  }
}

async function send(path: string, opts: RequestOptions): Promise<Response> {
  let res: Response;
  try {
    res = await globalThis.fetch(buildUrl(path, opts.query), buildInit(opts));
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError(0, "network_error", "Unable to reach the Bloody API. Check your connection and try again.");
  }
  if (!res.ok) {
    const error = await parseError(res);
    if (res.status === 401 && !opts.skipAuthRedirect) (unauthorizedHandler ?? defaultUnauthorized)();
    throw error;
  }
  return res;
}

/** Perform a JSON request. 204/empty bodies resolve to `undefined`. */
export async function apiRequest<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const res = await send(path, opts);
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  if (text.length === 0) return undefined as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError(res.status, "invalid_response", "The API returned an unreadable response.");
  }
}

export interface DownloadResult {
  blob: Blob;
  filename: string | null;
  contentType: string;
}

/** Parse RFC 6266 Content-Disposition (`filename*=UTF-8''…` preferred over `filename="…"`). */
export function filenameFromDisposition(header: string | null): string | null {
  if (!header) return null;
  const star = /filename\*\s*=\s*([^']*)'[^']*'([^;]+)/i.exec(header);
  if (star?.[2]) {
    try {
      return decodeURIComponent(star[2].trim().replace(/^"|"$/g, ""));
    } catch {
      /* fall through */
    }
  }
  const plain = /filename\s*=\s*"?([^";]+)"?/i.exec(header);
  return plain?.[1]?.trim() ?? null;
}

/** Request returning a file (report generation, evidence export). */
export async function apiDownload(path: string, opts: RequestOptions = {}): Promise<DownloadResult> {
  const res = await send(path, { ...opts, headers: { Accept: "*/*", ...opts.headers } });
  return {
    blob: await res.blob(),
    filename: filenameFromDisposition(res.headers.get("content-disposition")),
    contentType: res.headers.get("content-type") ?? "application/octet-stream",
  };
}

type BodylessOptions = Omit<RequestOptions, "method" | "body">;

export const api = {
  get: <T>(path: string, opts?: BodylessOptions) => apiRequest<T>(path, { ...opts, method: "GET" }),
  post: <T>(path: string, body?: unknown, opts?: BodylessOptions) => apiRequest<T>(path, { ...opts, method: "POST", body }),
  put: <T>(path: string, body?: unknown, opts?: BodylessOptions) => apiRequest<T>(path, { ...opts, method: "PUT", body }),
  patch: <T>(path: string, body?: unknown, opts?: BodylessOptions) => apiRequest<T>(path, { ...opts, method: "PATCH", body }),
  delete: <T>(path: string, opts?: BodylessOptions) => apiRequest<T>(path, { ...opts, method: "DELETE" }),
  download: (path: string, opts?: RequestOptions) => apiDownload(path, opts),
};

/** User-facing message for any thrown value. */
export function errorMessage(error: unknown): string {
  if (isApiError(error)) return error.message;
  if (error instanceof Error && error.message) return error.message;
  return "Something went wrong.";
}
