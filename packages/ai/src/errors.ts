import type { AiProviderKind } from "@bloody/contracts";

/**
 * Error taxonomy of the AI SOC package. Every error carries a stable machine-readable `code`
 * so the API can map it to an `ApiError` envelope without parsing messages. Messages never
 * contain credentials (provider bodies are redacted before they are attached).
 */
export class AiError extends Error {
  readonly code: string;
  readonly details: Record<string, unknown> | undefined;

  constructor(code: string, message: string, options?: { cause?: unknown; details?: Record<string, unknown> }) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = new.target.name;
    this.code = code;
    this.details = options?.details;
  }
}

export type AiProviderErrorCode =
  | "auth_failed"
  | "bad_request"
  | "not_found"
  | "rate_limited"
  | "overloaded"
  | "upstream_error"
  | "request_too_large"
  | "response_too_large"
  | "invalid_response"
  | "timeout"
  | "network_error"
  | "content_filtered"
  | "all_providers_failed";

export interface AiProviderErrorInit {
  code: AiProviderErrorCode;
  message: string;
  providerKind: AiProviderKind;
  providerId?: string | null;
  status?: number | null;
  retryable?: boolean;
  retryAfterMs?: number | null;
  cause?: unknown;
  details?: Record<string, unknown>;
}

/** A model provider failed (HTTP error, timeout, malformed response…). */
export class AiProviderError extends AiError {
  override readonly code: AiProviderErrorCode;
  readonly providerKind: AiProviderKind;
  readonly providerId: string | null;
  readonly status: number | null;
  readonly retryable: boolean;
  readonly retryAfterMs: number | null;

  constructor(init: AiProviderErrorInit) {
    super(init.code, init.message, {
      ...(init.cause !== undefined ? { cause: init.cause } : {}),
      ...(init.details !== undefined ? { details: init.details } : {}),
    });
    this.code = init.code;
    this.providerKind = init.providerKind;
    this.providerId = init.providerId ?? null;
    this.status = init.status ?? null;
    this.retryable = init.retryable ?? false;
    this.retryAfterMs = init.retryAfterMs ?? null;
  }
}

/** The caller aborted the request (never retried, never falls back). */
export class AiAbortError extends AiError {
  constructor(message = "AI request aborted by caller", cause?: unknown) {
    super("aborted", message, cause !== undefined ? { cause } : undefined);
  }
}

/** A tenant/data-governance policy forbids the operation (e.g. tenant data to a cloud model). */
export class AiPolicyError extends AiError {}

/** Provider configuration is incomplete or invalid. */
export class AiConfigError extends AiError {}

/** The principal is not allowed to perform the AI operation. */
export class AiAccessDeniedError extends AiError {}

/** Conversation / provider / entity not found within the caller's tenant. */
export class AiNotFoundError extends AiError {}

/** The model produced output that does not satisfy the required structure. */
export class AiOutputError extends AiError {}

/** Tenant AI quota (plan `aiRequestsPerDay`) exhausted. */
export class AiQuotaExceededError extends AiError {}

export type SsrfReason =
  | "invalid_url"
  | "unsupported_scheme"
  | "credentials_in_url"
  | "https_required"
  | "metadata_endpoint"
  | "link_local"
  | "loopback"
  | "private_address"
  | "private_hostname"
  | "reserved_address"
  | "unresolvable";

/** An endpoint was rejected by the SSRF guard. */
export class SsrfBlockedError extends AiError {
  readonly reason: SsrfReason;
  constructor(reason: SsrfReason, message: string) {
    super("ssrf_blocked", message, { details: { reason } });
    this.reason = reason;
  }
}

export function isAbortError(err: unknown): boolean {
  if (err instanceof AiAbortError) return true;
  return typeof err === "object" && err !== null && (err as { name?: unknown }).name === "AbortError";
}

/** Safe, credential-free description of an arbitrary thrown value. */
export function describeError(err: unknown): { code: string; message: string } {
  if (err instanceof AiError) return { code: err.code, message: err.message };
  if (err instanceof Error) return { code: "internal_error", message: err.message };
  return { code: "internal_error", message: String(err) };
}
