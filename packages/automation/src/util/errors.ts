/**
 * Typed errors of the automation package. Every error carries a stable machine `code` so the
 * API can map it onto the uniform `ApiError` envelope (e.g. `self_approval` → 403).
 */
export class AutomationError extends Error {
  readonly code: string;
  readonly details: Record<string, unknown> | undefined;

  constructor(code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "AutomationError";
    this.code = code;
    this.details = details;
  }
}

/** Invalid channel / rule / playbook configuration supplied by a user. */
export class ConfigError extends AutomationError {
  readonly issues: { path: string; message: string }[];

  constructor(message: string, issues: { path: string; message: string }[] = []) {
    super("invalid_config", message, { issues });
    this.name = "ConfigError";
    this.issues = issues;
  }
}

/** A notification channel delivery failed. `retryable` drives retry + dead-lettering. */
export class DeliveryError extends AutomationError {
  readonly retryable: boolean;
  readonly status: number | undefined;

  constructor(code: string, message: string, opts: { retryable: boolean; status?: number; details?: Record<string, unknown> }) {
    super(code, message, opts.details);
    this.name = "DeliveryError";
    this.retryable = opts.retryable;
    this.status = opts.status;
  }
}

/** A user-supplied URL / host resolves to a forbidden network range (SSRF guard). */
export class SsrfBlockedError extends DeliveryError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("ssrf_blocked", message, { retryable: false, ...(details ? { details } : {}) });
    this.name = "SsrfBlockedError";
  }
}

/** Optimistic-concurrency conflict (record changed since it was read). */
export class ConcurrencyError extends AutomationError {
  constructor(message: string, details?: Record<string, unknown>) {
    super("concurrent_modification", message, details);
    this.name = "ConcurrencyError";
  }
}
