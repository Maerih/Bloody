import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { ZodError } from "zod";
import type { ApiError as ApiErrorEnvelope } from "@bloody/contracts";

/**
 * Uniform error model. Every non-2xx response is `{ error: { code, message, requestId, details? } }`
 * (contracts `ApiError`). Internal details (SQL, stack traces) are logged, never returned.
 */
export class HttpError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
    readonly headers?: Record<string, string>,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export const badRequest = (message: string, details?: unknown) => new HttpError(400, "bad_request", message, details);
export const unauthorized = (message = "Authentication required", code = "unauthorized") => new HttpError(401, code, message);
export const forbidden = (message = "You do not have permission to perform this action", code = "forbidden") => new HttpError(403, code, message);
export const notFound = (what = "Resource") => new HttpError(404, "not_found", `${what} not found`);
export const conflict = (message: string, details?: unknown) => new HttpError(409, "conflict", message, details);
export const unprocessable = (message: string, details?: unknown) => new HttpError(422, "unprocessable", message, details);

function envelope(code: string, message: string, requestId: string, details?: unknown): ApiErrorEnvelope {
  return { error: { code, message, requestId, ...(details === undefined ? {} : { details }) } };
}

interface PgLikeError {
  code?: string;
  constraint?: string;
  detail?: string;
  severity?: string;
  routine?: string;
}

function isPgError(err: unknown): err is PgLikeError & Error {
  return err instanceof Error && typeof (err as PgLikeError).code === "string" && /^[0-9A-Z]{5}$/.test((err as PgLikeError).code!) && typeof (err as PgLikeError).severity === "string";
}

export function zodDetails(err: ZodError): Array<{ path: string; message: string; code: string }> {
  return err.issues.slice(0, 50).map((i) => ({ path: i.path.join("."), message: i.message, code: i.code }));
}

export function toHttpError(err: unknown): HttpError {
  if (err instanceof HttpError) return err;
  if (err instanceof ZodError) return new HttpError(400, "validation_error", "Request validation failed", zodDetails(err));
  if (isPgError(err)) {
    switch (err.code) {
      case "23505":
        return new HttpError(409, "conflict", "A record with the same unique key already exists", err.constraint ? { constraint: err.constraint } : undefined);
      case "23503":
        return new HttpError(409, "reference_conflict", "The request references a record that does not exist or is still referenced", err.constraint ? { constraint: err.constraint } : undefined);
      case "23514":
      case "23502":
      case "22P02":
      case "22001":
      case "22003":
      case "22007":
      case "22008":
        return new HttpError(400, "invalid_value", "A value is invalid for this field", err.constraint ? { constraint: err.constraint } : undefined);
      case "42501":
        // RLS WITH CHECK violations and append-only guards surface here.
        return new HttpError(403, "forbidden", "The operation is not permitted on this record");
      case "40001":
      case "40P01":
        return new HttpError(503, "retry", "Concurrent update conflict — please retry", undefined, { "retry-after": "1" });
      case "57014":
        return new HttpError(503, "timeout", "The query took too long — narrow the request");
      default:
        break;
    }
  }
  const fe = err as FastifyError;
  if (fe && typeof fe.statusCode === "number" && fe.statusCode >= 400 && fe.statusCode < 500) {
    if (fe.validation) return new HttpError(400, "validation_error", fe.message, fe.validation);
    if (fe.statusCode === 429) return new HttpError(429, "rate_limited", fe.message || "Too many requests");
    if (fe.statusCode === 413) return new HttpError(413, "payload_too_large", "Request body is too large");
    if (fe.statusCode === 415) return new HttpError(415, "unsupported_media_type", fe.message);
    return new HttpError(fe.statusCode, fe.code ? fe.code.toLowerCase().replace(/^fst_err_/, "") : "bad_request", fe.message);
  }
  return new HttpError(500, "internal_error", "An unexpected error occurred");
}

export function registerErrorHandling(app: FastifyInstance): void {
  app.setErrorHandler((err: unknown, request: FastifyRequest, reply: FastifyReply) => {
    const http = toHttpError(err);
    if (http.statusCode >= 500) request.log.error({ err }, "request failed");
    else if (!(err instanceof HttpError)) request.log.info({ err: { message: (err as Error)?.message, code: (err as PgLikeError)?.code } }, "request rejected");
    if (http.headers) for (const [k, v] of Object.entries(http.headers)) void reply.header(k, v);
    void reply.status(http.statusCode).send(envelope(http.code, http.message, request.id, http.details));
  });
  app.setNotFoundHandler((request: FastifyRequest, reply: FastifyReply) => {
    void reply.status(404).send(envelope("route_not_found", `No route for ${request.method} ${request.url.split("?")[0]}`, request.id));
  });
}
