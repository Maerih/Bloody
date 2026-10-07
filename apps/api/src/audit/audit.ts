import type { FastifyRequest } from "fastify";
import type { Queryable } from "../db/pool.js";

/**
 * Append-only audit trail. Rows are hash-chained per tenant by a database trigger and can
 * never be updated or deleted (trigger + revoked privileges). Domain handlers record inside
 * their own transaction (`recordAudit`) so the audit row commits atomically with the change;
 * the generic mutation hook (see app.ts) covers everything else, including denied requests.
 */

export type AuditOutcome = "success" | "denied" | "failure";

export interface AuditEntry {
  action: string;
  organizationId?: string | null;
  targetKind?: string | null;
  targetId?: string | null;
  outcome?: AuditOutcome;
  details?: Record<string, unknown>;
}

export interface AuditActor {
  tenantId: string;
  actorKind: "user" | "service" | "system" | "anonymous";
  actorId: string | null;
  actorLabel: string | null;
  ip: string | null;
  userAgent: string | null;
  requestId: string | null;
}

const SENSITIVE_KEY = /pass(word)?|secret|token|api[-_]?key|authorization|cookie|totp|otp|mfa.?code|^code$|credential|private|content(base64)?$/i;
const MAX_DETAIL_CHARS = 8_000;

/** Deep-redact credential-like keys and bound the size of audit details. */
export function redactDetails(value: unknown, depth = 0): unknown {
  if (depth > 6) return "[depth-limit]";
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redactDetails(v, depth + 1));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>).slice(0, 100)) out[k] = SENSITIVE_KEY.test(k) ? "[redacted]" : redactDetails(v, depth + 1);
    return out;
  }
  if (typeof value === "string" && value.length > 1000) return `${value.slice(0, 1000)}…`;
  return value;
}

export function boundedDetails(details: Record<string, unknown> | undefined): Record<string, unknown> {
  const redacted = (redactDetails(details ?? {}) as Record<string, unknown>) ?? {};
  const json = JSON.stringify(redacted);
  return json.length <= MAX_DETAIL_CHARS ? redacted : { truncated: true, preview: json.slice(0, MAX_DETAIL_CHARS) };
}

export async function writeAudit(tx: Queryable, actor: AuditActor, entry: AuditEntry): Promise<void> {
  await tx.query(
    `INSERT INTO audit_log (tenant_id, organization_id, actor_kind, actor_id, actor_label, action, target_kind, target_id, outcome, ip, user_agent, request_id, details)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
    [
      actor.tenantId,
      entry.organizationId ?? null,
      actor.actorKind,
      actor.actorId,
      actor.actorLabel,
      entry.action,
      entry.targetKind ?? null,
      entry.targetId ?? null,
      entry.outcome ?? "success",
      actor.ip,
      actor.userAgent?.slice(0, 500) ?? null,
      actor.requestId,
      JSON.stringify(boundedDetails(entry.details)),
    ],
  );
}

export function actorFromRequest(request: FastifyRequest, tenantId?: string): AuditActor {
  const auth = request.auth;
  const tid = tenantId ?? auth?.tenantId ?? request.auditState.tenantId;
  if (!tid) throw new Error("audit requires a tenant");
  return {
    tenantId: tid,
    actorKind: auth ? auth.principal.kind : "anonymous",
    actorId: auth ? auth.principal.id : null,
    actorLabel: auth ? (auth.principal.email ?? auth.principal.displayName ?? null) : (request.auditState.actorLabel ?? null),
    ip: request.ip ?? null,
    userAgent: (request.headers["user-agent"] as string | undefined) ?? null,
    requestId: request.id,
  };
}

/** Record an audit row inside the handler's transaction and mark the request as audited. */
export async function recordAudit(tx: Queryable, request: FastifyRequest, entry: AuditEntry): Promise<void> {
  await writeAudit(tx, actorFromRequest(request), entry);
  request.auditState.recorded = true;
}

export const SYSTEM_ACTOR = (tenantId: string, component: string): AuditActor => ({
  tenantId,
  actorKind: "system",
  actorId: component,
  actorLabel: component,
  ip: null,
  userAgent: null,
  requestId: null,
});
