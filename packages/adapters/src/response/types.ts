import { actionRisk, Uuid, type ActionRisk, type ResponseActionKey, type ResponseActionStatus } from "@bloody/contracts";
import { canonicalJson, sha256Hex } from "../core/hash.js";
import type { EngineClient } from "../http/client.js";
import { EngineError } from "../http/client.js";

/**
 * Response connectors drive containment through an engine's own API (Wazuh active
 * response, Velociraptor collections, firewall/DNS relays). They are the LAST hop after the
 * control plane's RBAC check, approval gate and audit write — and they re-check the
 * invariants themselves (defence in depth): high-risk actions need a recorded approver who
 * is not the requester, targets are validated, and every call returns a structured,
 * audit-ready result instead of throwing.
 */

export interface ResponseTarget {
  kind: "asset" | "identity" | "indicator" | "incident";
  id: string;
  label?: string;
}

export interface ResponseExecutionRequest {
  /** `ResponseActionRecord.id` — correlation id for audit and idempotency key for engines. */
  actionId: string;
  tenantId: string;
  organizationId: string;
  action: ResponseActionKey;
  target: ResponseTarget;
  parameters: Record<string, unknown>;
  reason: string;
  requestedBy: string;
  requestedVia: "user" | "playbook" | "ai";
  approvedBy?: string | null;
  /** Build and return the engine call without sending it (approval preview). */
  dryRun?: boolean;
}

export interface ResponseDeps {
  client: EngineClient;
  clock?: () => Date;
}

export type ResponseOutcome = "succeeded" | "partial" | "failed" | "rejected" | "dry_run";

/** What was (or would be) sent to the engine — safe to store: no credentials, body hashed. */
export interface EngineCallRecord {
  method: string;
  url: string;
  /** SHA-256 of the canonical request body, so auditors can prove what was sent. */
  bodySha256: string | null;
  /** The request body with secrets removed (small, structured). */
  body: unknown;
  status: number | null;
  durationMs: number | null;
}

export interface ResponseAuditRecord {
  /** `audit_log.action`, e.g. "response.isolate_endpoint". */
  action: string;
  at: string;
  tenantId: string;
  organizationId: string;
  actor: string;
  via: "user" | "playbook" | "ai";
  approvedBy: string | null;
  risk: ActionRisk;
  target: ResponseTarget;
  engine: string;
  connector: string;
  outcome: ResponseOutcome;
  reason: string;
  engineRef: string | null;
  details: Record<string, string | number | boolean>;
}

export interface ResponseExecutionResult {
  actionId: string;
  action: ResponseActionKey;
  connector: string;
  engine: string;
  outcome: ResponseOutcome;
  /** Status to store on the `ResponseActionRecord`. */
  status: ResponseActionStatus;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  target: ResponseTarget;
  /** Engine-side reference (Velociraptor flow id, Wazuh agent list…) for follow-up. */
  engineRef: string | null;
  affected: string[];
  failed: Array<{ id: string; reason: string }>;
  call: EngineCallRecord | null;
  /** One-line, human-readable summary for timelines, notifications and reports. */
  summary: string;
  error?: { code: string; message: string };
  /** How to undo this action, when the engine supports it. */
  reversal?: { action: ResponseActionKey; parameters: Record<string, unknown> };
  audit: ResponseAuditRecord;
}

export type ResponseActionHandler = (req: ResponseExecutionRequest, deps: ResponseDeps) => Promise<ResponseExecutionResult>;

export class ResponseGuardError extends Error {
  constructor(
    readonly code: "unsupported_action" | "approval_required" | "self_approval" | "invalid_target" | "invalid_parameters" | "invalid_request",
    message: string,
  ) {
    super(message);
    this.name = "ResponseGuardError";
  }
}

/** Invariants every connector enforces before touching an engine. */
export function guardRequest(req: ResponseExecutionRequest, supported: readonly ResponseActionKey[]): void {
  if (!Uuid.safeParse(req.actionId).success) throw new ResponseGuardError("invalid_request", "actionId must be a UUID");
  if (!Uuid.safeParse(req.tenantId).success || !Uuid.safeParse(req.organizationId).success) {
    throw new ResponseGuardError("invalid_request", "tenantId and organizationId must be UUIDs");
  }
  if (!supported.includes(req.action)) throw new ResponseGuardError("unsupported_action", `action ${req.action} is not supported by this connector`);
  if (!req.reason || req.reason.trim().length < 3) throw new ResponseGuardError("invalid_request", "a justification (reason) is required");
  if (req.dryRun) return;
  if (actionRisk(req.action) === "high") {
    if (!req.approvedBy) throw new ResponseGuardError("approval_required", `${req.action} is high-risk and requires a recorded approval`);
    if (req.approvedBy === req.requestedBy) throw new ResponseGuardError("self_approval", "the approver must be a different principal than the requester");
  }
}

export interface ConnectorMeta {
  connector: string;
  engine: string;
}

export interface PreparedCall {
  method: "GET" | "POST" | "PUT" | "DELETE";
  path: string;
  query?: Record<string, string | number | boolean | ReadonlyArray<string | number> | undefined>;
  json?: unknown;
  /** Pre-serialized body (e.g. when it is signed); sent verbatim with `contentType`. */
  body?: string;
  contentType?: string;
  headers?: Record<string, string>;
  /** Body as it may be stored in audit (secrets removed). Defaults to `json`. */
  auditBody?: unknown;
}

export interface ExecutionOutcome {
  outcome: Exclude<ResponseOutcome, "rejected" | "dry_run">;
  affected: string[];
  failed: Array<{ id: string; reason: string }>;
  engineRef: string | null;
  summary: string;
  details?: Record<string, string | number | boolean>;
  reversal?: ResponseExecutionResult["reversal"];
}

function statusFor(outcome: ResponseOutcome): ResponseActionStatus {
  switch (outcome) {
    case "succeeded":
      return "succeeded";
    case "partial":
    case "failed":
      return "failed";
    case "rejected":
      return "rejected";
    case "dry_run":
      return "pending_approval";
  }
}

/**
 * Shared execution pipeline: guard → prepare → (dry-run | send) → interpret → audit record.
 * Never throws: guard violations become `rejected`, engine errors become `failed`.
 */
export async function executeResponse(
  meta: ConnectorMeta,
  supported: readonly ResponseActionKey[],
  req: ResponseExecutionRequest,
  deps: ResponseDeps,
  prepare: (req: ResponseExecutionRequest) => PreparedCall,
  interpret: (data: unknown, status: number, call: PreparedCall) => ExecutionOutcome,
): Promise<ResponseExecutionResult> {
  const clock = deps.clock ?? (() => new Date());
  const startedAt = clock();
  const base = { actionId: req.actionId, action: req.action, connector: meta.connector, engine: meta.engine, target: req.target };
  const finish = (
    outcome: ResponseOutcome,
    rest: Partial<Omit<ResponseExecutionResult, "audit" | "outcome" | "status">> & { summary: string; details?: Record<string, string | number | boolean> },
  ): ResponseExecutionResult => {
    const finishedAt = clock();
    const { details, ...fields } = rest;
    const result: ResponseExecutionResult = {
      ...base,
      outcome,
      status: statusFor(outcome),
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      durationMs: Math.max(0, finishedAt.getTime() - startedAt.getTime()),
      engineRef: fields.engineRef ?? null,
      affected: fields.affected ?? [],
      failed: fields.failed ?? [],
      call: fields.call ?? null,
      summary: fields.summary,
      ...(fields.error ? { error: fields.error } : {}),
      ...(fields.reversal ? { reversal: fields.reversal } : {}),
      audit: {
        action: `response.${req.action}`,
        at: finishedAt.toISOString(),
        tenantId: req.tenantId,
        organizationId: req.organizationId,
        actor: req.requestedBy,
        via: req.requestedVia,
        approvedBy: req.approvedBy ?? null,
        risk: actionRisk(req.action),
        target: req.target,
        engine: meta.engine,
        connector: meta.connector,
        outcome,
        reason: req.reason,
        engineRef: fields.engineRef ?? null,
        details: details ?? {},
      },
    };
    return result;
  };

  let call: PreparedCall;
  let url: URL;
  try {
    guardRequest(req, supported);
    call = prepare(req);
    url = deps.client.resolve(call.path, call.query);
  } catch (err) {
    const code = err instanceof ResponseGuardError ? err.code : err instanceof EngineError ? err.code : "invalid_request";
    return finish("rejected", { summary: `Rejected ${req.action}: ${(err as Error).message}`, error: { code, message: (err as Error).message } });
  }

  const auditBody = call.auditBody ?? call.json ?? null;
  const record: EngineCallRecord = {
    method: call.method,
    url: url.toString(),
    bodySha256: call.body !== undefined ? sha256Hex(call.body) : call.json !== undefined ? sha256Hex(canonicalJson(call.json)) : null,
    body: auditBody,
    status: null,
    durationMs: null,
  };
  if (req.dryRun) {
    return finish("dry_run", { call: record, summary: `Dry run: would ${call.method} ${new URL(record.url).pathname} on ${meta.engine} for ${req.target.label ?? req.target.id}` });
  }

  try {
    const res = await deps.client.request<unknown>({
      method: call.method,
      path: call.path,
      ...(call.query ? { query: call.query } : {}),
      ...(call.body !== undefined ? { body: call.body } : call.json !== undefined ? { json: call.json } : {}),
      headers: { "idempotency-key": req.actionId, ...(call.body !== undefined ? { "content-type": call.contentType ?? "application/json" } : {}), ...call.headers },
      // Containment calls are never blindly retried: a timeout may still have executed.
      retry: false,
    });
    record.status = res.status;
    record.durationMs = res.durationMs;
    const out = interpret(res.data, res.status, call);
    return finish(out.outcome, { ...out, call: record });
  } catch (err) {
    if (err instanceof EngineError) {
      record.status = err.details.status ?? null;
      return finish("failed", {
        call: record,
        summary: `${req.action} via ${meta.engine} failed: ${err.code}`,
        error: { code: err.code, message: err.message },
        details: { retryable: err.details.retryable },
      });
    }
    return finish("failed", { call: record, summary: `${req.action} via ${meta.engine} failed`, error: { code: "interpretation_failed", message: (err as Error).message } });
  }
}

/** Read a string parameter. */
export function paramString(req: ResponseExecutionRequest, key: string): string | undefined {
  const v = req.parameters[key];
  return typeof v === "string" && v.trim() !== "" ? v.trim() : undefined;
}

export function paramStringList(req: ResponseExecutionRequest, key: string): string[] {
  const v = req.parameters[key];
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string" && x.trim() !== "").map((x) => x.trim());
  if (typeof v === "string" && v.trim() !== "") return v.split(",").map((x) => x.trim()).filter(Boolean);
  return [];
}
