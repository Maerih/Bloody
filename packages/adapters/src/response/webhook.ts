import type { ResponseActionKey } from "@bloody/contracts";
import { hmacSha256Hex, safeEqualHex } from "../core/hash.js";
import { isPublicDomain, normalizeObservable } from "../core/indicators.js";
import { field, int, str } from "../core/json.js";
import { classifyIp } from "../net/ip.js";
import {
  executeResponse,
  paramString,
  ResponseGuardError,
  type ExecutionOutcome,
  type PreparedCall,
  type ResponseActionHandler,
  type ResponseDeps,
  type ResponseExecutionRequest,
  type ResponseExecutionResult,
} from "./types.js";

/**
 * Generic firewall / DNS block connector. Posts a signed JSON instruction to a customer-run
 * relay (pfSense/OPNsense/Fortinet/Palo Alto automation, Pi-hole/Unbound/RPZ updater, cloud
 * WAF lambda…). The relay URL is validated by the EngineClient SSRF guard.
 *
 * Wire format (version 1):
 *   POST <path>  Content-Type: application/json
 *   X-Bloody-Timestamp: <unix seconds>
 *   X-Bloody-Signature: v1=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>
 *   Idempotency-Key: <actionId>
 *   { version, actionId, action, operation: "block"|"unblock", indicator: {type, value},
 *     ttlSeconds, reason, requestedBy, approvedBy, tenantId, organizationId, requestedAt }
 * Receivers verify with {@link verifyWebhookSignature} semantics and reject stale timestamps.
 *
 * Safety rails: never blocks loopback/link-local/metadata/multicast addresses, internal
 * (RFC 1918) addresses unless `allowInternalTargets`, or anything on `protectedValues`
 * (own domains, resolvers, gateways — "*.corp.example" suffix patterns supported).
 */

export interface WebhookBlockOptions {
  connector?: string;
  path?: string;
  /** HMAC secret shared with the relay (resolved from the secret store by the caller). */
  secret: string;
  protectedValues?: string[];
  allowInternalTargets?: boolean;
  defaultTtlSeconds?: number;
  maxTtlSeconds?: number;
  clock?: () => Date;
}

export const WEBHOOK_SIGNATURE_HEADER = "x-bloody-signature";
export const WEBHOOK_TIMESTAMP_HEADER = "x-bloody-timestamp";

export function signWebhookBody(secret: string, timestamp: number, body: string): string {
  return `v1=${hmacSha256Hex(secret, `${timestamp}.${body}`)}`;
}

/** Verify a signed webhook (for Bloody-operated relays and receiver test harnesses). */
export function verifyWebhookSignature(
  secret: string,
  timestampHeader: string | undefined,
  body: string,
  signatureHeader: string | undefined,
  opts: { toleranceSeconds?: number; now?: Date } = {},
): boolean {
  const ts = Number(timestampHeader);
  if (!Number.isInteger(ts) || !signatureHeader?.startsWith("v1=")) return false;
  const now = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  if (Math.abs(now - ts) > (opts.toleranceSeconds ?? 300)) return false;
  const expected = signWebhookBody(secret, ts, body).slice(3);
  return safeEqualHex(expected, signatureHeader.slice(3));
}

function isProtected(value: string, patterns: string[]): boolean {
  const v = value.toLowerCase();
  return patterns.some((p) => {
    const q = p.trim().toLowerCase();
    if (q.startsWith("*.")) return v === q.slice(2) || v.endsWith(q.slice(1));
    return v === q;
  });
}

export function createWebhookBlockConnector(opts: WebhookBlockOptions): {
  supported: ResponseActionKey[];
  handlers: Partial<Record<ResponseActionKey, ResponseActionHandler>>;
  execute: (req: ResponseExecutionRequest, deps: ResponseDeps) => Promise<ResponseExecutionResult>;
} {
  if (!opts.secret || opts.secret.length < 16) throw new Error("webhook block connector requires a secret of at least 16 characters");
  const supported: ResponseActionKey[] = ["block_ip", "block_domain"];
  const connector = opts.connector ?? "webhook.block";
  const clock = opts.clock ?? (() => new Date());
  const protectedValues = opts.protectedValues ?? [];

  const prepare = (req: ResponseExecutionRequest): PreparedCall => {
    if (req.target.kind !== "indicator") throw new ResponseGuardError("invalid_target", "block actions target an indicator");
    const operation = paramString(req, "operation") ?? "block";
    if (operation !== "block" && operation !== "unblock") throw new ResponseGuardError("invalid_parameters", 'parameters.operation must be "block" or "unblock"');
    let type: "ip" | "domain";
    let value: string | undefined;
    if (req.action === "block_ip") {
      type = "ip";
      value = normalizeObservable("ip", req.target.id);
      if (!value) throw new ResponseGuardError("invalid_target", "block_ip target must be an IP address");
      const cls = classifyIp(value);
      if (cls && ["loopback", "link_local", "metadata", "multicast", "broadcast", "unspecified", "reserved"].includes(cls)) {
        throw new ResponseGuardError("invalid_target", `refusing to block ${cls} address ${value}`);
      }
      if ((cls === "private" || cls === "shared") && !opts.allowInternalTargets) {
        throw new ResponseGuardError("invalid_target", `refusing to block internal address ${value} (allowInternalTargets is off)`);
      }
    } else {
      type = "domain";
      value = normalizeObservable("domain", req.target.id);
      if (!value) throw new ResponseGuardError("invalid_target", "block_domain target must be a domain name");
      if (!isPublicDomain(value) && !opts.allowInternalTargets) throw new ResponseGuardError("invalid_target", `refusing to block internal domain ${value}`);
      if (value.split(".").length < 2) throw new ResponseGuardError("invalid_target", "refusing to block a top-level domain");
    }
    if (isProtected(value, protectedValues)) throw new ResponseGuardError("invalid_target", `${value} is on the protected list and cannot be blocked`);
    const maxTtl = opts.maxTtlSeconds ?? 30 * 86_400;
    const ttl = Math.min(int(req.parameters["ttlSeconds"]) ?? opts.defaultTtlSeconds ?? 86_400, maxTtl);
    if (ttl <= 0) throw new ResponseGuardError("invalid_parameters", "ttlSeconds must be positive");
    const now = clock();
    const payload = {
      version: 1,
      actionId: req.actionId,
      action: req.action,
      operation,
      indicator: { type, value },
      ttlSeconds: ttl,
      reason: req.reason,
      requestedBy: req.requestedBy,
      approvedBy: req.approvedBy ?? null,
      tenantId: req.tenantId,
      organizationId: req.organizationId,
      requestedAt: now.toISOString(),
    };
    const body = JSON.stringify(payload);
    const ts = Math.floor(now.getTime() / 1000);
    return {
      method: "POST",
      path: opts.path ?? "/",
      body,
      contentType: "application/json",
      headers: { [WEBHOOK_TIMESTAMP_HEADER]: String(ts), [WEBHOOK_SIGNATURE_HEADER]: signWebhookBody(opts.secret, ts, body) },
      auditBody: payload,
    };
  };

  const interpret = (data: unknown, _status: number, call: PreparedCall): ExecutionOutcome => {
    const ref = str(field(data, "ref")) ?? str(field(data, "id")) ?? null;
    const relayStatus = str(field(data, "status"));
    const value = str(field(call.auditBody, "indicator.value")) ?? "";
    const op = str(field(call.auditBody, "operation")) ?? "block";
    if (relayStatus && /^(error|failed|rejected)$/i.test(relayStatus)) {
      return { outcome: "failed", affected: [], failed: [{ id: value, reason: str(field(data, "message")) ?? relayStatus }], engineRef: ref, summary: `Relay rejected ${op} of ${value}` };
    }
    return {
      outcome: "succeeded",
      affected: [value],
      failed: [],
      engineRef: ref,
      summary: `${op === "block" ? "Blocked" : "Unblocked"} ${value} via ${connector}${relayStatus ? ` (${relayStatus})` : ""}`,
      details: { ttlSeconds: Number(field(call.auditBody, "ttlSeconds") ?? 0), operation: op },
      ...(op === "block" ? { reversal: { action: call.auditBody && str(field(call.auditBody, "action")) === "block_domain" ? "block_domain" : "block_ip", parameters: { operation: "unblock" } } as ExecutionOutcome["reversal"] } : {}),
    };
  };

  const execute = (req: ResponseExecutionRequest, deps: ResponseDeps): Promise<ResponseExecutionResult> =>
    executeResponse({ connector, engine: "webhook" }, supported, req, { ...deps, clock: deps.clock ?? clock }, prepare, interpret);

  return { supported, handlers: { block_ip: execute, block_domain: execute }, execute };
}
