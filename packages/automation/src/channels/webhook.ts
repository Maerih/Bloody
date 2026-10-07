import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { NotificationChannel } from "@bloody/contracts";
import { z } from "zod";
import { ConfigError } from "../util/errors.js";
import { systemClock, uuidIds, type Clock, type IdGenerator } from "../util/runtime.js";
import { assertHttpOk, type HttpTransport } from "./http.js";
import type { SsrfPolicy } from "./ssrf.js";
import {
  buildTestMessage,
  checkConfig,
  defaultBrandingResolver,
  parseConfig,
  resolveUrl,
  type BrandingResolver,
  type ConfigCheck,
  type DeliveryResult,
  type NotificationMessage,
  type NotificationSender,
  type SecretResolver,
} from "./types.js";

export const SIGNATURE_HEADER = "X-Bloody-Signature";
export const TIMESTAMP_HEADER = "X-Bloody-Timestamp";
export const WEBHOOK_SCHEMA_VERSION = "2026-10-01";

const RESERVED_HEADERS = new Set(["host", "content-length", "content-type", "transfer-encoding", "connection", "user-agent", "cookie"]);

export const WebhookConfig = z
  .object({
    url: z.string().url().max(2048).optional(),
    urlRef: z.string().min(1).max(256).optional(),
    /** Secret-store reference of the HMAC signing secret (required unless signing is disabled by the platform). */
    secretRef: z.string().min(1).max(256).optional(),
    /** Optional secret-store reference of an Authorization header value ("Bearer …"). */
    authorizationRef: z.string().min(1).max(256).optional(),
    /** Extra non-secret headers. */
    headers: z
      .record(z.string().regex(/^[A-Za-z0-9-]{1,64}$/), z.string().max(512).regex(/^[^\r\n]*$/))
      .refine((h) => Object.keys(h).every((k) => !RESERVED_HEADERS.has(k.toLowerCase()) && !k.toLowerCase().startsWith("x-bloody-") && k.toLowerCase() !== "authorization"), {
        message: "reserved header names cannot be overridden",
      })
      .refine((h) => Object.keys(h).length <= 20, { message: "at most 20 custom headers" })
      .optional(),
    /** Include the structured `data` payload (default true). */
    includeData: z.boolean().default(true),
  })
  .refine((v) => Boolean(v.url) !== Boolean(v.urlRef), { message: "exactly one of url or urlRef is required" });
export type WebhookConfig = z.output<typeof WebhookConfig>;

/** Generate a strong signing secret for a new webhook channel (store it in the secret store). */
export function generateWebhookSecret(): string {
  return `whsec_${randomBytes(32).toString("base64url")}`;
}

/** `sha256=<hex>` over `${timestamp}.${body}`. */
export function signWebhookPayload(secret: string, timestamp: number, body: string): string {
  return `sha256=${createHmac("sha256", secret).update(`${timestamp}.${body}`, "utf8").digest("hex")}`;
}

/**
 * Receiver-side verification (documented for customers; also used by our own tests):
 * constant-time comparison + replay window.
 */
export function verifyWebhookSignature(input: { secret: string; signature: string | null | undefined; timestamp: string | number | null | undefined; body: string; now?: Date; toleranceSeconds?: number }): boolean {
  if (!input.signature || input.timestamp === null || input.timestamp === undefined) return false;
  const ts = typeof input.timestamp === "number" ? input.timestamp : Number(input.timestamp);
  if (!Number.isInteger(ts)) return false;
  const now = Math.floor((input.now ?? new Date()).getTime() / 1000);
  if (Math.abs(now - ts) > (input.toleranceSeconds ?? 300)) return false;
  const expected = Buffer.from(signWebhookPayload(input.secret, ts, input.body), "utf8");
  const given = Buffer.from(input.signature.trim(), "utf8");
  return expected.length === given.length && timingSafeEqual(expected, given);
}

/** The JSON document POSTed to webhooks (stable, versioned schema). */
export function buildWebhookPayload(message: NotificationMessage, opts: { includeData: boolean }): Record<string, unknown> {
  return {
    schemaVersion: WEBHOOK_SCHEMA_VERSION,
    id: message.id,
    event: message.event,
    occurredAt: message.occurredAt,
    tenantId: message.tenantId,
    organizationId: message.organizationId,
    organizationName: message.organizationName ?? null,
    severity: message.severity,
    subject: message.subject,
    text: message.text,
    facts: message.facts,
    link: message.link ?? null,
    dedupKey: message.dedupKey ?? null,
    origin: message.origin ?? null,
    ...(opts.includeData && message.data ? { data: message.data } : {}),
  };
}

export interface WebhookSenderDeps {
  http: HttpTransport;
  secrets: SecretResolver;
  clock?: Clock;
  ids?: IdGenerator;
  branding?: BrandingResolver;
  /** Refuse to send unsigned webhooks (default true — secure default). */
  requireSignature?: boolean;
  ssrf?: SsrfPolicy;
}

export class WebhookSender implements NotificationSender {
  readonly kind = "webhook" as const;
  private readonly deps: WebhookSenderDeps;

  constructor(deps: WebhookSenderDeps) {
    this.deps = deps;
  }

  validateConfig(config: unknown): ConfigCheck {
    const check = checkConfig(WebhookConfig, config);
    if (check.ok && (this.deps.requireSignature ?? true) && !(config as WebhookConfig).secretRef) {
      return { ok: false, issues: [{ path: "secretRef", message: "a signing secret is required (generate one with generateWebhookSecret and store it as a secret)" }] };
    }
    return check;
  }

  async send(channel: NotificationChannel, message: NotificationMessage): Promise<DeliveryResult> {
    const cfg = parseConfig(WebhookConfig, channel);
    const requireSignature = this.deps.requireSignature ?? true;
    if (requireSignature && !cfg.secretRef) throw new ConfigError("webhook channel has no signing secret configured", [{ path: "secretRef", message: "required" }]);
    const url = await resolveUrl(this.deps.secrets, channel.tenantId, cfg);
    const body = JSON.stringify(buildWebhookPayload(message, { includeData: cfg.includeData }));
    const timestamp = Math.floor((this.deps.clock ?? systemClock).now().getTime() / 1000);
    const headers: Record<string, string> = {
      ...(cfg.headers ?? {}),
      "Content-Type": "application/json; charset=utf-8",
      "X-Bloody-Event": message.event,
      "X-Bloody-Delivery": message.id,
      [TIMESTAMP_HEADER]: String(timestamp),
    };
    const warnings: string[] = [];
    if (cfg.secretRef) {
      const secret = await this.deps.secrets.resolve(channel.tenantId, cfg.secretRef);
      headers[SIGNATURE_HEADER] = signWebhookPayload(secret, timestamp, body);
    } else {
      warnings.push("payload is not signed (no secretRef configured)");
    }
    if (cfg.authorizationRef) headers["Authorization"] = (await this.deps.secrets.resolve(channel.tenantId, cfg.authorizationRef)).replace(/[\r\n]/g, "");
    const res = await this.deps.http.request({ url, method: "POST", headers, body, ...(this.deps.ssrf ? { ssrf: this.deps.ssrf } : {}) });
    assertHttpOk(res, "webhook endpoint");
    return { ok: true, channelId: channel.id, kind: "webhook", providerMessageId: message.id, detail: `HTTP ${res.status}`, ...(warnings.length ? { warnings } : {}) };
  }

  async test(channel: NotificationChannel, opts: { requestedBy?: string; now?: Date } = {}): Promise<DeliveryResult> {
    const brand = await (this.deps.branding ?? defaultBrandingResolver)(channel.tenantId, channel.organizationId);
    return this.send(channel, buildTestMessage(channel, brand, { ...opts, id: (this.deps.ids ?? uuidIds)(), now: opts.now ?? (this.deps.clock ?? systemClock).now() }));
  }
}
