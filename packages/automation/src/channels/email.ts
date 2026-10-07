import type { NotificationChannel } from "@bloody/contracts";
import nodemailer from "nodemailer";
import type { SendMailOptions, Transporter } from "nodemailer";
import { z } from "zod";
import { sanitizeHeaderValue, textToHtml } from "../template.js";
import { DeliveryError } from "../util/errors.js";
import { errorMessage, stableHash, systemClock, uuidIds, type Clock, type IdGenerator } from "../util/runtime.js";
import { renderEmailHtml, renderEmailText } from "./email-layout.js";
import {
  buildTestMessage,
  checkConfig,
  defaultBrandingResolver,
  parseConfig,
  SEVERITY_LABEL,
  type Branding,
  type BrandingResolver,
  type ConfigCheck,
  type DeliveryResult,
  type NotificationMessage,
  type NotificationSender,
} from "./types.js";

const Email = z.string().trim().toLowerCase().email().max(254);

export const EmailConfig = z
  .object({
    to: z.array(Email).min(1).max(50),
    cc: z.array(Email).max(50).default([]),
    bcc: z.array(Email).max(50).default([]),
    replyTo: Email.optional(),
    /** Short tag prepended to subjects, e.g. "[SOC]". */
    subjectPrefix: z
      .string()
      .max(40)
      .regex(/^[^\r\n]*$/)
      .optional(),
  })
  .refine((c) => c.to.length + c.cc.length + c.bcc.length <= 100, { message: "at most 100 recipients per channel" });
export type EmailConfig = z.output<typeof EmailConfig>;

/** Platform (or per-tenant) SMTP relay settings. Credentials come from the secret store. */
export const SmtpSettings = z.object({
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535).default(587),
  /** true = implicit TLS (465); false = STARTTLS, which is then REQUIRED. */
  secure: z.boolean().default(false),
  user: z.string().optional(),
  password: z.string().optional(),
  /** Envelope / header From address, e.g. "notifications@soc.example.com". */
  fromAddress: z.string().email(),
  /** Pool connections for throughput (default true). */
  pool: z.boolean().default(true),
});
export type SmtpSettings = z.input<typeof SmtpSettings>;

/** Create a hardened nodemailer SMTP transport: TLS ≥ 1.2 with verification, STARTTLS required. */
export function createSmtpTransport(input: SmtpSettings): Transporter {
  const s = SmtpSettings.parse(input);
  return nodemailer.createTransport({
    host: s.host,
    port: s.port,
    secure: s.secure,
    requireTLS: !s.secure,
    ...(s.user ? { auth: { user: s.user, pass: s.password ?? "" } } : {}),
    tls: { minVersion: "TLSv1.2", rejectUnauthorized: true },
    pool: s.pool,
    maxConnections: 5,
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 30_000,
  } as Parameters<typeof nodemailer.createTransport>[0]);
}

function dataUrlToAttachment(dataUrl: string): { content: Buffer; contentType: string; ext: string } | null {
  const m = /^data:(image\/(png|jpeg|gif|webp));base64,([A-Za-z0-9+/]+={0,2})$/.exec(dataUrl);
  if (!m) return null;
  const content = Buffer.from(m[3]!, "base64");
  if (content.length === 0 || content.length > 512 * 1024) return null;
  return { content, contentType: m[1]!, ext: m[2] === "jpeg" ? "jpg" : m[2]! };
}

export interface EmailComposeOptions {
  from: { address: string; name?: string };
  brand: Branding;
  config: EmailConfig;
  /** Base URL of the Command Center for "Manage notifications" links. */
  appBaseUrl?: string;
}

const LOGO_CID = "brand-logo@bloody";

/**
 * Compose the full nodemailer message: branded HTML + text alternative, inline logo, safe
 * single-line subject, threading headers (all notifications about one incident thread
 * together), auto-reply suppression and priority for critical/high events.
 */
export function composeEmail(message: NotificationMessage, opts: EmailComposeOptions): SendMailOptions {
  const { brand, config } = opts;
  const domain = opts.from.address.split("@")[1] ?? "bloody.local";
  const logo = brand.logoDataUrl ? dataUrlToAttachment(brand.logoDataUrl) : null;
  const subjectCore = sanitizeHeaderValue(message.subject, 200);
  const subject = sanitizeHeaderValue(config.subjectPrefix ? `${config.subjectPrefix} ${subjectCore}` : subjectCore, 250);
  const manageUrl = opts.appBaseUrl ? `${opts.appBaseUrl.replace(/\/+$/, "")}/settings/notifications` : null;
  const reason =
    message.origin?.kind === "automation_rule"
      ? `You are receiving this because the automation rule "${message.origin.name}" notifies this address.`
      : message.origin?.kind === "report_schedule"
        ? `You are receiving this because you are a recipient of the scheduled report "${message.origin.name}".`
        : message.origin?.kind === "test"
          ? "This is a test of your notification channel."
          : null;
  const attachmentsMeta = (message.attachments ?? []).map((a) => ({ filename: a.filename, sizeBytes: a.content.length }));
  const layoutBase = {
    brand,
    severity: message.severity,
    event: message.event,
    title: subjectCore,
    preheader: message.text.replace(/\s+/g, " ").slice(0, 140),
    facts: message.facts,
    cta: message.link ?? null,
    organizationName: message.organizationName ?? null,
    occurredAt: message.occurredAt,
    reason,
    manageUrl,
    attachments: attachmentsMeta,
  };
  const html = renderEmailHtml({ ...layoutBase, logoSrc: logo ? `cid:${LOGO_CID}` : null, bodyHtml: message.html ?? textToHtml(message.text, { linkColor: brand.primaryColor }) });
  const text = renderEmailText({ ...layoutBase, bodyText: message.text });
  const threadKey = message.dedupKey ? `<thread-${stableHash({ t: message.tenantId, k: message.dedupKey }, 24)}@${domain}>` : null;
  const urgent = message.severity === "critical" || message.severity === "high";
  const fromName = sanitizeHeaderValue(opts.from.name ?? `${brand.name} Security Operations`, 80).replace(/["\\]/g, "");
  const mail: SendMailOptions = {
    from: { name: fromName, address: opts.from.address },
    to: config.to,
    ...(config.cc.length ? { cc: config.cc } : {}),
    ...(config.bcc.length ? { bcc: config.bcc } : {}),
    ...(config.replyTo ? { replyTo: config.replyTo } : brand.supportEmail ? { replyTo: brand.supportEmail } : {}),
    subject,
    text,
    html,
    messageId: `<${message.id}@${domain}>`,
    ...(threadKey ? { inReplyTo: threadKey, references: [threadKey] } : {}),
    priority: urgent ? "high" : "normal",
    headers: {
      "X-Bloody-Event": sanitizeHeaderValue(message.event, 64),
      "X-Bloody-Severity": SEVERITY_LABEL[message.severity],
      "X-Bloody-Message-Id": message.id,
      "Auto-Submitted": "auto-generated",
      "X-Auto-Response-Suppress": "All",
      ...(manageUrl ? { "List-Unsubscribe": `<${manageUrl}>` } : {}),
    },
    attachments: [
      ...(logo ? [{ filename: `logo.${logo.ext}`, content: logo.content, contentType: logo.contentType, cid: LOGO_CID, contentDisposition: "inline" as const }] : []),
      ...(message.attachments ?? []).map((a) => ({ filename: sanitizeHeaderValue(a.filename, 120).replace(/[\\/]/g, "_"), content: a.content, contentType: a.contentType })),
    ],
    date: new Date(message.occurredAt),
  };
  return mail;
}

export interface EmailSenderDeps {
  transport: Transporter;
  from: { address: string; name?: string };
  branding?: BrandingResolver;
  appBaseUrl?: string;
  clock?: Clock;
  ids?: IdGenerator;
  /** Total attachment budget per e-mail (default 15 MB). */
  maxAttachmentBytes?: number;
}

/** SMTP e-mail channel (nodemailer). */
export class EmailSender implements NotificationSender {
  readonly kind = "email" as const;
  private readonly deps: EmailSenderDeps;

  constructor(deps: EmailSenderDeps) {
    if (!z.string().email().safeParse(deps.from.address).success) throw new Error("EmailSender: invalid from address");
    this.deps = deps;
  }

  validateConfig(config: unknown): ConfigCheck {
    return checkConfig(EmailConfig, config);
  }

  async compose(channel: NotificationChannel, message: NotificationMessage): Promise<SendMailOptions> {
    const config = parseConfig(EmailConfig, channel);
    const brand = await (this.deps.branding ?? defaultBrandingResolver)(channel.tenantId, message.organizationId ?? channel.organizationId);
    const fromName = brand.name === "Bloody" ? this.deps.from.name : `${brand.name} Security Operations`;
    const total = (message.attachments ?? []).reduce((n, a) => n + a.content.length, 0);
    const max = this.deps.maxAttachmentBytes ?? 15 * 1024 * 1024;
    if (total > max) throw new DeliveryError("attachment_too_large", `attachments total ${total} bytes exceeds ${max}`, { retryable: false });
    return composeEmail(message, {
      from: { address: this.deps.from.address, ...(fromName ? { name: fromName } : {}) },
      brand,
      config,
      ...(this.deps.appBaseUrl ? { appBaseUrl: this.deps.appBaseUrl } : {}),
    });
  }

  async send(channel: NotificationChannel, message: NotificationMessage): Promise<DeliveryResult> {
    const mail = await this.compose(channel, message);
    try {
      const info = (await this.deps.transport.sendMail(mail)) as { messageId?: string; rejected?: unknown[]; accepted?: unknown[]; response?: string };
      const rejected = Array.isArray(info.rejected) ? info.rejected.length : 0;
      const accepted = Array.isArray(info.accepted) ? info.accepted.length : null;
      if (accepted === 0 && rejected > 0) throw new DeliveryError("recipients_rejected", "all recipients were rejected by the SMTP server", { retryable: false });
      return {
        ok: true,
        channelId: channel.id,
        kind: "email",
        ...(info.messageId ? { providerMessageId: info.messageId } : {}),
        detail: info.response ?? "accepted",
        ...(rejected > 0 ? { warnings: [`${rejected} recipient(s) rejected`] } : {}),
      };
    } catch (err) {
      if (err instanceof DeliveryError) throw err;
      const e = err as { responseCode?: number; code?: string };
      // 4xx SMTP replies and connection problems are transient; 5xx are permanent.
      const permanent = typeof e.responseCode === "number" && e.responseCode >= 500;
      throw new DeliveryError(e.code ? `smtp_${e.code.toLowerCase()}` : "smtp_error", errorMessage(err).slice(0, 500), { retryable: !permanent, ...(e.responseCode ? { status: e.responseCode } : {}) });
    }
  }

  async test(channel: NotificationChannel, opts: { requestedBy?: string; now?: Date } = {}): Promise<DeliveryResult> {
    const brand = await (this.deps.branding ?? defaultBrandingResolver)(channel.tenantId, channel.organizationId);
    return this.send(channel, buildTestMessage(channel, brand, { ...opts, id: (this.deps.ids ?? uuidIds)(), now: opts.now ?? (this.deps.clock ?? systemClock).now() }));
  }

  /** Verify SMTP connectivity/credentials (settings page "Verify" button). */
  async verifyTransport(): Promise<{ ok: boolean; error?: string }> {
    try {
      await this.deps.transport.verify();
      return { ok: true };
    } catch (err) {
      return { ok: false, error: errorMessage(err) };
    }
  }
}
