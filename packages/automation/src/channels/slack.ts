import type { NotificationChannel } from "@bloody/contracts";
import { z } from "zod";
import { systemClock, truncate, uuidIds, type Clock, type IdGenerator } from "../util/runtime.js";
import { assertHttpOk, type HttpTransport } from "./http.js";
import {
  buildTestMessage,
  checkConfig,
  defaultBrandingResolver,
  eventLabel,
  parseConfig,
  resolveUrl,
  safeUrl,
  SEVERITY_COLORS,
  SEVERITY_LABEL,
  type Branding,
  type BrandingResolver,
  type ConfigCheck,
  type DeliveryResult,
  type NotificationMessage,
  type NotificationSender,
  type SecretResolver,
} from "./types.js";

export const SLACK_HOSTS = ["hooks.slack.com", "hooks.slack-gov.com"] as const;

export const SlackConfig = z
  .object({
    url: z.string().url().max(2048).optional(),
    urlRef: z.string().min(1).max(256).optional(),
    /** Prepend <!here>/<!channel> for critical notifications. */
    mentionOnCritical: z.enum(["here", "channel"]).nullable().default(null),
  })
  .refine((v) => Boolean(v.url) !== Boolean(v.urlRef), { message: "exactly one of url or urlRef is required" })
  .refine(
    (v) => {
      if (!v.url) return true;
      const u = safeUrl(v.url);
      return u !== null && u.protocol === "https:" && SLACK_HOSTS.some((h) => u.hostname === h);
    },
    { message: "url must be a Slack incoming-webhook URL (https://hooks.slack.com/…)" },
  );
export type SlackConfig = z.output<typeof SlackConfig>;

/** Escape Slack mrkdwn control characters (prevents <!channel>/<url|label> injection from event data). */
export function escapeSlack(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** Convert our light text formatting to Slack mrkdwn (after escaping). */
function toMrkdwn(text: string): string {
  return escapeSlack(text)
    .replace(/\*\*([^*]+?)\*\*/g, "*$1*")
    .replace(/^\s*[-*]\s+/gm, "• ");
}

/**
 * Slack incoming-webhook payload: fallback `text` (notifications / screen readers) plus a
 * severity-coloured attachment with Block Kit blocks — header, body, fact fields, context
 * line and an "Open" button.
 */
export function buildSlackPayload(message: NotificationMessage, brand: Branding, opts: { mention?: "here" | "channel" | null } = {}): Record<string, unknown> {
  const mention = message.severity === "critical" && opts.mention ? `<!${opts.mention}> ` : "";
  const sev = SEVERITY_LABEL[message.severity];
  const blocks: Record<string, unknown>[] = [
    { type: "header", text: { type: "plain_text", text: truncate(`${sev} · ${message.subject}`, 150), emoji: false } },
    { type: "section", text: { type: "mrkdwn", text: truncate(`${mention}${toMrkdwn(message.text)}`, 3000) } },
  ];
  const facts = message.facts.slice(0, 10);
  if (facts.length > 0) {
    blocks.push({
      type: "section",
      fields: facts.map((f) => ({ type: "mrkdwn", text: truncate(`*${escapeSlack(f.label)}*\n${escapeSlack(f.value)}`, 2000) })),
    });
  }
  const context = [brand.name, message.organizationName, eventLabel(message.event), new Date(message.occurredAt).toISOString().replace("T", " ").slice(0, 16) + " UTC"].filter(Boolean).join("  ·  ");
  blocks.push({ type: "context", elements: [{ type: "mrkdwn", text: truncate(escapeSlack(context), 2000) }] });
  if (message.link && /^https:\/\//i.test(message.link.url)) {
    blocks.push({
      type: "actions",
      elements: [{ type: "button", text: { type: "plain_text", text: truncate(message.link.label, 75), emoji: false }, url: message.link.url, style: message.severity === "critical" || message.severity === "high" ? "danger" : "primary" }],
    });
  }
  return {
    text: truncate(`${mention}[${sev}] ${escapeSlack(message.subject)}`, 3000),
    attachments: [{ color: SEVERITY_COLORS[message.severity], blocks }],
    unfurl_links: false,
    unfurl_media: false,
  };
}

export interface SlackSenderDeps {
  http: HttpTransport;
  secrets: SecretResolver;
  branding?: BrandingResolver;
  clock?: Clock;
  ids?: IdGenerator;
  /** Override for GovSlack / proxies; default {@link SLACK_HOSTS}. */
  allowedHosts?: readonly string[];
}

export class SlackSender implements NotificationSender {
  readonly kind = "slack" as const;
  private readonly deps: SlackSenderDeps;

  constructor(deps: SlackSenderDeps) {
    this.deps = deps;
  }

  validateConfig(config: unknown): ConfigCheck {
    return checkConfig(SlackConfig, config);
  }

  async send(channel: NotificationChannel, message: NotificationMessage): Promise<DeliveryResult> {
    const cfg = parseConfig(SlackConfig, channel);
    const url = await resolveUrl(this.deps.secrets, channel.tenantId, cfg);
    const brand = await (this.deps.branding ?? defaultBrandingResolver)(channel.tenantId, message.organizationId ?? channel.organizationId);
    const res = await this.deps.http.request({
      url,
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify(buildSlackPayload(message, brand, { mention: cfg.mentionOnCritical })),
      ssrf: { allowedHostSuffixes: this.deps.allowedHosts ?? SLACK_HOSTS },
    });
    assertHttpOk(res, "Slack");
    return { ok: true, channelId: channel.id, kind: "slack", detail: `HTTP ${res.status}` };
  }

  async test(channel: NotificationChannel, opts: { requestedBy?: string; now?: Date } = {}): Promise<DeliveryResult> {
    const brand = await (this.deps.branding ?? defaultBrandingResolver)(channel.tenantId, channel.organizationId);
    return this.send(channel, buildTestMessage(channel, brand, { ...opts, id: (this.deps.ids ?? uuidIds)(), now: opts.now ?? (this.deps.clock ?? systemClock).now() }));
  }
}
