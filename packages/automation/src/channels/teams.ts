import type { NotificationChannel, Severity } from "@bloody/contracts";
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
  SEVERITY_LABEL,
  type Branding,
  type BrandingResolver,
  type ConfigCheck,
  type DeliveryResult,
  type NotificationMessage,
  type NotificationSender,
  type SecretResolver,
} from "./types.js";

/** Teams incoming webhooks (Office 365 connectors) and Power Automate "Workflows" webhooks. */
export const TEAMS_HOST_SUFFIXES = ["webhook.office.com", "logic.azure.com", "api.powerplatform.com"] as const;

export const TeamsConfig = z
  .object({
    url: z.string().url().max(2048).optional(),
    urlRef: z.string().min(1).max(256).optional(),
  })
  .refine((v) => Boolean(v.url) !== Boolean(v.urlRef), { message: "exactly one of url or urlRef is required" })
  .refine(
    (v) => {
      if (!v.url) return true;
      const u = safeUrl(v.url);
      return u !== null && u.protocol === "https:" && TEAMS_HOST_SUFFIXES.some((s) => u.hostname === s || u.hostname.endsWith(`.${s}`));
    },
    { message: "url must be a Microsoft Teams / Power Automate webhook URL" },
  );
export type TeamsConfig = z.output<typeof TeamsConfig>;

/** Neutralise Adaptive Card markdown (links, emphasis) in data-derived text. */
export function escapeTeamsMarkdown(text: string): string {
  return text.replace(/([\\`*_[\]()<>#~|])/g, "\\$1");
}

const CONTAINER_STYLE: Record<Severity, string> = { critical: "attention", high: "warning", medium: "warning", low: "accent", info: "good" };
const TEXT_COLOR: Record<Severity, string> = { critical: "Attention", high: "Warning", medium: "Warning", low: "Accent", info: "Good" };

/** Teams message with a single Adaptive Card (schema 1.4 — supported by Teams desktop/web/mobile). */
export function buildTeamsPayload(message: NotificationMessage, brand: Branding): Record<string, unknown> {
  const sev = SEVERITY_LABEL[message.severity];
  const paragraphs = message.text
    .split(/\n{2,}/)
    .map((p) => p.trim())
    .filter(Boolean)
    .slice(0, 12);
  const body: Record<string, unknown>[] = [
    {
      type: "Container",
      style: CONTAINER_STYLE[message.severity],
      bleed: true,
      items: [
        {
          type: "ColumnSet",
          columns: [
            { type: "Column", width: "stretch", items: [{ type: "TextBlock", text: escapeTeamsMarkdown(`${brand.name} · ${eventLabel(message.event)}`), size: "Small", weight: "Bolder", wrap: true }] },
            { type: "Column", width: "auto", items: [{ type: "TextBlock", text: sev.toUpperCase(), size: "Small", weight: "Bolder", color: TEXT_COLOR[message.severity] }] },
          ],
        },
      ],
    },
    { type: "TextBlock", text: escapeTeamsMarkdown(truncate(message.subject, 300)), size: "Large", weight: "Bolder", wrap: true, spacing: "Medium" },
    ...paragraphs.map((p) => ({ type: "TextBlock", text: escapeTeamsMarkdown(truncate(p.replace(/\*\*([^*]+?)\*\*/g, "$1"), 2000)), wrap: true, spacing: "Small" })),
  ];
  if (message.facts.length > 0) {
    body.push({ type: "FactSet", spacing: "Medium", facts: message.facts.slice(0, 15).map((f) => ({ title: escapeTeamsMarkdown(truncate(f.label, 100)), value: escapeTeamsMarkdown(truncate(f.value, 500)) })) });
  }
  const footer = [message.organizationName, new Date(message.occurredAt).toISOString().replace("T", " ").slice(0, 16) + " UTC"].filter(Boolean).join(" · ");
  body.push({ type: "TextBlock", text: escapeTeamsMarkdown(footer), isSubtle: true, size: "Small", wrap: true, spacing: "Medium" });
  const actions = message.link && /^https:\/\//i.test(message.link.url) ? [{ type: "Action.OpenUrl", title: truncate(message.link.label, 60), url: message.link.url }] : [];
  return {
    type: "message",
    summary: truncate(`[${sev}] ${message.subject}`, 200),
    attachments: [
      {
        contentType: "application/vnd.microsoft.card.adaptive",
        contentUrl: null,
        content: {
          $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
          type: "AdaptiveCard",
          version: "1.4",
          msteams: { width: "Full" },
          body,
          ...(actions.length > 0 ? { actions } : {}),
        },
      },
    ],
  };
}

export interface TeamsSenderDeps {
  http: HttpTransport;
  secrets: SecretResolver;
  branding?: BrandingResolver;
  clock?: Clock;
  ids?: IdGenerator;
  allowedHostSuffixes?: readonly string[];
}

export class TeamsSender implements NotificationSender {
  readonly kind = "teams" as const;
  private readonly deps: TeamsSenderDeps;

  constructor(deps: TeamsSenderDeps) {
    this.deps = deps;
  }

  validateConfig(config: unknown): ConfigCheck {
    return checkConfig(TeamsConfig, config);
  }

  async send(channel: NotificationChannel, message: NotificationMessage): Promise<DeliveryResult> {
    const cfg = parseConfig(TeamsConfig, channel);
    const url = await resolveUrl(this.deps.secrets, channel.tenantId, cfg);
    const brand = await (this.deps.branding ?? defaultBrandingResolver)(channel.tenantId, message.organizationId ?? channel.organizationId);
    const res = await this.deps.http.request({
      url,
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify(buildTeamsPayload(message, brand)),
      ssrf: { allowedHostSuffixes: this.deps.allowedHostSuffixes ?? TEAMS_HOST_SUFFIXES },
    });
    assertHttpOk(res, "Microsoft Teams");
    return { ok: true, channelId: channel.id, kind: "teams", detail: `HTTP ${res.status}` };
  }

  async test(channel: NotificationChannel, opts: { requestedBy?: string; now?: Date } = {}): Promise<DeliveryResult> {
    const brand = await (this.deps.branding ?? defaultBrandingResolver)(channel.tenantId, channel.organizationId);
    return this.send(channel, buildTestMessage(channel, brand, { ...opts, id: (this.deps.ids ?? uuidIds)(), now: opts.now ?? (this.deps.clock ?? systemClock).now() }));
  }
}
