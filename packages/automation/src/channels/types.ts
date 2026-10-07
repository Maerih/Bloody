import type { NotificationChannel, NotificationChannelKind, Severity } from "@bloody/contracts";
import { z } from "zod";
import { ConfigError } from "../util/errors.js";

/**
 * White-label branding. MSSPs send customer-facing notifications and reports under their own
 * name, colour and logo; the default is Bloody's.
 */
export interface Branding {
  name: string;
  /** #RRGGBB */
  primaryColor: string;
  /** data:image/png|jpeg|gif|webp;base64,… — embedded in e-mails as an inline CID attachment. */
  logoDataUrl?: string | null;
  footerText?: string | null;
  supportEmail?: string | null;
  website?: string | null;
}

export const DEFAULT_BRANDING: Branding = {
  name: "Bloody",
  primaryColor: "#B4232C",
  logoDataUrl: null,
  footerText: null,
  supportEmail: null,
  website: null,
};

export const BrandingInput = z.object({
  name: z.string().trim().min(1).max(80),
  primaryColor: z.string().regex(/^#[0-9a-fA-F]{6}$/),
  logoDataUrl: z
    .string()
    .max(700_000)
    .regex(/^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/]+={0,2}$/, "logo must be a base64 PNG/JPEG/GIF/WebP data URL")
    .nullable()
    .optional(),
  footerText: z.string().max(500).nullable().optional(),
  supportEmail: z.string().email().nullable().optional(),
  website: z.string().url().startsWith("https://").nullable().optional(),
});

/** Validate branding; invalid input falls back field-by-field to the default brand. */
export function resolveBranding(input: Partial<Branding> | null | undefined): Branding {
  if (!input) return { ...DEFAULT_BRANDING };
  const parsed = BrandingInput.safeParse({ ...DEFAULT_BRANDING, ...input });
  if (parsed.success) return { ...DEFAULT_BRANDING, ...parsed.data };
  const out: Branding = { ...DEFAULT_BRANDING };
  const shape = BrandingInput.shape;
  for (const key of Object.keys(shape) as (keyof typeof shape)[]) {
    const v = (input as Record<string, unknown>)[key];
    if (v === undefined) continue;
    const r = shape[key].safeParse(v);
    if (r.success) (out as unknown as Record<string, unknown>)[key] = r.data;
  }
  return out;
}

/** Brand per (tenant, organization) — MSSP white-label lookup implemented by the API. */
export type BrandingResolver = (tenantId: string, organizationId: string | null) => Promise<Branding>;

export const defaultBrandingResolver: BrandingResolver = async () => ({ ...DEFAULT_BRANDING });

export interface NotificationFact {
  label: string;
  value: string;
}

export interface NotificationAttachment {
  filename: string;
  contentType: string;
  content: Buffer;
}

/** Channel-neutral message; each sender renders it natively (e-mail, Slack blocks, adaptive card…). */
export interface NotificationMessage {
  id: string;
  tenantId: string;
  organizationId: string | null;
  organizationName?: string;
  /** AUTOMATION_EVENTS value, "report.generated", or "channel.test". */
  event: string;
  severity: Severity;
  /** Single line. */
  subject: string;
  /** Plain-text body (light formatting: blank-line paragraphs, "- " bullets, **bold**). */
  text: string;
  /** Pre-rendered, already-safe HTML for the body (optional; derived from `text` otherwise). */
  html?: string;
  facts: NotificationFact[];
  link?: { url: string; label: string };
  occurredAt: string;
  /** Throttling / threading key (same incident → same e-mail thread). */
  dedupKey?: string;
  /** Structured payload for machine consumers (webhook JSON). */
  data?: Record<string, unknown>;
  attachments?: NotificationAttachment[];
  /** Who it is written for — drives tone in templates and the footer wording. */
  audience?: "soc" | "mssp" | "customer" | "business";
  /** Rule / schedule that produced it (shown in footers: "You receive this because …"). */
  origin?: { kind: "automation_rule" | "report_schedule" | "test" | "system"; id: string | null; name: string };
}

export interface DeliveryResult {
  ok: true;
  channelId: string;
  kind: NotificationChannelKind;
  providerMessageId?: string;
  detail?: string;
  warnings?: string[];
}

/** Resolves `…Ref` config values (webhook URLs, signing secrets) from the encrypted secret store. */
export interface SecretResolver {
  resolve(tenantId: string, ref: string): Promise<string>;
}

export interface ConfigCheck {
  ok: boolean;
  issues: { path: string; message: string }[];
}

export interface NotificationSender {
  readonly kind: NotificationChannelKind;
  /** Validate `channel.config` on create/update (before it is stored). */
  validateConfig(config: unknown): ConfigCheck;
  send(channel: NotificationChannel, message: NotificationMessage): Promise<DeliveryResult>;
  /** "Send test" button: a clearly-labelled test message through the real transport. */
  test(channel: NotificationChannel, opts?: { requestedBy?: string; now?: Date }): Promise<DeliveryResult>;
}

export function checkConfig<T extends z.ZodTypeAny>(schema: T, config: unknown): ConfigCheck {
  const r = schema.safeParse(config);
  return r.success ? { ok: true, issues: [] } : { ok: false, issues: r.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) };
}

export function parseConfig<T extends z.ZodTypeAny>(schema: T, channel: NotificationChannel): z.output<T> {
  const r = schema.safeParse(channel.config);
  if (!r.success) {
    throw new ConfigError(
      `invalid ${channel.kind} channel configuration`,
      r.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
    );
  }
  return r.data;
}

/** URL either inline (non-secret, e.g. dev) or by secret reference (default for prod). */
export const UrlOrRef = z
  .object({
    url: z.string().url().max(2048).optional(),
    urlRef: z.string().min(1).max(256).optional(),
  })
  .refine((v) => Boolean(v.url) !== Boolean(v.urlRef), { message: "exactly one of url or urlRef is required" });

export async function resolveUrl(secrets: SecretResolver, tenantId: string, cfg: { url?: string | undefined; urlRef?: string | undefined }): Promise<string> {
  if (cfg.url) return cfg.url;
  if (cfg.urlRef) return (await secrets.resolve(tenantId, cfg.urlRef)).trim();
  throw new ConfigError("channel has no url configured");
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#D03B3B",
  high: "#EC835A",
  medium: "#E0A100",
  low: "#4A3AA7",
  info: "#0D9488",
};

export const SEVERITY_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

export function eventLabel(event: string): string {
  if (event === "channel.test") return "Test notification";
  const [entity, verb] = event.split(".");
  const words = `${entity ?? ""} ${(verb ?? "").replace(/_/g, " ")}`.trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** The message every channel's "Send test" uses. */
export function buildTestMessage(channel: NotificationChannel, brand: Branding, opts: { requestedBy?: string; now?: Date; id: string }): NotificationMessage {
  const at = (opts.now ?? new Date()).toISOString();
  return {
    id: opts.id,
    tenantId: channel.tenantId,
    organizationId: channel.organizationId,
    event: "channel.test",
    severity: "info",
    subject: `[Test] ${brand.name} notification channel "${channel.name}"`,
    text: `This is a test message from ${brand.name}.\n\nIf you can read this, the ${channel.kind} channel "${channel.name}" is configured correctly and will receive security notifications.${opts.requestedBy ? `\n\nRequested by ${opts.requestedBy}.` : ""}`,
    facts: [
      { label: "Channel", value: channel.name },
      { label: "Type", value: channel.kind },
      { label: "Sent at", value: at },
    ],
    occurredAt: at,
    origin: { kind: "test", id: channel.id, name: "Send test" },
  };
}
