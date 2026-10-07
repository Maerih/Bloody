import { ROLE_KEYS, type NotificationChannel, type Severity } from "@bloody/contracts";
import { z } from "zod";
import { systemClock, uuidIds, type Clock, type IdGenerator } from "../util/runtime.js";
import {
  buildTestMessage,
  checkConfig,
  defaultBrandingResolver,
  parseConfig,
  type BrandingResolver,
  type ConfigCheck,
  type DeliveryResult,
  type NotificationFact,
  type NotificationMessage,
  type NotificationSender,
} from "./types.js";

export const InAppConfig = z.object({
  /** Specific users. */
  userIds: z.array(z.string().uuid()).max(500).default([]),
  /** Everyone holding one of these roles in the channel's organization (tenant-wide roles included). */
  roles: z.array(z.enum(ROLE_KEYS)).max(ROLE_KEYS.length).default([]),
});
export type InAppConfig = z.output<typeof InAppConfig>;

/** A notification in the Command Center bell / triage feed. */
export interface InAppNotification {
  id: string;
  tenantId: string;
  organizationId: string | null;
  recipients: { userIds: string[]; roles: string[] };
  event: string;
  severity: Severity;
  title: string;
  body: string;
  facts: NotificationFact[];
  link: { url: string; label: string } | null;
  createdAt: string;
  readBy: string[];
}

export interface InAppNotificationStore {
  insert(notification: InAppNotification): Promise<void>;
}

export class InMemoryInAppStore implements InAppNotificationStore {
  readonly items: InAppNotification[] = [];

  async insert(notification: InAppNotification): Promise<void> {
    this.items.push(structuredClone(notification));
  }
}

export interface InAppSenderDeps {
  store: InAppNotificationStore;
  branding?: BrandingResolver;
  clock?: Clock;
  ids?: IdGenerator;
}

export class InAppSender implements NotificationSender {
  readonly kind = "in_app" as const;
  private readonly deps: InAppSenderDeps;

  constructor(deps: InAppSenderDeps) {
    this.deps = deps;
  }

  validateConfig(config: unknown): ConfigCheck {
    return checkConfig(InAppConfig, config);
  }

  async send(channel: NotificationChannel, message: NotificationMessage): Promise<DeliveryResult> {
    const cfg = parseConfig(InAppConfig, channel);
    // In-app links must stay inside the Command Center (relative paths) or be https.
    const link = message.link && (/^\/(?!\/)/.test(message.link.url) || /^https:\/\//i.test(message.link.url)) ? message.link : null;
    const n: InAppNotification = {
      id: message.id,
      tenantId: message.tenantId,
      organizationId: message.organizationId,
      recipients: { userIds: cfg.userIds, roles: cfg.roles.length === 0 && cfg.userIds.length === 0 ? ["soc_analyst_t1", "soc_analyst_t2", "incident_responder", "org_admin"] : cfg.roles },
      event: message.event,
      severity: message.severity,
      title: message.subject.slice(0, 300),
      body: message.text.slice(0, 8000),
      facts: message.facts.slice(0, 20),
      link,
      createdAt: (this.deps.clock ?? systemClock).now().toISOString(),
      readBy: [],
    };
    await this.deps.store.insert(n);
    return { ok: true, channelId: channel.id, kind: "in_app", providerMessageId: n.id };
  }

  async test(channel: NotificationChannel, opts: { requestedBy?: string; now?: Date } = {}): Promise<DeliveryResult> {
    const brand = await (this.deps.branding ?? defaultBrandingResolver)(channel.tenantId, channel.organizationId);
    return this.send(channel, buildTestMessage(channel, brand, { ...opts, id: (this.deps.ids ?? uuidIds)(), now: opts.now ?? (this.deps.clock ?? systemClock).now() }));
  }
}
