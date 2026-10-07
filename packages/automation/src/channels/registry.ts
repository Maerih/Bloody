import type { NotificationChannel, NotificationChannelKind } from "@bloody/contracts";
import { ConfigError } from "../util/errors.js";
import type { ConfigCheck, DeliveryResult, NotificationMessage, NotificationSender } from "./types.js";

/** Kind → sender lookup with uniform validation / send / test entry points for the API. */
export class ChannelRegistry {
  private readonly senders = new Map<NotificationChannelKind, NotificationSender>();

  constructor(senders: readonly NotificationSender[] = []) {
    for (const s of senders) this.register(s);
  }

  register(sender: NotificationSender): this {
    this.senders.set(sender.kind, sender);
    return this;
  }

  has(kind: NotificationChannelKind): boolean {
    return this.senders.has(kind);
  }

  kinds(): NotificationChannelKind[] {
    return [...this.senders.keys()];
  }

  get(kind: NotificationChannelKind): NotificationSender {
    const s = this.senders.get(kind);
    if (!s) throw new ConfigError(`no sender registered for channel kind "${kind}"`);
    return s;
  }

  validate(kind: NotificationChannelKind, config: unknown): ConfigCheck {
    const s = this.senders.get(kind);
    return s ? s.validateConfig(config) : { ok: false, issues: [{ path: "kind", message: `channel kind "${kind}" is not available` }] };
  }

  send(channel: NotificationChannel, message: NotificationMessage): Promise<DeliveryResult> {
    return this.get(channel.kind).send(channel, message);
  }

  /** "Send test" — allowed on disabled channels so admins can verify before enabling. */
  test(channel: NotificationChannel, opts: { requestedBy?: string; now?: Date } = {}): Promise<DeliveryResult> {
    return this.get(channel.kind).test(channel, opts);
  }
}
