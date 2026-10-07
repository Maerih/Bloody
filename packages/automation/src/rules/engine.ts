import { AutomationEvent, type AutomationRule, type NotificationChannel, type Severity } from "@bloody/contracts";
import { evaluateConditions, validateConditions, type ConditionResult } from "../conditions.js";
import type { ChannelRegistry } from "../channels/registry.js";
import { defaultBrandingResolver, type BrandingResolver, type NotificationFact, type NotificationMessage } from "../channels/types.js";
import { renderTemplateDetailed, sanitizeHeaderValue, validateTemplate } from "../template.js";
import { safeAudit, type AuditSink } from "../util/audit.js";
import { AutomationError, DeliveryError } from "../util/errors.js";
import { backoffDelay, defaultSleep, errorMessage, systemClock, uuidIds, type Clock, type IdGenerator, type RandomFn, type RetryPolicy, type SleepFn } from "../util/runtime.js";
import type { AutomationRuleRepository, ChannelRepository, DeadLetter, DeadLetterStore, ThrottleStore } from "./stores.js";

/** An automation event raised by the API / engines / adapters (see AUTOMATION_EVENTS). */
export interface AutomationEventEnvelope {
  tenantId: string;
  organizationId: string | null;
  organizationName?: string;
  event: AutomationEvent;
  occurredAt: string;
  severity?: Severity;
  subject: { kind: string; id: string; label?: string };
  /** Throttling key; defaults to subject kind+id. */
  dedupKey?: string;
  link?: { url: string; label: string };
  /** Template / condition context specific to the event (incident, escalation, indicator…). */
  data: Record<string, unknown>;
  /** Extra key facts appended to every notification of this event. */
  facts?: NotificationFact[];
  audience?: NotificationMessage["audience"];
}

export type DeliveryStatus = "sent" | "failed" | "skipped";

export interface DeliveryOutcome {
  channelId: string;
  kind: string | null;
  status: DeliveryStatus;
  attempts: number;
  reason?: string;
  providerMessageId?: string;
  deadLetterId?: string;
  warnings?: string[];
}

export interface RuleEvaluation {
  ruleId: string;
  ruleName: string;
  matched: boolean;
  /** Explainability: why the rule matched or not. */
  conditions: ConditionResult[];
  throttled: boolean;
  suppressedInWindow: number;
  renderWarnings: string[];
  deliveries: DeliveryOutcome[];
}

export interface DispatchReport {
  event: AutomationEvent;
  tenantId: string;
  organizationId: string | null;
  evaluatedAt: string;
  rules: RuleEvaluation[];
  totals: { rulesMatched: number; sent: number; failed: number; throttled: number; skipped: number };
}

export interface RenderedNotification {
  subject: string;
  text: string;
  missing: string[];
  warnings: string[];
}

export interface AutomationRuleEngineDeps {
  rules: AutomationRuleRepository;
  channels: ChannelRepository;
  registry: ChannelRegistry;
  throttle: ThrottleStore;
  deadLetters: DeadLetterStore;
  branding?: BrandingResolver;
  clock?: Clock;
  ids?: IdGenerator;
  sleep?: SleepFn;
  random?: RandomFn;
  audit?: AuditSink;
  /** In-line delivery retries for transient failures before dead-lettering (default 3 attempts). */
  retry?: Partial<RetryPolicy>;
  /** IANA zone for date filters in templates (default UTC). */
  timeZone?: string;
}

const DEFAULT_DELIVERY_RETRY: RetryPolicy = { maxAttempts: 3, baseDelayMs: 500, maxDelayMs: 5_000, factor: 2 };

/**
 * "When <event> and <conditions>, notify <channels> using <template>."
 *
 * dispatch(): rules for the event → organization scoping → conditions (explained) → throttle per
 * rule + subject → render subject/body (logic-less templates; HTML escaping happens in the
 * e-mail renderer) → deliver to each in-scope channel with retries → dead-letter on failure.
 * A channel outside the event's tenant/organization is never used, even if a rule lists it.
 */
export class AutomationRuleEngine {
  private readonly deps: AutomationRuleEngineDeps;
  private readonly clock: Clock;
  private readonly ids: IdGenerator;
  private readonly sleep: SleepFn;
  private readonly random: RandomFn;
  private readonly retry: RetryPolicy;

  constructor(deps: AutomationRuleEngineDeps) {
    this.deps = deps;
    this.clock = deps.clock ?? systemClock;
    this.ids = deps.ids ?? uuidIds;
    this.sleep = deps.sleep ?? defaultSleep;
    this.random = deps.random ?? Math.random;
    const r = { ...DEFAULT_DELIVERY_RETRY, ...deps.retry };
    this.retry = { ...r, maxAttempts: Math.max(1, Math.min(10, Math.floor(r.maxAttempts))) };
  }

  /** Validate a rule draft for the editor: event, conditions, template syntax. */
  static validateRule(rule: Pick<AutomationRule, "event" | "conditions" | "template" | "channelIds" | "throttleMinutes">): { path: string; message: string }[] {
    const issues: { path: string; message: string }[] = [];
    if (!AutomationEvent.safeParse(rule.event).success) issues.push({ path: "event", message: `unknown event "${String(rule.event)}"` });
    issues.push(...validateConditions(rule.conditions));
    issues.push(...validateTemplate(rule.template.subject, { maxLength: 300 }).map((i) => ({ path: "template.subject", message: i.message })));
    issues.push(...validateTemplate(rule.template.body).map((i) => ({ path: "template.body", message: i.message })));
    if (rule.template.subject.trim().length === 0) issues.push({ path: "template.subject", message: "subject is required" });
    if (rule.channelIds.length === 0) issues.push({ path: "channelIds", message: "select at least one channel" });
    if (rule.channelIds.length > 20) issues.push({ path: "channelIds", message: "at most 20 channels per rule" });
    if (!Number.isInteger(rule.throttleMinutes) || rule.throttleMinutes < 0 || rule.throttleMinutes > 10080) issues.push({ path: "throttleMinutes", message: "throttle must be 0-10080 minutes" });
    return issues;
  }

  /** Build the condition/template context for an event. Reserved keys always win over data. */
  buildContext(envelope: AutomationEventEnvelope, brandName?: string): Record<string, unknown> {
    return {
      ...envelope.data,
      data: envelope.data,
      event: envelope.event,
      occurredAt: envelope.occurredAt,
      severity: envelope.severity ?? (typeof envelope.data["severity"] === "string" ? envelope.data["severity"] : "info"),
      organization: { id: envelope.organizationId, name: envelope.organizationName ?? null },
      subject: envelope.subject,
      link: envelope.link ?? null,
      brand: { name: brandName ?? "Bloody" },
    };
  }

  /** Render a rule's template for an event without sending (rule editor "Preview"). */
  render(rule: Pick<AutomationRule, "template">, envelope: AutomationEventEnvelope, brandName?: string): RenderedNotification {
    const ctx = this.buildContext(envelope, brandName);
    const tz = this.deps.timeZone ? { timeZone: this.deps.timeZone } : {};
    const subject = renderTemplateDetailed(rule.template.subject, ctx, { escape: "none", maxLength: 1000, ...tz });
    const body = renderTemplateDetailed(rule.template.body, ctx, { escape: "none", maxLength: 20_000, ...tz });
    return {
      subject: sanitizeHeaderValue(subject.output, 250) || `${envelope.event} — ${envelope.subject.label ?? envelope.subject.id}`,
      text: body.output.trim(),
      missing: [...new Set([...subject.missing, ...body.missing])],
      warnings: [...subject.warnings, ...body.warnings],
    };
  }

  async dispatch(envelope: AutomationEventEnvelope): Promise<DispatchReport> {
    if (!AutomationEvent.safeParse(envelope.event).success) throw new AutomationError("invalid_event", `unknown automation event "${envelope.event}"`);
    const now = this.clock.now();
    const rules = (await this.deps.rules.listForEvent(envelope.tenantId, envelope.event)).filter(
      (r) => r.enabled && r.tenantId === envelope.tenantId && r.event === envelope.event && (r.organizationId === null || r.organizationId === envelope.organizationId),
    );
    const brand = await (this.deps.branding ?? defaultBrandingResolver)(envelope.tenantId, envelope.organizationId);
    const ctx = this.buildContext(envelope, brand.name);
    const evaluations: RuleEvaluation[] = [];
    for (const rule of rules) {
      const evaluation = evaluateConditions(rule.conditions, ctx);
      const ev: RuleEvaluation = { ruleId: rule.id, ruleName: rule.name, matched: evaluation.matched, conditions: evaluation.results, throttled: false, suppressedInWindow: 0, renderWarnings: [], deliveries: [] };
      evaluations.push(ev);
      if (!evaluation.matched) continue;

      if (rule.throttleMinutes > 0) {
        const key = `${envelope.tenantId}:${rule.id}:${envelope.dedupKey ?? `${envelope.subject.kind}:${envelope.subject.id}`}`;
        const decision = await this.deps.throttle.hit(key, now, rule.throttleMinutes * 60_000);
        if (!decision.allowed) {
          ev.throttled = true;
          ev.suppressedInWindow = decision.suppressed;
          continue;
        }
      }

      const rendered = this.render(rule, envelope, brand.name);
      ev.renderWarnings = [...rendered.warnings, ...rendered.missing.map((m) => `variable "${m}" is not available for this event`)];
      const message: NotificationMessage = {
        id: this.ids(),
        tenantId: envelope.tenantId,
        organizationId: envelope.organizationId,
        ...(envelope.organizationName ? { organizationName: envelope.organizationName } : {}),
        event: envelope.event,
        severity: (ctx["severity"] as Severity) ?? "info",
        subject: rendered.subject,
        text: rendered.text,
        facts: envelope.facts ?? [],
        ...(envelope.link ? { link: envelope.link } : {}),
        occurredAt: envelope.occurredAt,
        dedupKey: envelope.dedupKey ?? `${envelope.subject.kind}:${envelope.subject.id}`,
        data: { event: envelope.event, subject: envelope.subject, ...envelope.data },
        ...(envelope.audience ? { audience: envelope.audience } : {}),
        origin: { kind: "automation_rule", id: rule.id, name: rule.name },
      };
      const channels = await this.deps.channels.getMany(envelope.tenantId, rule.channelIds);
      for (const channelId of rule.channelIds) {
        const channel = channels.find((c) => c.id === channelId);
        ev.deliveries.push(await this.deliverTo(channel, channelId, message, envelope, rule.id));
      }
    }
    const all = evaluations.flatMap((e) => e.deliveries);
    return {
      event: envelope.event,
      tenantId: envelope.tenantId,
      organizationId: envelope.organizationId,
      evaluatedAt: now.toISOString(),
      rules: evaluations,
      totals: {
        rulesMatched: evaluations.filter((e) => e.matched).length,
        sent: all.filter((d) => d.status === "sent").length,
        failed: all.filter((d) => d.status === "failed").length,
        skipped: all.filter((d) => d.status === "skipped").length,
        throttled: evaluations.filter((e) => e.throttled).length,
      },
    };
  }

  /** Deliver an arbitrary message (report delivery, AI-drafted notification) to channels with the same guarantees. */
  async deliver(message: NotificationMessage, channelIds: readonly string[], scope: { tenantId: string; organizationId: string | null }): Promise<DeliveryOutcome[]> {
    const channels = await this.deps.channels.getMany(scope.tenantId, channelIds);
    const out: DeliveryOutcome[] = [];
    for (const id of channelIds) out.push(await this.deliverTo(channels.find((c) => c.id === id), id, message, scope, null));
    return out;
  }

  /** Re-send a dead-lettered notification (admin "Retry" button). */
  async redrive(tenantId: string, deadLetterId: string, actor: { kind: "user" | "service" | "system"; id: string }): Promise<DeliveryOutcome> {
    const dl = await this.deps.deadLetters.get(tenantId, deadLetterId);
    if (!dl) throw new AutomationError("not_found", "dead letter not found");
    if (dl.status !== "pending") throw new AutomationError("not_pending", `dead letter is already ${dl.status}`);
    if (dl.message.attachments && dl.message.attachments.length > 0) {
      throw new AutomationError("not_redrivable", "notifications with attachments must be regenerated (attachments are not retained in the dead-letter queue)");
    }
    const [channel] = await this.deps.channels.getMany(tenantId, [dl.channelId]);
    const { attachments: _a, ...rest } = dl.message;
    const outcome = await this.deliverTo(channel, dl.channelId, rest, { tenantId, organizationId: dl.organizationId }, dl.ruleId, { deadLetter: dl });
    const now = this.clock.now().toISOString();
    if (outcome.status === "sent") await this.deps.deadLetters.update({ ...dl, status: "redriven", updatedAt: now, attempts: dl.attempts + outcome.attempts });
    await safeAudit(this.deps.audit, {
      tenantId,
      organizationId: dl.organizationId,
      actor,
      action: "notification.redrive",
      target: { kind: "dead_letter", id: dl.id },
      outcome: outcome.status === "sent" ? "success" : "failure",
      at: now,
      details: { channelId: dl.channelId, status: outcome.status, reason: outcome.reason },
    });
    return outcome;
  }

  async discardDeadLetter(tenantId: string, deadLetterId: string, actor: { kind: "user" | "service" | "system"; id: string }): Promise<void> {
    const dl = await this.deps.deadLetters.get(tenantId, deadLetterId);
    if (!dl) throw new AutomationError("not_found", "dead letter not found");
    const now = this.clock.now().toISOString();
    await this.deps.deadLetters.update({ ...dl, status: "discarded", updatedAt: now });
    await safeAudit(this.deps.audit, { tenantId, organizationId: dl.organizationId, actor, action: "notification.discard", target: { kind: "dead_letter", id: dl.id }, outcome: "success", at: now });
  }

  private async deliverTo(
    channel: NotificationChannel | undefined,
    channelId: string,
    message: NotificationMessage,
    scope: { tenantId: string; organizationId: string | null },
    ruleId: string | null,
    opts: { deadLetter?: DeadLetter } = {},
  ): Promise<DeliveryOutcome> {
    if (!channel) return { channelId, kind: null, status: "skipped", attempts: 0, reason: "channel not found in this tenant" };
    if (channel.tenantId !== scope.tenantId) return { channelId, kind: channel.kind, status: "skipped", attempts: 0, reason: "channel belongs to another tenant" };
    if (channel.organizationId !== null && channel.organizationId !== scope.organizationId) {
      return { channelId, kind: channel.kind, status: "skipped", attempts: 0, reason: "channel belongs to another organization" };
    }
    if (!channel.enabled) return { channelId, kind: channel.kind, status: "skipped", attempts: 0, reason: "channel is disabled" };
    if (!this.deps.registry.has(channel.kind)) return { channelId, kind: channel.kind, status: "skipped", attempts: 0, reason: `no sender for ${channel.kind}` };

    let attempts = 0;
    let lastError: { code: string; message: string; retryable: boolean } = { code: "unknown", message: "unknown error", retryable: false };
    for (let n = 1; n <= this.retry.maxAttempts; n++) {
      attempts = n;
      try {
        const res = await this.deps.registry.send(channel, message);
        return { channelId, kind: channel.kind, status: "sent", attempts, ...(res.providerMessageId ? { providerMessageId: res.providerMessageId } : {}), ...(res.warnings ? { warnings: res.warnings } : {}) };
      } catch (err) {
        const retryable = err instanceof DeliveryError ? err.retryable : !(err instanceof AutomationError);
        lastError = { code: err instanceof AutomationError ? err.code : "delivery_error", message: errorMessage(err).slice(0, 1000), retryable };
        if (!retryable || n === this.retry.maxAttempts) break;
        await this.sleep(backoffDelay(this.retry, n, this.random));
      }
    }
    const now = this.clock.now().toISOString();
    let deadLetterId: string | undefined;
    if (opts.deadLetter) {
      deadLetterId = opts.deadLetter.id;
      await this.deps.deadLetters.update({ ...opts.deadLetter, attempts: opts.deadLetter.attempts + attempts, error: lastError, updatedAt: now });
    } else {
      deadLetterId = this.ids();
      const { attachments, ...rest } = message;
      await this.deps.deadLetters.put({
        id: deadLetterId,
        tenantId: scope.tenantId,
        organizationId: scope.organizationId,
        ruleId,
        channelId,
        channelKind: channel.kind,
        event: message.event,
        message: { ...rest, ...(attachments ? { attachments: attachments.map((a) => ({ filename: a.filename, contentType: a.contentType, sizeBytes: a.content.length })) } : {}) },
        error: lastError,
        attempts,
        createdAt: now,
        updatedAt: now,
        status: "pending",
      });
    }
    await safeAudit(this.deps.audit, {
      tenantId: scope.tenantId,
      organizationId: scope.organizationId,
      actor: { kind: "system", id: "automation" },
      action: "notification.failed",
      target: { kind: "notification_channel", id: channelId },
      outcome: "failure",
      at: now,
      details: { event: message.event, ruleId, error: lastError, attempts, deadLetterId },
    });
    return { channelId, kind: channel.kind, status: "failed", attempts, reason: `${lastError.code}: ${lastError.message}`, deadLetterId };
  }
}
