import { createHash } from "node:crypto";
import { AUTOMATION_EVENTS, ROLE_KEYS, type AutomationEvent, type AutomationRule, type NotificationChannel, type NotificationChannelKind, type Severity } from "@bloody/contracts";
import {
  AutomationRuleEngine,
  ChannelRegistry,
  DeliveryError,
  EmailConfig,
  EmailSender,
  InAppSender,
  NodeHttpTransport,
  NodeSyslogTransport,
  SlackSender,
  SyslogSender,
  TeamsSender,
  WebhookSender,
  createSmtpTransport,
  generateWebhookSecret,
  resolveBranding,
  type AuditEntry,
  type AuditSink,
  type AutomationEventEnvelope,
  type AutomationRuleRepository,
  type Branding,
  type BrandingResolver,
  type ChannelRepository,
  type ConfigCheck,
  type DeadLetter,
  type DeadLetterStatus,
  type DeadLetterStore,
  type DeliveryResult,
  type EmailSenderDeps,
  type HttpTransport,
  type InAppNotification,
  type InAppNotificationStore,
  type NotificationMessage,
  type NotificationSender,
  type SecretResolver,
  type SyslogTransport,
  type ThrottleDecision,
  type ThrottleStore,
} from "@bloody/automation";
import { z } from "zod";
import { writeAudit, type AuditActor } from "../audit/audit.js";
import type { SmtpConfig } from "../config.js";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError, badRequest } from "../http/errors.js";
import type { PipelineLogger } from "../pipeline/analytics.js";
import type { Row } from "../repo/mappers.js";
import type { DomainEvent, DomainEventBus } from "./domain-events.js";
import { loadEventContext } from "./event-context.js";
import type { SecretStore } from "./secret-store.js";

/**
 * Notifications: channel repository + senders (e-mail, signed webhooks, Slack, Teams, syslog,
 * in-app), the automation rule engine (event → conditions → template → channels, throttling,
 * dead letters), and the built-in in-app notifications for the Command Center bell.
 *
 * Channel secrets (webhook / Slack / Teams URLs, signing secrets, Authorization values, SMTP
 * passwords, syslog CA) are write-only: the API stores them in the secret store and keeps only
 * the reference in the channel config. Clients can never supply `…Ref` values themselves.
 */

export type EmailTransport = EmailSenderDeps["transport"];

// ─── Stores ─────────────────────────────────────────────────────────────────

export function toChannel(r: Row): NotificationChannel {
  return {
    id: String(r.id),
    tenantId: String(r.tenant_id),
    organizationId: (r.organization_id as string | null) ?? null,
    name: String(r.name),
    kind: r.kind as NotificationChannelKind,
    config: (r.config as Record<string, unknown>) ?? {},
    enabled: Boolean(r.enabled),
  };
}

export function toRule(r: Row): AutomationRule {
  return {
    id: String(r.id),
    tenantId: String(r.tenant_id),
    organizationId: (r.organization_id as string | null) ?? null,
    name: String(r.name),
    event: r.event as AutomationEvent,
    conditions: (r.conditions as AutomationRule["conditions"]) ?? [],
    channelIds: (r.channel_ids as string[]) ?? [],
    template: r.template as AutomationRule["template"],
    throttleMinutes: Number(r.throttle_minutes),
    enabled: Boolean(r.enabled),
  };
}

class PgChannelRepository implements ChannelRepository {
  constructor(private readonly db: Database) {}
  async getMany(tenantId: string, ids: readonly string[]): Promise<NotificationChannel[]> {
    const valid = ids.filter((id) => /^[0-9a-f-]{36}$/i.test(id));
    if (valid.length === 0) return [];
    return this.db.withTenant(tenantId, async (tx) => (await tx.query<Row>("SELECT * FROM notification_channels WHERE id = ANY($1::uuid[])", [valid])).rows.map(toChannel));
  }
}

class PgRuleRepository implements AutomationRuleRepository {
  constructor(private readonly db: Database) {}
  async listForEvent(tenantId: string, event: AutomationEvent): Promise<AutomationRule[]> {
    return this.db.withTenant(tenantId, async (tx) => (await tx.query<Row>("SELECT * FROM automation_rules WHERE event = $1 AND enabled ORDER BY created_at", [event])).rows.map(toRule));
  }
  async get(tenantId: string, id: string): Promise<AutomationRule | null> {
    return this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM automation_rules WHERE id = $1", [id]);
      return rows[0] ? toRule(rows[0]) : null;
    });
  }
}

/** Throttle windows in Postgres (key = "<tenant>:<rule>:<subject>"). */
class PgThrottleStore implements ThrottleStore {
  constructor(private readonly db: Database) {}
  async hit(key: string, now: Date, windowMs: number): Promise<ThrottleDecision> {
    const tenantId = key.slice(0, 36);
    return this.db.withTenant(tenantId, async (tx) => {
      const end = new Date(now.getTime() + windowMs);
      const { rows } = await tx.query<{ window_started_at: string; window_ends_at: string; suppressed: number; fresh: boolean }>(
        `INSERT INTO automation_throttle AS t (tenant_id, key, window_started_at, window_ends_at, suppressed) VALUES ($1, $2, $3, $4, 0)
         ON CONFLICT (tenant_id, key) DO UPDATE SET
           window_started_at = CASE WHEN t.window_ends_at <= $3 THEN $3 ELSE t.window_started_at END,
           suppressed = CASE WHEN t.window_ends_at <= $3 THEN 0 ELSE t.suppressed + 1 END,
           window_ends_at = CASE WHEN t.window_ends_at <= $3 THEN $4 ELSE t.window_ends_at END
         RETURNING window_started_at, window_ends_at, suppressed, (window_started_at = $3) AS fresh`,
        [tenantId, key.slice(0, 1000), now.toISOString(), end.toISOString()],
      );
      const r = rows[0]!;
      return { allowed: r.fresh && r.suppressed === 0, suppressed: r.suppressed, windowStartedAt: new Date(r.window_started_at), windowEndsAt: new Date(r.window_ends_at) };
    });
  }
}

export function toDeadLetter(r: Row): DeadLetter {
  return {
    id: String(r.id),
    tenantId: String(r.tenant_id),
    organizationId: (r.organization_id as string | null) ?? null,
    ruleId: (r.rule_id as string | null) ?? null,
    channelId: String(r.channel_id),
    channelKind: String(r.channel_kind),
    event: String(r.event),
    message: r.message as DeadLetter["message"],
    error: r.error as DeadLetter["error"],
    attempts: Number(r.attempts),
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
    status: r.status as DeadLetterStatus,
  };
}

class PgDeadLetterStore implements DeadLetterStore {
  constructor(private readonly db: Database) {}
  async put(e: DeadLetter): Promise<void> {
    await this.db.withTenant(e.tenantId, (tx) =>
      tx.query(
        `INSERT INTO notification_dead_letters (id, tenant_id, organization_id, rule_id, channel_id, channel_kind, event, message, error, attempts, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, $11)`,
        [e.id, e.tenantId, e.organizationId, e.ruleId && /^[0-9a-f-]{36}$/i.test(e.ruleId) ? e.ruleId : null, e.channelId, e.channelKind, e.event, JSON.stringify(e.message), JSON.stringify(e.error), e.attempts, e.status],
      ),
    );
  }
  async get(tenantId: string, id: string): Promise<DeadLetter | null> {
    return this.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT * FROM notification_dead_letters WHERE id = $1", [id]);
      return rows[0] ? toDeadLetter(rows[0]) : null;
    });
  }
  async list(tenantId: string, filter: { status?: DeadLetterStatus; channelId?: string; limit?: number } = {}): Promise<DeadLetter[]> {
    return this.db.withTenant(tenantId, async (tx) => {
      const params: unknown[] = [];
      const where = ["TRUE"];
      if (filter.status) where.push(`status = $${params.push(filter.status)}`);
      if (filter.channelId) where.push(`channel_id = $${params.push(filter.channelId)}`);
      params.push(Math.min(filter.limit ?? 100, 500));
      const { rows } = await tx.query<Row>(`SELECT * FROM notification_dead_letters WHERE ${where.join(" AND ")} ORDER BY created_at DESC LIMIT $${params.length}`, params);
      return rows.map(toDeadLetter);
    });
  }
  async update(e: DeadLetter): Promise<void> {
    await this.db.withTenant(e.tenantId, (tx) => tx.query("UPDATE notification_dead_letters SET status = $2, attempts = $3, error = $4::jsonb WHERE id = $1", [e.id, e.status, e.attempts, JSON.stringify(e.error)]));
  }
}

class PgInAppStore implements InAppNotificationStore {
  constructor(private readonly db: Database) {}
  async insert(n: InAppNotification): Promise<void> {
    await this.db.withTenant(n.tenantId, (tx) => insertInApp(tx, n, "channel"));
  }
}

export async function insertInApp(tx: Queryable, n: InAppNotification, source: "system" | "channel", subject?: { kind: string; id: string }): Promise<void> {
  const roles = n.recipients.roles.filter((r) => (ROLE_KEYS as readonly string[]).includes(r));
  await tx.query(
    `INSERT INTO notifications (id, tenant_id, organization_id, event, severity, title, body, facts, link, recipient_user_ids, recipient_roles, source, subject_kind, subject_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::uuid[], $11, $12, $13, $14) ON CONFLICT (id) DO NOTHING`,
    [
      n.id,
      n.tenantId,
      n.organizationId,
      n.event.slice(0, 100),
      n.severity,
      n.title.slice(0, 500) || n.event,
      n.body.slice(0, 20_000),
      JSON.stringify(n.facts.slice(0, 20)),
      n.link ? JSON.stringify(n.link) : null,
      n.recipients.userIds.filter((u) => /^[0-9a-f-]{36}$/i.test(u)),
      roles,
      source,
      subject?.kind ?? null,
      subject?.id ?? null,
    ],
  );
}

/** Automation audit entries → audit_log (each in its own tenant transaction). */
export class DbAuditSink implements AuditSink {
  constructor(private readonly db: Database) {}
  async record(entry: AuditEntry): Promise<void> {
    const actorKind: AuditActor["actorKind"] = entry.actor.kind === "user" ? "user" : entry.actor.kind === "service" ? "service" : "system";
    const actorId = entry.actor.kind === "playbook" || entry.actor.kind === "ai" ? `${entry.actor.kind}:${entry.actor.id}` : entry.actor.id;
    await this.db.withTenant(entry.tenantId, (tx) =>
      writeAudit(
        tx,
        { tenantId: entry.tenantId, actorKind, actorId, actorLabel: entry.actor.kind === "user" ? null : entry.actor.kind, ip: null, userAgent: null, requestId: null },
        { action: entry.action, organizationId: entry.organizationId, targetKind: entry.target.kind, targetId: entry.target.id, outcome: entry.outcome, details: entry.details ?? {} },
      ),
    );
  }
}

// ─── E-mail sender with per-channel or platform SMTP ────────────────────────

const ChannelSmtp = z
  .object({
    host: z.string().min(1).max(255),
    port: z.number().int().min(1).max(65535).default(587),
    secure: z.boolean().default(false),
    user: z.string().max(255).optional(),
    passwordRef: z.string().max(256).optional(),
    fromAddress: z.string().email(),
    fromName: z.string().max(120).optional(),
  })
  .strict();

class TenantEmailSender implements NotificationSender {
  readonly kind = "email" as const;
  private readonly transports = new Map<string, EmailTransport>();
  private platformTransport: EmailTransport | null = null;

  constructor(
    private readonly deps: {
      platform: SmtpConfig | null;
      override: EmailTransport | null;
      secrets: SecretResolver;
      branding: BrandingResolver;
      appBaseUrl: string;
      now: () => number;
    },
  ) {}

  validateConfig(config: unknown): ConfigCheck {
    const { smtp, ...rest } = (config ?? {}) as Record<string, unknown>;
    const base = EmailConfig.safeParse(rest);
    const issues = base.success ? [] : base.error.issues.map((i) => ({ path: i.path.join("."), message: i.message }));
    if (smtp !== undefined) {
      const s = ChannelSmtp.safeParse(smtp);
      if (!s.success) issues.push(...s.error.issues.map((i) => ({ path: `smtp.${i.path.join(".")}`, message: i.message })));
    }
    return { ok: issues.length === 0, issues };
  }

  private async sender(channel: NotificationChannel): Promise<EmailSender> {
    const smtp = (channel.config as { smtp?: unknown }).smtp;
    let transport: EmailTransport;
    let from: { address: string; name?: string };
    if (smtp) {
      const s = ChannelSmtp.parse(smtp);
      const key = createHash("sha256").update(`${channel.id}:${JSON.stringify(s)}`).digest("hex");
      const password = s.passwordRef ? await this.deps.secrets.resolve(channel.tenantId, s.passwordRef) : undefined;
      transport = this.transports.get(key) ?? createSmtpTransport({ host: s.host, port: s.port, secure: s.secure, ...(s.user ? { user: s.user } : {}), ...(password ? { password } : {}), fromAddress: s.fromAddress, pool: false });
      this.transports.set(key, transport);
      from = { address: s.fromAddress, ...(s.fromName ? { name: s.fromName } : {}) };
    } else if (this.deps.override) {
      transport = this.deps.override;
      from = { address: this.deps.platform?.from ?? "notifications@bloody.local", name: this.deps.platform?.fromName ?? "Bloody Security Operations" };
    } else if (this.deps.platform) {
      const p = this.deps.platform;
      this.platformTransport ??= createSmtpTransport({ host: p.host, port: p.port, secure: p.secure, ...(p.user ? { user: p.user } : {}), ...(p.password ? { password: p.password } : {}), fromAddress: p.from, pool: true });
      transport = this.platformTransport;
      from = { address: p.from, name: p.fromName };
    } else {
      throw new DeliveryError("smtp_not_configured", "No SMTP relay is configured: set SMTP_HOST for the platform or an smtp block on the channel", { retryable: false });
    }
    return new EmailSender({ transport, from, branding: this.deps.branding, appBaseUrl: this.deps.appBaseUrl, clock: { now: () => new Date(this.deps.now()) } });
  }

  async send(channel: NotificationChannel, message: NotificationMessage): Promise<DeliveryResult> {
    return (await this.sender(channel)).send(channel, message);
  }

  async test(channel: NotificationChannel, opts?: { requestedBy?: string; now?: Date }): Promise<DeliveryResult> {
    return (await this.sender(channel)).test(channel, opts);
  }
}

// ─── Channel config (write-only secrets) ────────────────────────────────────

const SECRET_FIELDS: Record<NotificationChannelKind, Array<{ input: string; ref: string; purpose: string }>> = {
  webhook: [
    { input: "url", ref: "urlRef", purpose: "channel.webhook_url" },
    { input: "secret", ref: "secretRef", purpose: "channel.signing_secret" },
    { input: "authorization", ref: "authorizationRef", purpose: "channel.authorization" },
  ],
  slack: [{ input: "url", ref: "urlRef", purpose: "channel.slack_url" }],
  teams: [{ input: "url", ref: "urlRef", purpose: "channel.teams_url" }],
  syslog: [{ input: "ca", ref: "caRef", purpose: "channel.syslog_ca" }],
  email: [],
  in_app: [],
};

function rejectRefs(value: unknown, path = "config"): void {
  if (!value || typeof value !== "object") return;
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (/Ref$/.test(k)) throw badRequest(`${path}.${k} cannot be set directly — send the secret value; it is stored in the secret store`);
    if (v && typeof v === "object" && !Array.isArray(v)) rejectRefs(v, `${path}.${k}`);
  }
}

export interface PreparedChannelConfig {
  config: Record<string, unknown>;
  /** Generated webhook signing secret, shown to the caller exactly once. */
  generatedSecret: string | null;
  /** Secret references that became unused (to delete after commit). */
  releasedRefs: string[];
}

/** API view of a channel: secret references replaced by presence flags. */
export function channelView(c: NotificationChannel & { createdAt?: string; updatedAt?: string }) {
  const cfg: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(c.config)) {
    if (/Ref$/.test(k)) {
      cfg[`has${k.charAt(0).toUpperCase()}${k.slice(1, -3)}`] = typeof v === "string" && v.length > 0;
      continue;
    }
    if (k === "smtp" && v && typeof v === "object") {
      const { passwordRef, ...smtp } = v as Record<string, unknown>;
      cfg.smtp = { ...smtp, hasPassword: typeof passwordRef === "string" };
      continue;
    }
    cfg[k] = v;
  }
  return { id: c.id, tenantId: c.tenantId, organizationId: c.organizationId, name: c.name, kind: c.kind, config: cfg, enabled: c.enabled, ...(c.createdAt ? { createdAt: c.createdAt } : {}), ...(c.updatedAt ? { updatedAt: c.updatedAt } : {}) };
}

// ─── Service ────────────────────────────────────────────────────────────────

/** Events that always create an in-app notification for the SOC (bell), independent of rules. */
const SYSTEM_NOTICES: Partial<Record<AutomationEvent, { roles: string[]; minSeverity?: Severity; title: (e: DomainEvent, d: Record<string, unknown>) => string }>> = {
  "incident.created": { roles: ["soc_analyst_t1", "soc_analyst_t2", "incident_responder", "threat_hunter", "org_admin", "mssp_admin"], minSeverity: "high", title: (_e, d) => `New ${String((d.incident as { severity?: string } | undefined)?.severity ?? "")} incident #${String((d.incident as { number?: number } | undefined)?.number ?? "")}: ${String((d.incident as { title?: string } | undefined)?.title ?? "")}` },
  "incident.severity_changed": { roles: ["soc_analyst_t2", "incident_responder", "mssp_admin"], minSeverity: "high", title: (e) => `Incident escalated to ${e.severity ?? "higher severity"}: ${e.subject.label ?? e.subject.id}` },
  "escalation.created": { roles: ["soc_analyst_t1", "soc_analyst_t2", "incident_responder", "org_admin", "ciso", "customer_viewer", "mssp_admin"], title: (e) => `Escalation opened: ${e.subject.label ?? e.subject.id}` },
  "escalation.overdue": { roles: ["soc_analyst_t2", "incident_responder", "org_admin", "ciso", "mssp_admin"], title: (e) => `Escalation overdue: ${e.subject.label ?? e.subject.id}` },
  "response.pending_approval": { roles: ["incident_responder", "org_admin", "ciso", "mssp_admin"], title: (_e, d) => `Approval needed: ${String((d.action as { action?: string } | undefined)?.action ?? d.action ?? "response action")}` },
  "agent.unresponsive": { roles: ["security_engineer", "soc_analyst_t1", "org_admin"], title: (e) => `Agent unresponsive: ${e.subject.label ?? e.subject.id}` },
  "indicator.matched": { roles: ["soc_analyst_t2", "threat_hunter", "incident_responder"], title: (_e, d) => `Threat-intel match${Number(d.matches ?? 1) === 1 ? "" : `es (${String(d.matches)})`} in your environment` },
  "vulnerability.kev_detected": { roles: ["security_engineer", "org_admin", "ciso"], title: (_e, d) => `Known-exploited vulnerability ${String(d.cve ?? "")} on ${String(d.asset ?? "an asset")}` },
  "trial.ending": { roles: ["org_admin", "mssp_admin", "platform_admin"], title: (_e, d) => `Trial ending: ${String(d.moduleName ?? d.module ?? "module")}` },
  "usage.quota_exceeded": { roles: ["org_admin", "mssp_admin", "platform_admin"], title: (_e, d) => `Plan quota reached: ${String(d.meter ?? "usage")} (${String(d.used ?? "")}/${String(d.limit ?? "")})` },
  "report.generated": { roles: [], title: (e) => `Report ready: ${e.subject.label ?? "report"}` },
};
const SEV: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export interface NotificationServiceDeps {
  db: Database;
  secretStore: SecretStore;
  events: DomainEventBus;
  log: PipelineLogger;
  smtp: SmtpConfig | null;
  publicUrl: string;
  now: () => number;
  httpTransport?: HttpTransport | undefined;
  syslogTransport?: SyslogTransport | undefined;
  emailTransport?: EmailTransport | undefined;
}

export class NotificationService {
  readonly registry: ChannelRegistry;
  readonly engine: AutomationRuleEngine;
  readonly deadLetters: DeadLetterStore;
  readonly audit: DbAuditSink;
  readonly branding: BrandingResolver;

  constructor(private readonly deps: NotificationServiceDeps) {
    const secrets = deps.secretStore.strictResolver();
    this.branding = async (tenantId, organizationId) => {
      const b = await deps.db.withTenant(tenantId, async (tx) => {
        const org = organizationId ? (await tx.query<{ b: Partial<Branding> | null }>("SELECT settings->'branding' AS b FROM organizations WHERE id = $1", [organizationId])).rows[0]?.b : null;
        const acc = (await tx.query<{ b: Partial<Branding> | null }>("SELECT settings->'branding' AS b FROM accounts WHERE id = $1", [tenantId])).rows[0]?.b;
        return org ?? acc ?? null;
      });
      return resolveBranding(b);
    };
    const clock = { now: () => new Date(deps.now()) };
    const http = deps.httpTransport ?? new NodeHttpTransport({ timeoutMs: 10_000 });
    this.registry = new ChannelRegistry([
      new TenantEmailSender({ platform: deps.smtp, override: deps.emailTransport ?? null, secrets, branding: this.branding, appBaseUrl: deps.publicUrl, now: deps.now }),
      new WebhookSender({ http, secrets, clock, branding: this.branding }),
      new SlackSender({ http, secrets, clock, branding: this.branding }),
      new TeamsSender({ http, secrets, clock, branding: this.branding }),
      new SyslogSender({ transport: deps.syslogTransport ?? new NodeSyslogTransport(), secrets, clock, branding: this.branding }),
      new InAppSender({ store: new PgInAppStore(deps.db), branding: this.branding, clock }),
    ]);
    this.deadLetters = new PgDeadLetterStore(deps.db);
    this.audit = new DbAuditSink(deps.db);
    this.engine = new AutomationRuleEngine({
      rules: new PgRuleRepository(deps.db),
      channels: new PgChannelRepository(deps.db),
      registry: this.registry,
      throttle: new PgThrottleStore(deps.db),
      deadLetters: this.deadLetters,
      branding: this.branding,
      clock,
      audit: this.audit,
    });
  }

  link(path: string | null): { url: string; label: string } | undefined {
    if (!path) return undefined;
    return { url: `${this.deps.publicUrl.replace(/\/+$/, "")}${path}`, label: "Open in Bloody" };
  }

  /** Domain event → automation rules (+ built-in in-app notice). */
  async onDomainEvent(e: DomainEvent): Promise<void> {
    if (!(AUTOMATION_EVENTS as readonly string[]).includes(e.event)) return;
    const event = e.event as AutomationEvent;
    const ctx = await loadEventContext(this.deps.db, e, this.deps.now());
    const link = this.link(ctx.path);
    const envelope: AutomationEventEnvelope = {
      tenantId: e.tenantId,
      organizationId: e.organizationId,
      ...(ctx.organizationName ? { organizationName: ctx.organizationName } : {}),
      event,
      occurredAt: e.occurredAt,
      ...(e.severity ? { severity: e.severity } : {}),
      subject: e.subject,
      ...(e.dedupKey ? { dedupKey: e.dedupKey } : {}),
      ...(link ? { link } : {}),
      data: ctx.data,
    };
    await this.systemNotice(e, event, ctx.data, ctx.path);
    const report = await this.engine.dispatch(envelope);
    if (report.totals.failed > 0) this.deps.log.warn({ tenantId: e.tenantId, event, failed: report.totals.failed }, "automation deliveries failed (dead-lettered)");
    if (report.totals.sent > 0) {
      // Delivery meter (reports: notifications sent per organization and UTC day).
      await this.deps.db.withTenant(e.tenantId, (tx) =>
        tx.query(
          `INSERT INTO usage_counters (tenant_id, organization_id, metric, period_start, value) VALUES ($1, $2, 'notifications.sent', (now() AT TIME ZONE 'UTC')::date, $3)
           ON CONFLICT (tenant_id, org_key(organization_id), metric, period_start) DO UPDATE SET value = usage_counters.value + EXCLUDED.value`,
          [e.tenantId, e.organizationId, report.totals.sent],
        ),
      );
    }
  }

  private async systemNotice(e: DomainEvent, event: AutomationEvent, data: Record<string, unknown>, path: string | null): Promise<void> {
    const spec = SYSTEM_NOTICES[event];
    if (!spec) return;
    if (spec.minSeverity && SEV[e.severity ?? "info"] < SEV[spec.minSeverity]) return;
    const userIds = event === "report.generated" && typeof data.requestedBy === "string" && /^[0-9a-f-]{36}$/i.test(data.requestedBy) ? [data.requestedBy] : [];
    if (spec.roles.length === 0 && userIds.length === 0) return;
    const id = createHash("sha256").update(`${e.tenantId}:${event}:${e.dedupKey ?? `${e.subject.kind}:${e.subject.id}`}:${e.occurredAt}`).digest("hex");
    const uuid = `${id.slice(0, 8)}-${id.slice(8, 12)}-4${id.slice(13, 16)}-8${id.slice(17, 20)}-${id.slice(20, 32)}`;
    await this.deps.db.withTenant(e.tenantId, (tx) =>
      insertInApp(
        tx,
        {
          id: uuid,
          tenantId: e.tenantId,
          organizationId: e.organizationId,
          recipients: { userIds, roles: spec.roles },
          event,
          severity: e.severity ?? "info",
          title: spec.title(e, data).slice(0, 500),
          body: typeof data.summary === "string" ? data.summary : "",
          facts: [],
          link: path ? { url: path, label: "Open" } : null,
          createdAt: new Date(this.deps.now()).toISOString(),
          readBy: [],
        },
        "system",
        e.subject,
      ),
    );
  }

  /** Validate and seal a channel config: secret inputs → secret store refs. */
  async prepareConfig(
    tx: Queryable,
    tenantId: string,
    input: { kind: NotificationChannelKind; organizationId: string | null; name: string; config: Record<string, unknown> },
    existing: NotificationChannel | null,
    actor: string,
  ): Promise<PreparedChannelConfig> {
    rejectRefs(input.config);
    const out: Record<string, unknown> = {};
    const released: string[] = [];
    let generatedSecret: string | null = null;
    const prior = existing?.config ?? {};
    const secretInputs = new Set(SECRET_FIELDS[input.kind].map((f) => f.input));
    for (const [k, v] of Object.entries(input.config)) if (!secretInputs.has(k) && k !== "smtp") out[k] = v;
    for (const f of SECRET_FIELDS[input.kind]) {
      const supplied = input.config[f.input];
      const priorRef = typeof prior[f.ref] === "string" ? (prior[f.ref] as string) : null;
      if (supplied === null) {
        if (priorRef) released.push(priorRef);
        continue;
      }
      if (typeof supplied === "string" && supplied.length > 0) {
        if (supplied.length > 8192) throw badRequest(`config.${f.input} is too long`);
        if (priorRef) await this.deps.secretStore.replace(tx, tenantId, priorRef, supplied);
        const ref = priorRef ?? (await this.deps.secretStore.put(tx, tenantId, { value: supplied, name: `${input.name} (${f.input})`, purpose: f.purpose, organizationId: input.organizationId, createdBy: actor })).ref;
        out[f.ref] = ref;
        continue;
      }
      if (supplied !== undefined) throw badRequest(`config.${f.input} must be a string`);
      if (priorRef) out[f.ref] = priorRef;
      else if (input.kind === "webhook" && f.input === "secret") {
        generatedSecret = generateWebhookSecret();
        out[f.ref] = (await this.deps.secretStore.put(tx, tenantId, { value: generatedSecret, name: `${input.name} (signing secret)`, purpose: f.purpose, organizationId: input.organizationId, createdBy: actor })).ref;
      }
    }
    if (input.kind === "email" && input.config.smtp !== undefined && input.config.smtp !== null) {
      const smtpIn = input.config.smtp as Record<string, unknown>;
      if (typeof smtpIn !== "object" || Array.isArray(smtpIn)) throw badRequest("config.smtp must be an object");
      const { password, ...rest } = smtpIn;
      const priorSmtp = (prior.smtp as Record<string, unknown> | undefined) ?? {};
      const priorRef = typeof priorSmtp.passwordRef === "string" ? priorSmtp.passwordRef : null;
      const smtp: Record<string, unknown> = { ...rest };
      if (typeof password === "string" && password.length > 0) {
        if (priorRef) await this.deps.secretStore.replace(tx, tenantId, priorRef, password);
        smtp.passwordRef = priorRef ?? (await this.deps.secretStore.put(tx, tenantId, { value: password, name: `${input.name} (SMTP password)`, purpose: "channel.smtp_password", organizationId: input.organizationId, createdBy: actor })).ref;
      } else if (password === null) {
        if (priorRef) released.push(priorRef);
      } else if (priorRef) smtp.passwordRef = priorRef;
      out.smtp = smtp;
    } else if (input.kind === "email" && input.config.smtp === undefined && prior.smtp) {
      out.smtp = prior.smtp;
    }
    const check = this.registry.validate(input.kind, out);
    if (!check.ok) throw new HttpError(400, "invalid_channel_config", `Invalid ${input.kind} channel configuration`, check.issues);
    return { config: out, generatedSecret, releasedRefs: released };
  }

  /** Secret references held by a channel config (to delete with the channel). */
  static refsOf(config: Record<string, unknown>): string[] {
    const refs: string[] = [];
    for (const [k, v] of Object.entries(config)) {
      if (/Ref$/.test(k) && typeof v === "string") refs.push(v);
      if (k === "smtp" && v && typeof v === "object" && typeof (v as Record<string, unknown>).passwordRef === "string") refs.push((v as Record<string, string>).passwordRef!);
    }
    return refs;
  }
}
