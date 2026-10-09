import type pg from "pg";
import { MODULES, type ModuleKey } from "@bloody/contracts";
import type { ApprovalGate, PlaybookEngine } from "@bloody/automation";
import type { Database } from "../db/pool.js";
import type { PipelineLogger } from "../pipeline/analytics.js";
import type { PgConversationStore } from "./ai-store.js";
import { activeTenants } from "./approvals.js";
import type { EntitlementService } from "./commercial.js";
import type { DomainEventBus } from "./domain-events.js";
import type { ReportService } from "./reports.js";

/**
 * Background scheduler (one leader per database, elected with a session-level
 * `pg_try_advisory_lock`; every other replica stays passive and retries the lock each tick).
 *
 * Each tick, per active tenant:
 *   - approval expiry (ApprovalGate.expireDue → playbooks resume as expired, AI actions close);
 *   - due report schedules (cron, claimed per run) delivered through notification channels;
 *   - scheduled playbooks fired in (last tick, now] (SOAR-entitled tenants only);
 *   - escalations that became overdue in (last tick, now] → `escalation.overdue`;
 *   - agents whose last check-in crossed the 24 h silence threshold → `agent.unresponsive`;
 *   - module / account trials ending within 3 days → `trial.ending` (once per trial and day);
 * plus AI transcript retention (message expiry). Window boundaries come from `scheduler_state`,
 * so a restart neither repeats nor skips a window.
 */

const LOCK_KEY = 0x0b100d5c; // stable advisory-lock id for "bloody scheduler"
const SILENT_AFTER_MS = 24 * 3_600_000;
const TRIAL_NOTICE_DAYS = 3;

export interface SchedulerDeps {
  db: Database;
  events: DomainEventBus;
  gate: ApprovalGate;
  playbooks: PlaybookEngine;
  reports: ReportService;
  conversations: PgConversationStore;
  entitlements: EntitlementService;
  log: PipelineLogger;
  intervalSeconds: number;
  now: () => number;
}

export interface TickResult {
  leader: boolean;
  tenants: number;
  approvalsExpired: number;
  reportsRun: number;
  playbooksStarted: number;
  escalationsOverdue: number;
  agentsUnresponsive: number;
  trialNotices: number;
  messagesPurged: number;
  errors: string[];
}

export class Scheduler {
  private timer: NodeJS.Timeout | null = null;
  private lockClient: pg.PoolClient | null = null;
  private running: Promise<TickResult> | null = null;
  private stopped = false;

  constructor(private readonly deps: SchedulerDeps) {}

  start(): void {
    if (this.timer) return;
    this.stopped = false;
    const run = () => {
      void this.tick().catch((err) => this.deps.log.error({ err: err instanceof Error ? err.message : String(err) }, "scheduler tick failed"));
    };
    this.timer = setInterval(run, this.deps.intervalSeconds * 1000);
    this.timer.unref();
    setTimeout(run, 1000).unref();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    if (this.running) await this.running.catch(() => undefined);
    await this.releaseLock();
  }

  /** Acquire (or confirm) leadership on a dedicated connection. */
  private async lead(): Promise<boolean> {
    try {
      if (this.lockClient) {
        await this.lockClient.query("SELECT 1");
        return true;
      }
      const client = await this.deps.db.app.connect();
      const { rows } = await client.query<{ ok: boolean }>("SELECT pg_try_advisory_lock($1) AS ok", [LOCK_KEY]);
      if (rows[0]?.ok) {
        client.on("error", () => {
          this.lockClient = null;
        });
        this.lockClient = client;
        return true;
      }
      client.release();
      return false;
    } catch {
      await this.releaseLock(true);
      return false;
    }
  }

  private async releaseLock(broken = false): Promise<void> {
    const c = this.lockClient;
    this.lockClient = null;
    if (!c) return;
    try {
      if (!broken) await c.query("SELECT pg_advisory_unlock($1)", [LOCK_KEY]);
      c.release(broken);
    } catch {
      c.release(true);
    }
  }

  /** One scheduler pass (also callable directly, e.g. from tests). Concurrent calls share a run. */
  tick(opts: { force?: boolean } = {}): Promise<TickResult> {
    if (this.running) return this.running;
    this.running = this.run(opts).finally(() => {
      this.running = null;
    });
    return this.running;
  }

  private async window(job: string): Promise<{ from: Date; to: Date }> {
    const to = new Date(this.deps.now());
    const { rows } = await this.deps.db.app.query<{ last_tick_at: string | null }>("SELECT last_tick_at FROM scheduler_state WHERE job = $1", [job]);
    const last = rows[0]?.last_tick_at ? new Date(rows[0].last_tick_at) : new Date(to.getTime() - this.deps.intervalSeconds * 1000);
    // Never re-scan more than a day after downtime (older items were handled or are stale).
    const from = new Date(Math.max(last.getTime(), to.getTime() - 86_400_000));
    return { from, to };
  }

  private async commit(job: string, to: Date, result: Record<string, unknown>): Promise<void> {
    await this.deps.db.app.query(
      `INSERT INTO scheduler_state (job, last_tick_at, last_result) VALUES ($1, $2, $3::jsonb)
       ON CONFLICT (job) DO UPDATE SET last_tick_at = EXCLUDED.last_tick_at, last_result = EXCLUDED.last_result`,
      [job, to.toISOString(), JSON.stringify(result)],
    );
  }

  private async run(opts: { force?: boolean }): Promise<TickResult> {
    const result: TickResult = { leader: false, tenants: 0, approvalsExpired: 0, reportsRun: 0, playbooksStarted: 0, escalationsOverdue: 0, agentsUnresponsive: 0, trialNotices: 0, messagesPurged: 0, errors: [] };
    if (this.stopped && !opts.force) return result;
    if (!(await this.lead())) return result;
    result.leader = true;
    const guard = async (what: string, fn: () => Promise<void>) => {
      try {
        await fn();
      } catch (err) {
        const msg = `${what}: ${err instanceof Error ? err.message : String(err)}`;
        result.errors.push(msg.slice(0, 500));
        this.deps.log.warn({ job: what, err: msg }, "scheduler job failed");
      }
    };
    const tenants = await activeTenants(this.deps.db);
    result.tenants = tenants.length;
    const esc = await this.window("escalations.overdue");
    const agents = await this.window("agents.unresponsive");
    const pb = await this.window("playbooks.schedule");
    const now = new Date(this.deps.now());

    for (const t of tenants) {
      await guard(`approvals:${t.id}`, async () => {
        result.approvalsExpired += (await this.deps.gate.expireDue(t.id)).length;
      });
      await guard(`reports:${t.id}`, async () => {
        result.reportsRun += (await this.deps.reports.runDue(t.id)).filter((r) => r.status !== "skipped").length;
      });
      await guard(`playbooks:${t.id}`, async () => {
        if (!(await this.deps.entitlements.isEntitled(t.id, "soar"))) return;
        const orgs = await this.deps.db.withTenant(t.id, async (tx) => (await tx.query<{ id: string }>("SELECT id FROM organizations WHERE status IN ('active', 'onboarding')")).rows.map((r) => r.id));
        if (orgs.length === 0) return;
        const matches = await this.deps.playbooks.runDueSchedules({ tenantId: t.id, organizationIds: orgs, from: pb.from, to: pb.to });
        result.playbooksStarted += matches.filter((m) => m.matched && !m.deduplicated).length;
      });
      await guard(`escalations:${t.id}`, async () => {
        const rows = await this.deps.db.withTenant(t.id, async (tx) =>
          (
            await tx.query<{ id: string; organization_id: string; title: string; severity: string; due_at: string; incident_id: string | null }>(
              "SELECT id, organization_id, title, severity, due_at, incident_id FROM escalations WHERE status <> 'resolved' AND due_at > $1 AND due_at <= $2 ORDER BY due_at LIMIT 1000",
              [esc.from.toISOString(), esc.to.toISOString()],
            )
          ).rows,
        );
        for (const r of rows) {
          this.deps.events.publish({
            tenantId: t.id,
            organizationId: r.organization_id,
            event: "escalation.overdue",
            occurredAt: r.due_at,
            severity: r.severity as "critical",
            subject: { kind: "escalation", id: r.id, label: r.title },
            dedupKey: `escalation:${r.id}:overdue`,
            data: { dueAt: r.due_at, incidentId: r.incident_id },
          });
        }
        result.escalationsOverdue += rows.length;
      });
      await guard(`agents:${t.id}`, async () => {
        const fromCut = new Date(agents.from.getTime() - SILENT_AFTER_MS).toISOString();
        const toCut = new Date(agents.to.getTime() - SILENT_AFTER_MS).toISOString();
        const rows = await this.deps.db.withTenant(t.id, async (tx) =>
          (
            await tx.query<{ id: string; organization_id: string; hostname: string; last_checkin_at: string }>(
              "SELECT id, organization_id, hostname, last_checkin_at FROM agents WHERE status IN ('protected', 'outdated') AND last_checkin_at > $1 AND last_checkin_at <= $2 LIMIT 5000",
              [fromCut, toCut],
            )
          ).rows,
        );
        for (const r of rows) {
          this.deps.events.publish({
            tenantId: t.id,
            organizationId: r.organization_id,
            event: "agent.unresponsive",
            occurredAt: new Date(Date.parse(r.last_checkin_at) + SILENT_AFTER_MS).toISOString(),
            severity: "medium",
            subject: { kind: "agent", id: r.id, label: r.hostname },
            dedupKey: `agent:${r.id}:unresponsive`,
            data: { lastCheckinAt: r.last_checkin_at, silentHours: 24 },
          });
        }
        result.agentsUnresponsive += rows.length;
      });
      await guard(`trials:${t.id}`, async () => {
        result.trialNotices += await this.trialNotices(t.id, now);
      });
    }
    await guard("ai.retention", async () => {
      result.messagesPurged += await this.deps.conversations.purgeExpired(now);
    });
    await this.commit("escalations.overdue", esc.to, { count: result.escalationsOverdue });
    await this.commit("agents.unresponsive", agents.to, { count: result.agentsUnresponsive });
    await this.commit("playbooks.schedule", pb.to, { started: result.playbooksStarted });
    await this.commit("tick", now, { ...result, errors: result.errors.length });
    return result;
  }

  /** `trial.ending` once per trial and UTC day while fewer than 3 days remain. */
  private async trialNotices(tenantId: string, now: Date): Promise<number> {
    const { entitlements } = await this.deps.entitlements.forTenant(tenantId);
    const soon = entitlements.filter((e) => e.state === "trial" && e.trialEndsAt && Date.parse(e.trialEndsAt) - now.getTime() <= TRIAL_NOTICE_DAYS * 86_400_000 && Date.parse(e.trialEndsAt) > now.getTime());
    let sent = 0;
    const day = now.toISOString().slice(0, 10);
    for (const e of soon) {
      const first = await this.deps.db.withTenant(tenantId, async (tx) => {
        const { rows } = await tx.query(
          `INSERT INTO usage_counters (tenant_id, organization_id, metric, period_start, value) VALUES ($1, NULL, $2, $3::date, 1)
           ON CONFLICT (tenant_id, org_key(organization_id), metric, period_start) DO NOTHING RETURNING metric`,
          [tenantId, `trial_notice.${e.module}`, day],
        );
        return rows.length > 0;
      });
      if (!first) continue;
      const days = Math.max(0, Math.ceil((Date.parse(e.trialEndsAt!) - now.getTime()) / 86_400_000));
      this.deps.events.publish({
        tenantId,
        organizationId: null,
        event: "trial.ending",
        occurredAt: now.toISOString(),
        severity: days <= 1 ? "high" : "medium",
        subject: { kind: "module", id: e.module, label: MODULES.find((m) => m.key === e.module)?.name ?? e.module },
        dedupKey: `trial:${e.module}:${day}`,
        data: { module: e.module as ModuleKey, moduleName: MODULES.find((m) => m.key === e.module)?.name ?? e.module, trialEndsAt: e.trialEndsAt, daysLeft: days },
      });
      sent++;
    }
    return sent;
  }
}
