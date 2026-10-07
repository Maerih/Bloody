import type { AutomationRule, ReportSchedule } from "@bloody/contracts";
import { AUTOMATION_EVENTS } from "@bloody/contracts";
import nodemailer from "nodemailer";
import { describe, expect, it } from "vitest";
import { EmailSender } from "../channels/email.js";
import { InAppSender, InMemoryInAppStore } from "../channels/in-app.js";
import { ChannelRegistry } from "../channels/registry.js";
import { SlackSender } from "../channels/slack.js";
import { resolveBranding } from "../channels/types.js";
import { WebhookSender } from "../channels/webhook.js";
import { ScheduledReportRunner, formatPeriodLabel, type ReportScheduleStore } from "../reports/delivery.js";
import { channel, FakeClock, FakeHttp, FakeSecrets, ORG_A, ORG_B, OTHER_TENANT, sequentialIds, TENANT } from "../test-support/fixtures.js";
import { MemoryAuditSink } from "../util/audit.js";
import { DeliveryError } from "../util/errors.js";
import { validateTemplate } from "../template.js";
import { AutomationRuleEngine, type AutomationEventEnvelope } from "./engine.js";
import { InMemoryChannelRepository, InMemoryDeadLetterStore, InMemoryRuleRepository, InMemoryThrottleStore } from "./stores.js";
import { DEFAULT_RULE_TEMPLATES } from "./templates.js";

/** Read a (folded, possibly RFC 2047 encoded) header from a raw MIME message. */
function header(raw: string, name: string): string | null {
  const unfolded = raw.split(/\r?\n\r?\n/)[0]!.replace(/\r?\n[ \t]+/g, " ");
  const line = unfolded.split(/\r?\n/).find((l) => l.toLowerCase().startsWith(`${name.toLowerCase()}:`));
  if (!line) return null;
  const value = line.slice(name.length + 1).trim();
  return value
    .replace(/\?=\s+=\?/g, "?==?")
    .replace(/=\?UTF-8\?([QB])\?([^?]*)\?=/gi, (_m, enc: string, text: string) =>
      enc.toUpperCase() === "B"
        ? Buffer.from(text, "base64").toString("utf8")
        : Buffer.from(text.replace(/_/g, " ").replace(/=([0-9A-F]{2})/gi, (_x, h: string) => String.fromCharCode(parseInt(h, 16))), "latin1").toString("utf8"),
    );
}

const EMAIL_CH = "e0000000-0000-4000-8000-000000000001";
const SLACK_CH = "e0000000-0000-4000-8000-000000000002";
const OTHER_ORG_CH = "e0000000-0000-4000-8000-000000000003";
const HOOK_CH = "e0000000-0000-4000-8000-000000000004";
const FOREIGN_CH = "e0000000-0000-4000-8000-000000000005";
const INAPP_CH = "e0000000-0000-4000-8000-000000000006";

function rule(overrides: Partial<AutomationRule> = {}): AutomationRule {
  return {
    id: "r0000000-0000-4000-8000-000000000001".replace("r", "a"),
    tenantId: TENANT,
    organizationId: null,
    name: "Critical incidents to SOC",
    event: "incident.created",
    conditions: [{ field: "severity", op: "gte", value: "high" }],
    channelIds: [EMAIL_CH, SLACK_CH],
    template: DEFAULT_RULE_TEMPLATES["incident.created"],
    throttleMinutes: 30,
    enabled: true,
    ...overrides,
  };
}

function envelope(overrides: Partial<AutomationEventEnvelope> = {}): AutomationEventEnvelope {
  return {
    tenantId: TENANT,
    organizationId: ORG_A,
    organizationName: "Acme Corp",
    event: "incident.created",
    occurredAt: "2026-10-07T11:58:00.000Z",
    severity: "critical",
    subject: { kind: "incident", id: "inc-42", label: "#42" },
    link: { url: "https://app.bloody.example/incidents/inc-42", label: "Open incident" },
    data: {
      incident: { number: 42, title: `Ransomware <img src=x onerror=alert(1)> on FIN-WS-042`, summary: "Encryption precursor activity.", riskScore: 91, assetCount: 3, techniques: ["T1059.001", "T1486"], detectedAt: "2026-10-07T11:55:00Z" },
    },
    facts: [{ label: "Risk score", value: "91" }],
    ...overrides,
  };
}

function setup(opts: { http?: FakeHttp; rules?: AutomationRule[] } = {}) {
  const clock = new FakeClock("2026-10-07T12:00:00Z");
  const transport = nodemailer.createTransport({ streamTransport: true, buffer: true, newline: "unix" });
  const sent: string[] = [];
  const recordingTransport = {
    sendMail: async (mail: Parameters<typeof transport.sendMail>[0]) => {
      const info = (await transport.sendMail(mail)) as unknown as { message: Buffer; messageId: string };
      sent.push(info.message.toString("utf8"));
      return { messageId: info.messageId, accepted: [mail.to], rejected: [], response: "250 OK" };
    },
  } as unknown as typeof transport;
  const http = opts.http ?? new FakeHttp();
  const secrets = new FakeSecrets({ "hook-secret": "s3cret" });
  const branding = async (_t: string, org: string | null) => (org === ORG_A ? resolveBranding({ name: "Acme MSSP", primaryColor: "#0055AA" }) : resolveBranding(null));
  const inApp = new InMemoryInAppStore();
  const registry = new ChannelRegistry([
    new EmailSender({ transport: recordingTransport, from: { address: "notify@soc.example.com" }, branding, clock, ids: sequentialIds("aaaa0000") }),
    new SlackSender({ http, secrets, branding, clock }),
    new WebhookSender({ http, secrets, clock }),
    new InAppSender({ store: inApp, clock }),
  ]);
  const channels = new InMemoryChannelRepository([
    channel("email", { to: ["soc@acme.example"] }, { id: EMAIL_CH, organizationId: null }),
    channel("slack", { url: "https://hooks.slack.com/services/T/B/X" }, { id: SLACK_CH, organizationId: ORG_A }),
    channel("email", { to: ["soc@beta.example"] }, { id: OTHER_ORG_CH, organizationId: ORG_B }),
    channel("webhook", { url: "https://hooks.customer.example/x", secretRef: "hook-secret" }, { id: HOOK_CH }),
    channel("email", { to: ["x@foreign.example"] }, { id: FOREIGN_CH, tenantId: OTHER_TENANT }),
    channel("in_app", {}, { id: INAPP_CH }),
  ]);
  const deadLetters = new InMemoryDeadLetterStore();
  const audit = new MemoryAuditSink();
  const delays: number[] = [];
  const engine = new AutomationRuleEngine({
    rules: new InMemoryRuleRepository(opts.rules ?? [rule()]),
    channels,
    registry,
    throttle: new InMemoryThrottleStore(),
    deadLetters,
    branding,
    clock,
    ids: sequentialIds("bbbb0000"),
    audit,
    random: () => 0,
    sleep: async (ms) => {
      delays.push(ms);
    },
  });
  return { clock, engine, sent, http, deadLetters, audit, delays, inApp };
}

describe("AutomationRuleEngine", () => {
  it("matches, renders and delivers to e-mail and Slack with escaping", async () => {
    const { engine, sent, http } = setup();
    const report = await engine.dispatch(envelope());
    expect(report.totals).toEqual({ rulesMatched: 1, sent: 2, failed: 0, skipped: 0, throttled: 0 });
    expect(report.rules[0]!.conditions[0]!.explanation).toMatch(/severity ≥ "high" — actual "critical" → match/);
    expect(sent).toHaveLength(1);
    const raw = sent[0]!;
    expect(header(raw, "Subject")).toBe("[CRITICAL] Incident #42: Ransomware <img src=x onerror=alert(1)> on FIN-WS-042");
    expect(header(raw, "From")).toBe("Acme MSSP Security Operations <notify@soc.example.com>");
    // The HTML part never carries the raw tag (quoted-printable may wrap lines, so normalise first).
    const decoded = raw.replace(/=\r?\n/g, "").replace(/=3D/g, "=");
    const htmlPart = decoded.split("Content-Type: text/html")[1]!.split("----_")[0]!;
    expect(htmlPart).toContain("Ransomware &lt;img src&#61;x onerror&#61;alert(1)&gt; on FIN-WS-042");
    expect(htmlPart).not.toMatch(/<img src=x/);
    const slackBody = JSON.parse(http.requests[0]!.body);
    expect(slackBody.text).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(JSON.stringify(slackBody)).toContain("Acme MSSP");
  });

  it("explains non-matching rules and does not send", async () => {
    const { engine, sent } = setup();
    const report = await engine.dispatch(envelope({ severity: "low" }));
    expect(report.rules[0]!.matched).toBe(false);
    expect(report.totals.sent).toBe(0);
    expect(sent).toHaveLength(0);
  });

  it("throttles repeats per rule + subject within the window", async () => {
    const { engine, clock } = setup();
    expect((await engine.dispatch(envelope())).totals.sent).toBe(2);
    const second = await engine.dispatch(envelope());
    expect(second.rules[0]!.throttled).toBe(true);
    expect(second.rules[0]!.suppressedInWindow).toBe(1);
    expect(second.totals.sent).toBe(0);
    // A different subject is not throttled.
    expect((await engine.dispatch(envelope({ subject: { kind: "incident", id: "inc-43" } }))).totals.sent).toBe(2);
    clock.advance(31 * 60_000);
    expect((await engine.dispatch(envelope())).totals.sent).toBe(2);
  });

  it("enforces tenant and organization scope for rules and channels", async () => {
    const orgBRule = rule({ id: "a0000000-0000-4000-8000-0000000000b1", organizationId: ORG_B, throttleMinutes: 0 });
    const leaky = rule({ id: "a0000000-0000-4000-8000-0000000000b2", channelIds: [OTHER_ORG_CH, FOREIGN_CH, "e0000000-0000-4000-8000-00000000dead"], throttleMinutes: 0 });
    const { engine, sent } = setup({ rules: [orgBRule, leaky] });
    const report = await engine.dispatch(envelope());
    expect(report.rules.map((r) => r.ruleId)).toEqual([leaky.id]);
    expect(report.rules[0]!.deliveries.map((d) => [d.status, d.reason])).toEqual([
      ["skipped", "channel belongs to another organization"],
      ["skipped", "channel not found in this tenant"],
      ["skipped", "channel not found in this tenant"],
    ]);
    expect(sent).toHaveLength(0);
  });

  it("retries transient failures then dead-letters, and can redrive", async () => {
    const http = new FakeHttp([new DeliveryError("http_503", "busy", { retryable: true, status: 503 }), new DeliveryError("http_503", "busy", { retryable: true }), new DeliveryError("http_503", "busy", { retryable: true }), { status: 200, headers: {}, body: "ok" }]);
    const { engine, deadLetters, delays, audit } = setup({ http, rules: [rule({ channelIds: [HOOK_CH], throttleMinutes: 0 })] });
    const report = await engine.dispatch(envelope());
    const d = report.rules[0]!.deliveries[0]!;
    expect(d.status).toBe("failed");
    expect(d.attempts).toBe(3);
    expect(delays).toEqual([250, 500]);
    const dl = (await deadLetters.get(TENANT, d.deadLetterId!))!;
    expect(dl).toMatchObject({ status: "pending", channelId: HOOK_CH, attempts: 3, error: { code: "http_503", retryable: true } });
    expect(audit.entries.some((e) => e.action === "notification.failed")).toBe(true);
    const redriven = await engine.redrive(TENANT, dl.id, { kind: "user", id: "admin" });
    expect(redriven.status).toBe("sent");
    expect((await deadLetters.get(TENANT, dl.id))!.status).toBe("redriven");
    await expect(engine.redrive(TENANT, dl.id, { kind: "user", id: "admin" })).rejects.toMatchObject({ code: "not_pending" });
  });

  it("dead-letters permanent failures without retrying", async () => {
    const http = new FakeHttp([{ status: 410, headers: {}, body: "gone" }]);
    const { engine, delays, deadLetters } = setup({ http, rules: [rule({ channelIds: [HOOK_CH], throttleMinutes: 0 })] });
    const report = await engine.dispatch(envelope());
    expect(report.rules[0]!.deliveries[0]).toMatchObject({ status: "failed", attempts: 1 });
    expect(delays).toEqual([]);
    expect(await deadLetters.list(TENANT)).toHaveLength(1);
  });

  it("previews templates and validates rule drafts", () => {
    const { engine } = setup();
    const preview = engine.render({ template: { subject: "{{incident.title}} {{nope.x}}", body: "Risk {{incident.riskScore}}" } }, envelope());
    expect(preview.subject).toBe("Ransomware <img src=x onerror=alert(1)> on FIN-WS-042");
    expect(preview.missing).toEqual(["nope.x"]);
    expect(AutomationRuleEngine.validateRule({ event: "incident.created", conditions: [], template: { subject: "{{a | bogus}}", body: "" }, channelIds: [], throttleMinutes: 5 }).map((i) => i.path)).toEqual(["template.subject", "channelIds"]);
  });

  it("ships a valid default template for every automation event", () => {
    for (const ev of AUTOMATION_EVENTS) {
      const t = DEFAULT_RULE_TEMPLATES[ev];
      expect(t.event).toBe(ev);
      expect(validateTemplate(t.subject)).toEqual([]);
      expect(validateTemplate(t.body)).toEqual([]);
    }
  });

  it("delivers in-app notifications", async () => {
    const { engine, inApp } = setup({ rules: [rule({ channelIds: [INAPP_CH], throttleMinutes: 0 })] });
    await engine.dispatch(envelope());
    expect(inApp.items).toHaveLength(1);
    expect(inApp.items[0]!.title).toMatch(/^\[CRITICAL\] Incident #42/);
  });
});

describe("ScheduledReportRunner", () => {
  class MemorySchedules implements ReportScheduleStore {
    constructor(public rows: ReportSchedule[]) {}
    async listEnabled(): Promise<ReportSchedule[]> {
      return this.rows.filter((r) => r.enabled).map((r) => ({ ...r }));
    }
    async claimRun(tenantId: string, id: string, expected: string | null, ranAt: string): Promise<boolean> {
      const r = this.rows.find((x) => x.id === id && x.tenantId === tenantId);
      if (!r || r.lastRunAt !== expected) return false;
      r.lastRunAt = ranAt;
      return true;
    }
  }

  it("generates due reports and e-mails them as attachments, once per slot", async () => {
    const { engine, sent, clock } = setup({ rules: [] });
    clock.set("2026-10-01T07:00:30Z");
    const schedule: ReportSchedule = {
      id: "f0000000-0000-4000-8000-000000000001",
      tenantId: TENANT,
      organizationId: ORG_A,
      type: "customer_monthly",
      name: "Monthly service review",
      cron: "0 7 1 * *",
      format: "pdf",
      periodDays: 30,
      channelIds: [EMAIL_CH],
      enabled: true,
      lastRunAt: "2026-09-01T07:00:10.000Z",
    };
    const store = new MemorySchedules([schedule]);
    const periods: { from: string; to: string }[] = [];
    const generated: string[] = [];
    const runner = new ScheduledReportRunner({
      schedules: store,
      delivery: engine,
      clock,
      ids: sequentialIds("cccc0000"),
      generate: async (_s, p) => {
        periods.push({ from: p.from.toISOString(), to: p.to.toISOString() });
        return { filename: "acme-monthly-2026-09.pdf", contentType: "application/pdf", content: Buffer.from("%PDF-1.7\n"), title: "Customer monthly service review", summary: "23 incidents handled, 98% SLA attainment.", highlights: [{ label: "SLA attainment", value: "98%" }], organizationName: "Acme Corp" };
      },
      onGenerated: async (e) => {
        generated.push(e.event);
      },
    });
    const results = await runner.runDue();
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({ status: "delivered", scheduledFor: "2026-10-01T07:00:00.000Z" });
    expect(periods).toEqual([{ from: "2026-09-01T07:00:00.000Z", to: "2026-10-01T07:00:00.000Z" }]);
    expect(generated).toEqual(["report.generated"]);
    expect(sent).toHaveLength(1);
    expect(header(sent[0]!, "Subject")).toMatch(/^Customer monthly service review — 1 Sept? – 1 Oct 2026$/);
    expect(sent[0]).toContain("Content-Type: application/pdf; name=acme-monthly-2026-09.pdf");
    expect(sent[0]).toContain("Monthly service review");
    expect(await runner.runDue()).toEqual([]);
  });

  it("formats period labels", () => {
    expect(formatPeriodLabel(new Date("2025-12-01T00:00:00Z"), new Date("2026-01-01T00:00:00Z"))).toBe("1 Dec – 31 Dec 2025");
    expect(formatPeriodLabel(new Date("2025-12-15T00:00:00Z"), new Date("2026-01-15T00:00:00Z"))).toBe("15 Dec 2025 – 14 Jan 2026");
  });
});
