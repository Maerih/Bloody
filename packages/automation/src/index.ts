/**
 * @bloody/automation — SOAR, approvals, automation rules and notification channels.
 *
 *   PlaybookEngine         triggers → conditions → ordered steps through an ActionExecutor, with
 *                          approval gates (high-risk always), retries/backoff, idempotency,
 *                          execution log, global MSSP playbooks + per-organization overrides
 *   ApprovalGate           request → approve/reject by a different human with response:approve,
 *                          expiry, optional four-eyes, audit
 *   AutomationRuleEngine   AUTOMATION_EVENTS → conditions → logic-less templates → channels,
 *                          throttling per rule+subject, retries, dead-letter queue
 *   Channels               e-mail (SMTP/nodemailer, branded responsive layout), signed webhooks
 *                          (HMAC-SHA256, SSRF guard), Slack, Microsoft Teams, syslog RFC 5424, in-app
 *   Scheduling             5-field cron parser / next-run / due checks (+ time zones);
 *                          ScheduledReportRunner delivers scheduled reports by e-mail and chat
 *
 * All I/O (stores, transports, secrets, clock, audit) is injected.
 */

// utilities
export * from "./util/runtime.js";
export * from "./util/errors.js";
export * from "./util/audit.js";
export { getPath, isValidPath } from "./util/path.js";

// conditions & templates
export * from "./conditions.js";
export * from "./template.js";

// scheduling
export * from "./scheduling/cron.js";

// approvals
export * from "./approvals/types.js";
export * from "./approvals/gate.js";

// playbooks
export * from "./playbooks/types.js";
export * from "./playbooks/repository.js";
export * from "./playbooks/engine.js";

// channels
export * from "./channels/types.js";
export * from "./channels/ssrf.js";
export * from "./channels/http.js";
export * from "./channels/email-layout.js";
export * from "./channels/email.js";
export * from "./channels/webhook.js";
export * from "./channels/slack.js";
export * from "./channels/teams.js";
export * from "./channels/syslog.js";
export * from "./channels/in-app.js";
export * from "./channels/registry.js";

// automation rules
export * from "./rules/templates.js";
export * from "./rules/stores.js";
export * from "./rules/engine.js";

// scheduled report delivery
export * from "./reports/delivery.js";
