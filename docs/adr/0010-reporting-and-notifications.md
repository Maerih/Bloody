# ADR-0010: Reporting and notifications

- Status: Accepted
- Date: 2026-10-07
- Deciders: Product, platform architecture

## Context

Each audience needs different reports:

- **business**: executive/CISO summary, compliance posture;
- **SOC**: operations, incident, vulnerability and exposure, threat intelligence;
- **MSSP**: SLA performance, analyst activity, portfolio and revenue;
- **customers**: monthly service review.

Reports are generated on demand and on schedules, and exported as PDF, HTML, CSV and JSON. They
must be accurate: no invented numbers and real empty states. They must be explainable (risk
factors) and white-labelled for MSSPs. Notifications (incident created, escalation overdue,
approval pending, KEV detected, trial ending, quota exceeded) must reach e-mail, chat, webhooks
and SIEM syslog without becoming an exfiltration or SSRF vector.

## Decision

1. **Report builders** (`@bloody/reporting`, `buildReport`, `REPORT_BUILDERS`) are pure
   functions: report type + period + scoped data source → a typed report model (sections,
   tables, charts, recommendations, SLA metrics).
   - Data comes through a `datasource` interface that the API implements with tenant-scoped
     queries, so a builder cannot reach another tenant's data.
   - Builders render real empty states and never fabricate figures.
2. **Renderers.**
   - HTML: self-contained, with inline SVG charts from a deterministic chart-scene layout.
   - PDF: `pdfkit`, MIT.
   - CSV: formula-injection neutralization (`neutralizeFormula`) for cells beginning with
     `= + - @`.
   - JSON.

   Branding (MSSP logo, colours, contact lines) is applied at render time. Filenames are
   deterministic (`reportFilename`).
3. **Schedules** (`report_schedules`) use cron expressions (`@bloody/automation` scheduling).
   - A single scheduler process evaluates them; job runs take a Postgres advisory lock so they
     never double-fire (`infra/k8s/base/scheduler.yaml`).
   - Runs are recorded (`report_runs`) and delivered through notification channels.
4. **Notification channels** (`NotificationChannelKind`): e-mail (SMTP with STARTTLS and
   verified certificates), webhook (HMAC-signed JSON), Slack, Microsoft Teams, syslog (TCP/TLS or
   UDP, RFC 5424) and in-app.
   - Channel secrets (webhook URLs, tokens) are stored encrypted as `credentialRef`.
   - Outbound URLs pass the SSRF guard: no private, link-local or metadata targets unless the
     deployment explicitly allows them.
5. **Automation rules** (`AutomationRule`): "when `<event>` and `<conditions>`, notify
   `<channels>` with `<template>`".
   - A throttle window (`throttleMinutes`) suppresses repeats for the same subject.
   - Templates are logic-less, with escaped substitutions, so data cannot inject markup or
     links into e-mails and chat messages.
6. **Development delivery.** Mailpit catches every e-mail locally (`infra/docker-compose.yml`)
   over STARTTLS with a development CA, so the production code path (TLS verification on) is
   what gets tested.

## Consequences

- Reports are reproducible from data and model versions, and testable as pure functions.
- Customer reports reuse the same builders with organization scope and branding. There is no
  separate customer reporting stack.
- PDF generation is CPU- and memory-heavy, and scheduled bulk runs happen in the scheduler pod,
  which has a larger `/tmp` emptyDir. On-demand generation is rate-limited per tenant.
- Each chat or webhook integration format must be maintained. Delivery failures are retried with
  backoff and surfaced in the run history, not silently dropped.

## Alternatives considered

- **Headless-browser PDF (Chromium).** High fidelity, but a large attack surface and image size,
  and a sandbox that is awkward to run under read-only, non-root, no-capability containers.
  Rejected for now in favour of `pdfkit` plus SVG.
- **External BI tool for customer reports (e.g. Grafana, Metabase).** Licence issues (Grafana is
  AGPL), a second permission model, and the risk of tenant data leaking through shared
  dashboards. Rejected.
- **Notification SaaS (third-party API-keyed services).** Adds a processor of customer security
  data and a commercial dependency. Channels are implemented directly against open protocols.
