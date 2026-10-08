# MSSP, business and customer workflows

Bloody serves three audiences from one application and one API:

- the **MSSP / business operator**, who runs many customer SOCs;
- the **SOC** (analysts, hunters, responders, engineers);
- the **customer**: org admins, CISOs, executives and viewers.

This document describes how each of them works, and which platform mechanisms (contracts, roles,
APIs) back each step. Design rationale is in [ADR-0009](adr/0009-mssp-tenancy-and-customer-portal.md)
(tenancy and portal), [ADR-0008](adr/0008-soar-approval-gates.md) (approvals) and
[ADR-0010](adr/0010-reporting-and-notifications.md) (reports and notifications).

## 1. Model

```
MSSP account (tenant, kind = mssp)              ← hard isolation boundary (RLS on tenant_id)
 ├─ Organization "Acme Bank"                    ← one per customer: retention, plan entitlements,
 │    ├─ Organization "Acme Bank — Kenya"          integrations, playbook overrides, AI policy
 │    └─ Organization "Acme Bank — Uganda"      ← optional sub-organizations (parentOrganizationId)
 ├─ Organization "Globex Retail"
 └─ … hundreds more
Users ── role bindings {role, organizationId | null}
         null  = every organization of the account (MSSP staff)
         <org> = that organization only (dedicated analysts, customer users)
```

An **enterprise** uses the same structure (`kind = enterprise`), with organizations as business
units or subsidiaries and no MSSP commercial layer.

### Roles

| Role (`RoleKey`) | Typical holder | Scope | Highlights |
|---|---|---|---|
| `mssp_admin` | MSSP operations / management | tenant-wide | Everything, including billing, provisioning and global playbooks |
| `soc_analyst_t1` | Tier-1 analyst | tenant-wide or per customer | Triage, incidents, investigations, escalations, request response, AI |
| `soc_analyst_t2` | Tier-2 analyst | tenant-wide or per customer | + execute low/medium response, intel, reports |
| `threat_hunter` | Hunter | tenant-wide | + detection authoring |
| `incident_responder` | Responder / on-call approver | tenant-wide or per customer | + **approve** response actions |
| `security_engineer` | Detection / integration engineer | tenant-wide | Detections, playbooks, integrations, assets, AI configuration |
| `org_admin` | Customer administrator | own organization | Everything for their organization except `billing:write` |
| `ciso` | Customer CISO | own organization | Read all, reports, audit, billing read, **approve response**, AI |
| `executive` | Customer or MSSP executive | own organization | Incidents, risk, vulnerabilities, reports (read) |
| `customer_viewer` | Customer staff | own organization | Incidents, assets and reports (read); acknowledge and resolve escalations |
| `api_service` | Collector / integration key | own organization | `event:ingest`, asset sync, alert read |

`principalCan()` never lets an organization-scoped binding perform tenant-level actions. List
endpoints filter by `principalOrgScope()`.

## 2. Customer onboarding (provisioning)

| Step | Who | How |
|---|---|---|
| 1. Create the organization: name, slug, retention, optional parent | `mssp_admin` | `POST /api/v1/organizations` (`CreateOrganizationInput`) |
| 2. Assign plan and modules; optionally start module trials | `mssp_admin` | Entitlements per organization (`PLANS`: trial, essentials, professional, enterprise, mssp); `POST /api/v1/entitlements/:module/trial` |
| 3. Pin data region and retention | `mssp_admin` | `Account.dataRegion` (regional stack); `retentionDays` is capped by plan |
| 4. Create the customer team and assign analysts | `mssp_admin` | Teams plus organization-scoped role bindings for dedicated analysts |
| 5. Invite customer users (`org_admin`, `ciso`, `executive`, `customer_viewer`) | `mssp_admin` or customer `org_admin` | `POST /api/v1/users` with organization-scoped bindings. SSO through the customer's IdP (OIDC) where available, MFA for local accounts |
| 6. Connect telemetry | `security_engineer` | Create an `api_service` API key bound to the organization, then deploy Vector on site with `BLOODY_INGEST_API_KEY` (`infra/engines/vector`). The key binds tenant and organization server-side. Register engine integrations (Wazuh, Velociraptor, MISP, …) with credentials stored as `credentialRef` |
| 7. Notifications and escalation contacts | `mssp_admin` / customer `org_admin` | Notification channels (e-mail, Teams, Slack, webhook, syslog) and automation rules, e.g. `escalation.created` → customer on-call |
| 8. Response policy | `mssp_admin` with the customer CISO | Global playbooks apply automatically. Add organization overrides. Agree who approves high-risk actions (MSSP responders, customer CISO, or both: four-eyes) |
| 9. AI policy | `security_engineer` | Provider per organization (local-only or cloud), `allowCloudData`, `redactSensitive`, `maxToolTier` |
| 10. Reporting | `mssp_admin` | Report schedules: `customer_monthly`, `sla`, `executive`, with branding and recipients |
| 11. Go-live check | SOC lead | Events arriving (`bloody_ingest_batches_total{source}`), agents healthy, test escalation delivered, test approval round-trip |

Every step is a mutating API call, so each writes an `audit_log` row (actor, tenant,
organization, action, target, request id).

## 3. Daily SOC operations across customers

- **MSSP Command Center** (`GET /api/v1/mssp/overview` → `MsspOverview`) shows portfolio totals
  (organizations, assets, active and critical incidents, investigations, analysts, agents,
  events per day). Per customer it shows risk score, active and critical incidents, agents and
  unhealthy agents, SLA breaches and MRR. Sorting by risk compares customers on the same,
  versioned, explainable risk model (ADR-0006).
- **Switching customers.** The organization selector in the top bar scopes every view. MSSP
  staff with tenant-wide bindings switch without re-authenticating, and every action records the
  organization it touched.
- **Triage feed.** `CommandCenterSummary.triage` merges incidents, escalations and alerts across
  the analyst's organizations, ordered by severity and age.
- **Assignment.** Incidents carry `assigneeId`. Customer-dedicated teams see only their
  customers' queues.
- **Global vs customer content.** Detections and playbooks can be global (`organizationId =
  null`) or customer-specific. Organization overrides take precedence, which lets one detection
  engineering team serve hundreds of customers.

## 4. Incident lifecycle with the customer

```
alert(s) ─correlation→ incident ─→ investigation (timeline, evidence + chain of custody, tasks, notes, AI)
                                  └→ escalation to customer (dueAt = SLA) ─→ customer acknowledges / resolves
                                  └→ response request ─→ approval gate (MSSP responder and/or customer CISO)
                                                        ─→ execution via engine adapter ─→ audit + timeline
                                  └→ containment → remediation → closure → incident report / monthly review
```

- **Escalations** are the contract between the MSSP and the customer. Each has a severity, a
  `dueAt` (SLA), and status open → acknowledged → resolved. Overdue escalations raise
  `escalation.overdue` (notifications, SLA breach count).
- **Approvals.** A customer CISO (`response:approve` on their organization) can approve isolating
  *their* endpoint from the portal. Self-approval is impossible, and high-risk actions always
  need a human (ADR-0008). Pending approvals notify through `response.pending_approval`.
- **Evidence** keeps an append-only custody chain. Customers can receive evidence exports for
  legal or insurance purposes.

## 5. Customer portal

The customer portal is the same Command Center, scoped by role. Customers never see other
organizations, the MSSP portfolio or tenant settings.

| Capability | `customer_viewer` | `executive` | `ciso` | `org_admin` |
|---|---|---|---|---|
| Organization dashboard (role preset via `DashboardRole`) | ✓ | ✓ | ✓ | ✓ |
| Incidents (read) | ✓ | ✓ | ✓ | ✓ |
| Acknowledge / resolve escalations | ✓ | — | read only¹ | ✓ |
| Reports (read / download) | ✓ | ✓ | ✓ | ✓ |
| Generate and schedule reports | — | — | ✓ | ✓ |
| Risk, vulnerabilities, attack paths | — | ✓ (risk, vulns) | ✓ | ✓ |
| Approve response actions | — | — | ✓ | ✓ |
| AI SOC analyst | — | — | ✓ | ✓ |
| Audit log of their organization | — | — | ✓ | ✓ |
| Usage and billing (read) | — | — | ✓ | ✓ |
| Users and integrations of their organization | — | — | — | ✓ |
| Module manager (entitlements; trials²) | — | — | — | ✓ |

¹ `ciso` holds `escalation:read` but not `escalation:write` in `ROLE_PERMISSIONS`. Grant the CISO
an additional `customer_viewer` or `org_admin` binding if they should acknowledge escalations
themselves.
² Starting a trial is subject to the permission the API enforces on
`POST /api/v1/entitlements/:module/trial` and to the MSSP's commercial policy.

Commercial links in the UI (sales, support, docs, hub) are build-time configuration of the web
app (`VITE_*`), hidden when unset. Report branding carries the MSSP's identity.

## 6. Reporting

| Report (`REPORT_TYPES`) | Audience | Typical cadence |
|---|---|---|
| `customer_monthly`: monthly service review | customer | Monthly, scheduled, branded |
| `executive`: executive / CISO summary | business | Monthly / quarterly |
| `sla`: SLA performance (escalation acknowledgement and resolution vs due) | MSSP and customer | Monthly |
| `analyst_activity` | MSSP management | Weekly |
| `mssp_portfolio`: portfolio and revenue | MSSP management | Monthly |
| `soc_operations`, `incident`, `vulnerability`, `threat_intel`, `compliance` | SOC / business | On demand or scheduled |

Formats are PDF, HTML, CSV and JSON. Schedules use cron per organization. Delivery goes through
notification channels, with each run recorded. Reports contain real data and real empty states
only, and every score in them carries its risk factors.

## 7. Commercial operations

- **Plans and entitlements.** `PLANS` define modules and limits (endpoints, organizations,
  users, events per day, retention, AI requests per day). Each organization's module state is
  active, trial, trial ended, available or locked. Security code checks entitlements only and
  never prices.
- **Trials.** `POST /api/v1/entitlements/:module/trial` starts a module trial. `trial.ending`
  fires notifications before expiry, and conversion is an entitlement change.
- **Metering.** `usage_counters` per organization per day (events ingested, endpoints, AI
  requests), exposed by `GET /api/v1/billing/usage`. Exceeding a plan limit raises
  `usage.quota_exceeded`. Ingest is not dropped silently; the MSSP decides on throttling or an
  upgrade.
- **Billing integration.** Usage exports and entitlement changes feed the MSSP's billing system.
  Invoices and payment live outside the security domain. MRR per customer appears in the MSSP
  overview for portfolio management.

## 8. Offboarding (deprovisioning)

1. Disable the organization's integrations, and revoke its API keys and collector credentials.
2. Export what the contract requires: final reports, incident and evidence exports (with
   custody chain), and event exports for the retention window.
3. Remove customer users' role bindings. Sign-in through the customer IdP stops with the
   bindings.
4. Delete organization data per contract. Event partitions age out by retention; organization
   rows and objects are deleted by the deletion job. Audit records are retained for the
   compliance period.
5. Issue a deletion confirmation. The audit log records who offboarded what and when.

## 9. Guarantees to customers

- **Isolation.** Tenant isolation is enforced twice: by API context, and by PostgreSQL RLS with a
  runtime role that cannot bypass it (ADR-0002). Organization scoping inside the MSSP account is
  enforced by role bindings on every request.
- **Accountability.** Every mutation and every response decision is audited, and customer CISOs
  and admins can read their organization's audit trail.
- **Human control.** High-risk actions always need human approval, and AI can never execute
  beyond its configured tier (ADR-0007).
- **Data residency.** Tenants are pinned to a region (`dataRegion`). Backups and DR stay within
  the regions the contract allows ([OPERATIONS](OPERATIONS.md#backups-pitr-and-disaster-recovery)).
- **Privacy in AI.** No tenant data goes to cloud AI providers unless the customer's
  organization enables it. Secrets and PII are redacted by default.
