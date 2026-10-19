# Security review — October 2026

Internal review of authorization across every API route (43 route files, ~280 routes), plus
dependency audit and HTTP hardening checks. Proprietary — SCIAT AFRICA.

## Scope and method

- Every route was read together with the helpers and services it calls, checking:
  organization isolation inside a tenant (MSSP customers), permission strength for each action,
  privilege escalation, secret handling, and the credentials used by public routes (agent tokens,
  learner links, webhooks, ingest keys).
- Tenant isolation (Postgres row-level security via `withTenant`) held everywhere: the only query
  outside it is the pre-authentication login / API-key lookup, and tenant is always taken from the
  verified credential.
- Authentication is deny-by-default (`config.public` opt-out), with CSRF for cookie sessions,
  helmet headers, CORS allow-list, per-IP rate limits and per-account lockout.
- Each fix below has a regression test in `apps/api/src/routes/security-review.test.ts`; the key
  tests were checked to fail without their fix.

## Fixed

| Severity | Finding | Fix |
|---|---|---|
| High | An organization's MISP import could revoke threat indicators of other organizations and tenant-wide ones (`external_ref` match was not scoped). | Revocation only touches indicators in the import's own scope. |
| Medium-high | `response:execute` was never checked: Tier-1 analysts could run medium-risk actions (release from isolation, kill process, quarantine) and manual playbooks without approval. | Without `response:execute`, medium/high-risk actions and playbook steps wait for an approver. |
| Medium | The author of a scheduled/event-triggered playbook could approve its own high-risk steps. | The person who wrote the running playbook version cannot approve its steps. |
| Medium | The default ingest API-key role could switch App Control to enforce, add block rules, block RMM tools, record the legal port-scan authorization, launch scans, and accept findings. | These decisions require a signed-in person (`person_required`). |
| Medium | An organization admin could reset the password of a user who has wider access through a team. | Administering a user considers direct and team role bindings. |
| Medium | Write-only secrets could be redirected: changing an AI provider endpoint, a webhook URL or an SMTP server kept the stored key / Authorization header / password. | The credential must be entered again when the destination changes. |
| Medium | Repeating a "false positive" verdict on one alert three times auto-suppressed the detection for 30 days (bypassing `detection:write`). | Auto-suppression counts distinct alerts. |
| Low | Investigation leads / task assignees could be users of other organizations. | Assignee must be able to read that organization's investigations. |
| Low | API keys with `asset:write` could read the agent enrollment account key. | People only. |
| Low | Automatic agent updates (an account setting) needed only `asset:write`. | Needs `settings:write`. |
| Low | Customer-scoped users saw other organizations' playbook overrides and the configuration of tenant-wide integrations (e.g. the CoPilot customer map). | Filtered / redacted. |
| Low | Indicator match counts included other organizations. | Counted in the caller's organizations only. |
| Low | Admin password reset worked on one's own account without the current password. | Own password changes go through `/auth/password`. |
| Low | The shared demo-sandbox account could change its password/MFA/profile/sessions (one visitor affecting all). | Refused for demo-only accounts. |
| Low | OIDC accepted tokens without `email_verified` (accounts are linked by e-mail). | Requires `email_verified: true`; `OIDC_TRUST_UNVERIFIED_EMAIL=true` for IdPs that omit it. |
| Low | `/metrics` was public without `METRICS_TOKEN` and labelled ingest metrics with API-key names; `/readyz` returned database error text. | Metrics need the token in production, labels are bounded, readiness returns a generic reason. |
| Low | Sensitive actions did not require a recent second factor (a stolen session of an MFA user could grant roles or create API keys). | People with an authenticator must confirm a code within the last 10 minutes before granting/removing roles (users and teams), resetting a password, disabling a user, creating an API key, regenerating the agent account key, emergency response and approving/rejecting actions (`mfa_step_up_required`; the web app prompts and retries). |
| Low | Payment webhooks marked an invoice paid without comparing the amount charged (signature-verified, but a misconfigured or altered checkout could settle an invoice for less). | Every provider reports the amount and currency charged (Stripe `amount_total`, Paddle pre-tax subtotal, NOWPayments price, BTCPay invoice read back from the store); less than the invoice total or another currency leaves it open and writes a `billing.payment_mismatch` audit entry. |
| Dependencies | nodemailer (15 advisories, 6 high), OpenTelemetry (DoS). | nodemailer 10.1, OpenTelemetry 2.12. |

## Accepted / open

- **react-router 6 (2 moderate advisories):** open redirect via backslash paths in `<Link>`/`navigate`
  and error deserialization for server rendering. Not exploitable here: the only user-supplied
  navigation target (`?next=` after sign-in) is validated by `safeInternalPath`, which rejects
  backslashes and external URLs, and the app does not server-render. Upgrade to v7 after v1.
- **Microsoft 365 re-assessment needs `identity:read`:** read-only calls to Microsoft with the
  stored secret, rate-limited, secret never returned — kept so analysts can refresh it.
- **Command Center shows identity names to roles without `identity:read`** (within their own
  organizations): by design for the summary view; revisit if customers object.
- An external penetration test is still recommended before production use with customer data.
