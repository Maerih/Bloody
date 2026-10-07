# Bloody — Architecture

> A unified Security Operating Platform and Command Center for enterprises, internal SOCs,
> MSSPs and MDR providers — combining endpoint, identity, network, SIEM, exposure, cloud,
> threat intelligence, vulnerability, DFIR, SOAR and AI-driven security operations through
> **one Security Graph** and **one Risk Engine**.

Bloody is proprietary. Open-source security engines are an **extensible, replaceable engine
layer**; the Security Graph, Detection Engine, Risk Engine, Command Center, AI SOC, SaaS
control plane and operational workflows are the defensible core.

## 1. Three audiences, one platform

| Audience | Surface | Key capabilities |
|---|---|---|
| **Business / MSSP operator** | MSSP Command Center (`/mssp`) | Portfolio of customer orgs, aggregate posture, SLA, analyst load, plans/entitlements, usage & billing, customer provisioning, global playbooks, portfolio reports |
| **SOC (analysts, hunters, responders, engineers)** | Command Center + module workspaces | Triage feed, incidents, investigations workspace, graph pivoting, detections, SOAR approvals, AI analyst |
| **Customer** (org admins, CISO, viewers) | Same app scoped by role `customer_viewer`/`org_admin`/`ciso` | Their org's dashboard, escalations they must act on, reports, trial/module manager |

Role-aware dashboards: `DashboardRole` in `@bloody/contracts` selects widget presets.

## 2. Tenancy

```
Platform
  └─ Account (tenant, kind = mssp | enterprise)       ← hard isolation boundary (tenant_id)
       └─ Organization (customer / business unit)      ← delegated admin boundary (organization_id)
            ├─ users/teams (role bindings per org or tenant-wide)
            ├─ assets, agents, identities, events, alerts, incidents, investigations
            ├─ policies, playbook overrides, integrations, AI configuration
```

* Every customer-data table has `tenant_id uuid not null` and (except tenant-wide config)
  `organization_id uuid`. Postgres **row-level security** policies compare
  `tenant_id = current_setting('app.tenant_id')::uuid`; the API sets the GUC per transaction
  via `withTenant(tenantId, fn)`.
* Principal → role bindings (`RoleBinding{role, organizationId|null}`) → permissions
  (`ROLE_PERMISSIONS`). Handlers call `requirePermission(perm, orgId)`; list endpoints filter
  by `principalOrgScope()`.
* Caches/keys/object-storage paths are prefixed `t/{tenantId}/o/{orgId}/…`; AI context is
  built only from the requesting tenant's data.

## 3. Core data flow

```
Security sources → Collection (agents, OTel, Vector) → Data fabric (Kafka topics per tenant-partition)
 → Adapters/Normalization (→ Bloody Canonical Event, BCE) → Enrichment (CTI, asset, identity, geo)
 → Security Graph upsert → Detection Engine (Sigma/threshold/sequence) → Correlation (alerts → incidents)
 → Risk Engine (explainable) → Incident / Investigation → AI SOC → SOAR (+ human approval)
 → Response (via engine adapters) → Feedback (FP tracking, tuning)
```

In the single-process deployment the fabric is an in-process bus with the same interface
(`EventBus`) so the code is testable outside Docker; Kafka is a drop-in transport.

## 4. Packages

| Package | Responsibility | Key exports |
|---|---|---|
| `@bloody/contracts` | Shared zod schemas/types | `CanonicalEvent`, entities, RBAC, `MODULES`, `PLANS`, `ENGINES`, AI, SOAR, reporting, dashboard DTOs |
| `@bloody/engines` | Proprietary analytics core | `SecurityGraph` (+ `InMemoryGraphStore`, store interface), `RiskEngine`, `AttackPathEngine`, `DetectionEngine` (Sigma subset compiler, threshold, sequence), `Correlator` |
| `@bloody/ai` | AI provider abstraction + AI SOC | `createProvider(config, fetch)`, `AiOrchestrator`, `ToolGateway`, tool tiers READ→INVESTIGATE→RECOMMEND→REQUIRE_APPROVAL→EXECUTE |
| `@bloody/adapters` | Engine adapters | `Adapter` interface (`normalize(raw) → IngestEvent[]`, `healthCheck()`, `actions`), Wazuh, Zeek, Suricata, Falco, osquery, Velociraptor, OpenCanary, MISP, OpenCTI, Greenbone, Nuclei, Trivy, CoPilot sync |
| `@bloody/automation` | SOAR + notifications | `PlaybookEngine`, `ApprovalGate`, `AutomationRuleEngine`, channel senders (SMTP email, webhook, Slack, Teams, syslog) |
| `@bloody/reporting` | Reports | builders per `ReportType`, renderers HTML/PDF/CSV/JSON, scheduling helpers |
| `@bloody/api` | Control plane | Fastify app, migrations, repositories, routes, auth, audit, metrics |
| `@bloody/web` | Command Center UI | React SPA |

Packages never import from `apps/*`. Engines/ai/automation/reporting take I/O via injected
interfaces so they unit-test without Postgres.

## 5. API (`/api/v1`, JSON, zod-validated, cursor pagination, uniform `ApiError`)

Auth: `POST /auth/login` (email+password → httpOnly session cookie + bearer JWT),
`POST /auth/logout`, `GET /auth/me` → `{ principal, account, organizations, entitlements, plan }`.
API keys (`Authorization: Bearer bk_…`) for service accounts / ingestion. OIDC (Keycloak/Entra/Okta)
pluggable via `AuthProvider`.

| Area | Endpoints |
|---|---|
| Orgs/users | `GET/POST /organizations`, `GET/PATCH /organizations/:id`, `GET /users`, `POST /users`, `GET /teams` |
| Command Center | `GET /command-center/summary?organizationId&windowDays` → `CommandCenterSummary` |
| MSSP | `GET /mssp/overview` → `MsspOverview` |
| Assets & agents | `GET/POST /assets`, `GET /assets/:id`, `GET /agents`, `GET /identities` |
| Detection | `GET /alerts`, `GET/POST /detections`, `POST /detections/:id/test`, `POST /ingest/events`, `GET /events/search` |
| Incidents | `GET/POST /incidents`, `GET/PATCH /incidents/:id`, `GET /incidents/:id/graph` |
| Investigations | `GET/POST /investigations`, `GET /investigations/:id` (timeline, evidence, tasks, notes), `POST /investigations/:id/notes`, `POST /investigations/:id/evidence` |
| Escalations | `GET /escalations`, `POST /escalations/:id/acknowledge`, `POST /escalations/:id/resolve` |
| Graph & risk | `GET /graph/node/:id/neighbors`, `GET /graph/search?q`, `GET /attack-paths`, `GET /risk/assets/:id` |
| Exposure | `GET /vulnerabilities`, `GET /exposure/summary` |
| Intel | `GET/POST /intel/indicators`, `GET /intel/matches` |
| Response | `GET/POST /response/actions`, `POST /response/actions/:id/approve`, `POST /response/actions/:id/reject`, `GET/POST /playbooks` |
| AI SOC | `GET/POST /ai/providers`, `PATCH/DELETE /ai/providers/:id`, `POST /ai/providers/:id/test`, `POST /ai/chat`, `GET /ai/conversations`, `GET /ai/conversations/:id`, `POST /ai/actions/:id/approve` |
| Integrations | `GET /integrations/catalog` (ENGINES), `GET/POST /integrations`, `POST /integrations/:id/sync` |
| Automation | `GET/POST /notifications/channels`, `POST /notifications/channels/:id/test`, `GET/POST /automations` |
| Reporting | `GET /reports/types`, `POST /reports/generate` (→ file), `GET/POST /reports/schedules` |
| Commercial | `GET /entitlements`, `POST /entitlements/:module/trial`, `GET /billing/usage` |
| Platform | `GET /search?q` (global, tenant + permission aware), `GET /audit`, `GET /healthz`, `GET /readyz`, `GET /metrics` |

Every mutating call writes an `audit_log` row (actor, tenant, org, action, target, ip, request id).

## 6. Storage

* **PostgreSQL** — control plane + transactional data + Security Graph tables (`graph_nodes`,
  `graph_edges`) + events (partitioned by day, in the single-node deployment).
* **OpenSearch** — event search at scale (adapter `EventStore`); **ClickHouse** optional analytics.
* **Object storage (S3 API)** — raw events, evidence, report files.
* **Valkey** — cache / rate limits / short-lived state. **Kafka** — streaming backbone.

## 7. Security of the platform

Argon2id passwords, short-lived JWT + rotating session, MFA-ready (TOTP), SSO via OIDC,
API keys hashed (sha256) with prefix lookup, secrets referenced by `credentialRef` and stored
encrypted (AES-256-GCM, key from KMS/env) — never returned by the API, rate limiting, helmet
security headers, CORS allow-list, CSRF protection for cookie sessions (double-submit token),
SSRF guard for user-supplied URLs (AI endpoints, webhooks: block link-local/metadata ranges
unless explicitly allowed for local models), input validation, audit log, RLS, least privilege.

## 8. UI

Inspired by the supplied Command Center screenshots: dark slate top bar (account/org selector,
primary nav, Contact/Help/notifications/settings/menu), slim left icon rail with tiny module
labels (Home, EDR, ITDR, NDR, SIEM, XDR, ASM, ESPM, ISPM, CSPM, CIEM, SSPM, CTI, DFIR, SOAR, VM,
Cloud, K8s, Email, Deception, AI SOC, Trials, Hub) with hover flyouts, light-grey canvas with
white cards; severity bars red/orange/purple; teal donuts; right-hand Triage Feed. Dark and
light themes, global search (⌘K / Ctrl+K), keyboard shortcuts, saved views, drill-down panels.
Pivots: Alert→Incident→Investigation→Graph→Risk→Response; Asset→Vulnerability→Identity→Attack
Path→Exposure→Remediation; IOC→CTI→Environment matches→Incidents→Response.

## 9. Deployment

Docker/Kubernetes are packaging only. `infra/docker-compose.yml` runs Postgres + API + web;
`infra/docker-compose.engines.yml` adds the open-source engine layer. Kubernetes manifests in
`infra/k8s`. Proprietary code is independently testable without Docker.

## 10. Roadmap

1. Foundation — control plane, auth, orgs, RBAC, assets, incidents, investigations, audit, API, Command Center UI, BCE, data fabric. **(this repository)**
2. Telemetry — Wazuh, Zeek, Suricata, Velociraptor adapters, SIEM search, detection engine.
3. Graph & risk — Security Graph, correlation, entity resolution, risk engine, attack paths, exposure.
4. CTI & vulnerability — MISP, OpenCTI, Nuclei, Greenbone, Trivy, KEV/EPSS prioritization.
5. Response & DFIR — SOAR, playbooks, approvals, evidence, live response, containment.
6. AI SOC — model abstraction, local/cloud models, tool calling, AI investigation/hunting/reporting.
7. Commercialization — subscriptions, metering, billing, SSO/SCIM, MSSP mode, customer portal, SLA.
8. Proprietary replacement — own agent, detection, graph store, workflow layer where justified.
