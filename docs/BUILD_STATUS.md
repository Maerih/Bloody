# Bloody: build status and how to resume

_Paused on 2026-10-09 at the owner's request. Branch: `maerih/bloody`._

## Done

| Area | State |
|---|---|
| `packages/contracts` | Shared schemas: canonical event, RBAC, modules/plans, engine catalog, AI, SOAR, reporting, dashboard DTOs |
| `packages/engines` | Security Graph, explainable Risk Engine, Attack-Path Engine, Detection (Sigma subset, threshold, sequence, IOC), Correlator, built-in rule pack. 139 tests |
| `packages/ai` | Providers: Ollama, vLLM, LM Studio, OpenAI-compatible, OpenAI, Anthropic, Google, Azure OpenAI, Bedrock, Mistral. SSRF guard, redaction, tool gateway with tiers, orchestrator. 160 tests |
| `packages/adapters` | Wazuh, Zeek, Suricata, Falco, osquery, Velociraptor, OpenCanary, Trivy, Nuclei, Greenbone, syslog/CEF, Keycloak, CloudTrail, MISP, OpenCTI, STIX, KEV/EPSS, response connectors, SOCFortress CoPilot sync. 119 tests |
| `packages/automation` | SOAR playbooks, approval gates, automation rules, email (SMTP), webhook, Slack, Teams, syslog, in-app, cron. 115 tests |
| `packages/reporting` | Report builders for every audience; HTML/PDF/CSV/JSON; MSSP white-labelling. 80 tests |
| `apps/api` | Foundation done and tested: auth, sessions, CSRF, API keys, RBAC, Postgres RLS tenancy, audit, ingest pipeline, command center, MSSP, search. Part-B routes are written (AI, response/SOAR, playbooks, reports, integrations/CoPilot, notifications, commercial, MSSP admin, graph, detections, intel, vulnerabilities) and typecheck, but **part-B integration tests are not written yet**. 116+ tests |
| `apps/web` | Shell plus every module page, AI SOC and AI settings, graph, attack paths, investigations workspace, Hub, reports, automations, settings. 119 tests |
| `infra/`, `docs/`, `.github/` | Docker, compose (core and every engine), Kubernetes (kustomize), CI, licence gate, SBOM, ADRs 0001–0010, LICENSES, OPERATIONS, MSSP |

At pause time `pnpm -r typecheck` passed and all ~870 tests passed. The app runs end to end with the dev seed; screenshots are in `docs/screenshots/`.

## Remaining (in order)

1. **API part B: prove and close gaps** (`apps/api`), about 1 h.
   1. Compare the registered routes with `docs/ARCHITECTURE.md` §5.
   2. Add integration tests for:
      - response approval: no self-approval, high-risk actions always pending;
      - AI provider secret never returned, and tool-tier denial;
      - report generation in each format;
      - entitlement 402;
      - CoPilot sync idempotency;
      - a playbook run;
      - a notification channel test;
      - tenant isolation on part-B endpoints.
   3. Make the scheduler honour `BLOODY_SCHEDULER_ENABLED`.
2. **Web finish** (`apps/web`), about 45 min.
   1. Audit each module page for real hooks plus loading, empty and error states.
   2. Remove any remaining `ModulePlaceholderPage` routes.
   3. List every called endpoint in `apps/web/src/api/endpoints.ts`.
3. **Web ↔ API reconciliation**, about 45 min. Match every web call against the registered Fastify routes and response shapes; fix mismatches.
4. **End-to-end run**, about 1 h. Use Playwright on every page: zero console errors and zero failed requests, compare against the reference screenshots, check dark theme, then run `pnpm -r build`.
5. **Security, tenancy and completeness review, then fixes**, about 1.5 h.

Total: about 4–5 hours of agent work.

Known follow-ups from the infra report:
- gzip request decoding for collectors;
- OTLP log envelope unwrapping on `/ingest/:adapter`;
- Kafka `EventBus` transport;
- OpenSearch `EventStore`;
- a Valkey-backed rate limiter;
- OTel SDK instrumentation.

## How to resume

Open a Claude Code session on this repository and branch (`maerih/bloody`), then say:

> Resume the Bloody build from docs/BUILD_STATUS.md — do the "Remaining" steps in order.

## Run it locally

```bash
pnpm install
# Postgres 16 on localhost:5432 (postgres/postgres), or:
docker compose -f infra/docker-compose.yml up -d postgres valkey mailpit
pnpm db:migrate
pnpm db:seed          # dev demo data; prints the logins
pnpm dev:api          # http://localhost:4000/api/v1/healthz
pnpm dev:web          # http://localhost:5173
```

Log in as `admin@bloody.local` with password `ChangeMe!123` (MSSP admin). Customer-side logins use the same password: `ciso@kilimanjaro-bank.example`, `it.manager@savannah-logistics.example`, `viewer@nile-health.example`.

Run the checks with `pnpm -r typecheck` and `pnpm -r test`.
