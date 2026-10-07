# Bloody — engineering conventions

Bloody is a **proprietary**, multi-tenant SaaS Security Operating Platform / Command Center
(EDR, XDR, ITDR, NDR, SIEM, ASM, ESPM, ISPM, CSPM, CIEM, SSPM, VM, CTI, DFIR, SOAR, AI SOC).
It serves three audiences: the **MSSP/business** operating many customer SOCs, the **SOC analysts**,
and the **customers** (customer portal, customer reports). Full spec: `docs/ARCHITECTURE.md`.

## Non-negotiables
- **Proprietary core.** All code here is `UNLICENSED` (proprietary). Never copy source from
  open-source projects into this repo. GPL/AGPL/LGPL/MPL engines (Wazuh, Suricata, Velociraptor,
  MISP, Shuffle, Greenbone, CoPilot…) are only ever run as **separate, unmodified services** and
  reached through adapters over network APIs, event streams or file drops. Only permissive
  (MIT/Apache-2.0/BSD/ISC) npm libraries may be linked into our code.
- No commercial API-keyed services (VirusTotal, Shodan, GreyNoise…) in the default stack.
- **Tenant isolation everywhere.** Every customer-data row has `tenant_id` and `organization_id`.
  API handlers derive tenant from the authenticated principal — never from request bodies.
  Postgres RLS (`app.tenant_id` GUC) is the second line of defence.
- **No mock data in production paths.** Demo data lives only in `apps/api/src/db/seed-dev.ts`
  and test fixtures. UI never hard-codes data; it renders API responses and real empty states.
- Every score (risk, exposure, attack path) carries an explanation (`RiskFactor[]`).
- Dangerous actions (isolate, block, disable identity, revoke) require RBAC permission, an
  approval gate, and an audit record. AI can never execute beyond its configured tool tier.

## Layout (pnpm workspace, TypeScript strict, ESM, Node 22)
- `packages/contracts` — zod schemas + types shared by everything (canonical event, entities,
  RBAC, modules/plans, engine catalog, AI, SOAR, reporting, dashboard DTOs). Change carefully.
- `packages/engines` — Security Graph, Risk Engine, Attack-Path Engine, Detection Engine
  (Sigma subset, threshold, sequence), Correlation. Pure TS, storage behind interfaces.
- `packages/ai` — AI provider abstraction (Ollama, vLLM, LM Studio, OpenAI-compatible, OpenAI,
  Anthropic, Google, Azure OpenAI, Bedrock, Mistral) + tool gateway with permission tiers.
- `packages/adapters` — engine adapters (Wazuh, Zeek, Suricata, Falco, osquery, Velociraptor,
  MISP, OpenCTI, Greenbone, Nuclei, Trivy, OpenCanary, CoPilot…) → canonical events.
- `packages/automation` — SOAR playbooks, approvals, automation rules, notification channels.
- `packages/reporting` — report builders for business / SOC / MSSP / customer audiences.
- `apps/api` — Fastify control plane, `/api/v1`, Postgres (raw SQL migrations in
  `apps/api/migrations`), auth (JWT sessions, API keys, OIDC-ready), RBAC, audit, metrics.
- `apps/web` — React + Vite + Tailwind Command Center UI.
- `infra/` — docker-compose (dev + full OSS engine stack), Kubernetes manifests.
- `docs/` — architecture, ADRs, licence inventory.

## Code style
- Imports inside packages use `.js` extensions (NodeNext). Workspace packages are imported by
  name (`@bloody/contracts`), exporting TS source from `src/index.ts`.
- Validate all external input with zod. Prefer small pure functions; inject I/O (db, http, clock).
- Tests: vitest, colocated as `*.test.ts`. API integration tests use the real local Postgres
  (`DATABASE_URL`, default `postgres://postgres:postgres@localhost:5432/bloody_test`).
- Commands: `pnpm -r typecheck`, `pnpm -r test`, `pnpm --filter <pkg> test`.
- Do not run `pnpm install` for the whole workspace unless you added a dependency; if you must,
  add it only to your own package's `package.json`, and only permissive-licensed packages.
