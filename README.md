# Bloody

**A unified Security Operating Platform and Command Center** for enterprises, internal SOCs,
MSSPs and MDR providers — endpoint, identity, network, SIEM, exposure, cloud, threat
intelligence, vulnerability, DFIR, SOAR and AI-driven security operations through **one
Security Graph** and **one Risk Engine**.

> **Proprietary software.** Copyright (c) 2026 Bloody. All rights reserved. See [LICENSE](LICENSE).
> Open-source security engines are an extensible, replaceable *engine layer* run as separate,
> unmodified services; the Security Graph, Detection Engine, Risk Engine, Command Center,
> AI SOC, SaaS control plane and operational workflows are the proprietary core.

Modules: EDR · XDR · ITDR · NDR · SIEM · ASM · ESPM · ISPM · CSPM · CIEM · SSPM · VM · Container/K8s ·
CTI · DFIR · SOAR · Email · Deception · AI SOC — each a licensable entitlement (`MODULES`, `PLANS`
in `@bloody/contracts`).

## Three audiences, one platform

| Audience | Where they work | What they get |
|---|---|---|
| **MSSP / business operator** | MSSP Command Center (`/mssp`) | Portfolio of customer organizations, aggregate posture and risk comparison, SLA and analyst load, plans/entitlements/trials, usage metering, customer provisioning, global playbooks with per-customer overrides, white-label portfolio and customer reports — see [docs/MSSP.md](docs/MSSP.md) |
| **SOC** (tier 1–3 analysts, hunters, responders, engineers) | Command Center + module workspaces | Triage feed, alerts → incidents → investigations, Security Graph pivots, explainable risk, attack paths, detections-as-code, SOAR with approval gates, AI SOC analyst with permission-tiered tools |
| **Customer** (org admins, CISO, viewers) | Same app, scoped by role (`org_admin`, `ciso`, `customer_viewer`) | Their organization's dashboard, escalations to acknowledge, reports, trial/module manager — never another customer's data |

## Architecture

```mermaid
flowchart LR
  subgraph Sources["Security sources"]
    EP[Endpoints / servers]
    NET[Network sensors]
    IDP[IdPs / SaaS / cloud audit]
    SCAN[Scanners / intel feeds]
  end

  subgraph Engines["Open-source engine layer (separate, unmodified services)"]
    WZ[Wazuh · Velociraptor · osquery]
    NS[Zeek · Suricata · Arkime]
    TI[MISP · OpenCTI]
    VS[Greenbone · Nuclei · Trivy]
    DF[DFIR-IRIS · Shuffle · Plaso/Timesketch · CoPilot]
  end

  subgraph Fabric["Collection & data fabric"]
    COL[Vector / OTel Collector]
    K[(Kafka bloody.raw.*)]
  end

  subgraph Core["Bloody proprietary core"]
    ING["Ingest API /api/v1/ingest/:adapter · /ingest/events"]
    AD["@bloody/adapters → Canonical Event (BCE)"]
    DET["Detection · Correlation (@bloody/engines)"]
    SG["Security Graph"]
    RE["Risk · Attack-Path engines (explainable)"]
    INC[Incidents · Investigations · Escalations]
    AI["AI SOC (@bloody/ai, tool tiers)"]
    SOAR["SOAR · approvals · notifications (@bloody/automation)"]
    REP["Reporting (@bloody/reporting)"]
    CP["Control plane: tenancy · RBAC · audit · entitlements"]
  end

  subgraph Stores["Stores"]
    PG[(PostgreSQL + RLS)]
    OS[(OpenSearch)]
    VK[(Valkey)]
    S3[(Object storage)]
  end

  UI["Command Center UI (React)"]

  Sources --> Engines
  Sources --> COL
  Engines --> COL
  COL -->|HTTPS + API key| ING
  COL --> K --> AD
  ING --> AD --> DET --> INC
  AD --> SG --> RE --> INC
  INC --> AI --> SOAR
  SOAR -->|approved actions via adapters| Engines
  INC --> REP
  CP --- PG
  Core --- Stores
  UI <-->|/api/v1| Core
```

Data flow: sources → collection → data fabric → adapters/normalization (Bloody Canonical Event)
→ enrichment → Security Graph → detection → correlation → explainable risk → incident /
investigation → AI SOC → SOAR (+ human approval) → response through engine adapters → feedback.
Full specification: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Decisions: [docs/adr](docs/adr/README.md).

## Quick start

Prerequisites: Node.js ≥ 22, pnpm 10 (`corepack enable`), and either a local PostgreSQL 16 or Docker.

### Option A — everything in Docker

```bash
cp .env.example infra/.env                    # optional: every value has a dev default
docker compose -f infra/docker-compose.yml up -d --build
```

| URL | Service |
|---|---|
| http://localhost:8080 | Command Center (nginx; `/api` proxied to the API) |
| http://localhost:4000/api/v1/healthz | API health (`/readyz`, `/metrics`) |
| http://localhost:8025 | Mailpit — every notification / scheduled report e-mail lands here |
| http://keycloak.localhost:8180 | Keycloak (`--profile sso`; enable SSO in the API with `OIDC_ISSUER_URL=http://keycloak.localhost:8180/realms/bloody`) |

The `migrate` service applies the SQL migrations as the schema owner before the API starts. To
load development demo data into the Docker Postgres, run from the host:
`DATABASE_URL=postgres://postgres:postgres@localhost:5432/bloody pnpm db:seed`.

Add the open-source engine layer by profile (see `infra/docker-compose.engines.yml`):

```bash
docker compose -f infra/docker-compose.yml -f infra/docker-compose.engines.yml \
  --profile endpoint --profile network --profile collection up -d
# profiles: endpoint network search streaming collection intel case soar vuln asm cloud deception forensics copilot all
```

### Option B — local Postgres, processes on the host

```bash
pnpm install
# Postgres with the Bloody roles: either the Docker one …
docker compose -f infra/docker-compose.yml up -d postgres valkey mailpit
# … or your own PostgreSQL 16, initialised once with the same script (creates bloody_owner,
# bloody_app, keycloak and the databases bloody + bloody_test; the database "bloody" must exist):
PGHOST=localhost PGUSER=postgres POSTGRES_USER=postgres POSTGRES_DB=bloody \
  BLOODY_OWNER_DB_PASSWORD=bloody-owner-dev-only BLOODY_APP_DB_PASSWORD=bloody_app \
  KEYCLOAK_DB_PASSWORD=keycloak-dev-only sh infra/postgres/init/00-bloody-roles.sh

# The API reads two connections (apps/api/src/config.ts):
#   DATABASE_URL      privileged: migrations, dev seed, tests. Default postgres://postgres:postgres@localhost:5432/bloody
#   DATABASE_APP_URL  runtime role bloody_app (NOBYPASSRLS, RLS enforced). Default: derived from
#                     DATABASE_URL with user bloody_app and password $BLOODY_APP_DB_PASSWORD (default bloody_app)
pnpm db:migrate       # with the defaults above: as the local superuser
pnpm db:seed          # development demo data (apps/api/src/db/seed-dev.ts) — never in production
pnpm dev:api          # http://localhost:4000 — request handlers use bloody_app only
pnpm dev:web          # http://localhost:5173 (proxies /api to BLOODY_API_URL, default http://localhost:4000)
```

The proprietary code is fully testable without Docker; only the API integration tests need a
reachable Postgres (`DATABASE_URL`, default `postgres://postgres:postgres@localhost:5432/bloody_test`).

## Development commands

| Command | What it does |
|---|---|
| `pnpm -r typecheck` | TypeScript strict typecheck of every package |
| `pnpm -r test` | vitest suites (API integration tests use real Postgres) |
| `pnpm --filter <pkg> test` | one package, e.g. `@bloody/engines` |
| `pnpm build` | production builds (API bundle via tsup, SPA via Vite) |
| `pnpm db:migrate` / `pnpm db:seed` | raw SQL migrations / dev seed |
| `node scripts/license-check.mjs` | dependency licence gate (fails on GPL/AGPL/LGPL/SSPL/BUSL/ELv2/unknown) |
| `node --test scripts/*.test.mjs` | licence-gate self-tests |
| `scripts/sbom.sh [--image REF]` | CycloneDX/SPDX SBOMs (Syft) + dependency-graph SBOM |
| `scripts/db-backup.sh` | verified, optionally encrypted logical backup |
| `docker compose -f infra/docker-compose.engines.yml --profile all config -q` | validate the engine stack |
| `kustomize build infra/k8s/overlays/prod` | render Kubernetes manifests |

## Project layout

```
packages/contracts    zod schemas + types shared by everything (BCE, entities, RBAC, modules, engines, AI, SOAR, reports)
packages/engines      Security Graph, Risk Engine, Attack-Path Engine, Detection (Sigma subset/threshold/sequence), Correlation
packages/ai           AI provider abstraction (local + cloud) and permission-tiered tool gateway
packages/adapters     engine adapters → Canonical Events; engine API clients; response connectors
packages/automation   SOAR playbooks, approval gates, automation rules, notification channels, scheduling
packages/reporting    report builders (business / SOC / MSSP / customer) and HTML/PDF/CSV/JSON renderers
apps/api              Fastify control plane (/api/v1), raw SQL migrations, auth, RBAC, audit, metrics
apps/web              React + Vite + Tailwind Command Center
infra/docker          API / web images (distroless, nginx-unprivileged), nginx config
infra/docker-compose*.yml   core dev stack and the open-source engine layer (profiles)
infra/engines         engine configs: Vector, OTel Collector, Wazuh, Velociraptor, osquery, Arkime, …
infra/k8s             Kustomize base + overlays (dev, prod)
scripts               licence gate, SBOM, backups, dev PKI
docs                  architecture, ADRs, licence inventory, operations, MSSP workflows
.github               CI (verify, SBOM, image scan, CodeQL), Renovate
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [Architecture Decision Records](docs/adr/README.md)
- [Operations](docs/OPERATIONS.md) — observability, SLOs, backups/PITR/DR, hardening, upgrades
- [Licence inventory](docs/LICENSES.md) — engines and npm dependencies, policy and exceptions
- [MSSP & customer workflows](docs/MSSP.md)

## Roadmap

1. **Foundation** — control plane, auth, organizations, RBAC, assets, incidents, investigations, audit, API, Command Center UI, Canonical Event, data fabric.
2. **Telemetry** — Wazuh, Zeek, Suricata, Velociraptor adapters; SIEM search; detection engine.
3. **Graph & risk** — Security Graph, correlation, entity resolution, explainable risk, attack paths, exposure.
4. **CTI & vulnerability** — MISP, OpenCTI, Nuclei, Greenbone, Trivy, KEV/EPSS prioritisation.
5. **Response & DFIR** — SOAR, playbooks, approvals, evidence and chain of custody, live response, containment.
6. **AI SOC** — model abstraction, local/cloud models, tool calling, AI investigation/hunting/reporting, approval-based response.
7. **Commercialisation** — subscriptions, metering, billing, SSO/SCIM, MSSP mode, customer portals, SLA reporting, data residency.
8. **Proprietary replacement** — own endpoint agent, detection, graph store and workflow layer where it creates defensible value.

## Proprietary notice

This repository and everything in it is confidential and proprietary to Bloody (Bloody /
Dorisec Africa). No licence is granted by access to it. Third-party open-source components keep
their own licences ([docs/LICENSES.md](docs/LICENSES.md)); no open-source source code is copied
into this repository.
