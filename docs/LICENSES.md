# Licence inventory

Bloody is **proprietary** ("All rights reserved", see [`LICENSE`](../LICENSE); every workspace
`package.json` is `UNLICENSED`). This document lists every third-party component the platform
uses, how it is consumed, and the obligations that follow. The policy behind it is
[ADR-0004](adr/0004-open-source-engines-and-licence-policy.md). In short:

- **Linked code** (npm packages bundled into Bloody's API and web images) must be **permissive**.
  This is enforced in CI by `scripts/license-check.mjs`, together with
  `scripts/license-allowlist.json` for reviewed exceptions.
- **Copyleft and source-available engines** (GPL, AGPL, LGPL, MPL) run **unmodified, as separate
  services**, from upstream images at pinned versions. They are reached only through network
  APIs, event streams or file drops (`@bloody/adapters`). No engine source is copied into this
  repository.
- **SSPL, BSL/BUSL, ELv2, RSAL, Commons Clause** and non-commercial licences are not used, in
  any form.
- **Commercial API-keyed services** (VirusTotal, Shodan, GreyNoise, AbuseIPDB, Censys,
  SecurityTrails, Hybrid Analysis) are excluded from the default stack.

Machine-readable sources of truth:

| Artefact | Produced by |
|---|---|
| Engine catalogue (`ENGINES`: licence, risk, integration mode, notes) | `packages/contracts/src/engines.ts` |
| npm licence report (JSON / Markdown) | `node scripts/license-check.mjs --json reports/licenses.json --markdown reports/licenses.md` (CI artefact `licence-report`) |
| Source SBOM (CycloneDX + SPDX) | `scripts/sbom.sh`, CI job `sbom` (Syft via `anchore/sbom-action`) |
| Image SBOMs (incl. OS packages) | CI job `images` (`bloody-api.cdx.json`, `bloody-web.cdx.json`) |

## 1. Engine layer (separate services, unmodified)

Pinned versions are those in `infra/docker-compose.engines.yml` (Renovate proposes upgrades; see
[OPERATIONS](OPERATIONS.md#upgrades-and-upstream-updates)).

| Engine | Pinned version / image | Licence (SPDX) | Risk | Integration | Obligations and notes |
|---|---|---|---|---|---|
| Wazuh manager | `wazuh/wazuh-manager:4.14.8` | GPL-2.0-only | medium | REST `:55000`, `alerts.json` → collector | Unmodified; GPL source offer for redistributed images (customer-hosted: pull from upstream) |
| Wazuh indexer | `wazuh/wazuh-indexer:4.14.8` | Apache-2.0 | low | Wazuh-internal only | Keep NOTICE when redistributing |
| Wazuh certs generator | `wazuh/wazuh-certs-generator:0.0.4` | GPL-2.0-only | low | One-shot dev PKI | Dev only; production uses the organisation's PKI |
| Velociraptor | `bloody/engine-velociraptor:0.77.2` (upstream binary, SHA-256 pinned) | AGPL-3.0-only | medium | API client certificate, collections | **Unmodified** release binary in our wrapper image; AGPL text and upstream source link travel with it |
| osquery | `osquery/osquery:5.17.0-ubuntu24.04` | Apache-2.0 OR GPL-2.0-only | low | Filesystem logger → collector | Used under **Apache-2.0** |
| Falco | (customer clusters) | Apache-2.0 | low | JSON alerts (webhook) | — |
| Zeek | `zeek/zeek:8.0.10` | BSD-3-Clause | low | JSON logs | Attribution |
| Suricata | `jasonish/suricata:8.0.7` | GPL-2.0-only | medium | EVE JSON | Unmodified; ET Open rules via `suricata-update` (ET Pro needs a commercial licence) |
| Arkime | `ghcr.io/arkime/arkime/arkime:v5.8.2` | Apache-2.0 | low | Viewer API, PCAP | MaxMind GeoLite2 downloads disabled (EULA and licence key) |
| OpenSearch (events) | `opensearchproject/opensearch:3.9.0` | Apache-2.0 | low | `EventStore` | — |
| OpenSearch (engine backend) | `opensearchproject/opensearch:2.19.6` | Apache-2.0 | low | Arkime / OpenCTI / Shuffle / Timesketch | — |
| Apache Kafka | `apache/kafka:4.3.1` (KRaft) | Apache-2.0 | low | Topics `bloody.raw.*`, `bloody.events.ingested.v1`, `bloody.dlq` | — |
| OpenTelemetry Collector | `otel/opentelemetry-collector-contrib:0.162.0` | Apache-2.0 | low | Platform telemetry; optional engine-log shipper | — |
| Vector | `timberio/vector:0.59.0-distroless-libc` | MPL-2.0 | low | Default engine-log collector | File-level copyleft only for modified Vector sources; our config is ours |
| Sigma (format, SigmaHQ rules) | — | DRL-1.1 | low | Bloody's own compiler | Keep rule author/reference attribution when shipping SigmaHQ content |
| YARA | (scanner sidecar) | BSD-3-Clause | low | Scans | — |
| MISP + misp-modules | `ghcr.io/misp/misp-docker/misp-core:v2.5.48`, `misp-modules:v3.0.10` | AGPL-3.0-only | medium | REST sync | Unmodified; open feeds only |
| OpenCTI platform + worker | `opencti/platform:7.261002.0`, `opencti/worker:7.261002.0` | Apache-2.0 (Community Edition) | low | GraphQL sync | **Enterprise Edition features are separately licensed and never enabled** |
| DFIR-IRIS | `ghcr.io/dfir-iris/iriswebapp_*:v2.4.29` | LGPL-3.0-only | low | REST (optional) | Not linked |
| Shuffle | `ghcr.io/shuffle/shuffle-*:2.2.1` | AGPL-3.0-only | medium | Optional executor after approval | Unmodified; Orborus needs the Docker socket, so it runs on a dedicated host |
| Greenbone Community Edition | `registry.community.greenbone.net/community/*:${GREENBONE_VERSION}` | AGPL-3.0-or-later, GPL-2.0-or-later (components) | medium | GMP over TLS | **Community Feed terms need legal review before commercial scanning**; pin a digest in production |
| Nuclei | `projectdiscovery/nuclei:v3.11.1` | MIT | low | JSONL results | Templates MIT; authorised targets only |
| Subfinder / Amass | (optional) | MIT / Apache-2.0 | low | Passive discovery | Key-less sources only |
| Trivy | `aquasec/trivy:0.75.0` | Apache-2.0 | low | Server mode, JSON | Do not redistribute the vulnerability DB |
| Grype + Syft | `anchore/syft:v1.54.1` (CI) | Apache-2.0 | low | SBOMs | — |
| kube-bench | (customer clusters) | Apache-2.0 | low | JSON | — |
| Keycloak | `quay.io/keycloak/keycloak:26.8.0` | Apache-2.0 | low | OIDC provider | — |
| OpenCanary | `thinkst/opencanary:0.9.10` | BSD-3-Clause | low | JSON log | — |
| Plaso | `log2timeline/plaso:20260928` | Apache-2.0 | low | One-shot jobs | — |
| Timesketch | `us-docker.pkg.dev/osdfir-registry/timesketch/timesketch:20260630` | Apache-2.0 | low | Optional timeline UI | — |
| SOCFortress CoPilot | `ghcr.io/socfortress/copilot-{backend,frontend}` pinned by digest | AGPL-3.0-only | medium | REST sync | Unmodified; **its default Graylog (SSPL-1.0) and Grafana (AGPL-3.0) are not deployed**, and MinIO is replaced with SeaweedFS |
| ClickHouse | (optional) | Apache-2.0 | low | Analytics at scale | — |
| Ollama / vLLM | (customer choice) | MIT / Apache-2.0 | low | OpenAI-compatible API | **Model weights have their own licences**; check per model (field-of-use, attribution, acceptable-use terms) |

### Control-plane and engine-tier infrastructure

| Component | Image | Licence | Use |
|---|---|---|---|
| PostgreSQL | `postgres:16.15-alpine` | PostgreSQL | Control plane, graph, events (also engine-tier Postgres for Timesketch) |
| Valkey | `valkey/valkey:8.1.10-alpine` | BSD-3-Clause | Cache / short-lived state |
| Mailpit | `axllent/mailpit:v1.31.4` | MIT | **Development only**: e-mail catcher |
| MariaDB Server | `mariadb:11.8.9` | GPL-2.0-only | Engine tier only (MISP, CoPilot); Bloody never connects to it |
| RabbitMQ | `rabbitmq:4.3.6-management-alpine` | MPL-2.0 | Engine tier (OpenCTI, IRIS) |
| SeaweedFS | `chrislusf/seaweedfs:4.48` | Apache-2.0 | Engine-tier S3 (replaces AGPL MinIO) |
| busybox / socat / openssl | `busybox:1.37.0`, `alpine/socat:1.8.1.3`, `alpine/openssl:3.5.9` | GPL-2.0 / GPL-2.0 / Apache-2.0 | One-shot utilities (volume init, GMP TLS relay, dev PKI) |

### Bloody's own images

| Image | Contents | Licences inside |
|---|---|---|
| `bloody/api` | Bundled Bloody JavaScript, production npm closure (permissive only), Node.js 22 | Base: `gcr.io/distroless/nodejs22-debian13` (Node.js: MIT plus bundled third-party notices; Debian runtime libraries such as glibc are LGPL and run as system libraries, unmodified). See the image SBOM |
| `bloody/web` | Static SPA bundle (permissive npm only), nginx | Base: `nginxinc/nginx-unprivileged` (nginx: BSD-2-Clause; Alpine packages per SBOM) |

## 2. Data feeds and content

| Content | Licence / terms | Notes |
|---|---|---|
| CISA KEV | Public domain (US Government) | Default |
| FIRST EPSS | Free use with attribution | Default |
| MITRE ATT&CK (STIX) | ATT&CK Terms of Use (attribution) | Default |
| NIST NVD | Public domain; API key optional | Default |
| SigmaHQ rules | DRL-1.1 | Attribution kept in rule metadata |
| Emerging Threats Open (Suricata) | Open ruleset published by Proofpoint (licence terms included in the ruleset archive) | Review before redistributing rule content to customers |
| Nuclei templates | MIT | Authorised targets only |
| Greenbone Community Feed | Greenbone feed terms (NASL content largely GPL-2.0-or-later) | Legal review before commercial scanning; Enterprise Feed requires a contract |
| Trivy vulnerability DB | Aggregated advisories, terms vary by source | Consumed, not redistributed |
| MISP / OpenCTI feeds | Per feed (TLP and licence per source) | Only feeds whose terms permit commercial use |
| MaxMind GeoLite2 | MaxMind EULA, licence key required | **Not used** (disabled in Arkime); Bloody enriches geo itself |

## 3. Rejected components

| Component | Licence | Why rejected | Replacement |
|---|---|---|---|
| Elasticsearch / Kibana | SSPL-1.0 / ELv2 / AGPL-3.0 | ELv2 forbids managed-service use; SSPL service-source clause | OpenSearch |
| Graylog server | SSPL-1.0 | SSPL §13 (service source) is incompatible with proprietary SaaS | Vector / OTel → Bloody ingest → Postgres / OpenSearch |
| Redis ≥ 7.4 | RSALv2 / SSPLv1 (Redis 8: + AGPL-3.0) | Restricts proprietary SaaS use | Valkey |
| Redpanda Community | BSL-1.1 | Additional-use grant forbids streaming-as-a-service | Apache Kafka |
| TheHive 5 | Commercial (StrangeBee) | TheHive 4 (AGPL) is end-of-life | DFIR-IRIS (optional); Bloody's own case engine |
| Neo4j | GPL-3.0 (Community) / commercial (Enterprise) | Licence and multi-tenancy limits | PostgreSQL graph tables (ADR-0005); Apache AGE later if needed |
| Memgraph and other BSL graph databases | BSL-1.1 | Denied licence class | — |
| MinIO | AGPL-3.0 | AGPL plus discontinued community images | SeaweedFS (engine tier), cloud object storage (production) |
| Grafana | AGPL-3.0 | Network copyleft, second permission model | Bloody Command Center and reports; Prometheus-compatible metrics for operators' own tooling |
| HashiCorp Vault / Terraform | BSL-1.1 | Denied licence class | External Secrets Operator with any store; OpenBao / OpenTofu (MPL-2.0) if self-hosted |
| Wazuh dashboard | GPL-2.0 | Not needed: Bloody is the UI | — |

## 4. npm dependencies (linked into Bloody)

Current state: `node scripts/license-check.mjs` reports **469 packages (229 production, 240
development), 0 violations, 0 allowlisted exceptions** (licence classes: MIT, ISC, Apache-2.0,
BSD-2/3-Clause, MIT-0, 0BSD, `MIT AND ISC`, `(MIT AND Zlib)`, and CC-BY-4.0 for one
development-only package). The authoritative, always-current per-package table is generated
on every CI run (`reports/licenses.md`); this section summarizes it.

### Direct dependencies

| Package | Version | Licence | Scope | Used by |
|---|---|---|---|---|
| fastify, @fastify/cookie, @fastify/cors, @fastify/helmet, @fastify/rate-limit | 5.12.5, 11.1.2, 10.1.0, 12.0.1, 10.3.0 | MIT | prod | `@bloody/api` |
| pg | 8.23.1 | MIT | prod | `@bloody/api` |
| jose | 5.10.0 | MIT | prod | `@bloody/api` (JWT) |
| @node-rs/argon2 | 2.2.2 | MIT | prod | `@bloody/api` (password hashing) |
| prom-client | 15.1.3 | Apache-2.0 | prod | `@bloody/api` (metrics) |
| zod | 3.25.76 | MIT | prod | all packages |
| yaml | 2.9.1 | ISC | prod | `@bloody/engines` (Sigma rules) |
| nodemailer | 6.10.1 | MIT-0 | prod | `@bloody/automation` (SMTP) |
| pdfkit | 0.15.2 | MIT | prod | `@bloody/reporting` (PDF) |
| react, react-dom | 18.3.1 | MIT | prod | `@bloody/web` |
| react-router-dom | 6.30.6 | MIT | prod | `@bloody/web` |
| @tanstack/react-query | 5.104.1 | MIT | prod | `@bloody/web` |
| @xyflow/react | 12.12.0 | MIT | prod | `@bloody/web` (graph views) |
| recharts | 2.15.4 | MIT | prod | `@bloody/web` (charts) |
| lucide-react | 0.460.0 | ISC | prod | `@bloody/web` (icons) |
| clsx | 2.1.1 | MIT | prod | `@bloody/web` |
| typescript | 5.9.3 | Apache-2.0 | dev | workspace |
| vitest, tsx, tsup, vite, @vitejs/plugin-react | 2.1.9, 4.23.15, 8.5.1, 5.4.21, 4.7.0 | MIT | dev | build and test |
| tailwindcss, postcss, autoprefixer | 3.4.19, 8.5.29, 10.6.1 | MIT | dev | `@bloody/web` build |
| jsdom, @testing-library/react, @testing-library/jest-dom | 25.0.1, 16.3.3, 6.10.0 | MIT | dev | `@bloody/web` tests |
| @types/* | — | MIT | dev | type definitions |

### Transitive packages worth noting (all permitted)

| Package | Licence | Scope | Assessment |
|---|---|---|---|
| pako 1.0.11 (via pdfkit) | `(MIT AND Zlib)` | prod | Both operands permissive |
| victory-vendor 36.9.2 (via recharts) | `MIT AND ISC` | prod | Both operands permissive (vendored d3 modules) |
| d3-* (via recharts / @xyflow) | ISC, BSD-3-Clause | prod | Permissive |
| tslib 2.8.1 | 0BSD | prod | Permissive |
| nodemailer 6.10.1 | MIT-0 | prod | Permissive, no attribution required |
| png-js 1.1.0 (via pdfkit) | MIT (no `license` field; inferred from its LICENSE file) | prod | Verified from the licence text |
| fast-uri, secure-json-parse, light-my-request (via fastify) | BSD-3-Clause | prod | Permissive; attribution in NOTICE / SBOM |
| @opentelemetry/api | Apache-2.0 | prod | Permissive |
| caniuse-lite 1.0.30001815 (via autoprefixer / browserslist) | CC-BY-4.0 | **dev only** | Browser-support data used at build time; never shipped. The gate would require review if it ever became a production dependency |

### Exceptions register

`scripts/license-allowlist.json` currently has **no entries**: nothing in the tree needs an
exception. Every entry added later must state the package, the exact declared licence string,
the version(s) and scope, a justification of at least 20 characters, the approver, an optional
expiry, and for denied licences an `exceptionRef` pointing to the legal sign-off. Entries that
match nothing are reported as stale; an upstream licence change re-opens review automatically.

## 5. Obligations checklist for customer-hosted / air-gapped bundles

- [ ] Ship this file, the SBOMs (`sbom/`) and the `LICENSE` with every bundle.
- [ ] Reference engine images from their **upstream registries** where possible. When mirroring
      (air-gapped), mirror the matching **source archives** of GPL / AGPL / LGPL components, or
      include a written source offer.
- [ ] Include upstream licence texts and NOTICE files for redistributed Apache-2.0 components.
- [ ] Do not enable OpenCTI Enterprise Edition features, Greenbone Enterprise Feed or Suricata ET
      Pro without the corresponding commercial agreement.
- [ ] Confirm the licence and acceptable-use terms of any LLM weights the customer deploys.
- [ ] No engine modifications. If one becomes unavoidable, publish it in a public fork under the
      engine's licence and record it here.
