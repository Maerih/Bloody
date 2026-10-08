# ADR-0004: Open-source engines via adapters, and the licence policy

- Status: Accepted
- Date: 2026-10-07
- Deciders: Platform architecture, legal / licensing, security engineering

## Context

Bloody is proprietary software (`LICENSE`, `UNLICENSED` in every `package.json`), sold as SaaS and
also deployed customer-hosted, hybrid and, later, air-gapped. Mature open-source security
engines (Wazuh, Zeek, Suricata, Velociraptor, MISP, OpenCTI, Greenbone, …) give us years of
detection and collection capability. Many of them carry copyleft or source-available terms
(GPL, AGPL, LGPL, MPL, SSPL, BSL, ELv2) that are incompatible with linking into, or embedding
in, a proprietary product.

"Open source" does not mean "free to incorporate". Every licence has its own obligations: around
distribution, modification, network use (AGPL §13), attribution and trademarks. It also pulls in
transitive components, and data feeds carry separate terms. The architecture must also let us
**replace** any engine whose licence becomes commercially unsuitable. That has happened
repeatedly in this market: Elastic, Redis, HashiCorp, Graylog, TheHive and MinIO all changed
licence or distribution terms.

## Decision

### 1. Engines are separate services reached only through adapters

- Every engine runs **unmodified**, from its **upstream** image or release binary, at a
  **pinned** version, as a separate process or container
  (`infra/docker-compose.engines.yml`, own namespace in Kubernetes).
- Bloody talks to engines only through network APIs, event streams or file drops. This happens
  in `@bloody/adapters`, which normalizes into the BCE (ADR-0003) and executes response actions
  behind approval gates (ADR-0008).
- **No engine source is copied, vendored, patched or linked** into this repository. We write
  configuration files, which are ours; their headers carry the proprietary notice.
- Engines are not exposed to customers as product names: modules (`MODULES` in
  `@bloody/contracts`) are what customers buy. The integrations catalog may name engines
  factually (nominative use), with no upstream logos unless their trademark policy allows it.
- If an AGPL or GPL engine ever needs a code change, the change is **upstreamed or published**
  under that engine's licence in a separate public fork. It never lands in this repository, and
  the fork is recorded in `docs/LICENSES.md`.

### 2. Linked code (npm) must be permissive

- Only MIT, Apache-2.0, BSD-2/3-Clause, ISC, 0BSD, Zlib, Unlicense/CC0, BlueOak and similar
  licences may be linked into Bloody code.
- `scripts/license-check.mjs` walks the installed dependency graph of every workspace (prod and
  dev) and fails CI on:
  - GPL, AGPL and LGPL;
  - SSPL, BUSL/BSL-1.1, ELv2, Commons Clause, RSAL and PolyForm;
  - non-commercial or share-alike CC licences;
  - unknown or custom licences.
- The gate evaluates SPDX expressions properly: `A OR B` passes if one alternative is
  permissive, and that alternative is recorded as the one we use.
- Weak copyleft (MPL, EPL, CDDL) needs a reviewed entry in `scripts/license-allowlist.json`:
  justification, approver, optional expiry, and the exact licence string, so upstream
  relicensing re-triggers review. Denied licences additionally need an `exceptionRef` (legal
  sign-off).
- GitHub dependency review mirrors the deny list on pull requests. SBOMs (CycloneDX and SPDX)
  are produced for the source tree and for every image (`scripts/sbom.sh`, CI `sbom` and
  `images` jobs).

### 3. Adoption checklist for any new engine, image or data feed

1. Licence and SPDX id, for the engine **and everything its default stack pulls in**
   (transitivity: CoPilot's default stack pulls Graylog/SSPL, Grafana/AGPL and MinIO/AGPL).
2. Copyleft scope: none, file-level, library or strong. Network clause (AGPL §13, SSPL §13).
3. What triggers obligations: distribution (customer-hosted images), modification, or network use.
4. Attribution and NOTICE duties.
5. Trademark policy.
6. Commercial or field-of-use restrictions (BSL "as a service" clauses, ELv2 "managed service"
   ban, CE vs EE feature flags).
7. Data and content terms (vulnerability feeds, rule sets, GeoIP databases, model weights).
8. Does it need a commercial API key? Keyed services such as VirusTotal, Shodan, GreyNoise,
   AbuseIPDB, Censys, SecurityTrails and Hybrid Analysis are excluded from the default stack
   (`EXCLUDED_KEYED_SERVICES`).
9. Exit plan: which adapter changes, what replaces it.

The result is recorded in `ENGINES` (`license`, `licenseRisk`, `licenseNotes`, `mode`) and in
`docs/LICENSES.md`.

### 4. Distribution scenarios

| Scenario | What we distribute | Obligations we meet |
|---|---|---|
| SaaS (Bloody hosts) | Nothing to customers; customers use the Bloody UI/API | AGPL §13 applies only to *modified* AGPL programs we expose. Engines are unmodified and their UIs are not exposed to customers by default |
| Customer-hosted / hybrid | Our images (`bloody/api`, `bloody/web`); engine images are pulled **from upstream registries** by reference | Our images contain only permissive npm code plus their base OS packages (image SBOM). For engines we ship compose/Helm references, `docs/LICENSES.md`, upstream licence texts and source locations |
| Air-gapped | Mirrored upstream images, plus the matching source archives / written source offer for GPL/AGPL/LGPL components | Mirror source tarballs next to the images; ship `docs/LICENSES.md` and SBOMs with every bundle |
| `bloody/engine-velociraptor` (our wrapper of the unmodified release binary) | An AGPL binary inside an image we build | Image label `org.opencontainers.image.licenses=AGPL-3.0-only`; the AGPL text and an upstream source link ship with it; no modification |

### 5. Engine-by-engine decisions (`ENGINES` in `packages/contracts/src/engines.ts`)

| Engine | Licence | Risk | How Bloody uses it | Notes and obligations |
|---|---|---|---|---|
| Wazuh (manager + indexer) | GPL-2.0-only (manager); indexer is an Apache-2.0 OpenSearch distribution | medium | Manager REST API `:55000`, `alerts.json` via collectors, active response | Unmodified. The Wazuh dashboard (GPL) is not deployed: Bloody is the UI. Customer-hosted: point to the upstream source |
| Velociraptor | AGPL-3.0-only | medium | gRPC/API client certificate (`api,investigator` role), artifact collections | Unmodified release binary, SHA-256 pinned per architecture. Any server change would have to be published |
| osquery | Apache-2.0 OR GPL-2.0-only | low | Filesystem logger → collector → `osquery` adapter | Used under Apache-2.0 (dual licence; we choose the permissive option) |
| Falco | Apache-2.0 | low | JSON alerts via webhook / Falcosidekick | — |
| Zeek | BSD-3-Clause | low | JSON logs (file drop) | — |
| Suricata | GPL-2.0-only | medium | EVE JSON (file drop) | Unmodified. ET Open rules (no key). ET Pro needs a commercial licence |
| Arkime | Apache-2.0 | low | Viewer API, PCAP retrieval | GeoLite2/ASN downloads disabled (MaxMind EULA and key) |
| OpenSearch | Apache-2.0 | low | Event search store (`EventStore`), engine backend | Chosen over Elasticsearch (see below) |
| Apache Kafka | Apache-2.0 | low | Data fabric topics `bloody.*` | Chosen over Redpanda (see below) |
| OpenTelemetry Collector | Apache-2.0 | low | Platform telemetry; optional engine-log shipper | — |
| Vector | MPL-2.0 | low | Default engine-log collector | File-level copyleft applies only to modified Vector source files. Our VRL/YAML config is ours |
| Sigma | DRL-1.1 (rules) | low | Rule *format*; Bloody's own compiler | Keep author/reference attribution in rule metadata when shipping SigmaHQ content |
| YARA | BSD-3-Clause | low | Scanner sidecar / Velociraptor artifacts | — |
| MISP | AGPL-3.0-only | medium | REST `/attributes/restSearch` sync | Unmodified. Open feeds only |
| OpenCTI | Apache-2.0 (Community Edition) | low | GraphQL indicator sync | **Enterprise Edition features are separately licensed and never enabled** |
| DFIR-IRIS | LGPL-3.0-only | low | REST case sync (optional) | Not linked. Preferred over TheHive 5 |
| Shuffle | AGPL-3.0-only | medium | Optional executor behind Bloody's approval gate | Orborus needs the Docker socket, so it runs on a dedicated host or cluster |
| Greenbone / OpenVAS | AGPL-3.0-or-later and GPL-2.0-or-later | medium | GMP over TLS | **Community Feed has its own terms**: legal review before selling scanning. Production MSSP use: Greenbone Enterprise Feed under contract, or Nuclei/Trivy only |
| Nuclei | MIT | low | Scan runner, JSONL results | Templates MIT. Only authorised, in-scope targets, rate-limited |
| Subfinder | MIT | low | Passive subdomain discovery | Only sources that need no paid key |
| OWASP Amass | Apache-2.0 | low | Attack-surface mapping | Passive by default |
| Trivy | Apache-2.0 | low | Server mode, JSON reports | Vulnerability DB aggregates advisories with varying terms: no redistribution of the DB itself |
| Grype + Syft | Apache-2.0 | low | SBOM / vulnerability matching, Bloody's own SBOM | — |
| kube-bench | Apache-2.0 | low | CIS Kubernetes JSON | — |
| Keycloak | Apache-2.0 | low | OIDC provider for SSO (Bloody is the relying party) | — |
| OpenCanary | BSD-3-Clause | low | JSON log events | — |
| Plaso | Apache-2.0 | low | One-shot timeline jobs | — |
| Timesketch | Apache-2.0 | low | Optional analyst UI for very large timelines | — |
| SOCFortress CoPilot | AGPL-3.0-only | medium | REST sync of customers, agents, alerts, cases | Unmodified, pinned by digest (upstream publishes `latest` only). **Its default stack's Graylog (SSPL-1.0) and Grafana (AGPL-3.0) are not deployed**, and MinIO is replaced with SeaweedFS |
| PostgreSQL | PostgreSQL | low | Control plane, graph, events | — |
| ClickHouse | Apache-2.0 | low | Optional analytics at scale | — |
| Valkey | BSD-3-Clause | low | Cache / short-lived state | Chosen over Redis ≥ 7.4 (see below) |
| Ollama | MIT | low | Local LLM runtime | **Model weights carry their own licences**, checked per model (e.g. Llama community licence field-of-use and attribution terms) |
| vLLM | Apache-2.0 | low | Local OpenAI-compatible serving | Same model-weight caveat |

Engine-tier infrastructure in the dev/lab stack, also run unmodified:

- MariaDB Server, GPL-2.0, for MISP and CoPilot. Bloody never connects to it.
- RabbitMQ, MPL-2.0, for OpenCTI and IRIS.
- SeaweedFS, Apache-2.0, S3 for OpenCTI and CoPilot.
- Mailpit, MIT, for development only.
- Utility images: busybox, GPL-2.0; socat, GPL-2.0; and alpine/openssl, Apache-2.0.

### 6. Specific choices

- **CoPilot (AGPL-3.0).** Useful as an MSSP hub over Wazuh, Graylog and Velociraptor, and treated
  as an *optional sync source*. We run it unmodified and reach it only over its `/api` REST
  surface. We do not adopt its bundled stack, for two reasons:
  - Graylog's server is **SSPL-1.0**, whose §13 would require releasing the source of the entire
    service stack used to offer it, which is incompatible with proprietary SaaS.
  - Grafana is AGPL-3.0.

  Bloody's OpenSearch pipeline, Command Center and reporting replace both.
- **Graylog (SSPL-1.0, high risk).** Not used anywhere. Log management is Vector or OTel
  Collector → Bloody ingest → Postgres/OpenSearch.
- **Redis vs Valkey.** Redis moved to RSALv2/SSPLv1 in 7.4. Redis 8 added AGPLv3 as a third
  option, but every option still restricts proprietary SaaS use. **Valkey** (BSD-3-Clause, Linux
  Foundation) is protocol-compatible and is the only cache and short-lived-state store we deploy.
  Its clients (`ioredis`/`redis` npm, both MIT) remain permissive.
- **Redpanda (BSL-1.1) vs Kafka.** Redpanda Community is BSL-1.1. Its additional-use grant
  forbids offering it as a streaming or queuing service, the change date is about four years
  out, and BSL is denied by our gate. **Apache Kafka** (Apache-2.0, KRaft mode, no ZooKeeper) is
  the data-fabric default. The protocol is the same, so managed Kafka (MSK, Confluent Cloud,
  Aiven) works without code changes.
- **TheHive vs DFIR-IRIS.** TheHive 5 is commercially licensed by StrangeBee, and the AGPL TheHive
  4 line is end-of-life. **DFIR-IRIS** (LGPL-3.0) is the optional case-management integration.
  Bloody's own incident/investigation engine (evidence with chain of custody, timeline, tasks)
  remains the system of record.
- **Elastic vs OpenSearch.** Elasticsearch and Kibana are SSPL / ELv2 / AGPL-3.0 (tri-licence
  since 2024). ELv2 forbids providing the software as a managed service, and SSPL has the
  service-source clause. **OpenSearch** (Apache-2.0) is the search store. Bloody never ships
  Elastic components.
- **Neo4j (GPL-3.0 Community / commercial Enterprise) vs Postgres graph.** Neo4j Community's GPL
  plus its clustering limits, and Enterprise's commercial licence, conflict with our
  multi-tenant SaaS model. The Security Graph lives in PostgreSQL (`graph_nodes`/`graph_edges`,
  ADR-0005), behind the `SqlGraphStore` interface. Future options are permissive: Apache AGE
  (Apache-2.0) or JanusGraph (Apache-2.0). BSL graph databases are excluded.
- **MinIO (AGPL-3.0) → SeaweedFS (Apache-2.0)** for engine-tier S3. MinIO's community images were
  discontinued in 2025. Production uses the cloud provider's object storage.
- **HashiCorp Vault/Terraform (BSL-1.1 since 2023).** Not required by Bloody. Secrets come via
  External Secrets Operator from the operator's chosen store. If self-hosted tooling is needed,
  OpenBao and OpenTofu (MPL-2.0) are preferred.

## Consequences

- Any engine can be replaced by writing an adapter. BCE, detections, graph, risk and UI are
  untouched.
- Engine upgrades are infrastructure changes: pinned versions bumped by Renovate PRs, adapter
  compatibility fixtures, then staging, then production (`docs/OPERATIONS.md`).
- We maintain the licence inventory (`docs/LICENSES.md`), SBOMs and the allowlist as living
  artefacts. CI fails closed on new or unknown licences.
- Some capabilities cost extra operational effort because a convenient option was rejected on
  licence grounds (Kafka instead of Redpanda, OpenSearch instead of Elasticsearch, SeaweedFS
  instead of MinIO). We accept that cost.

## Alternatives considered

- **Fork engines into the monorepo and modify freely.** This would make Bloody a derivative work
  of GPL/AGPL code and destroy the proprietary licence. Rejected outright.
- **Embed engine libraries (libsuricata, Zeek plugins, Wazuh modules).** Same problem: linking
  creates a combined work. Rejected.
- **Only permissive engines.** This would exclude Wazuh, Suricata, Velociraptor, MISP and
  Greenbone, the best-in-class tools for their layers. Process separation plus no modification
  is a well-understood compliance pattern, so we accept the medium-risk engines under the
  controls above.
