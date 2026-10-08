# Operations

How Bloody is deployed, observed, kept resilient, secured and upgraded. Companion documents:
[ARCHITECTURE](ARCHITECTURE.md), [ADRs](adr/README.md), [LICENSES](LICENSES.md),
[MSSP](MSSP.md).

Contents:

1. Deployment topology
2. Runtime contract
3. Health checks
4. Observability
5. SLOs
6. Resilience
7. Backups, PITR and disaster recovery
8. Data retention
9. Data fabric
10. Search
11. Security hardening checklist
12. Engine credentials
13. Upgrades and upstream updates
14. Runbooks

---

## Deployment topology

| Environment | How | Notes |
|---|---|---|
| Laptop | `infra/docker-compose.yml` (Postgres, Valkey, API, web, Mailpit; Keycloak with `--profile sso`) plus optional `infra/docker-compose.engines.yml` profiles | Everything binds to `127.0.0.1`. Development credentials only |
| Lab / engine evaluation | `docker compose -f infra/docker-compose.yml -f infra/docker-compose.engines.yml --profile <…>` | Engines on the internal `engines` network (no egress). Feed downloads use `engines-egress` |
| Dev / preview cluster | `kustomize build infra/k8s/overlays/dev` | Namespace `bloody-dev`, 1 replica, staging certificates |
| Production | `kustomize build infra/k8s/overlays/prod` | ≥ 3 replicas across zones, digest-pinned images, PDBs, HPAs |
| Customer-hosted / hybrid | The same Kustomize base, with the customer's ingress, secret store and data services | Collectors (Vector) on customer sites ship to the SaaS ingest API or to a customer-local stack |
| Air-gapped (future) | Mirrored images plus source archives (see [LICENSES](LICENSES.md) §5) | Local AI providers only (`allowCloudData=false`) |

Kubernetes layout (namespaces):

```
ingress-nginx     ingress controller (TLS termination, cert-manager certificates)
bloody            bloody-api (Deployment + HPA + PDB), bloody-web, bloody-scheduler (1 replica),
                  bloody-migrate (Job, PreSync) — PSA "restricted", default-deny NetworkPolicies
bloody-data       PostgreSQL 16 (CloudNativePG or managed), Valkey, Kafka, OpenSearch
bloody-engines    engine layer + collectors (only what the customer licenses)
observability     OpenTelemetry Collector, tracing / log backends
monitoring        Prometheus (scrapes /api/v1/metrics on :4000)
```

The cluster must provide: a NetworkPolicy-enforcing CNI, metrics-server, cert-manager,
External Secrets Operator with a `ClusterSecretStore` named `bloody-secret-store`, and
Kubernetes ≥ 1.30 (the `preStop.sleep` action).

## Runtime contract

These are the environment variables and endpoints the deployment provides to the API image
(`bloody/api`). Names are those read by `apps/api/src/config.ts`. `BLOODY_`-prefixed aliases
are accepted for `JWT_SECRET`, `ENCRYPTION_KEY`, `ENCRYPTION_KEY_VERSION`,
`ENCRYPTION_PREVIOUS_KEYS`, `CORS_ORIGINS`, `PUBLIC_URL`, `COOKIE_SECURE`, `TRUST_PROXY` and
`METRICS_TOKEN`. Blank values mean "unset".

**Consumed by the API today**

| Variable | Purpose | Production value / source |
|---|---|---|
| `NODE_ENV` | `production` refuses to start without `JWT_SECRET` (≥ 32 chars) and `ENCRYPTION_KEY`, and requires an https OIDC issuer | ConfigMap: `production` |
| `HOST`, `PORT`, `LOG_LEVEL` | Listener and log level | `0.0.0.0`, `4000`, `info` |
| `DATABASE_APP_URL` | Runtime connection as `bloody_app` (NOBYPASSRLS, so RLS is always enforced) | Secret `DATABASE_APP_URL` |
| `DATABASE_URL` | "Privileged" pool: migrations, dev seed, tests. **The API Deployment gets the runtime role here too**; only the migrate Job gets the schema owner | API: secret `DATABASE_APP_URL`; migrate Job: `DATABASE_MIGRATION_URL` |
| `BLOODY_APP_DB_PASSWORD` | Password the migration runner uses when it must create `bloody_app`, and from which the API derives the runtime URL when `DATABASE_APP_URL` is unset | Secret (migrate Job) |
| `DATABASE_POOL_MAX`, `DATABASE_STATEMENT_TIMEOUT_MS` | Pool size, statement timeout | `20`, `30000` |
| `JWT_SECRET`, `JWT_ISSUER`, `JWT_AUDIENCE`, `ACCESS_TOKEN_TTL_SECONDS`, `SESSION_TTL_HOURS`, `SESSION_IDLE_MINUTES` | Sessions and tokens | Secret plus defaults |
| `ENCRYPTION_KEY`, `ENCRYPTION_KEY_VERSION`, `ENCRYPTION_PREVIOUS_KEYS` | AES-256-GCM keys for `credentialRef` secrets (rotation: see Runbooks) | Secret (KMS-wrapped) |
| `PUBLIC_URL`, `CORS_ORIGINS`, `COOKIE_SECURE`, `TRUST_PROXY` | Origin, CORS allow-list (never `*`), cookie flags, proxy trust | ConfigMap |
| `RATE_LIMIT_PER_MINUTE`, `LOGIN_*`, `BODY_LIMIT_BYTES` | Abuse protection | Defaults |
| `INGEST_MAX_BATCH`, `INGEST_BODY_LIMIT_BYTES`, `INGEST_MAX_EVENT_AGE_DAYS`, `PIPELINE_ENABLED` | Ingest limits; in-process analytics pipeline on/off | ConfigMap |
| `SMTP_*` | Notification and report e-mail | ConfigMap plus secret |
| `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`, `OIDC_SCOPES` | SSO (the discovery `issuer` must equal `OIDC_ISSUER_URL` exactly) | ConfigMap plus secret |
| `METRICS_TOKEN` | Bearer token required on `GET /api/v1/metrics` (≥ 16 chars) | Secret (optional) |
| `MIGRATIONS_DIR` | Migration files inside the image | `/app/apps/api/migrations` |
| `BLOODY_VERSION` | Version reported by `/api/v1/healthz` | Set in the image from the `VERSION` build arg |
| `NODE_EXTRA_CA_CERTS`, `NODE_OPTIONS` | Node.js runtime: extra CA bundle (private PKI), heap size | Per environment |

**Reserved (provided by the deployment, not consumed yet).** Wiring them in the API is tracked
work. Until then they are inert.

| Variable | Intended behaviour |
|---|---|
| `BLOODY_SCHEDULER_ENABLED` | `true` only in the single-replica `bloody-scheduler`; `false` on `bloody-api`, so schedules fire once |
| `BLOODY_EVENT_BUS`, `KAFKA_BROKERS` | `memory` (today's in-process `EventBus`) or `kafka` (topics in Data fabric) |
| `OPENSEARCH_URL` | Event search store (`EventStore`); empty means Postgres search |
| `VALKEY_URL` | Shared rate-limit store and caches across replicas |
| `BLOODY_AI_ALLOW_PRIVATE_ENDPOINTS` | Allow private-network AI endpoints (Ollama, vLLM) through the SSRF guard |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES` | OpenTelemetry SDK export of traces, metrics and logs to the collector |

**Endpoints the probes rely on:**

- `GET /api/v1/healthz`: liveness, the process answers.
- `GET /api/v1/readyz`: readiness. The database must be reachable through the runtime role,
  migrations applied, and the in-process pipeline's oldest batch younger than 15 minutes.
  Returns 503 with per-check details otherwise.
- `GET /api/v1/metrics`: Prometheus text format.

The web image serves `GET /healthz` itself.

## Health checks

| Component | Liveness | Readiness | Where configured |
|---|---|---|---|
| API | `GET /api/v1/healthz` (startup probe up to 2 min) | `GET /api/v1/readyz` | `infra/k8s/base/api.yaml`; image `HEALTHCHECK` (`infra/docker/healthcheck.mjs`, no shell) |
| Web | `GET /healthz` (nginx, no upstream call) | same | `infra/k8s/base/web.yaml`, image `HEALTHCHECK` |
| Scheduler | `GET /api/v1/healthz` | — (no Service) | `infra/k8s/base/scheduler.yaml` |
| Postgres / Valkey / Kafka / OpenSearch / engines | native checks (`pg_isready`, `valkey-cli ping`, broker API versions, cluster health, …) | — | compose `healthcheck:` blocks |
| Engine integrations | Adapter `healthCheck()` per integration | — | Integrations page; `POST /api/v1/integrations/:id/sync` |

Readiness must never depend on optional engines. An unreachable Wazuh degrades that integration;
it does not take the API out of rotation. The API refuses to start in production if its database
role is a superuser or has BYPASSRLS (`apps/api/src/server.ts`).

## Observability

### Metrics (Prometheus, `GET /api/v1/metrics`)

| Metric | Type | Labels | Use |
|---|---|---|---|
| `bloody_http_request_duration_seconds` | histogram | `method`, `route` (template), `status_code` | API latency and error rate (SLOs) |
| `bloody_ingest_events_total` | counter | `result` = accepted / duplicate / rejected, `source` | Ingestion health per source; rejection spikes signal an adapter regression |
| `bloody_ingest_batches_total` | counter | `source` | Collector activity; silence means a broken collector |
| `bloody_pipeline_events_processed_total` | counter | — | Pipeline throughput |
| `bloody_pipeline_detections_total` | counter | `severity` | Detection volume |
| `bloody_pipeline_incidents_total` | counter | `kind` | Correlation output |
| `bloody_pipeline_errors_total` | counter | `stage` | Graph / detection / correlation / risk failures |
| `bloody_pipeline_batch_duration_seconds` | histogram | — | Processing latency per ingest batch |
| `bloody_pipeline_queue_lag_seconds` | gauge | — | **Queue lag**: age of the oldest unprocessed batch (detection latency) |
| `bloody_pipeline_queue_depth` | gauge | — | Batches waiting |
| `bloody_process_*`, `bloody_nodejs_*` | default | — | CPU, memory, GC, event-loop lag |

Collectors and engines also export metrics:

- Vector: Prometheus exporter `:9598`, covering `vector_component_errors_total`, buffer sizes and
  sink retries.
- OTel Collector: `:8888` internal metrics, e.g. `otelcol_exporter_send_failed_log_records`, queue
  size; `:8889` for the platform metrics pipeline.
- Kafka: consumer-group lag via any Apache-2.0 exporter.
- PostgreSQL: `pg_stat_statements` is preloaded in development; use a postgres exporter in
  production.

Example alert rules (PromQL):

```promql
# API 5xx ratio > 1 % for 10 min (page)
sum(rate(bloody_http_request_duration_seconds_count{status_code=~"5.."}[5m]))
  / sum(rate(bloody_http_request_duration_seconds_count[5m])) > 0.01

# p95 API latency > 1 s (ticket)
histogram_quantile(0.95, sum by (le) (rate(bloody_http_request_duration_seconds_bucket{route!~".*/ingest/.*"}[10m]))) > 1

# Detection latency: oldest batch waiting > 2 min for 10 min (page)
max(bloody_pipeline_queue_lag_seconds) > 120

# Pipeline stage failures (ticket)
sum by (stage) (increase(bloody_pipeline_errors_total[15m])) > 0

# Ingest rejection ratio per source > 5 % (adapter regression or malformed collector)
sum by (source) (rate(bloody_ingest_events_total{result="rejected"}[15m]))
  / sum by (source) (rate(bloody_ingest_events_total[15m])) > 0.05

# A source that normally sends has gone silent for 30 min (collector / agent health)
sum by (source) (rate(bloody_ingest_batches_total[30m])) == 0
  and sum by (source) (rate(bloody_ingest_batches_total[1d] offset 1d)) > 0

# Event-loop saturation
max(bloody_nodejs_eventloop_lag_p99_seconds) > 0.5
```

Product-level health (agents unresponsive or outdated, sensors, integrations) is tenant data, not
platform telemetry. It is shown in the Command Center and drives automation events
(`agent.unresponsive`, notifications), not operator pages.

### Logs

- **API**: structured JSON (pino) on stdout. `authorization`, `cookie` and `set-cookie` are
  redacted. Every request carries a request id: an incoming `X-Request-Id` is accepted if it
  matches `^[A-Za-z0-9._:-]{8,128}$`, otherwise a UUID is minted. It is echoed in the
  `x-request-id` response header and recorded in audit rows.
- **Web (nginx)**: JSON access log with `$uri` only (no query strings, which may carry search
  terms), plus the request id, which it forwards to the API.
- **Audit log**: not a log stream. It is the `audit_log` table (append-only for the runtime
  role), tenant-scoped, readable through `GET /api/v1/audit` (`audit:read`). Export it to
  WORM storage for compliance retention.
- Ship container logs with the cluster's log pipeline (for example a Vector DaemonSet) to a
  **platform** log store that is separate from tenant event indices. Platform logs must never
  land in customer-visible search.

### Traces

The OTel Collector (`infra/engines/otel-collector/config.yaml`) accepts OTLP on `:4317`/`:4318`
and exposes `traces/platform`, `metrics/platform` and `logs/platform` pipelines. Production
overlays replace the `debug` exporter with the organisation's tracing backend. API SDK
instrumentation is a reserved contract (see Runtime contract). Until it lands, latency comes
from the histograms above.

## SLOs

| SLI | Objective (30-day window) | Measurement |
|---|---|---|
| API availability: non-5xx share of `/api/v1` requests (ingest excluded) | 99.9 % | `bloody_http_request_duration_seconds_count` |
| API latency: p95 of read endpoints | < 300 ms; p99 < 1 s | histogram |
| Ingest acceptance: valid events acknowledged | 99.9 % within 5 s | ingest route histogram plus `bloody_ingest_events_total` |
| Detection latency: event accepted → alert or incident stored | p95 < 60 s | `bloody_pipeline_queue_lag_seconds` + `bloody_pipeline_batch_duration_seconds` |
| Approval notification: `response.pending_approval` delivered | 99 % within 2 min | automation run history |
| Scheduled reports delivered | 99 % within 15 min of schedule | `report_runs` |
| Control-plane data durability | RPO ≤ 5 min, RTO ≤ 1 h | restore drills |

Use multi-window burn-rate alerts: page at 14.4× burn over 1 h / 5 min, ticket at 3× over
6 h / 30 min. Breaches of customer-facing SLAs (MSSP contracts) are tracked separately per
organization in the SLA report (`ReportType = "sla"`).

## Resilience

- **Horizontal scaling.** API pods are stateless (sessions live in Postgres). The HPA scales on
  CPU and memory (2–10 base, 3–20 prod). Today each replica runs its own in-process analytics
  pipeline for the batches it ingested. With the Kafka transport, ingest and pipeline workers
  scale independently by partition (tenant-keyed).
- **Backpressure.**
  - Ingest batches are capped (`INGEST_MAX_BATCH`, `INGEST_BODY_LIMIT_BYTES`): oversize bodies
    are rejected with `413`, and the rate limiter answers `429` with `Retry-After`.
  - Vector uses disk buffers with `when_full: block`, and the OTel Collector uses persistent
    `file_storage` queues, so collectors slow the source down instead of dropping.
  - Kafka absorbs bursts within topic retention.
- **Retries.** Collectors retry `429`/`5xx`/timeouts with exponential backoff and no give-up
  (Vector `retry_attempts: 1000`, OTel `max_elapsed_time: 0`). Notification channels and
  response executors retry with backoff and record each attempt.
- **Dead-letter queues.**
  - Unparseable records go to Vector's dead-letter files (`/var/lib/vector/dead-letter/*.ndjson`).
  - Normalization failures go to the Kafka topic `bloody.dlq` (14-day retention).
  - The in-process bus dead-letters a message after its retry budget (counted in `stats()`).

  Nothing is silently dropped. Re-drive after fixing the adapter: ingest is idempotent.
- **Idempotency.**
  - Deterministic event ids plus `ON CONFLICT DO NOTHING` (re-delivered events are counted as
    `duplicate`).
  - Deterministic alert ids and upserts in the pipeline.
  - Playbook runs keyed per `(tenant, idempotency key)`.
  - Response executors send an `idempotency-key` header (the action id).
- **Graceful degradation.**
  - Event search: served from Postgres today. Once `OPENSEARCH_URL` is wired, an OpenSearch
    outage degrades search to Postgres; it does not fail it.
  - AI provider down: configured fallback provider, otherwise AI features are visibly
    unavailable.
  - Engine down: the integration is marked unhealthy and its actions fail visibly (never
    silently "succeed").
  - SMTP down: notification retries, plus in-app notifications.
- **Rollouts.** `maxUnavailable: 0`, readiness gates, a `preStop` sleep to drain the ingress,
  PDBs (`minAvailable` 1 base, 2 prod), and topology spread across zones (hard in prod).

## Backups, PITR and disaster recovery

| Data | Mechanism | RPO | Retention |
|---|---|---|---|
| PostgreSQL (control plane, graph, events, audit) | Continuous WAL archiving plus nightly base backups to object storage: CloudNativePG Barman Cloud plugin, WAL-G (Apache-2.0) or pgBackRest (MIT), run as separate tools | ≤ 5 min (PITR) | 14 days PITR (prod), 7 days (staging) |
| PostgreSQL (logical) | `scripts/db-backup.sh`: `pg_dump` custom format, `pg_restore --list` verification, SHA-256 manifest, optional `age` encryption, pruning | 24 h | 30 days, in a **separate account / bucket with object lock** |
| Object storage (evidence, report files, raw archives) | Bucket versioning, object lock (compliance mode for evidence, preserving chain of custody), cross-region replication | ≈ 0 | Per organization retention / legal hold |
| OpenSearch (event search) | Daily snapshots to object storage; indices can be rebuilt from Postgres events or raw archives | 24 h | 14 days |
| Kafka | Not backed up: transport only. Raw topics 3 days, DLQ 14 days; state of record is Postgres | — | — |
| Secrets / keys | Secret manager versioning; KMS multi-region keys. **Losing `ENCRYPTION_KEY` makes every stored `credentialRef` unrecoverable** | — | Key versions kept until all data is re-encrypted |
| Engine state | Volume snapshots before every engine upgrade. Critical: Wazuh `/var/ossec/etc` (agent keys), the Velociraptor datastore (**server CA**, whose loss orphans all clients), and the MISP, OpenCTI and IRIS databases | 24 h | 7 days |

**Restore drill (monthly; record the measured RTO):**

1. Restore the latest base backup plus WAL to a scratch cluster at a chosen timestamp
   (`recovery_target_time`).
2. Run `node dist/db/migrate.js --status` with the restored URL: every migration must be
   `applied`, with no `modified`.
3. Verify isolation:
   - `SELECT relname FROM pg_class WHERE relrowsecurity AND relforcerowsecurity` covers every
     tenant table;
   - as `bloody_app` without `app.tenant_id`, `SELECT count(*) FROM incidents` returns 0.
4. Point a staging API at it and run the smoke checks: login, Command Center summary, ingest
   one event.

**Disaster recovery:**

- **Topology.** Warm standby in a second region: streaming replica or WAL-archive restore,
  container images in a replicated registry, GitOps manifests, object storage replicated. DNS
  fails over after promotion.
- **Data residency.** Tenants pinned to a region (`Account.dataRegion`) fail over only to a
  region allowed by their contract.
- **Order of recovery:** Postgres, then the API, then the web tier, then collectors (they
  buffer meanwhile), then engines.

## Data retention

- Event retention per organization is `organizations.retention_days`, capped by plan: trial 14,
  essentials 30, professional 90, enterprise / MSSP 365 days (`PLANS` in `@bloody/contracts`).
- `events` is partitioned by month (`ensure_events_partition`). Whole partitions older than the
  maximum retention are dropped. Per-organization deletion inside retained partitions is done by
  the retention job.
- The audit log is retained ≥ 1 year (or as contracted), independent of event retention.
- AI prompts and responses follow the provider's `retentionDays` (0 = not stored).
- Evidence follows the investigation's legal-hold state, never the event retention.

## Data fabric

| Topic | Key | Partitions | Retention | Producer → consumer |
|---|---|---|---|---|
| `bloody.raw.<adapter>` (wazuh, zeek, suricata, osquery, falco, velociraptor, opencanary, nuclei, trivy, greenbone, syslog, cef, keycloak, aws_cloudtrail, copilot) | collector integration id | 6 (dev) | 3 days | Vector / OTel → ingest consumer (adapter normalization) |
| `bloody.events.ingested.v1` | tenant id | 6 (dev) | 3 days | ingest → analytics pipeline (topic name of the API's `EventBus`) |
| `bloody.dlq` | — | 6 (dev) | 14 days | any consumer → operators (re-drive) |

- Topics are created explicitly (`infra/engines/kafka/create-topics.sh`). Broker auto-create is
  off, so a typo never creates a topic.
- Production settings:
  - replication 3 with `min.insync.replicas = 2`;
  - `SASL_SSL` (SCRAM or mTLS) with one principal per collector and prefix ACLs: WRITE on
    `bloody.raw.` only; the API consumer group gets READ;
  - producers idempotent with `acks=all`;
  - zstd compression.
- Monitor consumer lag per group, and alert when lag grows for more than 10 minutes.

## Search

Development runs OpenSearch without the security plugin, on the internal network only.
Production:

- TLS plus the security plugin (fine-grained access control); the API connects with a dedicated
  service user over `https` with certificate verification.
- Tenant isolation: indices per tenant and month (`bloody-events-<tenantId>-YYYY.MM`). Every
  query is built server-side with the tenant from the principal; roles restrict index patterns
  as defence in depth.
- ISM policies roll over and delete indices according to retention; snapshots go to object
  storage daily.

## Security hardening checklist

Platform configuration:

- [ ] `NODE_ENV=production`; `JWT_SECRET` ≥ 32 random bytes; `ENCRYPTION_KEY` = a KMS-wrapped
      32-byte key; all secrets come from the secret store (ExternalSecret), none from a ConfigMap
      or git.
- [ ] TLS everywhere: ingress TLS 1.2+ with HSTS, database `sslmode=verify-full`, Kafka
      `SASL_SSL`, OpenSearch https, SMTP STARTTLS with verification (`NODE_EXTRA_CA_CERTS` for
      private PKI; verification is never disabled).
- [ ] `COOKIE_SECURE=true`; `TRUST_PROXY=true` only behind the ingress; `CORS_ORIGINS` is the
      exact UI origin.
- [ ] `METRICS_TOKEN` set (or metrics reachable only from `monitoring`, as enforced by
      NetworkPolicy).
- [ ] SSO through OIDC; MFA (TOTP) mandatory for local administrator accounts; API keys only for
      service principals (`api_service`), least privilege, rotated at least every 90 days.

Database:

- [ ] Runtime role `bloody_app`: NOSUPERUSER NOBYPASSRLS NOINHERIT, owns nothing,
      `statement_timeout`, `idle_in_transaction_session_timeout` and `lock_timeout` set.
- [ ] Schema-owner credentials exist only in the migration Job; the migration runner verifies
      FORCE RLS on every tenant table.
- [ ] `audit_log` is append-only for the runtime role and exported to WORM storage.

Workloads (enforced by `infra/k8s` and the images):

- [ ] Non-root UID (API 65532 distroless, web 101), `readOnlyRootFilesystem`, all capabilities
      dropped, `allowPrivilegeEscalation: false`, seccomp `RuntimeDefault`; Pod Security
      Admission `restricted` on the namespace.
- [ ] No service-account token mounted; `enableServiceLinks: false`.
- [ ] NetworkPolicies default-deny; egress limited to data services, engines, OTLP and public
      443/587/465. Private ranges and cloud metadata (`169.254.0.0/16`) are blocked.
- [ ] Images: distroless API, no shell or package manager; no source maps in the web image;
      production pins digests; Trivy gate (fixable HIGH/CRITICAL and secrets fail CI); SBOMs per
      image; CodeQL; dependency review; licence gate; Renovate.
- [ ] Release images are signed (cosign keyless from CI) and the cluster admission policy
      verifies signatures. Track this as part of the release pipeline.

Engines:

- [ ] Every default engine credential rotated (see Engine credentials).
- [ ] Engines run in their own namespace or host. Scanners (Greenbone `ospd-openvas`, Nuclei)
      and Shuffle Orborus (Docker socket) run on dedicated hosts or clusters, never next to the
      control plane.
- [ ] Engine UIs are not exposed to the internet; operators reach them through VPN or SSO proxy.

## Engine credentials

The compose files ship **development defaults only**. Before anything beyond a laptop:

| Engine | Rotate | How Bloody authenticates |
|---|---|---|
| Wazuh indexer | `admin` and internal users (`wazuh-passwords-tool`) | — (Bloody does not query the indexer) |
| Wazuh manager API | `wazuh-wui` (`WAZUH_API_PASSWORD`, which must meet Wazuh's password policy) | Integration credential (`credentialRef`) |
| Velociraptor | Admin password; API client certificate (`api,investigator` role) written to the data volume on first boot | Move the API client config into the secret store, then delete the file |
| MISP | `ADMIN_PASSWORD`, `ADMIN_KEY` (40 chars) | Dedicated sync user with read-only role and its own key |
| OpenCTI | Admin password, `APP__ADMIN__TOKEN` | Dedicated lower-privileged connector token |
| DFIR-IRIS | Admin password, API key, secret key, password salt | Dedicated API key |
| Shuffle | Admin password, API key, encryption modifier | Dedicated API key |
| Greenbone | `gvmd` admin | Dedicated GMP user with scan-only permissions |
| Trivy server | `TRIVY_SERVER_TOKEN` | Token header |
| Arkime | password / server secrets, admin | Dedicated viewer user (digest auth) |
| CoPilot | DB password, admin | Dedicated API user |
| Keycloak | Bootstrap admin; client secret `BLOODY_OIDC_CLIENT_SECRET` | OIDC client secret |

Integration secrets are stored encrypted as `credentialRef` (AES-256-GCM) and are never
returned by the API.

## Upgrades and upstream updates

**Pin everything.**

- npm: `pnpm-lock.yaml`, installed with `--frozen-lockfile`.
- Images: exact tags in compose and Dockerfiles; digests for rolling upstream tags
  (distroless, CoPilot); production overlays pin release digests.
- Velociraptor: version plus per-architecture SHA-256 in its Dockerfile.
- GitHub Actions: by major version, digest-pinned by Renovate.

**Automated update detection.** Renovate (`.github/renovate.json5`) opens weekly PRs.

- Engine images are grouped per engine and **never auto-merged**.
- Majors wait for dashboard approval.
- Security fixes are raised immediately.
- Lockfile maintenance runs monthly.
- PRs carry upstream release notes, which serve as changelog tracking.

**Gates for every update PR (CI):**

- licence gate;
- typecheck;
- unit and integration tests (real Postgres);
- build;
- image build plus Trivy;
- SBOM;
- compose validation for every profile;
- Kustomize plus kubeconform;
- shellcheck;
- CodeQL;
- dependency review.

**Compatibility tests for engines.** Adapters are tested against recorded engine output fixtures
(`packages/adapters`). An engine upgrade PR must:

1. capture new sample output from the new version (lab compose profile);
2. add it as fixtures;
3. pass the adapter tests for both old and new versions while customers run mixed versions.

Proprietary adapters depend only on documented APIs and output formats, never on engine
internals.

**Promotion.** `main` → dev cluster (automatic) → staging (release candidate; 48 h soak for
engine upgrades) → production. Production rollout:

- CI writes the digests into `overlays/prod` (`kustomize edit set image …@sha256:…`);
- the migrate Job runs as PreSync;
- the rollout proceeds with `maxUnavailable: 0`.

**Database migrations** are forward-only, transactional per file, checksum-protected (an edited
applied migration aborts the run) and **expand/contract**: release N adds (columns, tables,
dual writes); release N+1 removes. Every schema state is compatible with the previous
application version, so the Deployment can roll back without touching the database.

**Rollback.**

- Application: `kubectl -n bloody rollout undo deploy/bloody-api deploy/bloody-web`, or revert
  the overlay digest commit (GitOps).
- Engine: restore the previous tag and the pre-upgrade volume snapshot.
- Never roll back a migration by hand: ship a new forward migration.

**Forks.** None. A fork of an engine is allowed only with a strong technical or commercial
reason, must be public under the engine's licence (ADR-0004), and is recorded in
[LICENSES](LICENSES.md).

## Runbooks

**Ingest backlog (`bloody_pipeline_queue_lag_seconds` rising)**

1. Check `bloody_pipeline_errors_total` by stage and recent deploys.
2. Scale the API (HPA max) if CPU-bound. Check Postgres for lock waits and slow queries
   (`pg_stat_statements`).
3. If one tenant floods, apply that integration's rate limit. Collectors buffer on disk and
   catch up.

**Adapter regression (rejection ratio spike for one `source`)**

1. Sample the rejected records: the ingest response `rejected[]`, the Vector dead-letter files,
   `bloody.dlq`.
2. Fix the adapter with a fixture from the sample and deploy.
3. Re-drive the DLQ. Ingest is idempotent, so duplicates are ignored.

**Postgres primary failure**

1. The operator (CloudNativePG or managed service) promotes a replica.
2. API pods reconnect (pool `connectionTimeoutMillis` 10 s) and readiness recovers.
3. If PITR is needed, restore to a new cluster (see the restore drill), switch the
   `DATABASE_APP_URL` / `DATABASE_MIGRATION_URL` secrets, and restart the API.

**Rotate `JWT_SECRET`**

1. Write the new secret to the store. ExternalSecret refresh is 15 min in prod; restart the API
   for an immediate effect.
2. Access tokens signed with the old secret (default TTL 15 min, `ACCESS_TOKEN_TTL_SECONDS`)
   stop validating. Clients obtain new ones through their session or sign in again, so schedule
   rotations outside peak hours.

**Rotate `ENCRYPTION_KEY`**

1. Add the current key to `ENCRYPTION_PREVIOUS_KEYS` as `<oldVersion>:<base64>`.
2. Set the new key with `ENCRYPTION_KEY_VERSION` incremented, and deploy. New secrets are
   encrypted with the new version; old ones stay decryptable.
3. Re-encrypt stored secrets (credential re-save or maintenance job), then remove the old
   version once nothing references it.

**Engine down**

1. The integration health check fails and the Command Center shows it. Response actions on
   that engine fail visibly.
2. Restart or restore the engine. Collectors buffer, and alerts flow again once the engine
   writes logs.
