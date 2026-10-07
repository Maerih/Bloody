# @bloody/adapters

The integration layer between Bloody's proprietary core and the open-source engines it drives.
Every vendor format stops here and leaves as one of four typed, validated outputs:

| Output | Produced by | Consumed by |
|---|---|---|
| `NormalizedEvent` (contracts `IngestEvent`, BCE 1.0) | event adapters (`Adapter.normalize`) | ingest API → data fabric → detection / graph |
| `IndicatorRecord` | intel connectors (MISP, OpenCTI, STIX, CISA KEV) | `POST /intel/indicators` upsert on `externalRef` |
| `ResponseExecutionResult` (+ `ResponseAuditRecord`) | response connectors | `ResponseActionRecord` + `audit_log` |
| `CoPilotSyncPlan` | `CoPilotSync` | one tenant transaction in the API |

Alongside them: `IngestReport` / `CoPilotSyncReport` (report-ready aggregates) and `AdapterSignal`
(automation triggers for email / Slack / Teams / webhook channels, tagged per audience).

## Licensing rule

Bloody is proprietary. **No engine source is copied, linked or vendored.** GPL / AGPL engines
(Wazuh, Suricata, Velociraptor, MISP, Greenbone, CoPilot) run as separate, unmodified services and are
reached only through their network APIs, event streams or file outputs. Every mapping in this
package was written from the engines' public output/API documentation; test fixtures are authored
test data. The only runtime dependency is `zod` (MIT) plus Node built-ins.

## Adapters

| Adapter key | Engine | Licence (engine) | Integration mode | What is consumed | Response actions |
|---|---|---|---|---|---|
| `wazuh` | Wazuh | GPL-2.0-only | network_api (alerts stream + REST) | `alerts.json` lines, `wazuh-alerts-*` documents; Windows Security & Sysmon (`data.win.*`), FIM (syscheck), vulnerability-detector, SCA, auth, web, auditd | `block_ip` (firewall-drop), `disable_identity` (disable-account); `isolate_endpoint`, `release_endpoint`, `kill_process`, `quarantine_file` when a customer AR script is configured |
| `zeek` | Zeek | BSD-3-Clause | file_drop / stream | JSON logs: conn, dns, http, ssl, files, notice (`_path` or inferred) | — |
| `suricata` | Suricata | GPL-2.0-only | file_drop / stream | EVE JSON: alert, dns (v2/v3), http, tls, flow, fileinfo | — |
| `falco` | Falco | Apache-2.0 | event_stream | JSON alerts (syscall, k8s_audit), Falcosidekick payloads | — |
| `osquery` | osquery | Apache-2.0 | agent (logger) | differential, batched differential and snapshot results | — |
| `velociraptor` | Velociraptor | AGPL-3.0-only | network_api (API gateway) | collection envelopes, hunt / notebook JSONL rows (Pslist, Netstat, YARA, Sigma/Hayabusa, EVTX, persistence, files, client info) | `isolate_endpoint`, `release_endpoint`, `collect_evidence` (allow-listed), `run_yara_scan`; `kill_process`, `quarantine_file` with customer artifacts |
| `opencanary` | OpenCanary | BSD-3-Clause | event_stream | JSON alerts (logtype 2000–19001, user 99000+); captured passwords are redacted | — |
| `trivy` | Trivy | Apache-2.0 | file_drop | `--format json` reports (image/fs/repo/vm/sbom) and `trivy k8s` reports → vulnerability, misconfiguration, secret events | — |
| `nuclei` | Nuclei | MIT | network_api (scan jobs) | `-jsonl` findings with `info.classification` (request/response bodies dropped) | — |
| `greenbone` | Greenbone / OpenVAS | AGPL-3.0-or-later AND GPL-2.0-or-later | network_api (GMP) | `get_reports` XML (secure minimal parser, DOCTYPE refused) or JSON export | — |
| `syslog` | generic (RFC 5424/3164) | n/a | event_stream | syslog lines; sshd / sudo / su / pam auth semantics; embedded CEF | — |
| `cef` | generic (ArcSight CEF) | n/a | event_stream | CEF:0/1 with or without syslog header | — |
| `keycloak` | Keycloak | Apache-2.0 | network_api | Admin REST `/events` and `/admin-events` (representations never stored) | — |
| `aws_cloudtrail` | generic (AWS CloudTrail) | n/a | file_drop | `{Records:[…]}` files (gzip), EventBridge envelopes, single records | — |
| `copilot` | SOCFortress CoPilot | AGPL-3.0-only | network_api | CoPilot alerts → detection events (entities come from `CoPilotSync`) | — |

### Intel connectors

| Connector | Source | Licence | Mode | Consumed | Output |
|---|---|---|---|---|---|
| `pullMispIndicators` | MISP | AGPL-3.0-only | network_api | `POST /attributes/restSearch` (API key header) | `IndicatorRecord[]` (confidence model, TLP, galaxies → actor/malware/ATT&CK) |
| `pullOpenCtiIndicators` | OpenCTI (CE) | Apache-2.0 | network_api | GraphQL `indicators` (bearer token), incremental on `modified` | `IndicatorRecord[]` (score, markings, `indicates` relationships) |
| `parseStixBundle` | any STIX 2.1 producer / TAXII export | n/a | file_drop | bundles: indicators, relationships, markings, attack patterns | `IndicatorRecord[]` (benign skipped, conjunctive patterns keep hashes only) |
| `KevCatalog` / `fetchKevCatalog` | CISA KEV | public domain | network_api (key-less) | `known_exploited_vulnerabilities.json` | KEV lookups, `cve` indicators, `vulnerability.kev_detected` signals |
| `EpssTable` / `fetchEpssScores` | FIRST EPSS | free with attribution | network_api (key-less) | daily CSV (gzip) or `api.first.org/data/v1/epss` | EPSS probability + percentile |
| `ATTACK_TECHNIQUES` | MITRE ATT&CK | ATT&CK Terms of Use | curated table | hand-written subset of technique names / tactics | technique naming and validation |

### Response connectors

| Connector | Engine | Call | Actions |
|---|---|---|---|
| `createWazuhActiveResponse` | Wazuh API (JWT via `createWazuhApiClient`) | `PUT /active-response?agents_list=…` | as in the Wazuh row above |
| `createVelociraptorResponse` | Velociraptor API gateway | `POST /api/v1/CollectArtifact` → flow id | as in the Velociraptor row above |
| `createWebhookBlockConnector` | customer firewall / DNS relay | signed `POST` (`X-Bloody-Signature: v1=HMAC-SHA256(ts.body)`) | `block_ip`, `block_domain` (+ `operation: "unblock"`) |

Every connector re-checks the control plane's invariants: high-risk actions need a recorded approver
who is **not** the requester, targets are validated (no loopback / metadata / protected values, no
fleet-wide actions unless enabled), containment calls are never auto-retried, and the result always
carries `call.bodySha256`, a redacted body, the engine reference and a ready-to-store audit record.
`dryRun: true` returns the exact call for the approval screen without sending it.

### SOCFortress CoPilot (MSSP / business **and** customer side)

`CoPilotClient` talks only to CoPilot's REST API (`/api/auth/token` OAuth2 password form → bearer).
`CoPilotSync.run()` takes a read-only snapshot and `planCoPilotSync` (pure) maps it:

| CoPilot | Bloody | `externalRef` |
|---|---|---|
| customer (`parent_customer_code`) | organization (parents first, slug from `customer_code`) | `copilot:customer:<code>` |
| agent | asset (+ `critical_asset` → `crown_jewel`/`high`) and agent (`quarantined` → isolated, disconnected/stale → unresponsive, below min version → outdated) | `copilot:asset:<agent_id>`, `copilot:agent:<agent_id>` |
| alert | alert (severity, verdict, status, explainable `riskFactors`, IOCs) | `copilot:alert:<id>` |
| case | incident | `copilot:case:<id>` |
| `PENDING_CUSTOMER` / escalated | escalation (`customer_action` / `soc_escalation`, SLA due date) | `copilot:escalation:<alert\|case>:<id>` |
| customer-portal user | `customer_viewer` role binding (staff accounts are never mapped) | `copilot:binding:<user_id>:<code>` |

`portal: "customer"` logs in through `/api/auth/token/customer-portal`, so a customer can connect
their own CoPilot scope; `organizationOverrides` maps codes onto existing Bloody organizations.
Records for customers outside the integration's scope are dropped with a warning — never attached
to another organization. The API persists the plan in one tenant transaction, upserting on
`(tenant_id, integration_id, externalRef)`.

## Using the package (API side)

```ts
import { createDefaultRegistry, buildIngestReport } from "@bloody/adapters";

const registry = createDefaultRegistry();
const { result, report } = registry.ingest("suricata", body, {
  receivedAt: new Date().toISOString(),
  integrationId,              // source.integrationId
  idNamespace: principal.tenantId, // deterministic, tenant-scoped event ids (idempotent replays)
});
// result.events → IngestEvent[]   result.rejected / skipped → per-record reasons
// report → data-source health (acceptance rate, severity mix, ATT&CK coverage, headline)
```

Engine calls always go through `EngineClient` (injected `fetch`, basic / bearer / API-key / token
auth, per-attempt timeout, bounded body size, idempotent-only retries, redirects refused, SSRF
guard incl. post-DNS check; private networks only with `urlPolicy.allowPrivateNetworks` for on-prem
relays). TLS verification cannot be disabled: trust private CAs via `NODE_EXTRA_CA_CERTS` or pass an
undici `dispatcher` with the CA / client certificate.

## Canonical event conventions

* `labels.severity_basis` — why the event has its severity (e.g. `wazuh rule.level 10`).
* `labels.dedup_key` — stable hash of the engine's native id; `id` is set only with `idNamespace`.
* `labels.timestamp_source = received_at` — the record had no usable timestamp.
* `provenance.raw` — the record with secrets redacted (passwords, tokens, cookies, honeypot
  captures, CloudTrail secret keys, Keycloak representations, Nuclei request/response); omitted
  above `maxRawBytes` (`labels.raw_omitted`).
* Internal IPs / internal domains are never emitted as indicators.

## Reporting and automation (SOC, MSSP, customer)

* `buildIngestReport` / `mergeIngestReports` — events analysed, severity mix, categories, top
  assets, ATT&CK techniques & tactics, indicator counts, rejection reasons, health + headline.
* `CoPilotSyncReport` — per-organization agent coverage, critical assets, open alerts by severity,
  open incidents, items awaiting customer action, headline (MSSP portfolio + customer monthly).
* `AdapterSignal` — `event` from contracts `AUTOMATION_EVENTS` (`agent.unresponsive`,
  `incident.created`, `escalation.created`, `vulnerability.kev_detected`, …), `audience`
  (`soc` / `mssp` / `customer`), email-ready `title` + `summary`, template `facts`, `dedupKey`
  for throttling and `emit` (`always` / `on_create` / `on_change`).
* `vulnerabilityFindingsFromEvents` + `enrichCve` — scanner events → asset-scoped findings with
  CVSS, EPSS, KEV, patch availability, KEV due dates and evidence lines; `kevSignals` alerts the SOC
  and the customer (MSSP too for ransomware-linked CVEs).

## Tests

`pnpm --filter @bloody/adapters typecheck` and `pnpm --filter @bloody/adapters test`.
One fixture-based test file per adapter (`src/**/*.test.ts`, fixtures in `fixtures/`), every
emitted event validated against the contracts `IngestEvent` schema; engine APIs are exercised with
a mocked `fetch` (`src/test-support/http.ts`).

## Adding an adapter

1. Pick the `ENGINES` key (or add a `GENERIC_SOURCES` entry for protocols / cloud log formats).
2. Write `src/normalizers/<key>.ts` with `defineAdapter({ key, version, map })` — map from the
   engine's documented output only; set `severity_basis`, `dedupKey`, `redactRaw`.
3. Add authored fixtures + `<key>.test.ts`, register it in `createBuiltinAdapters`, update this table.
