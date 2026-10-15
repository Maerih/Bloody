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

## Progress since the pause (one feature at a time, each tested)

- API tests added for: SOAR response approvals; AI SOC (write-only keys, connection test, chat, tool-tier enforcement); reports (all types, PDF/CSV/JSON, white-label, schedules) and entitlements (402, usage); CoPilot sync (idempotent); notification channels, automation rules and playbooks; MSSP customer provisioning. The API suite is at 156+ tests.
- Bugs fixed: manually created incidents never fired automations or playbooks; the AI provider connection test ignored the host-resolver setting.
- **Endpoint isolation with release from the platform.** Two modes: *LAN isolation*, which blocks the local network but keeps the internet, and *Full isolation*.
  - Both modes always keep the Bloody platform and the Wazuh manager reachable, so the endpoint can be released from Bloody.
  - Endpoint scripts are in `infra/agent/active-response/`: `bloody-isolate` uses nftables on Linux, and `bloody-isolate.ps1` uses Windows Firewall.
  - Each Wazuh integration has an *Isolation allow-list* field.
  - The Isolate dialog has a mode picker. Agents show "Isolated · LAN only" or "Isolated · full", and have a Release button.
  - Heartbeats and CoPilot syncs no longer clear an isolation.
  - Velociraptor clients can also be isolated in LAN mode. This uses the `Custom.Bloody.Isolate` artifact in `infra/agent/velociraptor/`, which runs the same scripts. Without that artifact, only full quarantine is available, through the stock Velociraptor artifact.
  - Also fixed: connecting an engine from the UI was rejected because the UI sent `engine` and the API expected `kind`.
- New web pages: Simulate an incident (runs the real pipeline), Download agent, Demo sandbox, Support, Feedback. No hamburger-menu link is a placeholder any more.

## Remaining (in order)

1. ~~**API part B: prove and close gaps**~~ (DONE) (`apps/api`), about 1 h.
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
2. ~~**Web finish**~~ (DONE, except endpoints.ts, which is folded into step 3) (`apps/web`), about 45 min.
   1. Audit each module page for real hooks plus loading, empty and error states.
   2. Remove any remaining `ModulePlaceholderPage` routes.
   3. List every called endpoint in `apps/web/src/api/endpoints.ts`.
3. ~~**Web ↔ API reconciliation**~~ (DONE: all 84 web calls match API routes; a browser crawl of all 153 pages against the live API found 2 bugs, both fixed — Billing page crash and the SOAR actions limit), about 45 min. Match every web call against the registered Fastify routes and response shapes; fix mismatches.
4. ~~**End-to-end run**~~ (DONE: crawl clean, dark theme checked, `pnpm -r build` and typecheck pass), about 1 h. Use Playwright on every page: zero console errors and zero failed requests, compare against the reference screenshots, check dark theme, then run `pnpm -r build`.
5. ~~**Security, tenancy and completeness review**~~ (first pass DONE: no raw-HTML rendering in the UI; SQL interpolation is limited to constants and fixed allow-lists; every flagged route authorizes, directly or through a helper; a live probe as a customer viewer found no cross-customer data in 61 list endpoints and every write was refused with 403. Still recommended: a deeper third-party pentest before production), about 1.5 h.

Total: about 4–5 hours of agent work.

Known follow-ups from the infra report:
- ~~gzip request decoding for collectors~~ (DONE: gzip/deflate/br with zip-bomb guard; Vector and OTel now send gzip);
- ~~OTLP log envelope unwrapping on `/ingest/:adapter`~~ (DONE, tested with Suricata and syslog);
- ~~Kafka `EventBus` transport~~ (DONE: tested against a real Kafka 4.3 broker — ordering, retry, DLQ, end-to-end incident);
- ~~OpenSearch event search~~ (DONE: enable with `BLOODY_EVENT_SEARCH=opensearch`; tested against a real OpenSearch 3.9. Every query is checked against Postgres for identical results, and Postgres answers automatically when OpenSearch is down. `search:backfill` copies events stored before it was enabled. See ADR-0011);
- ~~a Valkey-backed rate limiter~~ (DONE: shared across replicas, fail-open, tested with two replicas);
- ~~OTel SDK instrumentation~~ (DONE: request tracing over OTLP/HTTP with traceparent propagation; tested in-memory and against a live OTLP receiver).

## How to resume

Open a Claude Code session on this repository and branch (`maerih/bloody`), then say:

> Resume the Bloody build from docs/BUILD_STATUS.md — do the "Remaining" steps in order.

## Run it on a server (one command)

This works on any Ubuntu/Debian or Fedora/RHEL server: home, office, a client site, or a VPS. It works on a fresh machine and on an existing install.

```bash
git clone <repo-url> bloody && cd bloody && git switch maerih/bloody   # or: git pull
./install.sh                                                            # LAN: home / office / client network
./install.sh --domain soc.example.com --email you@example.com           # VPS with a domain (trusted HTTPS)
./install.sh --public                                                    # VPS without a domain (self-signed HTTPS on the IP)
```

**LAN mode** is chosen automatically on a private address:

- Open `http://<server-ip>:5173`, or `http://<hostname>.local:5173`. The `.local` name stays the same when the IP changes.
- The install follows IP changes. Saving works on whatever address is used, and each start updates `PUBLIC_URL`.
- Demo login: `admin@bloody.local` / `ChangeMe!123`.

**Public mode** is chosen automatically on a public address, or with `--domain`/`--public`:

- HTTPS through Caddy. Only ports 80/443 are exposed.
- Production settings: Secure cookies and HSTS.
- No demo data. The first administrator (`--admin-email`, default `admin@<domain>`) gets a random password, shown once.

A cloud VM behind NAT looks private. The installer warns about this and suggests `--domain` or `--public`.

Tested on brand-new Ubuntu 24.04 systems:

- **LAN mode:** an upgrade of an existing install, as a normal sudo user.
- **Public mode with a self-signed certificate:** HTTPS login and saving, Secure cookies, HSTS, and port 5173 closed to the outside.
- **Domain mode:** checked up to certificate issuance, which needs real DNS.

Also tested:

- **Stale IP:** detected and repaired on restart.
- **Saves via the `.local` name:** work.
- **Forged cross-site saves and unknown host names:** refused (403).

| Task | Command |
|---|---|
| Check everything | `bash scripts/doctor.sh` |
| Status / logs | `sudo systemctl status bloody` / `journalctl -u bloody -f` |
| Restart | `sudo systemctl restart bloody` (each start applies new migrations and picks up a new LAN IP) |
| Update | `git pull && ./install.sh` |
| New account / lost password | `pnpm admin create-account --name "Customer SOC" --email admin@customer.example` / `pnpm admin reset-password --email <addr>` |
| Back up now | `bash scripts/backup.sh` (runs daily by itself; the newest 14 are kept in `backups/`) |
| Restore (same or a new server) | `bash scripts/restore.sh backups/<file>.tar` (takes a safety backup first; brings the encryption key along) |
| Re-anchor demo data at "now" (before a demo) | `pnpm db:seed --refresh`, then restart |

Without systemd (containers, WSL), the installer starts Bloody in the background and logs to `logs/bloody.log`. In that case, re-run it after a reboot.

Checks: `pnpm -r typecheck`, `pnpm -r test`.
