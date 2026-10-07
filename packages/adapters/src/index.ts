/**
 * @bloody/adapters — the integration layer between Bloody's proprietary core and the
 * open-source engines it drives. Engines are reached only through their network APIs,
 * event streams or file outputs; every vendor format stops here and leaves as a validated
 * Bloody Canonical Event, indicator record, response result or sync plan.
 *
 *   core/        Adapter contract, finalize/validate pipeline, ATT&CK table, observables,
 *                time/IP parsing, ingest reports, automation signals, XML parser
 *   http/        EngineClient (injected fetch, auth, timeouts, SSRF guard), health checks
 *   normalizers/ Wazuh (+Windows/Sysmon), Zeek, Suricata, Falco, osquery, Velociraptor,
 *                OpenCanary, Trivy, Nuclei, Greenbone, syslog/CEF, Keycloak, CloudTrail
 *   intel/       MISP, OpenCTI, STIX 2.1, CISA KEV, FIRST EPSS, vulnerability enrichment
 *   response/    Wazuh active response, Velociraptor collections, signed block webhooks
 *   copilot/     SOCFortress CoPilot client, sync planner, alert adapter
 */

// core
export * from "./core/adapter.js";
export * from "./core/attack.js";
export * from "./core/hash.js";
export * from "./core/indicators.js";
export * from "./core/json.js";
export * from "./core/records.js";
export * from "./core/report.js";
export * from "./core/severity.js";
export * from "./core/signals.js";
export * from "./core/time.js";
export * from "./core/xml.js";
export * from "./net/ip.js";

// http
export * from "./http/client.js";
export * from "./http/health.js";
export * from "./http/url-guard.js";

// normalizers
export * from "./normalizers/cloudtrail.js";
export * from "./normalizers/falco.js";
export * from "./normalizers/greenbone.js";
export * from "./normalizers/keycloak.js";
export * from "./normalizers/nuclei.js";
export * from "./normalizers/opencanary.js";
export * from "./normalizers/osquery.js";
export * from "./normalizers/suricata.js";
export * from "./normalizers/syslog.js";
export * from "./normalizers/trivy.js";
export * from "./normalizers/velociraptor.js";
export * from "./normalizers/wazuh.js";
export * from "./normalizers/windows.js";
export * from "./normalizers/zeek.js";

// intel
export * from "./intel/epss.js";
export * from "./intel/kev.js";
export * from "./intel/misp.js";
export * from "./intel/opencti.js";
export * from "./intel/stix.js";
export * from "./intel/types.js";
export * from "./intel/vulnerabilities.js";

// response
export * from "./response/types.js";
export * from "./response/velociraptor.js";
export * from "./response/wazuh.js";
export * from "./response/webhook.js";

// CoPilot
export * from "./copilot/client.js";
export * from "./copilot/events.js";
export * from "./copilot/schemas.js";
export * from "./copilot/sync.js";

// registry
export * from "./registry.js";
