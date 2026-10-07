import { z } from "zod";
import type { ModuleKey } from "./modules.js";

/**
 * Catalog of the open-source engines Bloody can drive. Each is consumed ONLY as a separate
 * process/container through a proprietary adapter (network API, event stream, or file drop).
 * No engine source is copied into, or linked with, the proprietary core.
 *
 * Commercial services that require a paid API key (VirusTotal, Shodan, GreyNoise, etc.) are
 * intentionally excluded from the default stack.
 */
export const IntegrationMode = z.enum(["network_api", "event_stream", "file_drop", "agent", "library_permissive"]);
export type IntegrationMode = z.infer<typeof IntegrationMode>;

export const LicenseRisk = z.enum(["low", "medium", "high"]);
export type LicenseRisk = z.infer<typeof LicenseRisk>;

export interface EngineDefinition {
  key: string;
  name: string;
  layer:
    | "endpoint"
    | "runtime"
    | "network"
    | "search"
    | "streaming"
    | "collection"
    | "detection"
    | "intel"
    | "case"
    | "soar"
    | "vulnerability"
    | "asm"
    | "cloud"
    | "identity"
    | "deception"
    | "forensics"
    | "storage"
    | "ai";
  role: string;
  /** SPDX expression. */
  license: string;
  licenseRisk: LicenseRisk;
  licenseNotes: string;
  mode: IntegrationMode;
  /** Product modules this engine powers. */
  powers: ModuleKey[];
  core: boolean;
  homepage: string;
}

export const ENGINES: EngineDefinition[] = [
  { key: "wazuh", name: "Wazuh", layer: "endpoint", role: "HIDS / endpoint telemetry & FIM", license: "GPL-2.0-only", licenseRisk: "medium", licenseNotes: "Run unmodified as a separate service; consume via REST API + alert stream. Never link.", mode: "network_api", powers: ["edr", "xdr", "siem"], core: true, homepage: "https://wazuh.com" },
  { key: "velociraptor", name: "Velociraptor", layer: "forensics", role: "DFIR / live endpoint response & collection", license: "AGPL-3.0-only", licenseRisk: "medium", licenseNotes: "AGPL network clause: any modification of the server must be published. Run unmodified; drive via gRPC API.", mode: "network_api", powers: ["edr", "dfir"], core: true, homepage: "https://docs.velociraptor.app" },
  { key: "osquery", name: "osquery", layer: "endpoint", role: "Endpoint inventory & SQL querying", license: "Apache-2.0 OR GPL-2.0-only", licenseRisk: "low", licenseNotes: "Use under Apache-2.0. Results shipped as logs.", mode: "agent", powers: ["edr", "espm"], core: true, homepage: "https://osquery.io" },
  { key: "falco", name: "Falco", layer: "runtime", role: "Linux / Kubernetes runtime threat detection", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "Consume JSON alerts via Falcosidekick/webhook.", mode: "event_stream", powers: ["container", "xdr"], core: true, homepage: "https://falco.org" },
  { key: "zeek", name: "Zeek", layer: "network", role: "Network telemetry (conn/dns/http/ssl/files)", license: "BSD-3-Clause", licenseRisk: "low", licenseNotes: "Consume JSON logs.", mode: "file_drop", powers: ["ndr", "siem"], core: true, homepage: "https://zeek.org" },
  { key: "suricata", name: "Suricata", layer: "network", role: "IDS/IPS & NSM (EVE JSON)", license: "GPL-2.0-only", licenseRisk: "medium", licenseNotes: "Run unmodified; consume EVE JSON output only.", mode: "file_drop", powers: ["ndr", "siem"], core: true, homepage: "https://suricata.io" },
  { key: "arkime", name: "Arkime", layer: "network", role: "Full packet capture & session hunting", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "Query via viewer API; PCAP retrieval for evidence.", mode: "network_api", powers: ["ndr", "dfir"], core: true, homepage: "https://arkime.com" },
  { key: "opensearch", name: "OpenSearch", layer: "search", role: "Security event search & analytics store", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "Preferred over Elasticsearch (SSPL/ELv2/AGPL).", mode: "network_api", powers: ["siem", "xdr"], core: true, homepage: "https://opensearch.org" },
  { key: "kafka", name: "Apache Kafka", layer: "streaming", role: "Event backbone", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "Redpanda is BSL-1.1 (restricts offering as a service) — Kafka is the default for SaaS.", mode: "event_stream", powers: ["siem", "xdr"], core: true, homepage: "https://kafka.apache.org" },
  { key: "otel", name: "OpenTelemetry Collector", layer: "collection", role: "Vendor-neutral telemetry collection", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "Also used for Bloody's own observability.", mode: "event_stream", powers: ["siem"], core: true, homepage: "https://opentelemetry.io" },
  { key: "vector", name: "Vector", layer: "collection", role: "High-performance log routing", license: "MPL-2.0", licenseRisk: "low", licenseNotes: "File-level copyleft only for modified Vector files; config is ours.", mode: "event_stream", powers: ["siem"], core: true, homepage: "https://vector.dev" },
  { key: "sigma", name: "Sigma", layer: "detection", role: "Detection-as-code rule format", license: "DRL-1.1", licenseRisk: "low", licenseNotes: "Community rules under Detection Rule License: keep attribution in rule metadata. Bloody compiles Sigma with its own proprietary compiler.", mode: "library_permissive", powers: ["siem", "edr", "xdr"], core: true, homepage: "https://sigmahq.io" },
  { key: "yara", name: "YARA", layer: "detection", role: "Malware / file pattern matching", license: "BSD-3-Clause", licenseRisk: "low", licenseNotes: "Run as scanner sidecar.", mode: "network_api", powers: ["edr", "dfir"], core: true, homepage: "https://virustotal.github.io/yara/" },
  { key: "misp", name: "MISP", layer: "intel", role: "IOC sharing & intelligence platform", license: "AGPL-3.0-only", licenseRisk: "medium", licenseNotes: "Run unmodified; sync via REST API.", mode: "network_api", powers: ["cti"], core: true, homepage: "https://www.misp-project.org" },
  { key: "opencti", name: "OpenCTI", layer: "intel", role: "Threat intelligence knowledge graph (STIX2)", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "Community Edition only; Enterprise Edition features are separately licensed — do not enable.", mode: "network_api", powers: ["cti"], core: true, homepage: "https://filigran.io" },
  { key: "dfir_iris", name: "DFIR-IRIS", layer: "case", role: "Collaborative incident case management", license: "LGPL-3.0-only", licenseRisk: "low", licenseNotes: "Preferred over TheHive 5 (commercial licence). Optional: Bloody has its own case engine.", mode: "network_api", powers: ["dfir"], core: false, homepage: "https://dfir-iris.org" },
  { key: "shuffle", name: "Shuffle", layer: "soar", role: "Automation / workflow apps", license: "AGPL-3.0-only", licenseRisk: "medium", licenseNotes: "Optional executor behind Bloody's proprietary SOAR engine; run unmodified.", mode: "network_api", powers: ["soar"], core: false, homepage: "https://shuffler.io" },
  { key: "greenbone", name: "Greenbone / OpenVAS", layer: "vulnerability", role: "Network vulnerability scanning", license: "AGPL-3.0-or-later AND GPL-2.0-or-later", licenseRisk: "medium", licenseNotes: "Community Feed has its own terms — review before commercial use. Drive via GMP.", mode: "network_api", powers: ["vuln"], core: true, homepage: "https://greenbone.github.io/docs/" },
  { key: "nuclei", name: "Nuclei", layer: "asm", role: "Template-based exposure scanning", license: "MIT", licenseRisk: "low", licenseNotes: "Only against authorized, in-scope targets with rate limits.", mode: "network_api", powers: ["asm", "vuln"], core: true, homepage: "https://github.com/projectdiscovery/nuclei" },
  { key: "subfinder", name: "Subfinder", layer: "asm", role: "Passive subdomain discovery", license: "MIT", licenseRisk: "low", licenseNotes: "Use only sources that need no paid API key.", mode: "network_api", powers: ["asm"], core: false, homepage: "https://github.com/projectdiscovery/subfinder" },
  { key: "amass", name: "OWASP Amass", layer: "asm", role: "Attack surface mapping", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "Passive mode by default.", mode: "network_api", powers: ["asm"], core: false, homepage: "https://github.com/owasp-amass/amass" },
  { key: "trivy", name: "Trivy", layer: "cloud", role: "Container / IaC / K8s vulnerability & misconfig scanning", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "Consume JSON reports.", mode: "file_drop", powers: ["container", "vuln", "cspm"], core: true, homepage: "https://trivy.dev" },
  { key: "grype", name: "Grype + Syft", layer: "cloud", role: "SBOM generation & vulnerability matching", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "Also used for Bloody's own SBOM.", mode: "file_drop", powers: ["vuln", "container"], core: false, homepage: "https://github.com/anchore/grype" },
  { key: "kube_bench", name: "kube-bench", layer: "cloud", role: "CIS Kubernetes benchmark", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "JSON output.", mode: "file_drop", powers: ["container", "cspm"], core: false, homepage: "https://github.com/aquasecurity/kube-bench" },
  { key: "keycloak", name: "Keycloak", layer: "identity", role: "SSO / OIDC / SAML broker for the platform", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "Bloody acts as OIDC relying party.", mode: "network_api", powers: ["itdr"], core: true, homepage: "https://www.keycloak.org" },
  { key: "opencanary", name: "OpenCanary", layer: "deception", role: "Honeypot / canary services", license: "BSD-3-Clause", licenseRisk: "low", licenseNotes: "Alerts via webhook/syslog.", mode: "event_stream", powers: ["deception"], core: true, homepage: "https://github.com/thinkst/opencanary" },
  { key: "plaso", name: "Plaso", layer: "forensics", role: "Super-timeline extraction", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "Run as job container on evidence.", mode: "file_drop", powers: ["dfir"], core: true, homepage: "https://plaso.readthedocs.io" },
  { key: "timesketch", name: "Timesketch", layer: "forensics", role: "Collaborative timeline analysis", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "Optional analyst UI for very large timelines.", mode: "network_api", powers: ["dfir"], core: false, homepage: "https://timesketch.org" },
  { key: "copilot", name: "SOCFortress CoPilot", layer: "case", role: "Open-source SOC/MSSP management hub (customers, agents, alerts, cases, customer portal) over Wazuh/Graylog/Velociraptor", license: "AGPL-3.0-only", licenseRisk: "medium", licenseNotes: "Run unmodified as a separate service; Bloody syncs customers, agents, alerts and cases via its /api REST surface. No CoPilot source is copied. Its default stack pulls Graylog (SSPL-1.0, high risk for SaaS) and Grafana (AGPL) — prefer Bloody's OpenSearch pipeline in SaaS deployments.", mode: "network_api", powers: ["command_center", "edr", "siem", "dfir"], core: false, homepage: "https://github.com/socfortress/CoPilot" },
  { key: "postgres", name: "PostgreSQL", layer: "storage", role: "Control-plane & transactional store (with RLS)", license: "PostgreSQL", licenseRisk: "low", licenseNotes: "Permissive.", mode: "network_api", powers: ["command_center"], core: true, homepage: "https://www.postgresql.org" },
  { key: "clickhouse", name: "ClickHouse", layer: "storage", role: "High-volume analytics", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "Optional at scale.", mode: "network_api", powers: ["siem"], core: false, homepage: "https://clickhouse.com" },
  { key: "valkey", name: "Valkey", layer: "storage", role: "Cache / short-lived state", license: "BSD-3-Clause", licenseRisk: "low", licenseNotes: "Chosen over Redis ≥7.4 (RSAL/SSPL).", mode: "network_api", powers: ["command_center"], core: true, homepage: "https://valkey.io" },
  { key: "ollama", name: "Ollama", layer: "ai", role: "Local LLM runtime", license: "MIT", licenseRisk: "low", licenseNotes: "Model weights carry their own licences — check per model.", mode: "network_api", powers: ["ai_soc"], core: false, homepage: "https://ollama.com" },
  { key: "vllm", name: "vLLM", layer: "ai", role: "High-throughput local LLM serving", license: "Apache-2.0", licenseRisk: "low", licenseNotes: "OpenAI-compatible API.", mode: "network_api", powers: ["ai_soc"], core: false, homepage: "https://vllm.ai" },
];

/** Free, key-less intelligence sources used by default. */
export const OPEN_INTEL_SOURCES = [
  { key: "cisa_kev", name: "CISA Known Exploited Vulnerabilities", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", license: "Public domain (US Gov)" },
  { key: "first_epss", name: "FIRST EPSS", url: "https://www.first.org/epss/", license: "Free use with attribution" },
  { key: "mitre_attack", name: "MITRE ATT&CK (STIX)", url: "https://attack.mitre.org", license: "ATT&CK Terms of Use (attribution)" },
  { key: "nvd", name: "NIST NVD CVE feed", url: "https://nvd.nist.gov", license: "Public domain (US Gov); API key optional" },
  { key: "sigmahq", name: "SigmaHQ rules", url: "https://github.com/SigmaHQ/sigma", license: "DRL-1.1" },
] as const;

/** Explicitly excluded: require commercial/paid API keys. */
export const EXCLUDED_KEYED_SERVICES = ["VirusTotal", "Shodan", "GreyNoise", "AbuseIPDB", "Censys", "SecurityTrails", "Hybrid Analysis"] as const;
