import { ENGINES, OPEN_INTEL_SOURCES, type EngineDefinition, type IntegrationMode, type LicenseRisk, type ResponseActionKey, type SourceKind } from "@bloody/contracts";
import type { Adapter, AdapterContext, NormalizationResult } from "./core/adapter.js";
import { buildIngestReport, type IngestReport, type IngestReportOptions } from "./core/report.js";
import { createCoPilotAlertAdapter } from "./copilot/events.js";
import { createCloudTrailAdapter } from "./normalizers/cloudtrail.js";
import { createFalcoAdapter } from "./normalizers/falco.js";
import { createGreenboneAdapter } from "./normalizers/greenbone.js";
import { createKeycloakAdapter } from "./normalizers/keycloak.js";
import { createNucleiAdapter } from "./normalizers/nuclei.js";
import { createOpenCanaryAdapter } from "./normalizers/opencanary.js";
import { createOsqueryAdapter } from "./normalizers/osquery.js";
import { createSuricataAdapter } from "./normalizers/suricata.js";
import { createCefAdapter, createSyslogAdapter } from "./normalizers/syslog.js";
import { createTrivyAdapter } from "./normalizers/trivy.js";
import { createVelociraptorAdapter } from "./normalizers/velociraptor.js";
import { createWazuhAdapter } from "./normalizers/wazuh.js";
import { createZeekAdapter } from "./normalizers/zeek.js";
import { createVelociraptorResponse, type VelociraptorResponseOptions } from "./response/velociraptor.js";
import { createWazuhActiveResponse, wazuhHealthCheck, type WazuhActiveResponseOptions } from "./response/wazuh.js";

/**
 * Sources that are not engines in the `ENGINES` catalog (protocols, cloud-provider log
 * formats). Adapter keys must be an `ENGINES` key or one of these.
 */
export const GENERIC_SOURCES: ReadonlyArray<{ key: string; name: string; license: string; mode: IntegrationMode; role: string }> = [
  { key: "syslog", name: "Syslog", license: "n/a (IETF RFC 5424 / RFC 3164 protocol)", mode: "event_stream", role: "Generic log transport (network devices, Linux hosts)" },
  { key: "cef", name: "Common Event Format", license: "n/a (published log format)", mode: "event_stream", role: "Security appliance events (firewalls, proxies, IDS)" },
  { key: "aws_cloudtrail", name: "AWS CloudTrail", license: "n/a (cloud provider audit log format)", mode: "file_drop", role: "AWS control-plane audit trail" },
];

export interface AdapterCatalogEntry {
  key: string;
  name: string;
  version: string;
  sourceKind: SourceKind;
  consumes: readonly string[];
  /** Engine metadata from the contracts catalog; null for generic sources. */
  engine: { name: string; license: string; licenseRisk: LicenseRisk; licenseNotes: string; mode: IntegrationMode; homepage: string } | null;
  generic: boolean;
  actions: ResponseActionKey[];
  healthCheck: boolean;
}

export class AdapterRegistryError extends Error {
  constructor(
    readonly code: "unknown_adapter" | "duplicate_adapter" | "invalid_key",
    message: string,
  ) {
    super(message);
    this.name = "AdapterRegistryError";
  }
}

const ENGINE_BY_KEY = new Map<string, EngineDefinition>(ENGINES.map((e) => [e.key, e]));
const GENERIC_KEYS = new Set(GENERIC_SOURCES.map((g) => g.key));

export function isKnownSourceKey(key: string): boolean {
  return ENGINE_BY_KEY.has(key) || GENERIC_KEYS.has(key);
}

export class AdapterRegistry {
  private readonly adapters = new Map<string, Adapter>();

  constructor(private readonly opts: { allowCustomKeys?: boolean } = {}) {}

  register(adapter: Adapter, opts: { replace?: boolean } = {}): this {
    if (!/^[a-z0-9_]{2,64}$/.test(adapter.key)) throw new AdapterRegistryError("invalid_key", `invalid adapter key "${adapter.key}"`);
    if (!this.opts.allowCustomKeys && !isKnownSourceKey(adapter.key)) {
      throw new AdapterRegistryError("invalid_key", `adapter key "${adapter.key}" is neither an ENGINES key nor a generic source`);
    }
    if (this.adapters.has(adapter.key) && !opts.replace) throw new AdapterRegistryError("duplicate_adapter", `adapter "${adapter.key}" already registered`);
    this.adapters.set(adapter.key, adapter);
    return this;
  }

  has(key: string): boolean {
    return this.adapters.has(key);
  }

  get(key: string): Adapter | undefined {
    return this.adapters.get(key);
  }

  require(key: string): Adapter {
    const a = this.adapters.get(key);
    if (!a) throw new AdapterRegistryError("unknown_adapter", `no adapter registered for "${key}"`);
    return a;
  }

  list(): Adapter[] {
    return [...this.adapters.values()].sort((a, b) => a.key.localeCompare(b.key));
  }

  /** Normalize a payload with the adapter registered under `key`. */
  normalize(key: string, raw: unknown, ctx: AdapterContext): NormalizationResult {
    return this.require(key).normalizeDetailed(raw, ctx);
  }

  /** Normalize and build the ingest report (data-source health, severity mix, ATT&CK). */
  ingest(key: string, raw: unknown, ctx: AdapterContext, reportOpts?: IngestReportOptions): { result: NormalizationResult; report: IngestReport } {
    const result = this.normalize(key, raw, ctx);
    return { result, report: buildIngestReport(result, reportOpts) };
  }

  supportedActions(key: string): ResponseActionKey[] {
    return Object.keys(this.require(key).actions ?? {}) as ResponseActionKey[];
  }

  /** Catalog rows for `GET /integrations/catalog` and the adapters README. */
  catalog(): AdapterCatalogEntry[] {
    return this.list().map((a) => {
      const e = ENGINE_BY_KEY.get(a.key);
      return {
        key: a.key,
        name: a.name,
        version: a.version,
        sourceKind: a.sourceKind,
        consumes: a.consumes,
        engine: e ? { name: e.name, license: e.license, licenseRisk: e.licenseRisk, licenseNotes: e.licenseNotes, mode: e.mode, homepage: e.homepage } : null,
        generic: !e,
        actions: Object.keys(a.actions ?? {}) as ResponseActionKey[],
        healthCheck: typeof a.healthCheck === "function",
      };
    });
  }
}

export interface BuiltinAdapterOptions {
  /** Wazuh active response; `false` disables response actions. Default: stock scripts only. */
  wazuhActiveResponse?: WazuhActiveResponseOptions | false;
  /** Velociraptor collections; `false` disables response actions. */
  velociraptorResponse?: VelociraptorResponseOptions | false;
}

/** All built-in adapters (normalizers + engine response actions + health probes). */
export function createBuiltinAdapters(opts: BuiltinAdapterOptions = {}): Adapter[] {
  const wazuhAr = opts.wazuhActiveResponse === false ? null : createWazuhActiveResponse(opts.wazuhActiveResponse ?? {});
  const velo = opts.velociraptorResponse === false ? null : createVelociraptorResponse(opts.velociraptorResponse ?? {});
  return [
    createWazuhAdapter({ healthCheck: wazuhHealthCheck, ...(wazuhAr ? { actions: wazuhAr.handlers } : {}) }),
    createZeekAdapter(),
    createSuricataAdapter(),
    createFalcoAdapter(),
    createOsqueryAdapter(),
    createVelociraptorAdapter(velo ? { actions: velo.handlers } : {}),
    createOpenCanaryAdapter(),
    createTrivyAdapter(),
    createNucleiAdapter(),
    createGreenboneAdapter(),
    createSyslogAdapter(),
    createCefAdapter(),
    createKeycloakAdapter(),
    createCloudTrailAdapter(),
    createCoPilotAlertAdapter(),
  ];
}

export function createDefaultRegistry(opts: BuiltinAdapterOptions = {}): AdapterRegistry {
  const registry = new AdapterRegistry();
  for (const a of createBuiltinAdapters(opts)) registry.register(a);
  return registry;
}

/** Non-event connectors (threat intel and response) for the integrations catalog. */
export const INTEL_CONNECTORS = [
  { key: "misp", consumes: "POST /attributes/restSearch (JSON) → indicator records", engine: true },
  { key: "opencti", consumes: "GraphQL indicators query → indicator records", engine: true },
  { key: "stix", consumes: "STIX 2.1 bundles (files, TAXII collection exports) → indicator records", engine: false },
  ...OPEN_INTEL_SOURCES.filter((s) => s.key === "cisa_kev" || s.key === "first_epss").map((s) => ({ key: s.key, consumes: s.name, engine: false })),
] as const;

export const RESPONSE_CONNECTORS = [
  { key: "wazuh.active_response", engine: "wazuh", actions: ["block_ip", "disable_identity", "isolate_endpoint*", "release_endpoint*", "kill_process*", "quarantine_file*"], note: "* requires a customer-deployed active-response script" },
  { key: "velociraptor.collect", engine: "velociraptor", actions: ["isolate_endpoint", "release_endpoint", "collect_evidence", "run_yara_scan", "kill_process*", "quarantine_file*"], note: "* requires a customer-approved artifact" },
  { key: "webhook.block", engine: "webhook", actions: ["block_ip", "block_domain"], note: "signed JSON to a customer firewall/DNS relay" },
] as const;
