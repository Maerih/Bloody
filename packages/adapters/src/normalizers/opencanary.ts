import type { EventCategory, Severity } from "@bloody/contracts";
import { technique } from "../core/attack.js";
import { defineAdapter, skip, type Adapter, type AdapterExtras, type MapOutput } from "../core/adapter.js";
import { ObservableSet } from "../core/indicators.js";
import { int, isRecord, port, rec, redactKeys, str, type JsonRecord } from "../core/json.js";
import { toIso } from "../core/time.js";
import { inferDirection } from "../net/ip.js";

/**
 * OpenCanary adapter — consumes honeypot alerts (JSON log lines, webhook or syslog JSON).
 *
 * Any interaction with a canary is high-signal by construction: nothing legitimate talks to
 * it. Login attempts → high (T1110), connection/scan probes → medium (T1046), boot/debug/
 * housekeeping log types (1000-1006) are skipped. Attempted passwords captured by the
 * honeypot are NEVER stored: they may be real credentials an employee mistyped.
 */
export const OPENCANARY_ADAPTER_VERSION = "1.0.0";

interface CanaryType {
  name: string;
  service: string;
  category: EventCategory;
  severity: Severity;
  attack?: string;
  login?: boolean;
}

/** OpenCanary `logtype` codes (documented log type constants). */
export const OPENCANARY_LOGTYPES: Record<number, CanaryType> = {
  2000: { name: "ftp_login_attempt", service: "ftp", category: "authentication", severity: "high", attack: "T1110", login: true },
  3000: { name: "http_get", service: "http", category: "http", severity: "medium", attack: "T1595" },
  3001: { name: "http_login_attempt", service: "http", category: "authentication", severity: "high", attack: "T1110", login: true },
  4000: { name: "ssh_new_connection", service: "ssh", category: "network", severity: "medium", attack: "T1046" },
  4001: { name: "ssh_remote_version_sent", service: "ssh", category: "network", severity: "medium", attack: "T1046" },
  4002: { name: "ssh_login_attempt", service: "ssh", category: "authentication", severity: "high", attack: "T1110", login: true },
  5000: { name: "smb_file_open", service: "smb", category: "file", severity: "high", attack: "T1039" },
  5001: { name: "port_syn", service: "portscan", category: "network", severity: "medium", attack: "T1046" },
  5002: { name: "port_nmap_os", service: "portscan", category: "network", severity: "medium", attack: "T1046" },
  5003: { name: "port_nmap_null", service: "portscan", category: "network", severity: "medium", attack: "T1046" },
  5004: { name: "port_nmap_xmas", service: "portscan", category: "network", severity: "medium", attack: "T1046" },
  5005: { name: "port_nmap_fin", service: "portscan", category: "network", severity: "medium", attack: "T1046" },
  6001: { name: "telnet_login_attempt", service: "telnet", category: "authentication", severity: "high", attack: "T1110", login: true },
  7001: { name: "httpproxy_login_attempt", service: "httpproxy", category: "authentication", severity: "high", attack: "T1110", login: true },
  8001: { name: "mysql_login_attempt", service: "mysql", category: "authentication", severity: "high", attack: "T1110", login: true },
  9001: { name: "mssql_login_sqlauth", service: "mssql", category: "authentication", severity: "high", attack: "T1110", login: true },
  9002: { name: "mssql_login_winauth", service: "mssql", category: "authentication", severity: "high", attack: "T1110", login: true },
  10001: { name: "tftp", service: "tftp", category: "network", severity: "medium" },
  11001: { name: "ntp_monlist", service: "ntp", category: "network", severity: "medium", attack: "T1498" },
  12001: { name: "vnc", service: "vnc", category: "authentication", severity: "high", attack: "T1021", login: true },
  13001: { name: "snmp_cmd", service: "snmp", category: "network", severity: "medium", attack: "T1046" },
  14001: { name: "rdp", service: "rdp", category: "authentication", severity: "high", attack: "T1021.001", login: true },
  15001: { name: "sip_request", service: "sip", category: "network", severity: "medium" },
  16001: { name: "git_clone_request", service: "git", category: "network", severity: "high", attack: "T1213" },
  17001: { name: "redis_command", service: "redis", category: "network", severity: "high", attack: "T1210" },
  18001: { name: "tcp_banner_connection", service: "tcpbanner", category: "network", severity: "medium", attack: "T1046" },
  18002: { name: "tcp_banner_keepalive_connection", service: "tcpbanner", category: "network", severity: "medium", attack: "T1046" },
  18003: { name: "tcp_banner_keepalive_secret", service: "tcpbanner", category: "network", severity: "high" },
  18004: { name: "tcp_banner_keepalive_data", service: "tcpbanner", category: "network", severity: "medium" },
  18005: { name: "tcp_banner_data", service: "tcpbanner", category: "network", severity: "medium" },
  19001: { name: "llmnr_query_response", service: "llmnr", category: "network", severity: "high", attack: "T1557" },
};

const SECRET_LOGDATA = new Set(["password", "passwd", "pass", "secret", "hash", "ntlm_hash", "credentials"]);

function mapCanary(record: unknown): MapOutput {
  if (!isRecord(record)) return skip("not a JSON object");
  const logtype = int(record["logtype"]);
  if (logtype === undefined) return skip("not an OpenCanary event (no logtype)");
  if (logtype >= 1000 && logtype < 2000) return skip(`OpenCanary housekeeping log type ${logtype}`);
  const spec: CanaryType = OPENCANARY_LOGTYPES[logtype] ?? {
    name: logtype >= 99000 ? `user_defined_${logtype}` : `logtype_${logtype}`,
    service: "unknown",
    category: "network",
    severity: "medium",
  };
  const logdata = rec(record["logdata"]) ?? {};
  const ld = (k: string): string | undefined => str(logdata[k]) ?? str(logdata[k.toLowerCase()]);
  const src = str(record["src_host"]);
  const dst = str(record["dst_host"]);
  const node = str(record["node_id"]);
  const username = ld("USERNAME") ?? ld("USER") ?? ld("username");
  const obs = new ObservableSet().add("ip", src);
  const t = spec.attack ? technique(spec.attack) : undefined;
  const ts = toIso(record["utc_time"]) ?? toIso(record["local_time_adjusted"]) ?? toIso(record["local_time"]);
  return {
    timestamp: ts,
    category: spec.category,
    eventType: `opencanary.${spec.name}`,
    action: spec.name,
    outcome: spec.login ? "failure" : "unknown",
    message: `Honeypot ${node ?? dst ?? ""} ${spec.service} interaction from ${src ?? "unknown source"}${username ? ` (user "${username}")` : ""}`.replace(/\s+/g, " "),
    asset: { hostname: node, ip: dst ? [dst] : undefined },
    user: username ? { name: username } : undefined,
    identity: spec.login ? { provider: `honeypot:${spec.service}`, principal: username, sourceIp: src, outcome: "failure" } : undefined,
    network: { srcIp: src, srcPort: port(record["src_port"]), dstIp: dst, dstPort: port(record["dst_port"]), protocol: spec.service, direction: inferDirection(src, dst) },
    file: logtype === 5000 ? { path: ld("FILENAME") ?? ld("PATH"), name: ld("FILENAME"), action: "read" } : undefined,
    indicators: obs.toArray(),
    severity: spec.severity,
    detection: { ruleId: `opencanary:${logtype}`, ruleName: `Honeypot ${spec.service} ${spec.name.replace(/_/g, " ")}`, engine: "opencanary", confidence: 0.95 },
    attack: t ? [t] : [],
    labels: {
      severity_basis: "honeypot interaction (no legitimate traffic expected)",
      "canary.node": node,
      "canary.logtype": logtype,
      "canary.service": spec.service,
      "canary.remote_version": ld("REMOTEVERSION"),
      "canary.user_agent": ld("USERAGENT"),
      "canary.path": ld("PATH"),
      "canary.password_captured": Object.keys(logdata).some((k) => SECRET_LOGDATA.has(k.toLowerCase())) || undefined,
    },
    dedupKey: `${node ?? ""}:${logtype}:${ts ?? str(record["local_time"]) ?? ""}:${src ?? ""}:${str(record["src_port"]) ?? ""}`,
    source: { kind: "network", sensorId: node },
    raw: record,
  };
}

export function createOpenCanaryAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    ...extras,
    key: "opencanary",
    version: OPENCANARY_ADAPTER_VERSION,
    name: "OpenCanary honeypot alerts",
    sourceKind: "network",
    vendor: "Thinkst",
    consumes: ["OpenCanary JSON log lines / webhook alerts (logtype 2000-19001, user-defined 99000+)"],
    map: mapCanary,
    // Captured credentials are replaced before the record is embedded as provenance.
    redactRaw: (r) => redactKeys(r, SECRET_LOGDATA),
  });
}

export type OpenCanaryRecord = JsonRecord;
