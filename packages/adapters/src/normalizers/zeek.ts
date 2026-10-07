import type { AttackTechnique, Severity } from "@bloody/contracts";
import { technique } from "../core/attack.js";
import { defineAdapter, type Adapter, type AdapterExtras, skip, type EventDraft, type MapContext, type MapOutput } from "../core/adapter.js";
import { ObservableSet } from "../core/indicators.js";
import { bool, field, isRecord, num, port, str, strArr, uint, type JsonRecord } from "../core/json.js";
import { toIso } from "../core/time.js";
import { inferDirection, isIp } from "../net/ip.js";

/**
 * Zeek adapter — consumes Zeek JSON logs (`LogAscii::use_json=T`, JSON streaming/Kafka
 * writers, Corelight-style `_path` envelopes). Each record's log type is taken from `_path`
 * (or the `logType` option for single-log files) and otherwise inferred from its fields.
 *
 * Supported logs: conn, dns, http, ssl, files, notice. Other logs are reported as skipped.
 */
export const ZEEK_ADAPTER_VERSION = "1.0.0";

type ZeekLog = "conn" | "dns" | "http" | "ssl" | "files" | "notice";
const SUPPORTED: ReadonlySet<string> = new Set(["conn", "dns", "http", "ssl", "files", "notice"]);

export function zeekLogType(r: JsonRecord, hint?: string): string | undefined {
  const declared = str(r["_path"]) ?? str(r["_log"]) ?? str(r["@stream"]) ?? str(r["log_type"]) ?? hint;
  if (declared) return declared.toLowerCase().replace(/^zeek[._-]?/, "").replace(/\.log$/, "");
  const has = (k: string): boolean => Object.prototype.hasOwnProperty.call(r, k);
  if (has("note") && has("msg")) return "notice";
  if (has("query") && (has("qtype_name") || has("rcode_name") || has("trans_id"))) return "dns";
  if (has("method") && (has("uri") || has("host")) && has("trans_depth")) return "http";
  if ((has("server_name") || has("cipher")) && has("version") && (has("established") || has("resumed"))) return "ssl";
  if (has("fuid") && (has("mime_type") || has("analyzers") || has("seen_bytes") || has("total_bytes"))) return "files";
  if (has("conn_state") || (has("proto") && has("duration"))) return "conn";
  if (has("name") && has("addl")) return "weird";
  return undefined;
}

const FAILED_CONN_STATES = new Set(["S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"]);

interface NoticeSpec {
  severity: Severity;
  attack?: string;
}

/** Severity/technique for well-known notice types; unknown notices default to medium. */
const NOTICES: Array<[RegExp, NoticeSpec]> = [
  [/^Scan::(Port|Address)_Scan$/, { severity: "medium", attack: "T1046" }],
  [/^SSH::Password_Guessing$/, { severity: "high", attack: "T1110.001" }],
  [/^FTP::Bruteforcing$/, { severity: "high", attack: "T1110" }],
  [/^HTTP::SQL_Injection_(Attacker|Victim)$/, { severity: "high", attack: "T1190" }],
  [/^Intel::Notice$/, { severity: "high" }],
  [/^TeamCymruMalwareHashRegistry::Match$/, { severity: "high", attack: "T1105" }],
  [/^Signatures::/, { severity: "medium" }],
  [/^Software::Vulnerable_Version$/, { severity: "medium", attack: "T1190" }],
  [/^SSL::(Invalid_Server_Cert|Certificate_Expired|Certificate_Not_Valid_Yet|Weak_Key|Old_Version|Weak_Cipher)/, { severity: "low" }],
  [/^SSH::(Login_By_Password_Guesser|Interesting_Hostname_Login)$/, { severity: "high", attack: "T1021.004" }],
  [/^DNS::External_Name$/, { severity: "low" }],
  [/^(CaptureLoss|PacketFilter|Weird|Notice)::/, { severity: "info" }],
];

function noticeSpec(note: string): NoticeSpec {
  for (const [re, spec] of NOTICES) if (re.test(note)) return spec;
  return { severity: "medium" };
}

function endpoints(r: JsonRecord): { srcIp?: string; srcPort?: number; dstIp?: string; dstPort?: number } {
  return {
    srcIp: str(field(r, "id.orig_h")),
    srcPort: port(field(r, "id.orig_p")),
    dstIp: str(field(r, "id.resp_h")),
    dstPort: port(field(r, "id.resp_p")),
  };
}

function direction(r: JsonRecord, src?: string, dst?: string): "inbound" | "outbound" | "lateral" | "unknown" {
  const lo = bool(r["local_orig"]);
  const lr = bool(r["local_resp"]);
  if (lo !== undefined && lr !== undefined) {
    if (lo && lr) return "lateral";
    if (lo && !lr) return "outbound";
    if (!lo && lr) return "inbound";
  }
  return inferDirection(src, dst);
}

function mapZeek(record: unknown, ctx: MapContext): MapOutput {
  if (!isRecord(record)) return skip("not a JSON object");
  const hint = str(ctx.options["logType"]);
  const log = zeekLogType(record, hint);
  if (!log) return skip("unrecognized Zeek log record");
  if (!SUPPORTED.has(log)) return skip(`Zeek log "${log}" is not modelled`);
  const r = record;
  const ts = toIso(r["ts"]);
  const uid = str(r["uid"]);
  const ep = endpoints(r);
  const obs = new ObservableSet().add("ip", ep.srcIp).add("ip", ep.dstIp);
  const sensor = str(r["_system_name"]) ?? str(r["peer_descr"]) ?? str(r["_node"]);
  const base: Pick<EventDraft, "timestamp" | "raw" | "source"> = {
    timestamp: ts,
    raw: r,
    ...(sensor ? { source: { sensorId: sensor } } : {}),
  };
  const labels: Record<string, string | number | boolean | undefined> = { "zeek.log": log, "zeek.uid": uid, "zeek.community_id": str(r["community_id"]) };

  switch (log as ZeekLog) {
    case "conn": {
      const state = str(r["conn_state"]);
      const service = str(r["service"]);
      labels["zeek.conn_state"] = state;
      labels["zeek.history"] = str(r["history"]);
      labels["zeek.duration"] = num(r["duration"]);
      labels["zeek.proto"] = str(r["proto"]);
      labels["zeek.orig_pkts"] = uint(r["orig_pkts"]);
      labels["zeek.resp_pkts"] = uint(r["resp_pkts"]);
      return {
        ...base,
        category: "network",
        eventType: "zeek.conn",
        action: "connection",
        outcome: state ? (FAILED_CONN_STATES.has(state) ? "failure" : "success") : "unknown",
        network: {
          ...ep,
          protocol: (service?.split(",")[0] ?? str(r["proto"]))?.toLowerCase(),
          direction: direction(r, ep.srcIp, ep.dstIp),
          bytesOut: uint(r["orig_bytes"]),
          bytesIn: uint(r["resp_bytes"]),
        },
        indicators: obs.toArray(),
        severity: "info",
        labels,
        dedupKey: uid ? `conn:${uid}` : undefined,
      };
    }
    case "dns": {
      const query = str(r["query"]);
      const rcode = str(r["rcode_name"]);
      obs.add("domain", query);
      for (const a of strArr(r["answers"])) {
        if (isIp(a)) obs.add("ip", a);
        else obs.add("domain", a);
      }
      labels["dns.qtype"] = str(r["qtype_name"]);
      labels["dns.rcode"] = rcode;
      labels["dns.answers"] = strArr(r["answers"]).slice(0, 20).join(",") || undefined;
      labels["dns.rejected"] = bool(r["rejected"]);
      return {
        ...base,
        category: "dns",
        eventType: "zeek.dns",
        action: "dns-query",
        outcome: rcode === undefined ? "unknown" : rcode === "NOERROR" ? "success" : "failure",
        network: { ...ep, protocol: "dns", dnsQuery: query, direction: direction(r, ep.srcIp, ep.dstIp) },
        indicators: obs.toArray(),
        severity: "info",
        labels,
        dedupKey: uid ? `dns:${uid}:${str(r["trans_id"]) ?? ""}:${query ?? ""}:${str(r["ts"]) ?? ""}` : undefined,
      };
    }
    case "http": {
      const host = str(r["host"]);
      const uri = str(r["uri"]);
      const statusCode = uint(r["status_code"]);
      const ua = str(r["user_agent"]);
      const url = host ? `http://${host}${uri ?? "/"}` : undefined;
      obs.addHost(host).add("url", url).add("user_agent", ua);
      labels["http.method"] = str(r["method"]);
      labels["http.status_code"] = statusCode;
      labels["http.user_agent"] = ua;
      labels["http.referrer"] = str(r["referrer"]);
      labels["http.resp_mime_types"] = strArr(r["resp_mime_types"]).join(",") || undefined;
      labels["http.request_body_len"] = uint(r["request_body_len"]);
      labels["http.response_body_len"] = uint(r["response_body_len"]);
      return {
        ...base,
        category: "http",
        eventType: "zeek.http",
        action: str(r["method"])?.toLowerCase(),
        outcome: statusCode === undefined ? "unknown" : statusCode < 400 ? "success" : "failure",
        network: {
          ...ep,
          protocol: "http",
          httpHost: host,
          httpUrl: url ?? uri,
          direction: direction(r, ep.srcIp, ep.dstIp),
          bytesOut: uint(r["request_body_len"]),
          bytesIn: uint(r["response_body_len"]),
        },
        indicators: obs.toArray(),
        severity: "info",
        labels,
        dedupKey: uid ? `http:${uid}:${str(r["trans_depth"]) ?? "1"}` : undefined,
      };
    }
    case "ssl": {
      const sni = str(r["server_name"]);
      const ja3 = str(r["ja3"]);
      const established = bool(r["established"]);
      obs.add("domain", sni).add("ja3", ja3);
      labels["tls.version"] = str(r["version"]);
      labels["tls.cipher"] = str(r["cipher"]);
      labels["tls.subject"] = str(r["subject"]);
      labels["tls.issuer"] = str(r["issuer"]);
      labels["tls.validation_status"] = str(r["validation_status"]);
      labels["tls.ja3s"] = str(r["ja3s"]);
      labels["tls.resumed"] = bool(r["resumed"]);
      const validation = str(r["validation_status"]);
      return {
        ...base,
        category: "tls",
        eventType: "zeek.ssl",
        action: "tls-handshake",
        outcome: established === undefined ? "unknown" : established ? "success" : "failure",
        network: { ...ep, protocol: "tls", tlsSni: sni, ja3, direction: direction(r, ep.srcIp, ep.dstIp) },
        indicators: obs.toArray(),
        severity: validation && validation !== "ok" && /self signed|expired|unable to get/i.test(validation) ? "low" : "info",
        labels,
        dedupKey: uid ? `ssl:${uid}` : undefined,
      };
    }
    case "files": {
      const fuid = str(r["fuid"]);
      const mime = str(r["mime_type"]);
      const tx = strArr(r["tx_hosts"]);
      const rx = strArr(r["rx_hosts"]);
      const src = tx[0] ?? (bool(r["is_orig"]) ? ep.srcIp : ep.dstIp);
      const dst = rx[0] ?? (bool(r["is_orig"]) ? ep.dstIp : ep.srcIp);
      const sha256 = str(r["sha256"]);
      const md5 = str(r["md5"]);
      const sha1 = str(r["sha1"]);
      obs.add("ip", src).add("ip", dst).addHash(sha256).addHash(md5).addHash(sha1);
      const executable = mime ? /dosexec|x-executable|x-mach-o|x-elf|x-msdownload|java-archive|x-msi/.test(mime) : false;
      labels["file.mime_type"] = mime;
      labels["file.source"] = str(r["source"]);
      labels["file.analyzers"] = strArr(r["analyzers"]).join(",") || undefined;
      labels["file.sha1"] = sha1;
      labels["file.executable"] = executable || undefined;
      labels["zeek.fuid"] = fuid;
      const dir = inferDirection(src, dst);
      return {
        ...base,
        category: "file",
        eventType: "zeek.files",
        action: "file-transfer",
        file: { name: str(r["filename"]), sha256, md5, size: uint(r["total_bytes"]) ?? uint(r["seen_bytes"]) },
        network: { srcIp: src, dstIp: dst, protocol: str(r["source"])?.toLowerCase(), direction: dir },
        indicators: obs.toArray(),
        severity: executable && dir === "inbound" ? "low" : "info",
        labels: { ...labels, severity_basis: executable && dir === "inbound" ? "executable file transferred from outside" : undefined },
        dedupKey: fuid ? `files:${fuid}` : undefined,
      };
    }
    case "notice": {
      const note = str(r["note"]) ?? "Notice::Unknown";
      const spec = noticeSpec(note);
      const src = str(r["src"]) ?? ep.srcIp;
      const dst = str(r["dst"]) ?? ep.dstIp;
      obs.add("ip", src).add("ip", dst);
      const attack: AttackTechnique[] = [];
      if (spec.attack) {
        const t = technique(spec.attack);
        if (t) attack.push(t);
      }
      labels["zeek.notice_sub"] = str(r["sub"]);
      labels["zeek.notice_actions"] = strArr(r["actions"]).join(",") || undefined;
      labels["severity_basis"] = `zeek notice ${note}`;
      return {
        ...base,
        category: "detection",
        eventType: "zeek.notice",
        action: note,
        message: str(r["msg"]) ?? note,
        network: { srcIp: src, srcPort: ep.srcPort, dstIp: dst, dstPort: port(r["p"]) ?? ep.dstPort, protocol: str(r["proto"])?.toLowerCase(), direction: inferDirection(src, dst) },
        indicators: obs.toArray(),
        severity: spec.severity,
        detection: { ruleId: note, ruleName: str(r["msg"]) ?? note, engine: "zeek" },
        attack,
        labels,
        dedupKey: `notice:${uid ?? str(r["fuid"]) ?? ""}:${note}:${str(r["ts"]) ?? ""}:${src ?? ""}`,
      };
    }
  }
}

export function createZeekAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    ...extras,
    key: "zeek",
    version: ZEEK_ADAPTER_VERSION,
    name: "Zeek network logs",
    sourceKind: "network",
    vendor: "Zeek Project",
    consumes: ["conn.log", "dns.log", "http.log", "ssl.log", "files.log", "notice.log (JSON / JSON Lines)"],
    map: mapZeek,
  });
}

