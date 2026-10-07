import type { AttackTechnique, Severity } from "@bloody/contracts";
import { technique } from "../core/attack.js";
import { defineAdapter, type Adapter, type AdapterExtras, skip, type EventDraft, type MapOutput } from "../core/adapter.js";
import { ObservableSet } from "../core/indicators.js";
import { arr, bool, field, int, isRecord, omitKeys, port, rec, redactKeys, str, strArr, uint, type JsonRecord } from "../core/json.js";
import { atLeast, isSensitiveKey, severityFromWord } from "../core/severity.js";
import { toIso } from "../core/time.js";
import { inferDirection, isIp } from "../net/ip.js";

/**
 * Suricata adapter — consumes EVE JSON (`eve.json` lines, Redis/Kafka EVE output).
 * Supported event types: alert, dns, http, tls, flow, fileinfo. Sensor statistics (`stats`)
 * and other app-layer types are reported as skipped.
 *
 *   alert.severity 1/2/3/4 → high/medium/low/info, raised by metadata.signature_severity
 *   ("Critical" → critical, "Major" → high); metadata.mitre_technique_id → attack[].
 */
export const SURICATA_ADAPTER_VERSION = "1.0.0";

export function suricataSeverity(alertSeverity: number | undefined, signatureSeverity?: string): Severity {
  let sev: Severity = alertSeverity === 1 ? "high" : alertSeverity === 2 ? "medium" : alertSeverity === 3 ? "low" : "info";
  const word = signatureSeverity?.toLowerCase();
  if (word === "critical") sev = "critical";
  else if (word === "major") sev = atLeast(sev, "high");
  else if (word) sev = atLeast(sev, severityFromWord(word));
  return sev;
}

function attackFromMetadata(meta: JsonRecord | undefined): AttackTechnique[] {
  if (!meta) return [];
  const ids = strArr(meta["mitre_technique_id"]);
  const names = strArr(meta["mitre_technique_name"]);
  const tactics = strArr(meta["mitre_tactic_name"]);
  const out: AttackTechnique[] = [];
  ids.forEach((id, i) => {
    const t = technique(id, names[i]?.replace(/_/g, " "), tactics[i] ?? tactics[0]);
    if (t) out.push(t);
  });
  return out;
}

function dnsDetails(dns: JsonRecord | undefined, obs: ObservableSet): { query?: string; rrtype?: string; rcode?: string; type?: string; answers: string[] } {
  if (!dns) return { answers: [] };
  const queries = arr(dns["queries"]).filter(isRecord);
  const query = str(dns["rrname"]) ?? str(queries[0]?.["rrname"]);
  const rrtype = str(dns["rrtype"]) ?? str(queries[0]?.["rrtype"]);
  const answers: string[] = [];
  for (const a of arr(dns["answers"])) {
    if (!isRecord(a)) continue;
    const rdata = str(a["rdata"]);
    if (rdata) answers.push(rdata);
  }
  const grouped = rec(dns["grouped"]);
  if (grouped) for (const v of Object.values(grouped)) answers.push(...strArr(v));
  obs.add("domain", query);
  for (const a of answers) {
    if (isIp(a)) obs.add("ip", a);
    else obs.add("domain", a);
  }
  return { query, rrtype, rcode: str(dns["rcode"]), type: str(dns["type"]), answers: [...new Set(answers)] };
}

function mapEve(record: unknown): MapOutput {
  if (!isRecord(record)) return skip("not a JSON object");
  const r = record;
  const eventType = str(r["event_type"]);
  if (!eventType) return skip("not an EVE record (no event_type)");
  if (!["alert", "dns", "http", "tls", "flow", "fileinfo"].includes(eventType)) return skip(`EVE event_type "${eventType}" is not modelled`);

  const srcIp = str(r["src_ip"]);
  const dstIp = str(r["dest_ip"]);
  const appProto = str(r["app_proto"]);
  const flowId = str(r["flow_id"]);
  const obs = new ObservableSet().add("ip", srcIp).add("ip", dstIp);
  const labels: Record<string, string | number | boolean | undefined> = {
    "suricata.flow_id": flowId,
    "suricata.community_id": str(r["community_id"]),
    "suricata.in_iface": str(r["in_iface"]),
    "suricata.app_proto": appProto,
    "suricata.transport": str(r["proto"])?.toLowerCase(),
  };
  const network: NonNullable<EventDraft["network"]> = {
    srcIp,
    srcPort: port(r["src_port"]),
    dstIp,
    dstPort: port(r["dest_port"]),
    protocol: (appProto && appProto !== "failed" ? appProto : str(r["proto"]))?.toLowerCase(),
    direction: inferDirection(srcIp, dstIp),
  };
  const sensor = str(r["host"]) ?? str(r["sensor_name"]);
  const base: Pick<EventDraft, "timestamp" | "raw" | "source"> = {
    timestamp: toIso(r["timestamp"]),
    raw: r,
    ...(sensor ? { source: { sensorId: sensor } } : {}),
  };

  // App-layer details are present on their own event types and, when enabled, on alerts.
  const http = rec(r["http"]);
  const tls = rec(r["tls"]);
  const dns = dnsDetails(rec(r["dns"]), obs);
  if (http) {
    const host = str(http["hostname"]);
    const path = str(http["url"]);
    const url = host && path ? (/^https?:\/\//i.test(path) ? path : `http://${host}${path.startsWith("/") ? path : `/${path}`}`) : undefined;
    network.httpHost = host;
    network.httpUrl = url ?? path;
    obs.addHost(host).add("url", url).add("user_agent", str(http["http_user_agent"]));
    labels["http.method"] = str(http["http_method"]);
    labels["http.status"] = int(http["status"]);
    labels["http.user_agent"] = str(http["http_user_agent"]);
    labels["http.content_type"] = str(http["http_content_type"]);
    labels["http.length"] = uint(http["length"]);
  }
  if (tls) {
    const sni = str(tls["sni"]);
    const ja3 = str(field(tls, "ja3.hash"));
    network.tlsSni = sni;
    network.ja3 = ja3;
    obs.add("domain", sni).add("ja3", ja3);
    labels["tls.version"] = str(tls["version"]);
    labels["tls.subject"] = str(tls["subject"]);
    labels["tls.issuer"] = str(tls["issuerdn"]);
    labels["tls.fingerprint"] = str(tls["fingerprint"]);
    labels["tls.ja3s"] = str(field(tls, "ja3s.hash"));
  }
  if (dns.query) {
    network.dnsQuery = dns.query;
    labels["dns.rrtype"] = dns.rrtype;
    labels["dns.rcode"] = dns.rcode;
    labels["dns.answers"] = dns.answers.slice(0, 20).join(",") || undefined;
  }

  switch (eventType) {
    case "alert": {
      const alert = rec(r["alert"]) ?? {};
      const meta = rec(alert["metadata"]);
      const sid = str(alert["signature_id"]);
      const signature = str(alert["signature"]);
      const sigSev = strArr(meta?.["signature_severity"])[0];
      const action = str(alert["action"]);
      labels["severity_basis"] = `suricata alert.severity ${int(alert["severity"]) ?? "?"}${sigSev ? ` / signature_severity ${sigSev}` : ""}`;
      labels["suricata.category"] = str(alert["category"]);
      labels["suricata.gid"] = int(alert["gid"]);
      labels["suricata.rev"] = int(alert["rev"]);
      labels["suricata.action"] = action;
      labels["suricata.attack_target"] = strArr(meta?.["attack_target"])[0];
      return {
        ...base,
        category: "detection",
        eventType: "suricata.alert",
        action: action === "blocked" ? "blocked" : "alerted",
        outcome: action === "blocked" ? "failure" : "unknown",
        message: signature,
        network,
        indicators: obs.toArray(),
        severity: suricataSeverity(int(alert["severity"]), sigSev),
        detection: { ruleId: sid, ruleName: signature, engine: "suricata" },
        attack: attackFromMetadata(meta),
        labels,
        dedupKey: `alert:${flowId ?? ""}:${sid ?? ""}:${str(r["timestamp"]) ?? ""}:${str(r["tx_id"]) ?? ""}`,
      };
    }
    case "dns":
      return {
        ...base,
        category: "dns",
        eventType: "suricata.dns",
        action: dns.type === "answer" || dns.type === "response" ? "dns-answer" : "dns-query",
        outcome: dns.rcode === undefined ? "unknown" : dns.rcode === "NOERROR" ? "success" : "failure",
        network: { ...network, protocol: "dns" },
        indicators: obs.toArray(),
        severity: "info",
        labels,
        dedupKey: `dns:${flowId ?? ""}:${str(field(r, "dns.id")) ?? ""}:${dns.type ?? ""}:${dns.query ?? ""}:${str(r["timestamp"]) ?? ""}`,
      };
    case "http": {
      const status = int(http?.["status"]);
      return {
        ...base,
        category: "http",
        eventType: "suricata.http",
        action: str(http?.["http_method"])?.toLowerCase(),
        outcome: status === undefined ? "unknown" : status < 400 ? "success" : "failure",
        network: { ...network, protocol: "http" },
        indicators: obs.toArray(),
        severity: "info",
        labels,
        dedupKey: `http:${flowId ?? ""}:${str(r["tx_id"]) ?? ""}`,
      };
    }
    case "tls":
      return {
        ...base,
        category: "tls",
        eventType: "suricata.tls",
        action: "tls-handshake",
        network: { ...network, protocol: "tls" },
        indicators: obs.toArray(),
        severity: "info",
        labels,
        dedupKey: `tls:${flowId ?? ""}:${str(r["timestamp"]) ?? ""}`,
      };
    case "flow": {
      const flow = rec(r["flow"]) ?? {};
      const state = str(flow["state"]);
      labels["flow.state"] = state;
      labels["flow.reason"] = str(flow["reason"]);
      labels["flow.age"] = uint(flow["age"]);
      labels["flow.alerted"] = bool(flow["alerted"]);
      labels["flow.pkts_toserver"] = uint(flow["pkts_toserver"]);
      labels["flow.pkts_toclient"] = uint(flow["pkts_toclient"]);
      return {
        ...base,
        timestamp: toIso(flow["start"]) ?? base.timestamp,
        category: "network",
        eventType: "suricata.flow",
        action: "connection",
        outcome: state === "established" || state === "closed" ? "success" : state === "new" ? "failure" : "unknown",
        network: { ...network, bytesOut: uint(flow["bytes_toserver"]), bytesIn: uint(flow["bytes_toclient"]) },
        indicators: obs.toArray(),
        severity: "info",
        labels,
        dedupKey: `flow:${flowId ?? ""}`,
      };
    }
    case "fileinfo": {
      const fi = rec(r["fileinfo"]) ?? {};
      const sha256 = str(fi["sha256"]);
      const md5 = str(fi["md5"]);
      obs.addHash(sha256).addHash(md5).addHash(str(fi["sha1"]));
      labels["file.magic"] = str(fi["magic"]);
      labels["file.state"] = str(fi["state"]);
      labels["file.stored"] = bool(fi["stored"]);
      labels["file.sha1"] = str(fi["sha1"]);
      const executable = /PE32|ELF|Mach-O|MS-DOS executable/i.test(str(fi["magic"]) ?? "");
      return {
        ...base,
        category: "file",
        eventType: "suricata.fileinfo",
        action: "file-transfer",
        file: { name: str(fi["filename"]), sha256, md5, size: uint(fi["size"]) },
        network,
        indicators: obs.toArray(),
        // executable crossing the perimeter (EVE direction semantics vary per app-layer)
        severity: executable && (network.direction === "outbound" || network.direction === "inbound") ? "low" : "info",
        labels,
        dedupKey: `fileinfo:${flowId ?? ""}:${str(fi["tx_id"]) ?? ""}:${str(fi["filename"]) ?? ""}`,
      };
    }
    default:
      return skip(`EVE event_type "${eventType}" is not modelled`);
  }
}

export function createSuricataAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    ...extras,
    key: "suricata",
    version: SURICATA_ADAPTER_VERSION,
    name: "Suricata EVE JSON",
    sourceKind: "network",
    vendor: "OISF",
    consumes: ["EVE JSON: alert, dns (v2/v3), http, tls, flow, fileinfo"],
    map: mapEve,
    // Header dumps and payload captures can carry cookies/credentials: never retained.
    redactRaw: (r) => redactKeys(omitKeys(r, new Set(["request_headers", "response_headers", "payload", "payload_printable", "packet", "http_request_body", "http_response_body"])), isSensitiveKey),
  });
}
