import type { EventCategory, Severity } from "@bloody/contracts";
import { technique } from "../core/attack.js";
import { defineAdapter, skip, type Adapter, type AdapterExtras, type EventDraft, type MapContext, type MapOutput } from "../core/adapter.js";
import { canonicalJson, sha256Hex } from "../core/hash.js";
import { ObservableSet, hashType } from "../core/indicators.js";
import { basename, int, port, uint } from "../core/json.js";
import { textRecords } from "../core/records.js";
import { severityFromWord } from "../core/severity.js";
import { toIso } from "../core/time.js";
import { inferDirection, isIp } from "../net/ip.js";

/**
 * Generic syslog (RFC 5424 / RFC 3164) and ArcSight CEF parsers.
 *
 * Two adapters share the parsers: `syslog` (any syslog line; CEF payloads inside syslog are
 * detected and mapped as CEF) and `cef` (CEF lines with or without a syslog header). Common
 * Linux auth messages (sshd, sudo, su, pam_unix) get authentication/process semantics;
 * everything else becomes a `device` event carrying the message.
 */
export const SYSLOG_ADAPTER_VERSION = "1.0.0";

export interface SyslogMessage {
  format: "rfc5424" | "rfc3164" | "bare";
  facility?: number;
  severity?: number;
  timestamp?: string;
  hostname?: string;
  appName?: string;
  procId?: string;
  msgId?: string;
  structuredData: Record<string, Record<string, string>>;
  message: string;
}

const RFC5424_HEAD = /^<(\d{1,3})>(\d{1,2}) (\S+) (\S+) (\S+) (\S+) (\S+) /;
const RFC3164 = /^(?:<(\d{1,3})>)?((?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)|(?:\d{4}-\d{2}-\d{2}T\S+))\s+(\S+)\s+([^\s:[]+)(?:\[([^\]]*)\])?:\s?([\s\S]*)$/;
const nil = (v: string | undefined): string | undefined => (v === undefined || v === "-" ? undefined : v);

function parseStructuredData(input: string): { sd: Record<string, Record<string, string>>; rest: string } {
  const sd: Record<string, Record<string, string>> = {};
  let i = 0;
  if (input.startsWith("-")) return { sd, rest: input.slice(1).replace(/^ /, "") };
  while (input[i] === "[") {
    let j = i + 1;
    const idEnd = input.slice(j).search(/[ \]]/);
    if (idEnd < 0) break;
    const id = input.slice(j, j + idEnd);
    j += idEnd;
    const params: Record<string, string> = {};
    while (input[j] === " ") {
      j++;
      const eq = input.indexOf("=", j);
      if (eq < 0 || input[eq + 1] !== '"') break;
      const name = input.slice(j, eq);
      let k = eq + 2;
      let value = "";
      while (k < input.length && input[k] !== '"') {
        if (input[k] === "\\" && k + 1 < input.length) {
          value += input[k + 1];
          k += 2;
        } else value += input[k++];
      }
      params[name] = value;
      j = k + 1;
    }
    if (input[j] !== "]") break;
    sd[id] = params;
    i = j + 1;
  }
  return { sd, rest: input.slice(i).replace(/^ /, "") };
}

export function parseSyslog(line: string, reference?: Date): SyslogMessage {
  const trimmed = line.replace(/\r?\n$/, "");
  const m5 = RFC5424_HEAD.exec(trimmed);
  if (m5) {
    const pri = Number(m5[1]);
    const { sd, rest } = parseStructuredData(trimmed.slice(m5[0].length));
    return {
      format: "rfc5424",
      facility: pri >> 3,
      severity: pri & 7,
      timestamp: toIso(nil(m5[3])),
      hostname: nil(m5[4]),
      appName: nil(m5[5]),
      procId: nil(m5[6]),
      msgId: nil(m5[7]),
      structuredData: sd,
      message: rest.replace(/^﻿/, ""),
    };
  }
  const m3 = RFC3164.exec(trimmed);
  if (m3) {
    const pri = m3[1] !== undefined ? Number(m3[1]) : undefined;
    return {
      format: "rfc3164",
      ...(pri !== undefined ? { facility: pri >> 3, severity: pri & 7 } : {}),
      timestamp: toIso(m3[2], reference ? { reference } : {}),
      hostname: m3[3],
      appName: m3[4],
      procId: m3[5],
      structuredData: {},
      message: m3[6] ?? "",
    };
  }
  const pri = /^<(\d{1,3})>/.exec(trimmed);
  return {
    format: "bare",
    ...(pri ? { facility: Number(pri[1]) >> 3, severity: Number(pri[1]) & 7 } : {}),
    structuredData: {},
    message: pri ? trimmed.slice(pri[0].length) : trimmed,
  };
}

// ─── CEF ────────────────────────────────────────────────────────────────────

export interface CefMessage {
  version: number;
  vendor: string;
  product: string;
  productVersion: string;
  signatureId: string;
  name: string;
  severity: string;
  extensions: Record<string, string>;
}

function unescapeCefHeader(s: string): string {
  return s.replace(/\\([|\\])/g, "$1");
}

function unescapeCefValue(s: string): string {
  return s.replace(/\\(.)/g, (_m, c: string) => (c === "n" ? "\n" : c === "r" ? "\r" : c));
}

/** Parse "CEF:0|vendor|product|version|sigid|name|severity|k=v k2=v with spaces". */
export function parseCef(input: string): CefMessage | undefined {
  const start = input.indexOf("CEF:");
  if (start < 0) return undefined;
  const s = input.slice(start + 4);
  const header: string[] = [];
  let cur = "";
  let i = 0;
  for (; i < s.length && header.length < 7; i++) {
    const c = s[i];
    if (c === "\\" && i + 1 < s.length) {
      cur += c + s[i + 1];
      i++;
    } else if (c === "|") {
      header.push(unescapeCefHeader(cur));
      cur = "";
    } else cur += c;
  }
  if (header.length < 7) return undefined;
  const ext = s.slice(i);
  const extensions: Record<string, string> = {};
  // keys are matched where an unescaped "key=" begins; values run until the next key
  const keyRe = /(?:^|\s)([A-Za-z0-9_.[\]-]+)=/g;
  const positions: Array<{ key: string; start: number; valueStart: number }> = [];
  for (const m of ext.matchAll(keyRe)) {
    const at = m.index ?? 0;
    if (at > 0 && ext[at - 1] === "\\") continue;
    const keyStart = at + (m[0].length - m[1]!.length - 1);
    if (keyStart > 0 && ext[keyStart - 1] === "\\") continue;
    positions.push({ key: m[1]!, start: at, valueStart: at + m[0].length });
  }
  positions.forEach((p, idx) => {
    const end = idx + 1 < positions.length ? positions[idx + 1]!.start : ext.length;
    extensions[p.key] = unescapeCefValue(ext.slice(p.valueStart, end).trim());
  });
  const version = Number.parseInt((header[0] ?? "0").trim(), 10);
  return {
    version: Number.isFinite(version) ? version : 0,
    vendor: header[1] ?? "",
    product: header[2] ?? "",
    productVersion: header[3] ?? "",
    signatureId: header[4] ?? "",
    name: header[5] ?? "",
    severity: (header[6] ?? "").trim(),
    extensions,
  };
}

export function cefSeverity(value: string): Severity {
  const n = Number(value);
  if (value !== "" && Number.isFinite(n)) {
    if (n >= 9) return "critical";
    if (n >= 7) return "high";
    if (n >= 4) return "medium";
    if (n >= 1) return "low";
    return "info";
  }
  return severityFromWord(value) ?? "info";
}

const slug = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "") || "unknown";

function cefDraft(cef: CefMessage, sys: SyslogMessage | undefined, line: string, reference: Date): EventDraft {
  const e = (k: string): string | undefined => {
    const v = cef.extensions[k];
    return v === undefined || v === "" ? undefined : v;
  };
  const src = e("src") ?? e("sourceTranslatedAddress");
  const dst = e("dst") ?? e("destinationTranslatedAddress");
  const severity = cefSeverity(cef.severity);
  const obs = new ObservableSet().add("ip", src).add("ip", dst);
  const request = e("request");
  if (request && /^https?:\/\//i.test(request)) obs.add("url", request);
  obs.addHost(e("dhost") && !isIp(e("dhost") ?? "") ? e("dhost") : undefined);
  obs.add("domain", e("destinationDnsDomain"));
  const fileHash = e("fileHash");
  if (fileHash && hashType(fileHash)) obs.addHash(fileHash);
  const outcome = (e("outcome") ?? "").toLowerCase();
  const authLike = /auth|logon|login|sign[- ]?in/i.test(`${e("cat") ?? ""} ${cef.name}`);
  let category: EventCategory;
  if (authLike) category = "authentication";
  else if (request) category = "http";
  else if (e("fname") || e("filePath")) category = "file";
  else if (e("destinationDnsDomain")) category = "dns";
  else if ((src || dst) && severity !== "medium" && severity !== "high" && severity !== "critical") category = "network";
  else category = "detection";

  const labels: Record<string, string | number | boolean | undefined> = {
    severity_basis: `cef severity ${cef.severity || "unknown"}`,
    "cef.vendor": cef.vendor,
    "cef.product": cef.product,
    "cef.product_version": cef.productVersion,
    "cef.signature_id": cef.signatureId,
    "cef.category": e("cat"),
    "cef.external_id": e("externalId"),
    "cef.device_action": e("act"),
    "cef.source_host": e("shost"),
    "cef.destination_host": e("dhost"),
    "cef.app": e("app"),
  };
  for (let n = 1; n <= 6; n++) {
    const v = e(`cs${n}`);
    if (v !== undefined) labels[`cef.${slug(e(`cs${n}Label`) ?? `cs${n}`)}`] = v;
  }
  for (let n = 1; n <= 3; n++) {
    const v = e(`cn${n}`);
    if (v !== undefined) labels[`cef.${slug(e(`cn${n}Label`) ?? `cn${n}`)}`] = v;
  }
  const direction = e("deviceDirection") === "0" ? "inbound" : e("deviceDirection") === "1" ? "outbound" : inferDirection(src, dst);
  const ts = toIso(e("rt"), { reference }) ?? toIso(e("end"), { reference }) ?? toIso(e("start"), { reference }) ?? sys?.timestamp;
  const user = e("duser") ?? e("suser");
  const procPath = e("sproc") ?? e("dproc");
  const fpath = e("filePath") ?? e("fname");
  return {
    timestamp: ts,
    category,
    eventType: `cef.${slug(cef.vendor)}.${slug(cef.product)}`,
    action: e("act") ?? e("requestMethod")?.toLowerCase(),
    outcome: /^(success|allow|accept|permit)/.test(outcome) ? "success" : /^(fail|deny|denied|block|drop|reject)/.test(outcome) ? "failure" : authLike ? "unknown" : undefined,
    message: e("msg") ?? cef.name,
    severity,
    asset: { hostname: e("dvchost") ?? sys?.hostname, ip: e("dvc") ? [e("dvc")!] : undefined, mac: e("dvcmac") ? [e("dvcmac")!] : undefined },
    user: user ? { name: user, domain: e("dntdom") ?? e("sntdom") } : undefined,
    identity: authLike ? { provider: slug(cef.product), principal: user, sourceIp: src, outcome: /^(success|allow)/.test(outcome) ? "success" : /^(fail|deny)/.test(outcome) ? "failure" : "unknown" } : undefined,
    process: procPath || e("spid") || e("dpid") ? { name: basename(procPath), path: procPath, pid: int(e("spid") ?? e("dpid")) } : undefined,
    file: fpath ? { path: fpath, name: e("fname") ?? basename(fpath), size: uint(e("fsize")), sha256: fileHash && hashType(fileHash) === "sha256" ? fileHash.toLowerCase() : undefined } : undefined,
    network:
      src || dst || request
        ? {
            srcIp: src,
            srcPort: port(e("spt")),
            dstIp: dst,
            dstPort: port(e("dpt")),
            protocol: e("app")?.toLowerCase() ?? e("proto")?.toLowerCase(),
            direction,
            bytesIn: uint(e("in")),
            bytesOut: uint(e("out")),
            httpUrl: request,
            dnsQuery: e("destinationDnsDomain"),
          }
        : undefined,
    indicators: obs.toArray(),
    detection: { ruleId: cef.signatureId || undefined, ruleName: cef.name || undefined, engine: slug(cef.product) },
    attack: [],
    labels,
    source: { product: slug(cef.product), vendor: cef.vendor || undefined },
    dedupKey: e("externalId") ? `cef:${cef.vendor}:${cef.product}:${e("externalId")}` : `cef:${sha256Hex(line).slice(0, 32)}`,
    raw: { syslog: sys ? { hostname: sys.hostname, appName: sys.appName, timestamp: sys.timestamp } : undefined, cef: { ...cef } },
  };
}

// ─── Linux auth heuristics ──────────────────────────────────────────────────

interface AuthMatch {
  outcome: "success" | "failure";
  user?: string;
  srcIp?: string;
  srcPort?: number;
  method?: string;
  privileged?: boolean;
  command?: string;
  kind: "ssh" | "sudo" | "su" | "pam";
}

export function matchLinuxAuth(app: string | undefined, msg: string): AuthMatch | undefined {
  const a = (app ?? "").toLowerCase();
  let m = /^Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)/.exec(msg);
  if (m) return { kind: "ssh", outcome: "failure", method: m[1], user: m[2], srcIp: m[3], srcPort: Number(m[4]) };
  m = /^Accepted (\S+) for (\S+) from (\S+) port (\d+)/.exec(msg);
  if (m) return { kind: "ssh", outcome: "success", method: m[1], user: m[2], srcIp: m[3], srcPort: Number(m[4]) };
  m = /^Invalid user (\S*) from (\S+)(?: port (\d+))?/.exec(msg);
  if (m) return { kind: "ssh", outcome: "failure", user: m[1] || undefined, srcIp: m[2], ...(m[3] ? { srcPort: Number(m[3]) } : {}) };
  if (a === "sudo") {
    m = /^\s*(\S+) : .*?(?:USER=(\S+) ;)?.*COMMAND=(.*)$/.exec(msg);
    if (m) return { kind: "sudo", outcome: /incorrect password|NOT in sudoers|authentication failure/i.test(msg) ? "failure" : "success", user: m[1], privileged: true, command: m[3]?.trim() };
  }
  m = /^FAILED su for (\S+) by (\S+)/.exec(msg) ?? /^'su (\S+)' failed for (\S+)/.exec(msg);
  if (m) return { kind: "su", outcome: "failure", user: m[2], privileged: true };
  m = /pam_unix\([^)]*\): authentication failure;.*?rhost=(\S*).*?user=(\S+)/.exec(msg);
  if (m) return { kind: "pam", outcome: "failure", user: m[2], srcIp: m[1] || undefined };
  return undefined;
}

function syslogSeverity(sev: number | undefined): Severity {
  if (sev === undefined) return "info";
  if (sev <= 1) return "medium";
  if (sev <= 3) return "low";
  return "info";
}

function syslogDraft(sys: SyslogMessage, line: string): EventDraft {
  const auth = matchLinuxAuth(sys.appName, sys.message);
  const labels: Record<string, string | number | boolean | undefined> = {
    "syslog.format": sys.format,
    "syslog.facility": sys.facility,
    "syslog.severity": sys.severity,
    "syslog.app": sys.appName,
    "syslog.procid": sys.procId,
    "syslog.msgid": sys.msgId,
    severity_basis: `syslog severity ${sys.severity ?? "n/a"}`,
  };
  for (const [id, params] of Object.entries(sys.structuredData)) {
    for (const [k, v] of Object.entries(params)) labels[`sd.${id}.${k}`] = v;
  }
  const base: EventDraft = {
    timestamp: sys.timestamp,
    category: "device",
    eventType: `syslog.${slug(sys.appName ?? "message")}`,
    message: sys.message,
    severity: syslogSeverity(sys.severity),
    asset: { hostname: sys.hostname },
    labels,
    dedupKey: `syslog:${sha256Hex(canonicalJson([sys.hostname, sys.timestamp, sys.appName, sys.procId, sys.message])).slice(0, 32)}`,
    raw: line,
  };
  if (!auth) return base;
  const obs = new ObservableSet().add("ip", auth.srcIp);
  const failure = auth.outcome === "failure";
  if (auth.kind === "sudo" && !failure) {
    return {
      ...base,
      category: "process",
      eventType: "syslog.sudo_command",
      action: "sudo",
      outcome: "success",
      user: auth.user ? { name: auth.user } : undefined,
      process: { commandLine: auth.command, user: auth.user, name: basename(auth.command?.split(/\s+/)[0]) },
      identity: { provider: "host", principal: auth.user, privileged: true, outcome: "success" },
      labels: { ...labels, severity_basis: "privileged command execution via sudo" },
    };
  }
  const t = failure ? technique("T1110") : undefined;
  return {
    ...base,
    category: "authentication",
    eventType: `syslog.${auth.kind}_${failure ? "auth_failure" : "auth_success"}`,
    action: auth.kind === "ssh" ? `ssh-${auth.method ?? "login"}` : auth.kind,
    outcome: auth.outcome,
    severity: failure ? "low" : "info",
    user: auth.user ? { name: auth.user } : undefined,
    identity: { provider: auth.kind === "ssh" ? "ssh" : "host", principal: auth.user, sourceIp: auth.srcIp, privileged: auth.privileged, outcome: auth.outcome },
    network: auth.srcIp ? { srcIp: auth.srcIp, srcPort: auth.srcPort, protocol: auth.kind === "ssh" ? "ssh" : undefined } : undefined,
    indicators: obs.toArray(),
    attack: t ? [t] : [],
    labels: { ...labels, severity_basis: failure ? "authentication failure" : labels["severity_basis"] },
  };
}

function mapLine(mode: "syslog" | "cef") {
  return (record: unknown, ctx: MapContext): MapOutput => {
    if (typeof record !== "string") return skip("not a text line");
    const line = record.trim();
    if (line === "") return skip("empty line");
    const cefAt = line.indexOf("CEF:");
    if (cefAt >= 0) {
      const cef = parseCef(line.slice(cefAt));
      if (cef) {
        // A syslog header in front of the CEF payload supplies host and time.
        const sys = cefAt > 0 ? parseSyslog(line, ctx.receivedDate) : undefined;
        return cefDraft(cef, sys, line, ctx.receivedDate);
      }
      if (mode === "cef") return skip("malformed CEF header");
    } else if (mode === "cef") {
      return skip("line is not CEF");
    }
    return syslogDraft(parseSyslog(line, ctx.receivedDate), line);
  };
}

export function createSyslogAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    ...extras,
    key: "syslog",
    version: SYSLOG_ADAPTER_VERSION,
    name: "Syslog (RFC 5424 / 3164)",
    sourceKind: "custom",
    consumes: ["RFC 5424 and RFC 3164 lines (UDP/TCP/TLS relays, files)", "sshd / sudo / su / pam_unix auth messages", "CEF payloads inside syslog"],
    split: (raw) => textRecords(raw),
    map: mapLine("syslog"),
  });
}

export function createCefAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    ...extras,
    key: "cef",
    version: SYSLOG_ADAPTER_VERSION,
    name: "ArcSight Common Event Format",
    sourceKind: "custom",
    consumes: ["CEF:0/1 lines, with or without syslog header"],
    split: (raw) => textRecords(raw),
    map: mapLine("cef"),
  });
}
