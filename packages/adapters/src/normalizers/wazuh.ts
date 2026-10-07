import type { AttackTechnique, EventCategory, Severity } from "@bloody/contracts";
import { mergeTechniques, technique } from "../core/attack.js";
import { defineAdapter, type Adapter, type AdapterExtras, type EventDraft, type MapOutput } from "../core/adapter.js";
import { ObservableSet } from "../core/indicators.js";
import { basename, field, int, num, port, rec, redactKeys, str, strArr, uint, type JsonRecord } from "../core/json.js";
import { atLeast, isSensitiveKey, severityFromCvss, severityFromWord } from "../core/severity.js";
import { toIso } from "../core/time.js";
import { inferDirection } from "../net/ip.js";
import { mapWindowsEvent } from "./windows.js";

/**
 * Wazuh adapter — consumes manager alerts (`alerts.json` lines, the indexer
 * `wazuh-alerts-*` documents, or Integrator/webhook payloads; all share the alert schema).
 *
 * Mapping (written from Wazuh's documented alert fields):
 *   rule.level 0-15      → severity (0-2 info · 3-6 low · 7-9 medium · 10-12 high · 13-15 critical)
 *   rule.mitre.id[]      → attack[] (names/tactics from rule.mitre.technique/tactic)
 *   agent.{id,name,ip}   → asset (agentId, hostname, ip)
 *   syscheck.*           → file (path, action, sha256/md5, size) — registry FIM → registry
 *   data.win.*           → Windows Security / Sysmon semantics (process, user, network…)
 *   data.srcip/dstuser…  → network / user / identity for auth and IDS decoders
 *   data.vulnerability.* → vulnerability (CVE indicator, CVSS, package)
 */
export const WAZUH_ADAPTER_VERSION = "1.0.0";

export function wazuhLevelToSeverity(level: number | undefined): Severity {
  if (level === undefined) return "info";
  if (level >= 13) return "critical";
  if (level >= 10) return "high";
  if (level >= 7) return "medium";
  if (level >= 3) return "low";
  return "info";
}

const SYSCHECK_ACTION: Record<string, "create" | "modify" | "delete" | "rename"> = {
  added: "create",
  modified: "modify",
  deleted: "delete",
  renamed: "rename",
};

const AUTH_SUCCESS_GROUPS = ["authentication_success"];
const AUTH_FAILURE_GROUPS = ["authentication_failed", "authentication_failures", "invalid_login", "win_authentication_failed"];

function mitre(rule: unknown): AttackTechnique[] {
  const ids = strArr(field(rule, "mitre.id"));
  const names = strArr(field(rule, "mitre.technique"));
  const tactics = strArr(field(rule, "mitre.tactic"));
  const out: AttackTechnique[] = [];
  ids.forEach((id, i) => {
    // Wazuh lists tactics per rule, not per technique; use the positional tactic when the
    // arrays line up, otherwise the curated table decides.
    const t = technique(id, names[i], ids.length === tactics.length ? tactics[i] : undefined);
    if (t) out.push(t);
  });
  return out;
}

/** auditd EXECVE record ({a0, a1, …}) → command line. */
function auditArgv(execve: JsonRecord | undefined): string | undefined {
  if (!execve) return undefined;
  const args = Object.keys(execve)
    .filter((k) => /^a\d+$/.test(k))
    .sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)))
    .map((k) => str(execve[k]))
    .filter((v): v is string => v !== undefined);
  return args.length > 0 ? args.join(" ") : undefined;
}

function mapAlert(alert: unknown): MapOutput {
  const rule = rec(field(alert, "rule"));
  if (!rule) return { skip: "not a Wazuh alert (no rule)" };
  const level = int(rule["level"]);
  const groups = strArr(rule["groups"]);
  const ruleId = str(rule["id"]);
  const description = str(rule["description"]);
  const data = rec(field(alert, "data")) ?? {};
  const agentId = str(field(alert, "agent.id"));
  const agentName = str(field(alert, "agent.name"));
  const agentIp = str(field(alert, "agent.ip"));
  const location = str(field(alert, "location"));
  const predecoderHost = str(field(alert, "predecoder.hostname"));

  const obs = new ObservableSet();
  let severity = wazuhLevelToSeverity(level);
  let category: EventCategory = "detection";
  let eventType = "wazuh.alert";
  let attack = mitre(rule);
  const labels: Record<string, string | number | boolean | undefined> = {
    "severity_basis": `wazuh rule.level ${level ?? "?"}`,
    "wazuh.rule_groups": groups.join(","),
    "wazuh.decoder": str(field(alert, "decoder.name")),
    "wazuh.location": location,
    "wazuh.manager": str(field(alert, "manager.name")),
    "wazuh.rule_firedtimes": int(rule["firedtimes"]),
    "wazuh.cluster": str(field(alert, "cluster.name")),
  };

  const draft: EventDraft = {
    timestamp: toIso(field(alert, "timestamp")) ?? toIso(field(alert, "@timestamp")),
    category,
    eventType,
    message: description,
    asset: {
      hostname: agentId === "000" && predecoderHost ? predecoderHost : agentName ?? predecoderHost,
      ip: agentIp && agentIp !== "any" ? [agentIp] : undefined,
      agentId,
    },
    detection: { ruleId, ruleName: description, engine: "wazuh" },
    dedupKey: str(field(alert, "id")) ? `${str(field(alert, "manager.name")) ?? ""}:${str(field(alert, "id"))}` : undefined,
    raw: alert,
  };

  // ── Windows Security / Sysmon ─────────────────────────────────────────────
  const win = rec(data["win"]);
  const winMap = win ? mapWindowsEvent(win["system"], win["eventdata"]) : undefined;
  if (winMap) {
    Object.assign(draft, winMap.draft);
    category = winMap.draft.category;
    eventType = winMap.draft.eventType;
    attack = mergeTechniques(attack, winMap.draft.attack ?? []);
    severity = atLeast(severity, winMap.severityFloor);
    for (const o of winMap.draft.indicators ?? []) obs.add(o.type, o.value);
    Object.assign(labels, winMap.draft.labels);
    const computer = str(field(win, "system.computer"));
    if (computer && draft.asset && !draft.asset.hostname) draft.asset.hostname = computer;
  }

  // ── File integrity monitoring ─────────────────────────────────────────────
  const sys = rec(field(alert, "syscheck"));
  if (!winMap && sys) {
    const path = str(sys["path"]);
    const ev = str(sys["event"]) ?? "modified";
    const isRegistry = /^HKEY_/i.test(path ?? "") || str(sys["value_name"]) !== undefined;
    category = isRegistry ? "registry" : "file";
    eventType = `wazuh.fim.${isRegistry ? "registry_" : ""}${ev}`;
    draft.action = ev;
    if (!isRegistry) {
      draft.file = {
        path,
        name: basename(path),
        action: SYSCHECK_ACTION[ev],
        sha256: str(sys["sha256_after"]),
        md5: str(sys["md5_after"]),
        size: uint(sys["size_after"]),
      };
      obs.addHash(str(sys["sha256_after"]));
    } else {
      labels["registry.key"] = path;
      labels["registry.value"] = str(sys["value_name"]);
    }
    labels["fim.changed_attributes"] = strArr(sys["changed_attributes"]).join(",") || undefined;
    labels["fim.owner"] = str(sys["uname_after"]);
    labels["fim.mode"] = str(sys["mode"]);
    const actor = str(field(sys, "audit.user.name")) ?? str(field(sys, "audit.login_user.name"));
    if (actor) draft.user = { name: actor };
    const proc = str(field(sys, "audit.process.name"));
    if (proc) draft.process = { name: basename(proc), path: proc, pid: int(field(sys, "audit.process.id")) };
  }

  // ── Vulnerability detector ────────────────────────────────────────────────
  const vuln = rec(data["vulnerability"]);
  if (!winMap && !sys && vuln) {
    const cve = str(vuln["cve"]);
    category = "vulnerability";
    eventType = "wazuh.vulnerability";
    draft.action = str(vuln["status"])?.toLowerCase();
    const cvss = num(field(vuln, "cvss.cvss3.base_score")) ?? num(field(vuln, "score.base")) ?? num(field(vuln, "cvss.cvss2.base_score"));
    const vs = severityFromWord(str(vuln["severity"])) ?? severityFromCvss(cvss);
    if (vs) {
      severity = vs;
      labels["severity_basis"] = `vulnerability severity ${str(vuln["severity"]) ?? `cvss ${cvss}`}`;
    }
    obs.add("cve", cve);
    draft.message = str(vuln["title"]) ?? (cve ? `${cve} in ${str(field(vuln, "package.name")) ?? "package"}` : description);
    labels["vuln.cve"] = cve;
    labels["vuln.cvss"] = cvss;
    labels["vuln.package"] = str(field(vuln, "package.name"));
    labels["vuln.installed_version"] = str(field(vuln, "package.version"));
    labels["vuln.fixed_version"] = str(field(vuln, "package.condition"));
    labels["vuln.reference"] = str(vuln["reference"]);
  }

  // ── Security configuration assessment ─────────────────────────────────────
  const sca = rec(data["sca"]);
  if (!winMap && !sys && !vuln && sca) {
    category = "configuration";
    eventType = "wazuh.sca";
    draft.outcome = str(field(sca, "check.result")) === "passed" ? "success" : "failure";
    labels["sca.policy"] = str(sca["policy"]);
    labels["sca.check_id"] = str(field(sca, "check.id"));
    labels["sca.check_title"] = str(field(sca, "check.title"));
    labels["sca.result"] = str(field(sca, "check.result"));
  }

  // ── Generic decoders: auth, IDS, web, auditd ──────────────────────────────
  if (!winMap && !sys && !vuln && !sca) {
    const srcIp = str(data["srcip"]);
    const dstIp = str(data["dstip"]);
    const srcUser = str(data["srcuser"]);
    const dstUser = str(data["dstuser"]);
    const isAuthSuccess = groups.some((g) => AUTH_SUCCESS_GROUPS.includes(g));
    const isAuthFailure = groups.some((g) => AUTH_FAILURE_GROUPS.includes(g));
    if (srcIp || dstIp) {
      draft.network = {
        srcIp,
        srcPort: port(data["srcport"]),
        dstIp,
        dstPort: port(data["dstport"]),
        protocol: str(data["protocol"])?.toLowerCase(),
        direction: inferDirection(srcIp, dstIp),
      };
      obs.add("ip", srcIp).add("ip", dstIp);
    }
    if (isAuthSuccess || isAuthFailure) {
      category = "authentication";
      eventType = isAuthFailure ? "wazuh.authentication_failure" : "wazuh.authentication_success";
      draft.outcome = isAuthFailure ? "failure" : "success";
      const principal = dstUser ?? srcUser;
      if (principal) draft.user = { name: principal };
      draft.identity = { provider: groups.includes("sshd") ? "ssh" : str(field(alert, "decoder.name")) ?? "host", principal, sourceIp: srcIp, outcome: draft.outcome };
      if (isAuthFailure && attack.length === 0 && groups.some((g) => /brute|multiple|failures/.test(g))) {
        const t = technique("T1110");
        if (t) attack.push(t);
      }
    } else if (groups.includes("web") || groups.includes("accesslog")) {
      category = "http";
      eventType = "wazuh.web_access";
      const url = str(data["url"]);
      draft.network = { ...draft.network, httpUrl: url };
      labels["http.status"] = str(data["id"]);
      labels["http.method"] = str(data["protocol"]);
    } else if (groups.includes("ids") || groups.includes("suricata")) {
      category = "network";
      eventType = "wazuh.ids";
    } else if (groups.includes("audit") && rec(data["audit"])) {
      const exe = str(field(data, "audit.exe"));
      category = exe ? "process" : "audit";
      eventType = "wazuh.auditd";
      if (exe) draft.process = { name: basename(exe), path: exe, commandLine: auditArgv(rec(field(data, "audit.execve"))) ?? str(field(data, "audit.command")), pid: int(field(data, "audit.pid")) };
      const auid = str(field(data, "audit.auid"));
      labels["audit.auid"] = auid;
      labels["audit.euid"] = str(field(data, "audit.euid"));
      labels["audit.key"] = str(field(data, "audit.key"));
    }
    if (!draft.user && (srcUser || dstUser)) draft.user = { name: dstUser ?? srcUser };
    const url = str(data["url"]);
    if (url && /^https?:\/\//i.test(url)) obs.add("url", url);
    obs.addHash(str(data["sha256"])).addHash(str(data["md5"]));
  }

  draft.category = category;
  draft.eventType = eventType;
  draft.severity = severity;
  draft.attack = attack;
  draft.indicators = obs.toArray();
  draft.labels = labels;
  if (!draft.message) draft.message = description;
  return draft;
}

/** Extras: `actions` from `createWazuhActiveResponse`, `healthCheck` = `wazuhHealthCheck`. */
export function createWazuhAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    ...extras,
    key: "wazuh",
    version: WAZUH_ADAPTER_VERSION,
    name: "Wazuh alerts",
    sourceKind: "endpoint",
    vendor: "Wazuh",
    consumes: [
      "alerts.json / alerts JSON lines",
      "wazuh-alerts-* indexer documents (_source)",
      "Windows Security & Sysmon events (data.win.*)",
      "FIM (syscheck), vulnerability-detector, SCA, auth, web and auditd decoders",
    ],
    map: (record) => {
      // Indexer search hits wrap the alert in _source.
      const src = rec(field(record, "_source"));
      return mapAlert(src ?? record);
    },
    redactRaw: (r) => redactKeys(r, isSensitiveKey),
  });
}

