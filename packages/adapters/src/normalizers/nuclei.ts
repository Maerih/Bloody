import { techniquesInText } from "../core/attack.js";
import { defineAdapter, skip, type Adapter, type AdapterExtras, type MapOutput } from "../core/adapter.js";
import { ObservableSet, isCve } from "../core/indicators.js";
import { isRecord, num, omitKeys, port, rec, str, strArr } from "../core/json.js";
import { severityFromCvss, severityFromWord } from "../core/severity.js";
import { toIso } from "../core/time.js";
import { isIp } from "../net/ip.js";

/**
 * Nuclei adapter — consumes `nuclei -jsonl` findings (one result per line), including the
 * `info.classification` block (CVE/CWE ids, CVSS, EPSS). Each finding is an exposure on an
 * asset Bloody scanned (authorized, in-scope targets only).
 *
 * Request/response bodies and the curl reproduction are never retained — they routinely
 * contain session cookies or tokens of the scanned application.
 */
export const NUCLEI_ADAPTER_VERSION = "1.0.0";

const DROP_FROM_RAW: ReadonlySet<string> = new Set(["request", "response", "curl-command", "interaction"]);

function hostOf(value: string | undefined): { host?: string; scheme?: string } {
  if (!value) return {};
  try {
    const u = new URL(value.includes("://") ? value : `tcp://${value}`);
    return { host: u.hostname.replace(/^\[|\]$/g, ""), scheme: u.protocol.replace(/:$/, "") };
  } catch {
    return { host: value };
  }
}

function mapNuclei(record: unknown): MapOutput {
  if (!isRecord(record)) return skip("not a JSON object");
  const templateId = str(record["template-id"]) ?? str(record["templateID"]);
  const info = rec(record["info"]);
  if (!templateId || !info) return skip("not a Nuclei finding (template-id/info missing)");
  const classification = rec(info["classification"]);
  const cves = strArr(classification?.["cve-id"]).map((c) => c.toUpperCase()).filter(isCve);
  const cvssScore = num(classification?.["cvss-score"]);
  const word = str(info["severity"]);
  const severity = severityFromWord(word) ?? severityFromCvss(cvssScore) ?? "info";
  const matchedAt = str(record["matched-at"]) ?? str(record["matched"]);
  const hostField = str(record["host"]);
  const { host, scheme } = hostOf(hostField ?? matchedAt);
  const ip = str(record["ip"]);
  const type = str(record["type"]);
  const tags = strArr(info["tags"]).flatMap((t) => t.split(","));
  const obs = new ObservableSet();
  for (const c of cves) obs.add("cve", c);
  const isHttp = type === "http" || scheme === "http" || scheme === "https";
  const name = str(info["name"]) ?? templateId;
  const ts = toIso(record["timestamp"]);
  return {
    timestamp: ts,
    category: "vulnerability",
    eventType: cves.length > 0 ? "nuclei.vulnerability" : "nuclei.exposure",
    action: str(record["matcher-name"]) ?? "matched",
    message: `${name} at ${matchedAt ?? hostField ?? "target"}`,
    severity,
    asset: {
      hostname: host && !isIp(host) ? host : undefined,
      ip: ip ? [ip] : host && isIp(host) ? [host] : undefined,
    },
    network: {
      dstIp: ip ?? (host && isIp(host) ? host : undefined),
      dstPort: port(record["port"]),
      protocol: isHttp ? scheme ?? "http" : type,
      httpHost: isHttp && host ? host : undefined,
      httpUrl: isHttp ? matchedAt : undefined,
      direction: "inbound",
    },
    indicators: obs.toArray(),
    detection: { ruleId: templateId, ruleName: name, engine: "nuclei", confidence: record["matcher-status"] === false ? 0.3 : 0.9 },
    attack: techniquesInText(tags),
    labels: {
      severity_basis: word ? `nuclei template severity ${word}` : `cvss ${cvssScore ?? "n/a"}`,
      "nuclei.template": str(record["template"]) ?? str(record["template-path"]),
      "nuclei.type": type,
      "nuclei.matcher": str(record["matcher-name"]),
      "nuclei.extracted": strArr(record["extracted-results"]).slice(0, 5).join(" | ") || undefined,
      "nuclei.tags": tags.join(",") || undefined,
      "vuln.cve": cves.join(",") || undefined,
      "vuln.cwe": strArr(classification?.["cwe-id"]).join(",").toUpperCase() || undefined,
      "vuln.cvss": cvssScore,
      "vuln.cvss_vector": str(classification?.["cvss-metrics"]),
      "vuln.epss": num(classification?.["epss-score"]),
      "vuln.epss_percentile": num(classification?.["epss-percentile"]),
      "vuln.cpe": str(classification?.["cpe"]),
      "vuln.remediation": str(info["remediation"]),
      internet_facing: true,
    },
    dedupKey: `${templateId}|${matchedAt ?? hostField ?? ""}|${str(record["matcher-name"]) ?? ""}|${ts ?? ""}`,
    raw: omitKeys(record, DROP_FROM_RAW),
  };
}

export function createNucleiAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    ...extras,
    key: "nuclei",
    version: NUCLEI_ADAPTER_VERSION,
    name: "Nuclei exposure findings",
    sourceKind: "vuln_scanner",
    vendor: "ProjectDiscovery",
    consumes: ["nuclei -jsonl findings (template-id, info.classification, matched-at)"],
    map: mapNuclei,
  });
}
