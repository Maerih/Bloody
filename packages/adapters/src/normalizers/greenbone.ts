import { defineAdapter, skip, type Adapter, type AdapterExtras, type MapContext, type MapOutput } from "../core/adapter.js";
import { ObservableSet, isCve } from "../core/indicators.js";
import { arr, int, isRecord, num, rec, str, type JsonRecord } from "../core/json.js";
import { jsonRecords, payloadToText, type SplitItem } from "../core/records.js";
import { severityFromCvss } from "../core/severity.js";
import { toIso } from "../core/time.js";
import { parseXml, xmlChild, xmlChildren, xmlDescendants, xmlText, type XmlElement } from "../core/xml.js";
import { isIp } from "../net/ip.js";

/**
 * Greenbone / OpenVAS adapter — consumes GMP `get_reports` responses (XML, as returned by
 * gvmd) or a JSON export using the same GMP field names. One event per `<result>`.
 *
 *   severity (CVSS) → severity band · threat "Log" → info · "False Positive" → skipped
 *   nvt/refs/ref[type=cve] → CVE indicators · qod/value → detection confidence
 *   nvt/solution[type] → patch availability (VendorFix)
 *
 * Option `minQod` (default 0) skips low quality-of-detection results (gvmd's UI uses 70).
 */
export const GREENBONE_ADAPTER_VERSION = "1.0.0";

/** Normalized result in GMP field names — the JSON export shape this adapter accepts. */
export interface GreenboneResult {
  id?: string;
  name?: string;
  host?: { ip?: string; hostname?: string; assetId?: string };
  port?: string;
  nvt?: {
    oid?: string;
    name?: string;
    family?: string;
    type?: string;
    cvssBase?: number;
    cvssVector?: string;
    refs?: Array<{ type: string; id: string }>;
    solution?: { type?: string; text?: string };
    tags?: Record<string, string>;
  };
  threat?: string;
  severity?: number;
  qod?: number;
  description?: string;
  creationTime?: string;
  modificationTime?: string;
  reportId?: string;
  taskName?: string;
}

function parseTags(tags: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!tags) return out;
  for (const part of tags.split("|")) {
    const eq = part.indexOf("=");
    if (eq > 0) out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}

/** Convert a GMP `<result>` element into {@link GreenboneResult}. */
export function greenboneResultFromXml(el: XmlElement, report?: { id?: string; taskName?: string }): GreenboneResult {
  const host = xmlChild(el, "host");
  const nvt = xmlChild(el, "nvt");
  const sev = xmlChildren(xmlChild(nvt, "severities"), "severity")[0];
  const solution = xmlChild(nvt, "solution");
  const tags = parseTags(xmlText(nvt, "tags"));
  return {
    id: el.attrs["id"],
    name: xmlText(el, "name"),
    host: {
      ip: host?.text.trim() || undefined,
      hostname: xmlText(host, "hostname"),
      assetId: xmlChild(host, "asset")?.attrs["asset_id"],
    },
    port: xmlText(el, "port"),
    nvt: {
      oid: nvt?.attrs["oid"],
      name: xmlText(nvt, "name"),
      family: xmlText(nvt, "family"),
      type: xmlText(nvt, "type"),
      cvssBase: num(xmlText(nvt, "cvss_base")) ?? num(xmlText(sev, "score")),
      cvssVector: xmlText(sev, "value") ?? tags["cvss_base_vector"],
      refs: xmlChildren(xmlChild(nvt, "refs"), "ref").map((r) => ({ type: r.attrs["type"] ?? "", id: r.attrs["id"] ?? "" })),
      solution: { type: solution?.attrs["type"] ?? tags["solution_type"], text: solution?.text.trim() || tags["solution"] },
      tags,
    },
    threat: xmlText(el, "threat"),
    severity: num(xmlText(el, "severity")),
    qod: int(xmlText(el, "qod/value")),
    description: xmlText(el, "description"),
    creationTime: xmlText(el, "creation_time"),
    modificationTime: xmlText(el, "modification_time"),
    ...(report?.id ? { reportId: report.id } : {}),
    ...(report?.taskName ? { taskName: report.taskName } : {}),
  };
}

/** Accept a JSON export record in GMP field names (snake_case like the XML). */
export function greenboneResultFromJson(r: JsonRecord): GreenboneResult {
  const host = r["host"];
  const hostRec = rec(host);
  const nvt = rec(r["nvt"]) ?? {};
  const refsRaw = rec(nvt["refs"]) ? arr(rec(nvt["refs"])?.["ref"]) : arr(nvt["refs"]);
  const qod = rec(r["qod"]);
  const sol = nvt["solution"];
  return {
    id: str(r["id"]) ?? str(r["@id"]),
    name: str(r["name"]),
    host: hostRec
      ? { ip: str(hostRec["ip"]) ?? str(hostRec["#text"]) ?? str(hostRec["__text"]), hostname: str(hostRec["hostname"]), assetId: str(hostRec["asset_id"]) }
      : { ip: str(host) },
    port: str(r["port"]),
    nvt: {
      oid: str(nvt["oid"]) ?? str(nvt["@oid"]),
      name: str(nvt["name"]),
      family: str(nvt["family"]),
      type: str(nvt["type"]),
      cvssBase: num(nvt["cvss_base"]),
      cvssVector: str(nvt["cvss_base_vector"]) ?? parseTags(str(nvt["tags"]))["cvss_base_vector"],
      refs: refsRaw.filter(isRecord).map((x) => ({ type: str(x["type"]) ?? str(x["@type"]) ?? "", id: str(x["id"]) ?? str(x["@id"]) ?? "" })),
      solution: isRecord(sol) ? { type: str(sol["type"]) ?? str(sol["@type"]), text: str(sol["text"]) ?? str(sol["#text"]) } : { text: str(sol) },
      tags: parseTags(str(nvt["tags"])),
    },
    threat: str(r["threat"]),
    severity: num(r["severity"]),
    qod: qod ? int(qod["value"]) : int(r["qod"]),
    description: str(r["description"]),
    creationTime: str(r["creation_time"]),
    modificationTime: str(r["modification_time"]),
  };
}

/** Marker for results already converted from XML by the splitter. */
class ParsedGmpResult {
  constructor(readonly result: GreenboneResult) {}
}

function* splitGreenbone(raw: unknown): Generator<SplitItem> {
  let text: string | undefined;
  try {
    text = typeof raw === "string" || raw instanceof Uint8Array ? payloadToText(raw) : undefined;
  } catch (err) {
    yield { ok: false, index: 0, error: `payload could not be decoded: ${(err as Error).message}` };
    return;
  }
  if (text !== undefined && text.trimStart().startsWith("<")) {
    let doc: XmlElement;
    try {
      doc = parseXml(text);
    } catch (err) {
      yield { ok: false, index: 0, error: `invalid GMP XML: ${(err as Error).message}` };
      return;
    }
    const reports = doc.name === "report" ? [doc] : xmlDescendants(doc, "report").filter((r) => xmlChild(r, "results") !== undefined);
    let index = 0;
    const seen = new Set<XmlElement>();
    for (const report of reports.length > 0 ? reports : [doc]) {
      const info = { id: report.attrs["id"], taskName: xmlText(report, "task/name") };
      for (const results of xmlChildren(report, "results")) {
        for (const el of xmlChildren(results, "result")) {
          if (seen.has(el)) continue;
          seen.add(el);
          yield { ok: true, index: index++, value: new ParsedGmpResult(greenboneResultFromXml(el, info)) };
        }
      }
    }
    return;
  }
  // JSON export: {results:[…]}, {report:{results:{result:[…]}}} or a bare array / JSONL
  yield* jsonRecords(text ?? raw, {
    unwrap: (o) => {
      const results = o["results"];
      if (Array.isArray(results)) return results;
      const nested = rec(results)?.["result"] ?? rec(rec(o["report"])?.["results"])?.["result"];
      return nested !== undefined ? arr(nested) : undefined;
    },
  });
}

function mapResult(record: unknown, ctx: MapContext): MapOutput {
  let r: GreenboneResult;
  if (record instanceof ParsedGmpResult) r = record.result;
  else if (isRecord(record)) r = greenboneResultFromJson(record);
  else return skip("not a result object");
  const threat = r.threat ?? "";
  if (/false positive/i.test(threat)) return skip("result overridden as False Positive");
  if (/^debug$/i.test(threat)) return skip("debug-level result");
  const minQod = num(ctx.options["minQod"]) ?? 0;
  if (r.qod !== undefined && r.qod < minQod) return skip(`quality of detection ${r.qod} below minimum ${minQod}`);

  const score = r.severity ?? r.nvt?.cvssBase;
  const severity = /^log$/i.test(threat) ? "info" : severityFromCvss(score) ?? "info";
  const cves = (r.nvt?.refs ?? []).filter((x) => x.type.toLowerCase() === "cve" && isCve(x.id)).map((x) => x.id.toUpperCase());
  const obs = new ObservableSet();
  for (const c of cves) obs.add("cve", c);
  const ip = r.host?.ip;
  const [portNum, proto] = (r.port ?? "").split("/");
  const solutionType = r.nvt?.solution?.type;
  const name = r.name ?? r.nvt?.name ?? "Greenbone finding";
  return {
    timestamp: toIso(r.creationTime) ?? toIso(r.modificationTime),
    category: "vulnerability",
    eventType: cves.length > 0 ? "greenbone.vulnerability" : "greenbone.finding",
    action: solutionType ? `solution:${solutionType}` : "detected",
    message: `${name}${r.port && r.port !== "general/tcp" ? ` on ${r.port}` : ""}`,
    severity,
    asset: { hostname: r.host?.hostname, ip: ip && isIp(ip) ? [ip] : undefined },
    network: portNum && /^\d+$/.test(portNum) ? { dstIp: ip && isIp(ip) ? ip : undefined, dstPort: Number(portNum), protocol: proto } : undefined,
    indicators: obs.toArray(),
    detection: { ruleId: r.nvt?.oid, ruleName: r.nvt?.name ?? name, engine: "greenbone", confidence: r.qod !== undefined ? Math.min(1, Math.max(0, r.qod / 100)) : undefined },
    labels: {
      severity_basis: /^log$/i.test(threat) ? "greenbone threat Log" : `greenbone severity ${score ?? "n/a"}`,
      "greenbone.threat": threat || undefined,
      "greenbone.qod": r.qod,
      "greenbone.nvt_family": r.nvt?.family,
      "greenbone.report_id": r.reportId,
      "greenbone.task": r.taskName,
      "greenbone.asset_id": r.host?.assetId,
      "vuln.cve": cves.join(",") || undefined,
      "vuln.cvss": score,
      "vuln.cvss_vector": r.nvt?.cvssVector,
      "vuln.solution_type": solutionType,
      "vuln.solution": r.nvt?.solution?.text,
      "vuln.patch_available": solutionType ? solutionType === "VendorFix" : undefined,
      "vuln.summary": r.nvt?.tags?.["summary"],
    },
    dedupKey: r.id ? `result:${r.id}` : `${ip ?? ""}|${r.port ?? ""}|${r.nvt?.oid ?? ""}|${r.creationTime ?? ""}`,
    raw: r,
  };
}

export function createGreenboneAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    ...extras,
    key: "greenbone",
    version: GREENBONE_ADAPTER_VERSION,
    name: "Greenbone / OpenVAS reports",
    sourceKind: "vuln_scanner",
    vendor: "Greenbone",
    consumes: ["GMP get_reports XML (report/results/result)", "JSON export with GMP field names"],
    split: splitGreenbone,
    map: mapResult,
  });
}
