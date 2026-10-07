import type { Severity } from "@bloody/contracts";
import { defineAdapter, skip, type Adapter, type AdapterExtras, type EventDraft, type MapContext, type MapOutput } from "../core/adapter.js";
import { ObservableSet, isCve } from "../core/indicators.js";
import { arr, isRecord, num, rec, str, strArr, type JsonRecord } from "../core/json.js";
import { severityFromCvss, severityFromWord } from "../core/severity.js";
import { toIso } from "../core/time.js";

/**
 * Trivy adapter — consumes `trivy … --format json` reports (SchemaVersion 2) for images,
 * filesystems, repositories, VMs and SBOMs, plus `trivy k8s --format json` cluster reports.
 * Each vulnerability, failed misconfiguration and secret finding becomes one event:
 *
 *   Vulnerabilities[]       → category "vulnerability"  (CVE indicator, CVSS, fixed version)
 *   Misconfigurations[FAIL] → category "configuration"
 *   Secrets[]               → category "configuration"  (the matched secret is never stored)
 *
 * Options: `hostname` (asset the scan ran on, for fs/rootfs/vm scans), `includePassedMisconfigurations`.
 */
export const TRIVY_ADAPTER_VERSION = "1.0.0";

const VENDOR_PREFERENCE = ["nvd", "ghsa", "redhat", "ubuntu", "debian", "amazon", "alma", "rocky", "oracle-oval", "photon"];

/** Best CVSS score + vector from Trivy's per-vendor CVSS map (NVD v3 first). */
export function trivyCvss(cvss: JsonRecord | undefined): { score?: number; vector?: string; source?: string } {
  if (!cvss) return {};
  const vendors = [...VENDOR_PREFERENCE.filter((v) => cvss[v] !== undefined), ...Object.keys(cvss).filter((v) => !VENDOR_PREFERENCE.includes(v))];
  for (const v of vendors) {
    const entry = rec(cvss[v]);
    const score = num(entry?.["V3Score"]) ?? num(entry?.["V40Score"]);
    if (score !== undefined) return { score, vector: str(entry?.["V3Vector"]) ?? str(entry?.["V40Vector"]), source: v };
  }
  for (const v of vendors) {
    const entry = rec(cvss[v]);
    const score = num(entry?.["V2Score"]);
    if (score !== undefined) return { score, vector: str(entry?.["V2Vector"]), source: v };
  }
  return {};
}

interface ReportContext {
  artifactName?: string;
  artifactType?: string;
  createdAt?: string;
  imageId?: string;
  os?: string;
  hostname?: string;
  k8s?: { cluster?: string; namespace?: string; kind?: string; name?: string };
}

function base(rc: ReportContext): Pick<EventDraft, "timestamp" | "asset" | "cloudResource"> & { labels: Record<string, string | number | boolean | undefined> } {
  const k8s = rc.k8s;
  return {
    timestamp: rc.createdAt,
    asset: rc.hostname ? { hostname: rc.hostname, os: rc.os } : undefined,
    cloudResource: k8s
      ? { provider: "kubernetes", accountId: k8s.cluster, resourceType: k8s.kind, resourceId: [k8s.namespace, k8s.name].filter(Boolean).join("/") || undefined }
      : undefined,
    labels: {
      "artifact.name": rc.artifactName,
      "artifact.type": rc.artifactType,
      "image.id": rc.imageId,
      "artifact.os": rc.os,
    },
  };
}

function resultDrafts(result: JsonRecord, rc: ReportContext, includePassed: boolean): EventDraft[] {
  const out: EventDraft[] = [];
  const target = str(result["Target"]);
  const klass = str(result["Class"]);
  const type = str(result["Type"]);
  const scope = `${rc.artifactName ?? ""}|${target ?? ""}`;

  for (const v of arr(result["Vulnerabilities"])) {
    if (!isRecord(v)) continue;
    const id = str(v["VulnerabilityID"]);
    if (!id) continue;
    const pkg = str(v["PkgName"]);
    const installed = str(v["InstalledVersion"]);
    const fixed = str(v["FixedVersion"]);
    const cvss = trivyCvss(rec(v["CVSS"]));
    const word = str(v["Severity"]);
    const severity: Severity = severityFromWord(word) ?? severityFromCvss(cvss.score) ?? "info";
    const obs = new ObservableSet();
    if (isCve(id)) obs.add("cve", id);
    for (const alias of strArr(v["VendorIDs"])) if (isCve(alias)) obs.add("cve", alias);
    const b = base(rc);
    out.push({
      ...b,
      category: "vulnerability",
      eventType: "trivy.vulnerability",
      action: str(v["Status"]) ?? (fixed ? "fixed" : "affected"),
      message: `${id} in ${pkg ?? "package"} ${installed ?? ""}${fixed ? ` (fixed in ${fixed})` : ""} — ${target ?? rc.artifactName ?? ""}`.trim(),
      severity,
      indicators: obs.toArray(),
      detection: { ruleId: id, ruleName: str(v["Title"]) ?? id, engine: "trivy" },
      labels: {
        ...b.labels,
        severity_basis: word ? `trivy severity ${word}${str(v["SeveritySource"]) ? ` (${str(v["SeveritySource"])})` : ""}` : `cvss ${cvss.score ?? "n/a"}`,
        target,
        "target.class": klass,
        "target.type": type,
        "vuln.id": id,
        "vuln.cvss": cvss.score,
        "vuln.cvss_vector": cvss.vector,
        "vuln.cvss_source": cvss.source,
        "vuln.cwe": strArr(v["CweIDs"]).join(",") || undefined,
        "vuln.primary_url": str(v["PrimaryURL"]),
        "vuln.published": str(v["PublishedDate"]),
        "vuln.patch_available": fixed !== undefined,
        "pkg.name": pkg,
        "pkg.id": str(v["PkgID"]),
        "pkg.path": str(v["PkgPath"]),
        "pkg.installed_version": installed,
        "pkg.fixed_version": fixed,
      },
      dedupKey: `vuln:${scope}|${str(v["PkgID"]) ?? `${pkg}@${installed}`}|${id}|${rc.createdAt ?? ""}`,
      raw: { ...v, Target: target, ArtifactName: rc.artifactName },
    });
  }

  for (const m of arr(result["Misconfigurations"])) {
    if (!isRecord(m)) continue;
    const status = str(m["Status"]) ?? "FAIL";
    if (status !== "FAIL" && !includePassed) continue;
    const id = str(m["ID"]) ?? str(m["AVDID"]);
    const b = base(rc);
    out.push({
      ...b,
      category: "configuration",
      eventType: "trivy.misconfiguration",
      action: status.toLowerCase(),
      outcome: status === "FAIL" ? "failure" : "success",
      message: `${str(m["Title"]) ?? id ?? "Misconfiguration"}${str(m["Message"]) ? `: ${str(m["Message"])}` : ""} — ${target ?? ""}`.trim(),
      severity: status === "FAIL" ? severityFromWord(str(m["Severity"])) ?? "medium" : "info",
      detection: { ruleId: id, ruleName: str(m["Title"]), engine: "trivy" },
      labels: {
        ...b.labels,
        severity_basis: `trivy misconfiguration severity ${str(m["Severity"]) ?? "n/a"}`,
        target,
        "misconfig.id": id,
        "misconfig.avd_id": str(m["AVDID"]),
        "misconfig.type": str(m["Type"]),
        "misconfig.resolution": str(m["Resolution"]),
        "misconfig.primary_url": str(m["PrimaryURL"]),
        "misconfig.status": status,
      },
      dedupKey: `misconfig:${scope}|${id ?? ""}|${str(m["Message"]) ?? ""}|${rc.createdAt ?? ""}`,
      raw: { ...m, CauseMetadata: undefined, Target: target },
    });
  }

  for (const s of arr(result["Secrets"])) {
    if (!isRecord(s)) continue;
    const ruleId = str(s["RuleID"]);
    const b = base(rc);
    out.push({
      ...b,
      category: "configuration",
      eventType: "trivy.secret",
      action: "secret-exposed",
      message: `${str(s["Title"]) ?? "Secret"} exposed in ${target ?? "artifact"}${num(s["StartLine"]) !== undefined ? `:${num(s["StartLine"])}` : ""}`,
      severity: severityFromWord(str(s["Severity"])) ?? "high",
      detection: { ruleId, ruleName: str(s["Title"]), engine: "trivy" },
      attack: [{ id: "T1552.001", name: "Credentials In Files", tactic: "Credential Access" }],
      labels: {
        ...b.labels,
        severity_basis: `trivy secret severity ${str(s["Severity"]) ?? "n/a"}`,
        target,
        "secret.rule_id": ruleId,
        "secret.category": str(s["Category"]),
        "secret.start_line": num(s["StartLine"]),
      },
      dedupKey: `secret:${scope}|${ruleId ?? ""}|${str(s["StartLine"]) ?? ""}|${rc.createdAt ?? ""}`,
      // The matched secret (even masked) is deliberately not retained.
      raw: { RuleID: ruleId, Category: str(s["Category"]), Severity: str(s["Severity"]), Title: str(s["Title"]), Target: target, StartLine: num(s["StartLine"]) },
    });
  }
  return out;
}

function mapReport(record: unknown, ctx: MapContext): MapOutput {
  if (!isRecord(record)) return skip("not a JSON object");
  const includePassed = ctx.options["includePassedMisconfigurations"] === true;
  const hostname = str(ctx.options["hostname"]);
  const created = toIso(record["CreatedAt"]);
  const drafts: EventDraft[] = [];

  // trivy k8s report
  const cluster = str(record["ClusterName"]);
  const resources = [...arr(record["Resources"]), ...arr(record["Vulnerabilities"]), ...arr(record["Misconfigurations"])].filter(
    (r): r is JsonRecord => isRecord(r) && Array.isArray(r["Results"]),
  );
  if (cluster !== undefined && resources.length > 0) {
    for (const res of resources) {
      const rc: ReportContext = {
        artifactName: str(res["Name"]),
        artifactType: "kubernetes_resource",
        createdAt: created,
        k8s: { cluster, namespace: str(res["Namespace"]), kind: str(res["Kind"]), name: str(res["Name"]) },
      };
      for (const result of arr(res["Results"])) if (isRecord(result)) drafts.push(...resultDrafts(result, rc, includePassed));
    }
    return drafts.length > 0 ? drafts : skip("Trivy k8s report contains no findings");
  }

  if (!Array.isArray(record["Results"]) && record["SchemaVersion"] === undefined) return skip("not a Trivy JSON report");
  const meta = rec(record["Metadata"]);
  const osFamily = str(rec(meta?.["OS"])?.["Family"]);
  const osName = str(rec(meta?.["OS"])?.["Name"]);
  const rc: ReportContext = {
    artifactName: str(record["ArtifactName"]),
    artifactType: str(record["ArtifactType"]),
    createdAt: created,
    imageId: str(meta?.["ImageID"]),
    os: osFamily ? `${osFamily}${osName ? ` ${osName}` : ""}` : undefined,
    // Host scans (fs/rootfs/vm) are attributed to the host only when the collector says which.
    hostname,
  };
  for (const result of arr(record["Results"])) if (isRecord(result)) drafts.push(...resultDrafts(result, rc, includePassed));
  return drafts.length > 0 ? drafts : skip("Trivy report contains no findings");
}

export function createTrivyAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    ...extras,
    key: "trivy",
    version: TRIVY_ADAPTER_VERSION,
    name: "Trivy scan reports",
    sourceKind: "vuln_scanner",
    vendor: "Aqua Security",
    consumes: ["trivy --format json reports (image, fs, rootfs, repo, vm, sbom)", "trivy k8s --format json cluster reports"],
    map: mapReport,
  });
}
