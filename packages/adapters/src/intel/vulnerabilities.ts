import { maxSeverity, type Severity } from "@bloody/contracts";
import type { NormalizedEvent } from "../core/adapter.js";
import { isCve } from "../core/indicators.js";
import { num } from "../core/json.js";
import { severityFromCvss } from "../core/severity.js";
import { signal, type AdapterSignal } from "../core/signals.js";
import type { EpssTable } from "./epss.js";
import type { KevCatalog, KevEntry } from "./kev.js";

/**
 * Vulnerability enrichment (KEV + EPSS) and finding extraction from scanner events
 * (Trivy, Nuclei, Greenbone, Wazuh vulnerability-detector). Produces the inputs the API
 * needs for the contracts `Vulnerability` entity — CVE, CVSS, EPSS, knownExploited, patch
 * availability, SLA due date — each with human-readable evidence.
 */

export interface VulnerabilityEnrichment {
  cve: string;
  knownExploited: boolean;
  kev: Pick<KevEntry, "dateAdded" | "dueDate" | "requiredAction" | "knownRansomwareCampaignUse" | "vendorProject" | "product" | "name"> | null;
  epss: number | null;
  epssPercentile: number | null;
  epssDate: string | null;
  /** Minimum severity implied by exploitation evidence. */
  severityFloor: Severity | null;
  evidence: string[];
}

export interface EnrichmentSources {
  kev?: KevCatalog;
  epss?: EpssTable;
}

/** EPSS probability bands used for the severity floor (explicit, documented thresholds). */
export const EPSS_HIGH_THRESHOLD = 0.5;
export const EPSS_MEDIUM_THRESHOLD = 0.1;

export function enrichCve(cve: string, sources: EnrichmentSources): VulnerabilityEnrichment {
  const id = cve.trim().toUpperCase();
  const evidence: string[] = [];
  const kev = sources.kev?.get(id);
  const epss = sources.epss?.get(id);
  let floor: Severity | null = null;
  if (kev) {
    floor = kev.knownRansomwareCampaignUse ? "critical" : "high";
    evidence.push(`Listed in CISA KEV since ${kev.dateAdded?.slice(0, 10) ?? "unknown date"}${kev.knownRansomwareCampaignUse ? "; used in ransomware campaigns" : ""}`);
    if (kev.dueDate) evidence.push(`CISA remediation due date ${kev.dueDate.slice(0, 10)}: ${kev.requiredAction}`);
  }
  if (epss) {
    const pct = Math.round(epss.percentile * 1000) / 10;
    evidence.push(`EPSS ${(epss.epss * 100).toFixed(1)}% probability of exploitation in 30 days (percentile ${pct})`);
    if (epss.epss >= EPSS_HIGH_THRESHOLD) floor = floor ? maxSeverity(floor, "high") : "high";
    else if (epss.epss >= EPSS_MEDIUM_THRESHOLD) floor = floor ? maxSeverity(floor, "medium") : "medium";
  }
  return {
    cve: id,
    knownExploited: kev !== undefined,
    kev: kev
      ? {
          dateAdded: kev.dateAdded,
          dueDate: kev.dueDate,
          requiredAction: kev.requiredAction,
          knownRansomwareCampaignUse: kev.knownRansomwareCampaignUse,
          vendorProject: kev.vendorProject,
          product: kev.product,
          name: kev.name,
        }
      : null,
    epss: epss?.epss ?? null,
    epssPercentile: epss?.percentile ?? null,
    epssDate: epss?.date ?? null,
    severityFloor: floor,
    evidence,
  };
}

export interface VulnerabilityFindingDraft {
  /** Stable identity of the finding (source + asset + vulnerability) for upserts. */
  findingKey: string;
  source: string;
  cve: string | null;
  /** Scanner rule/template/NVT id when there is no CVE. */
  ruleId: string | null;
  title: string;
  cvss: number | null;
  epss: number | null;
  epssPercentile: number | null;
  knownExploited: boolean;
  /** Scanner severity raised to the KEV/EPSS floor. */
  severity: Severity;
  patchAvailable: boolean;
  /** KEV due date when known-exploited (otherwise the API applies the org's SLA policy). */
  slaDueAt: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  observations: number;
  /** What the API needs to resolve `assetId`. */
  asset: { hostname?: string; ip?: string[]; agentId?: string; artifact?: string; cloudResourceId?: string };
  evidence: string[];
}

function assetKey(e: NormalizedEvent): string {
  return e.asset?.agentId ?? e.asset?.hostname ?? e.asset?.ip?.[0] ?? e.cloudResource?.resourceId ?? e.labels["artifact.name"] ?? e.labels["target"] ?? "unknown-asset";
}

/** Group vulnerability events into findings (one per asset × vulnerability), enriched. */
export function vulnerabilityFindingsFromEvents(events: readonly NormalizedEvent[], sources: EnrichmentSources = {}): VulnerabilityFindingDraft[] {
  const byKey = new Map<string, VulnerabilityFindingDraft>();
  for (const e of events) {
    if (e.category !== "vulnerability") continue;
    const cves = e.indicators.filter((i) => i.type === "cve" && isCve(i.value)).map((i) => i.value.toUpperCase());
    const ids: Array<string | null> = cves.length > 0 ? cves : [null];
    for (const cve of ids) {
      const ruleId = e.detection?.ruleId ?? null;
      const vulnId = cve ?? ruleId ?? e.eventType;
      const key = `${e.provenance.adapter}|${assetKey(e)}|${vulnId}|${e.labels["pkg.name"] ?? ""}`;
      const cvss = num(e.labels["vuln.cvss"]) ?? null;
      const patch = e.labels["vuln.patch_available"] === "true" || e.labels["pkg.fixed_version"] !== undefined;
      const prev = byKey.get(key);
      if (prev) {
        if (e.timestamp < prev.firstSeenAt) prev.firstSeenAt = e.timestamp;
        if (e.timestamp > prev.lastSeenAt) prev.lastSeenAt = e.timestamp;
        prev.observations++;
        prev.severity = maxSeverity(prev.severity, e.severity);
        prev.patchAvailable ||= patch;
        continue;
      }
      const enrichment = cve ? enrichCve(cve, sources) : null;
      const scannerEpss = num(e.labels["vuln.epss"]);
      const scannerSeverity = e.severity !== "info" ? e.severity : severityFromCvss(cvss ?? undefined) ?? "info";
      const severity = enrichment?.severityFloor ? maxSeverity(scannerSeverity, enrichment.severityFloor) : scannerSeverity;
      const evidence = [`${e.provenance.adapter} reported ${vulnId} (${e.labels["severity_basis"] ?? `severity ${e.severity}`})`, ...(enrichment?.evidence ?? [])];
      if (severity !== scannerSeverity) evidence.push(`severity raised from ${scannerSeverity} to ${severity} by exploitation evidence`);
      if (patch) evidence.push(`fix available${e.labels["pkg.fixed_version"] ? ` (${e.labels["pkg.fixed_version"]})` : ""}`);
      byKey.set(key, {
        findingKey: key,
        source: e.provenance.adapter,
        cve,
        ruleId,
        title: e.detection?.ruleName ?? e.message ?? vulnId,
        cvss,
        epss: enrichment?.epss ?? scannerEpss ?? null,
        epssPercentile: enrichment?.epssPercentile ?? num(e.labels["vuln.epss_percentile"]) ?? null,
        knownExploited: enrichment?.knownExploited ?? false,
        severity,
        patchAvailable: patch,
        slaDueAt: enrichment?.kev?.dueDate ?? null,
        firstSeenAt: e.timestamp,
        lastSeenAt: e.timestamp,
        observations: 1,
        asset: {
          ...(e.asset?.hostname ? { hostname: e.asset.hostname } : {}),
          ...(e.asset?.ip?.length ? { ip: e.asset.ip } : {}),
          ...(e.asset?.agentId ? { agentId: e.asset.agentId } : {}),
          ...(e.labels["artifact.name"] ? { artifact: e.labels["artifact.name"] } : {}),
          ...(e.cloudResource?.resourceId ? { cloudResourceId: e.cloudResource.resourceId } : {}),
        },
        evidence,
      });
    }
  }
  return [...byKey.values()];
}

/**
 * `vulnerability.kev_detected` signals for findings that are known-exploited. Routed to the
 * SOC and the customer (they own patching) and to the MSSP when ransomware use is known.
 */
export function kevSignals(findings: readonly VulnerabilityFindingDraft[], ctx: { organizationRef: string | null; now: string }): AdapterSignal[] {
  const out: AdapterSignal[] = [];
  for (const f of findings) {
    if (!f.knownExploited || !f.cve) continue;
    const assetLabel = f.asset.hostname ?? f.asset.artifact ?? f.asset.ip?.[0] ?? f.asset.cloudResourceId ?? "an asset";
    const ransomware = f.evidence.some((e) => /ransomware/i.test(e));
    const s = signal({
      event: "vulnerability.kev_detected",
      severity: f.severity,
      at: ctx.now,
      dedupKey: `kev:${f.findingKey}`,
      emit: "on_create",
      organizationRef: ctx.organizationRef,
      subject: { kind: "vulnerability", ref: f.findingKey, label: `${f.cve} on ${assetLabel}` },
      title: `Known-exploited vulnerability ${f.cve} found on ${assetLabel}`,
      summary: [
        `${f.title}`,
        ...f.evidence,
        f.slaDueAt ? `Remediate before ${f.slaDueAt.slice(0, 10)}.` : "Remediate according to your vulnerability SLA.",
      ].join("\n"),
      facts: {
        cve: f.cve,
        asset: assetLabel,
        severity: f.severity,
        cvss: f.cvss ?? "n/a",
        epss: f.epss ?? "n/a",
        patchAvailable: f.patchAvailable,
        dueDate: f.slaDueAt ?? "n/a",
        source: f.source,
        ransomware,
      },
      audience: ransomware ? ["soc", "customer", "mssp"] : ["soc", "customer"],
    });
    if (s) out.push(s);
  }
  return out;
}
