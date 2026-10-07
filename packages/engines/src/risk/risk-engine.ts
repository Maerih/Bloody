import type { AssetKind, AttackTechnique, Criticality, IncidentStatus, Severity } from "@bloody/contracts";
import { CRITICALITY_VALUE, vulnerabilityExploitability } from "../graph/attack-semantics.js";
import { systemClock, toEpochMs, type Clock } from "../util/clock.js";
import { clamp01, noisyOr, round, saturate } from "../util/math.js";
import { computeRisk, DEFAULT_RISK_CURVE, RISK_MODEL_VERSION, type ExplainedRiskAssessment, type FactorInput, type RiskCurve } from "./model.js";
import { tacticsOf, LATE_STAGE_TACTICS, IMPACT_TACTICS } from "./tactics.js";

/** Contribution of one severity level when severities are combined (noisy-OR, never summed). */
export const SEVERITY_WEIGHT: Record<Severity, number> = { info: 0.1, low: 0.25, medium: 0.5, high: 0.8, critical: 1 };

export interface VulnerabilitySignal {
  cve?: string | null;
  title?: string;
  cvss?: number | null;
  epss?: number | null;
  knownExploited?: boolean;
  severity?: Severity;
  status?: "open" | "in_remediation" | "accepted" | "mitigated" | "resolved";
  patchAvailable?: boolean;
}

export interface IntelSignal {
  value: string;
  /** 0..100 like the contract `Indicator.confidence`. */
  confidence: number;
  severity: Severity;
  threatActor?: string | null;
  campaign?: string | null;
}

export interface DetectionSignal {
  ruleId?: string | null;
  title?: string;
  severity: Severity;
  /** 0..1 */
  confidence: number;
  source?: string;
  attack?: AttackTechnique[];
}

export interface CompensatingControls {
  edr?: boolean | "healthy" | "degraded";
  mfa?: boolean | "phishing_resistant";
  segmentation?: boolean;
  firewall?: boolean;
  isolated?: boolean;
  conditionalAccess?: boolean;
  /** Privileged access management / just-in-time elevation. */
  pam?: boolean;
  /** Web application firewall / virtual patching / IPS signature in front of the asset. */
  virtualPatching?: boolean;
  custom?: Array<{ key: string; label: string; strength: number; explanation?: string }>;
}

export interface AssetRiskInput {
  asset: { name: string; kind?: AssetKind; criticality: Criticality; internetFacing: boolean };
  exposure?: { openPorts?: number; exposedServices?: string[]; exposedAdminInterfaces?: number };
  vulnerabilities?: VulnerabilitySignal[];
  /** Identities with sessions / rights on the asset. */
  identities?: Array<{ principal: string; privileged: boolean }>;
  intelMatches?: IntelSignal[];
  /** Active (un-closed) alerts on the asset. */
  detections?: DetectionSignal[];
  attackPaths?: { total: number; toCrownJewels: number };
  /** Explicit 0..1, or derived from data sensitivity / regulation. */
  businessImpact?: number | { dataSensitivity?: "public" | "internal" | "confidential" | "restricted"; regulated?: boolean; revenueCritical?: boolean };
  blastRadius?: { reachableNodes: number; reachableCrownJewels: number };
  controls?: CompensatingControls;
  history?: { incidentsLast90d?: number; anomalyScore?: number };
}

export interface IdentityRiskInput {
  identity: {
    principal: string;
    kind?: "user" | "service_account" | "service_principal" | "machine" | "api_key" | "group";
    privileged: boolean;
    mfaEnabled: boolean;
    enabled?: boolean;
    lastActivityAt?: string | null;
  };
  adminOfAssets?: number;
  crownJewelAccess?: number;
  privilegedGroups?: number;
  detections?: DetectionSignal[];
  signIns?: { failures?: number; impossibleTravel?: number; riskySignIns?: number; newCountries?: number };
  credentialExposure?: { leaked?: boolean; cachedOnHosts?: number; nonExpiringPassword?: boolean; passwordAgeDays?: number };
  intelMatches?: IntelSignal[];
  controls?: CompensatingControls;
  history?: { incidentsLast90d?: number; anomalyScore?: number };
}

export interface IncidentRiskInput {
  title?: string;
  status?: IncidentStatus;
  attack?: AttackTechnique[];
  alerts: DetectionSignal[];
  assets: Array<{ name?: string; criticality: Criticality; edr?: boolean }>;
  identities: Array<{ principal?: string; privileged: boolean }>;
  intelMatches?: IntelSignal[];
  businessImpact?: number;
}

export interface VulnerabilityRiskInput {
  vulnerability: VulnerabilitySignal & { title: string };
  asset: { name: string; criticality: Criticality; internetFacing: boolean };
  /** Threat intel referencing this CVE (actor campaigns, exploit kits). */
  intelMatches?: IntelSignal[];
  businessImpact?: number;
  controls?: CompensatingControls;
}

export type VulnerabilityPriorityLevel = "P1" | "P2" | "P3" | "P4";

export interface VulnerabilityPriority extends ExplainedRiskAssessment {
  priority: VulnerabilityPriorityLevel;
  slaDays: number;
  recommendedAction: "patch_now" | "patch" | "mitigate" | "monitor";
  rationale: string;
}

export interface ExposureInputs {
  organizationName?: string;
  assets: { total: number; internetFacing: number; crownJewels: number };
  external?: { exposedServices?: number; exposedAdminInterfaces?: number; unmanagedExternalAssets?: number };
  vulnerabilities?: { open?: number; critical?: number; high?: number; knownExploited?: number; knownExploitedOnInternetFacing?: number; knownExploitedOnCrownJewels?: number; highEpss?: number; overdueSla?: number };
  identities?: { total?: number; privileged?: number; privilegedWithoutMfa?: number; dormantPrivileged?: number; riskyServiceAccounts?: number };
  cloud?: { publicStorage?: number; failingCriticalControls?: number; failingControls?: number; totalControls?: number; overPrivilegedRoles?: number };
  saas?: { riskyOauthApps?: number; failingControls?: number; totalControls?: number };
  misconfigurations?: { failing?: number; total?: number; critical?: number };
  attackPaths?: { total?: number; toCrownJewels?: number; shortestHopsToCrownJewel?: number | null };
  threatIntel?: { activeCampaignsTargeting?: number; matchesLast30d?: number };
  controls?: { edrCoverage?: number; mfaCoverage?: number; segmentation?: number | boolean; backupCoverage?: number };
  /** Baseline business impact of a breach for this organization (default 0.5). */
  businessImpact?: number;
}

export type ExposureDomain = "external" | "vulnerability" | "identity" | "cloud" | "saas" | "misconfiguration" | "attack_path" | "threat_intel";

export interface ExposureAssessment extends ExplainedRiskAssessment {
  domains: Record<ExposureDomain, { score: number; drivers: string[] }>;
}

export interface AttackPathRiskInput {
  entryLabel: string;
  targetLabel: string;
  steps: number;
  /** Π of raw step success probabilities along the path. */
  chainProbability: number;
  exploitability: number;
  knownExploited: boolean;
  exploitedCves: string[];
  /** Entry exposure 0..1 (1 = directly internet-facing). */
  exposure: number;
  privilegeEscalation: number;
  identityPrivilege: number;
  privilegedIdentities: string[];
  threatIntel: number;
  lateralHops: number;
  targetCriticality: Criticality;
  blastRadius: { reachableNodes: number; reachableCrownJewels: number };
  controls: Array<{ key: string; label: string; strength: number; on: string }>;
}

export interface RiskEngineOptions {
  clock?: Clock;
  curve?: RiskCurve;
  /** Per-factor weight overrides keyed "<scorer>.<factor>", e.g. "asset.exposure": 0.5. */
  weights?: Record<string, number>;
  /** SLA days per vulnerability priority. */
  vulnerabilitySlaDays?: Record<VulnerabilityPriorityLevel, number>;
  /**
   * Attack-path feasibility = chainProbability^exponent (default 0.5). Step probabilities are
   * priors, and treating them as fully independent over-penalizes long but realistic chains
   * (an attacker who succeeds once is likely to succeed at similar steps); the exponent damps
   * that compounding. 1 = raw product, 0 = ignore path complexity.
   */
  pathComplexityExponent?: number;
}

/** Default factor weights (see model.ts for semantics). Tunable per tenant via `weights`. */
export const DEFAULT_WEIGHTS: Record<string, number> = {
  "asset.exposure": 0.45,
  "asset.exploitability": 0.5,
  "asset.active_exploitation": 0.55,
  "asset.vulnerability_severity": 0.3,
  "asset.threat_intel": 0.5,
  "asset.detection_confidence": 0.6,
  "asset.historical_behavior": 0.25,
  "asset.criticality": 0.85,
  "asset.business_impact": 0.6,
  "asset.identity_privilege": 0.5,
  "asset.attack_path": 0.45,
  "asset.blast_radius": 0.4,
  "identity.detection_confidence": 0.6,
  "identity.risky_sign_ins": 0.55,
  "identity.credential_exposure": 0.6,
  "identity.threat_intel": 0.5,
  "identity.dormancy": 0.3,
  "identity.historical_behavior": 0.25,
  "identity.privilege": 0.8,
  "identity.admin_reach": 0.55,
  "identity.group_privilege": 0.35,
  "identity.identity_type": 0.3,
  "incident.detection_confidence": 0.75,
  "incident.corroboration": 0.45,
  "incident.attack_progression": 0.5,
  "incident.threat_intel": 0.5,
  "incident.asset_criticality": 0.85,
  "incident.identity_privilege": 0.55,
  "incident.scope": 0.4,
  "incident.business_impact": 0.6,
  "incident.impact_tactics": 0.5,
  "vulnerability.exploit_prediction": 0.7,
  "vulnerability.known_exploited": 0.85,
  "vulnerability.cvss_exploitability": 0.35,
  "vulnerability.exposure": 0.45,
  "vulnerability.threat_intel": 0.5,
  "vulnerability.no_patch": 0.15,
  "vulnerability.severity": 0.6,
  "vulnerability.asset_criticality": 0.85,
  "vulnerability.business_impact": 0.6,
  "exposure.external": 0.5,
  "exposure.vulnerability": 0.55,
  "exposure.identity": 0.5,
  "exposure.cloud": 0.45,
  "exposure.saas": 0.35,
  "exposure.misconfiguration": 0.35,
  "exposure.attack_path": 0.55,
  "exposure.threat_intel": 0.45,
  "exposure.crown_jewel_reachability": 0.7,
  "exposure.privileged_exposure": 0.5,
  "exposure.business_baseline": 0.5,
  "path.exploitability": 0.6,
  "path.known_exploitation": 0.7,
  "path.exposure": 0.5,
  "path.threat_intel": 0.45,
  "path.lateral_movement": 0.3,
  "path.asset_criticality": 0.85,
  "path.identity_privilege": 0.5,
  "path.privilege": 0.45,
  "path.blast_radius": 0.4,
};

export const DEFAULT_VULN_SLA_DAYS: Record<VulnerabilityPriorityLevel, number> = { P1: 7, P2: 14, P3: 30, P4: 90 };

/**
 * Explainable Risk Engine. Every method returns an {@link ExplainedRiskAssessment} whose
 * factor contributions sum to the score (see model.ts for the math). Inputs are plain
 * structures so callers can feed DB rows, graph context or correlator drafts.
 */
export class RiskEngine {
  private readonly clock: Clock;
  private readonly curve: RiskCurve;
  private readonly weights: Record<string, number>;
  private readonly slaDays: Record<VulnerabilityPriorityLevel, number>;
  private readonly pathExponent: number;

  constructor(options: RiskEngineOptions = {}) {
    this.clock = options.clock ?? systemClock;
    this.curve = options.curve ?? DEFAULT_RISK_CURVE;
    this.weights = { ...DEFAULT_WEIGHTS, ...(options.weights ?? {}) };
    this.slaDays = options.vulnerabilitySlaDays ?? DEFAULT_VULN_SLA_DAYS;
    this.pathExponent = clamp01(options.pathComplexityExponent ?? 0.5);
  }

  private w(key: string): number {
    return this.weights[key] ?? 0;
  }

  private f(scorer: string, key: string, label: string, value: number, explanation: string): FactorInput {
    return { key, label, value: clamp01(value), weight: this.w(`${scorer}.${key}`), explanation };
  }

  // ─── Asset ────────────────────────────────────────────────────────────────

  scoreAsset(input: AssetRiskInput): ExplainedRiskAssessment {
    const a = input.asset;
    const vulns = openVulns(input.vulnerabilities ?? []);
    const L: FactorInput[] = [];
    const I: FactorInput[] = [];

    const services = input.exposure?.exposedServices?.length ?? 0;
    const admin = input.exposure?.exposedAdminInterfaces ?? 0;
    const ports = input.exposure?.openPorts ?? 0;
    const exposure = a.internetFacing ? 0.7 + 0.3 * saturate(services + 2 * admin, 2) : 0.2 * saturate(ports, 10);
    L.push(
      this.f(
        "asset",
        "exposure",
        "Internet exposure",
        exposure,
        a.internetFacing
          ? `Internet-facing${services ? ` with ${services} exposed service(s) (${input.exposure!.exposedServices!.slice(0, 5).join(", ")})` : ""}${admin ? ` and ${admin} exposed admin interface(s)` : ""}.`
          : ports
            ? `Not internet-facing; ${ports} internally reachable open port(s).`
            : "Not internet-facing.",
      ),
    );

    if (vulns.length > 0) {
      const ranked = vulns.map((v) => ({ v, e: vulnerabilityExploitability(v) })).sort((x, y) => y.e - x.e);
      const best = ranked[0]!;
      L.push(this.f("asset", "exploitability", "Exploitability", best.e, `Most exploitable open finding ${vulnName(best.v)} (${describeVuln(best.v)}) — exploitability ${round(best.e * 100, 0)}%.`));
      const kev = vulns.filter((v) => v.knownExploited);
      L.push(
        this.f(
          "asset",
          "active_exploitation",
          "Known exploited vulnerability",
          kev.length > 0 ? 1 : 0,
          kev.length > 0 ? `${kev.length} open finding(s) on the CISA KEV list: ${kev.slice(0, 4).map(vulnName).join(", ")}.` : "No open known-exploited (KEV) vulnerabilities.",
        ),
      );
      L.push(
        this.f(
          "asset",
          "vulnerability_severity",
          "Vulnerability severity",
          noisyOr(vulns.map((v) => 0.5 * SEVERITY_WEIGHT[v.severity ?? severityFromCvss(v.cvss)])),
          `${countBySeverity(vulns.map((v) => v.severity ?? severityFromCvss(v.cvss)))} open finding(s) (combined with diminishing returns, not counted).`,
        ),
      );
    }

    const intel = input.intelMatches ?? [];
    if (intel.length > 0) L.push(this.f("asset", "threat_intel", "Threat intelligence match", intelValue(intel), describeIntel(intel)));
    const dets = input.detections ?? [];
    if (dets.length > 0) L.push(this.f("asset", "detection_confidence", "Active detections", detectionValue(dets), describeDetections(dets)));
    const h = input.history;
    if (h && ((h.incidentsLast90d ?? 0) > 0 || (h.anomalyScore ?? 0) > 0)) {
      L.push(
        this.f(
          "asset",
          "historical_behavior",
          "Historical behavior",
          noisyOr([saturate(h.incidentsLast90d ?? 0, 2), clamp01(h.anomalyScore ?? 0)]),
          `${h.incidentsLast90d ?? 0} incident(s) in the last 90 days${h.anomalyScore ? `; behavioral anomaly score ${round(h.anomalyScore * 100, 0)}%` : ""}.`,
        ),
      );
    }

    I.push(this.f("asset", "criticality", "Asset criticality", CRITICALITY_VALUE[a.criticality], `Business criticality "${a.criticality.replace("_", " ")}".`));
    const bi = businessImpactValue(input.businessImpact);
    if (bi) I.push(this.f("asset", "business_impact", "Business impact", bi.value, bi.explanation));
    const ids = input.identities ?? [];
    if (ids.length > 0) {
      const priv = ids.filter((i) => i.privileged);
      I.push(
        this.f(
          "asset",
          "identity_privilege",
          "Privileged identity exposure",
          priv.length > 0 ? 0.6 + 0.4 * saturate(priv.length - 1, 2) : 0.2 * saturate(ids.length, 20),
          priv.length > 0
            ? `${priv.length} privileged identit${priv.length === 1 ? "y has" : "ies have"} sessions or rights here (${priv.slice(0, 3).map((p) => p.principal).join(", ")}) — credential theft would escalate.`
            : `${ids.length} non-privileged identit${ids.length === 1 ? "y" : "ies"} with access.`,
        ),
      );
    }
    const ap = input.attackPaths;
    if (ap && ap.total > 0) {
      I.push(
        this.f(
          "asset",
          "attack_path",
          "Attack path membership",
          ap.toCrownJewels > 0 ? 0.6 + 0.4 * saturate(ap.toCrownJewels - 1, 2) : 0.5 * saturate(ap.total, 3),
          `On ${ap.total} attack path(s)${ap.toCrownJewels ? `, ${ap.toCrownJewels} leading to crown-jewel assets` : ""}.`,
        ),
      );
    }
    const br = input.blastRadius;
    if (br && br.reachableNodes > 0) I.push(this.f("asset", "blast_radius", "Blast radius", noisyOr([saturate(br.reachableNodes, 25), 0.8 * saturate(br.reachableCrownJewels, 1)]), describeBlast(br)));

    return computeRisk({ subject: `Asset ${a.name}`, likelihood: L, impact: I, controls: this.controls(input.controls), curve: this.curve, modelVersion: `${RISK_MODEL_VERSION}#asset` });
  }

  // ─── Identity ─────────────────────────────────────────────────────────────

  scoreIdentity(input: IdentityRiskInput): ExplainedRiskAssessment {
    const id = input.identity;
    const L: FactorInput[] = [];
    const I: FactorInput[] = [];
    const dets = input.detections ?? [];
    if (dets.length > 0) L.push(this.f("identity", "detection_confidence", "Active detections", detectionValue(dets), describeDetections(dets)));
    const s = input.signIns;
    if (s) {
      const v = noisyOr([0.9 * saturate(s.impossibleTravel ?? 0, 1), 0.7 * saturate(s.riskySignIns ?? 0, 2), 0.4 * saturate(s.failures ?? 0, 20), 0.4 * saturate(s.newCountries ?? 0, 1)]);
      const parts = [
        s.impossibleTravel ? `${s.impossibleTravel} impossible-travel event(s)` : "",
        s.riskySignIns ? `${s.riskySignIns} risky sign-in(s)` : "",
        s.failures ? `${s.failures} failed sign-in(s)` : "",
        s.newCountries ? `sign-ins from ${s.newCountries} new countr${s.newCountries === 1 ? "y" : "ies"}` : "",
      ].filter(Boolean);
      L.push(this.f("identity", "risky_sign_ins", "Risky sign-in activity", v, parts.length ? `${parts.join(", ")}.` : "No risky sign-in activity."));
    }
    const c = input.credentialExposure;
    if (c) {
      const v = noisyOr([c.leaked ? 0.95 : 0, 0.5 * saturate(c.cachedOnHosts ?? 0, 5), c.nonExpiringPassword ? 0.3 : 0, (c.passwordAgeDays ?? 0) > 365 ? 0.3 : 0]);
      const parts = [
        c.leaked ? "credentials found in a leak" : "",
        c.cachedOnHosts ? `credentials cached on ${c.cachedOnHosts} host(s)` : "",
        c.nonExpiringPassword ? "password never expires" : "",
        (c.passwordAgeDays ?? 0) > 365 ? `password ${c.passwordAgeDays} days old` : "",
      ].filter(Boolean);
      L.push(this.f("identity", "credential_exposure", "Credential exposure", v, parts.length ? `${capitalize(parts.join("; "))}.` : "No credential exposure signals."));
    }
    const intel = input.intelMatches ?? [];
    if (intel.length > 0) L.push(this.f("identity", "threat_intel", "Threat intelligence match", intelValue(intel), describeIntel(intel)));
    if (id.lastActivityAt && id.enabled !== false) {
      const days = (this.clock.now() - toEpochMs(id.lastActivityAt)) / 86_400_000;
      if (days > 90) {
        L.push(
          this.f("identity", "dormancy", "Dormant but enabled", saturate(days - 90, 90) * (id.privileged ? 1 : 0.6), `No activity for ${Math.floor(days)} days while still enabled — dormant accounts are attractive takeover targets.`),
        );
      }
    }
    const h = input.history;
    if (h && ((h.incidentsLast90d ?? 0) > 0 || (h.anomalyScore ?? 0) > 0)) {
      L.push(
        this.f(
          "identity",
          "historical_behavior",
          "Historical behavior",
          noisyOr([saturate(h.incidentsLast90d ?? 0, 2), clamp01(h.anomalyScore ?? 0)]),
          `${h.incidentsLast90d ?? 0} incident(s) in the last 90 days${h.anomalyScore ? `; behavioral anomaly score ${round(h.anomalyScore * 100, 0)}%` : ""}.`,
        ),
      );
    }

    const kind = id.kind ?? "user";
    I.push(this.f("identity", "privilege", "Identity privilege", id.privileged ? 1 : kind === "user" ? 0.25 : 0.4, id.privileged ? "Privileged (administrative) identity." : `Standard ${kind.replace("_", " ")} privileges.`));
    if ((input.adminOfAssets ?? 0) > 0 || (input.crownJewelAccess ?? 0) > 0) {
      I.push(
        this.f(
          "identity",
          "admin_reach",
          "Administrative reach",
          noisyOr([saturate(input.adminOfAssets ?? 0, 5), (input.crownJewelAccess ?? 0) > 0 ? 0.9 : 0]),
          `Administrator of ${input.adminOfAssets ?? 0} asset(s)${input.crownJewelAccess ? `; access to ${input.crownJewelAccess} crown-jewel asset(s)` : ""}.`,
        ),
      );
    }
    if ((input.privilegedGroups ?? 0) > 0) I.push(this.f("identity", "group_privilege", "Privileged group membership", saturate(input.privilegedGroups ?? 0, 1), `Member of ${input.privilegedGroups} privileged group(s).`));
    if (kind !== "user" && kind !== "group") {
      I.push(this.f("identity", "identity_type", "Non-human identity", kind === "api_key" || kind === "service_principal" ? 0.7 : 0.5, `${capitalize(kind.replace("_", " "))} — non-interactive credentials are often over-privileged and rarely rotated.`));
    }

    const controls = { ...(input.controls ?? {}) };
    if (controls.mfa === undefined) controls.mfa = id.mfaEnabled;
    const ctl = this.controls(controls, { mfaStrength: 0.45 });
    if (id.enabled === false) ctl.push({ key: "disabled", label: "Account disabled", value: 1, weight: 0.95, explanation: "The account is disabled; it cannot authenticate." });
    return computeRisk({ subject: `Identity ${id.principal}`, likelihood: L, impact: I, controls: ctl, curve: this.curve, modelVersion: `${RISK_MODEL_VERSION}#identity` });
  }

  // ─── Incident ─────────────────────────────────────────────────────────────

  scoreIncident(input: IncidentRiskInput): ExplainedRiskAssessment {
    const L: FactorInput[] = [];
    const I: FactorInput[] = [];
    const alerts = input.alerts;
    if (alerts.length > 0) {
      L.push(this.f("incident", "detection_confidence", "Detection confidence", detectionValue(alerts), describeDetections(alerts)));
      const sources = new Set(alerts.map((a) => a.source ?? "unknown"));
      const rules = new Set(alerts.map((a) => a.ruleId ?? a.title ?? "?"));
      L.push(
        this.f(
          "incident",
          "corroboration",
          "Cross-source corroboration",
          noisyOr([saturate(sources.size - 1, 1.5), 0.5 * saturate(rules.size - 1, 3)]),
          `${rules.size} distinct detection(s) from ${sources.size} source(s) (${[...sources].slice(0, 4).join(", ")}).`,
        ),
      );
    }
    const techniques = dedupeTechniques([...(input.attack ?? []), ...alerts.flatMap((a) => a.attack ?? [])]);
    const tactics = tacticsOf(techniques);
    if (tactics.size > 0) {
      const late = [...tactics].filter((t) => LATE_STAGE_TACTICS.has(t));
      L.push(
        this.f(
          "incident",
          "attack_progression",
          "Kill-chain progression",
          noisyOr([saturate(tactics.size - 1, 2), late.length > 0 ? 0.7 : 0]),
          `${tactics.size} ATT&CK tactic(s) observed (${[...tactics].join(", ")})${late.length ? `; late-stage: ${late.join(", ")}` : ""}.`,
        ),
      );
    }
    const intel = input.intelMatches ?? [];
    if (intel.length > 0) L.push(this.f("incident", "threat_intel", "Threat intelligence match", intelValue(intel), describeIntel(intel)));

    if (input.assets.length > 0) {
      const crit = input.assets.map((a) => CRITICALITY_VALUE[a.criticality]);
      const top = input.assets.reduce((best, a) => (CRITICALITY_VALUE[a.criticality] > CRITICALITY_VALUE[best.criticality] ? a : best));
      I.push(this.f("incident", "asset_criticality", "Affected asset criticality", Math.max(...crit), `Most critical affected asset${top.name ? ` ${top.name}` : ""} is "${top.criticality.replace("_", " ")}".`));
    }
    if (input.identities.length > 0) {
      const priv = input.identities.filter((i) => i.privileged);
      I.push(
        this.f(
          "incident",
          "identity_privilege",
          "Privileged identities involved",
          priv.length > 0 ? 1 : 0.3 * saturate(input.identities.length, 5),
          priv.length > 0 ? `${priv.length} privileged identit${priv.length === 1 ? "y" : "ies"} involved${priv[0]?.principal ? ` (${priv.slice(0, 3).map((p) => p.principal).join(", ")})` : ""}.` : `${input.identities.length} standard identit${input.identities.length === 1 ? "y" : "ies"} involved.`,
        ),
      );
    }
    const scope = input.assets.length + input.identities.length;
    if (scope > 1) I.push(this.f("incident", "scope", "Incident scope", saturate(scope - 1, 4), `${input.assets.length} asset(s) and ${input.identities.length} identit${input.identities.length === 1 ? "y" : "ies"} affected.`));
    if (input.businessImpact !== undefined) I.push(this.f("incident", "business_impact", "Business impact", input.businessImpact, `Business impact rated ${round(input.businessImpact * 100, 0)}%.`));
    const impactTactics = [...tactics].filter((t) => IMPACT_TACTICS.has(t));
    if (impactTactics.length > 0) {
      I.push(
        this.f(
          "incident",
          "impact_tactics",
          "Data theft / destructive activity",
          impactTactics.some((t) => t === "exfiltration" || t === "impact") ? 1 : 0.5,
          `Observed ${impactTactics.join(", ")} activity.`,
        ),
      );
    }

    const ctl: FactorInput[] = [];
    const status = input.status;
    if (status === "contained") ctl.push({ key: "containment", label: "Contained", value: 1, weight: 0.7, explanation: "Incident is contained; attacker activity is restricted." });
    if (status === "remediated") ctl.push({ key: "containment", label: "Remediated", value: 1, weight: 0.9, explanation: "Incident is remediated." });
    if (status === "closed" || status === "false_positive") ctl.push({ key: "containment", label: status === "closed" ? "Closed" : "False positive", value: 1, weight: 0.98, explanation: `Incident is ${status.replace("_", " ")}.` });
    if (input.assets.length > 0) {
      const covered = input.assets.filter((a) => a.edr).length;
      if (covered > 0) ctl.push({ key: "edr", label: "EDR coverage", value: covered / input.assets.length, weight: 0.2, explanation: `${covered} of ${input.assets.length} affected asset(s) have healthy EDR (response actions available).` });
    }
    return computeRisk({ subject: input.title ? `Incident "${input.title}"` : "Incident", likelihood: L, impact: I, controls: ctl, curve: this.curve, modelVersion: `${RISK_MODEL_VERSION}#incident` });
  }

  // ─── Vulnerability (risk-based prioritization) ───────────────────────────

  scoreVulnerability(input: VulnerabilityRiskInput): VulnerabilityPriority {
    const v = input.vulnerability;
    const a = input.asset;
    const L: FactorInput[] = [];
    const I: FactorInput[] = [];
    const cvssPart = v.cvss !== null && v.cvss !== undefined ? (clamp01(v.cvss / 10)) ** 2 : null;
    if (v.epss !== null && v.epss !== undefined) {
      L.push(this.f("vulnerability", "exploit_prediction", "Exploit prediction (EPSS)", v.epss, `EPSS ${round(v.epss * 100, 1)}% probability of exploitation activity in the next 30 days.`));
    } else {
      L.push(this.f("vulnerability", "exploit_prediction", "Exploit prediction (estimated)", 0.6 * (cvssPart ?? 0.25), "No EPSS score available; estimated from CVSS."));
    }
    L.push(this.f("vulnerability", "known_exploited", "Known exploited (KEV)", v.knownExploited ? 1 : 0, v.knownExploited ? "Listed in CISA Known Exploited Vulnerabilities — exploited in the wild." : "Not on the KEV list."));
    if (cvssPart !== null) L.push(this.f("vulnerability", "cvss_exploitability", "CVSS base score", cvssPart, `CVSS ${v.cvss}.`));
    L.push(this.f("vulnerability", "exposure", "Asset exposure", a.internetFacing ? 1 : 0.15, a.internetFacing ? `${a.name} is internet-facing.` : `${a.name} is internal only.`));
    const intel = input.intelMatches ?? [];
    if (intel.length > 0) L.push(this.f("vulnerability", "threat_intel", "Threat actor targeting", intelValue(intel), describeIntel(intel)));
    if (v.patchAvailable === false) L.push(this.f("vulnerability", "no_patch", "No vendor patch", 1, "No vendor patch is available — the exposure window stays open until mitigated."));

    I.push(this.f("vulnerability", "severity", "Technical severity", cvssPart !== null ? clamp01((v.cvss ?? 0) / 10) : SEVERITY_WEIGHT[v.severity ?? "medium"], `Severity ${v.severity ?? severityFromCvss(v.cvss)}${v.cvss != null ? ` (CVSS ${v.cvss})` : ""}.`));
    I.push(this.f("vulnerability", "asset_criticality", "Asset criticality", CRITICALITY_VALUE[a.criticality], `${a.name} criticality "${a.criticality.replace("_", " ")}".`));
    if (input.businessImpact !== undefined) I.push(this.f("vulnerability", "business_impact", "Business impact", input.businessImpact, `Business impact rated ${round(input.businessImpact * 100, 0)}%.`));

    const ctl = this.controls(input.controls);
    if (v.status === "mitigated") ctl.push({ key: "mitigated", label: "Mitigation applied", value: 1, weight: 0.8, explanation: "A mitigation has been applied to this finding." });
    const name = vulnName(v);
    const r = computeRisk({ subject: `${name} on ${a.name}`, likelihood: L, impact: I, controls: ctl, curve: this.curve, modelVersion: `${RISK_MODEL_VERSION}#vulnerability` });

    let priority: VulnerabilityPriorityLevel;
    if ((v.knownExploited && (a.internetFacing || a.criticality === "crown_jewel")) || r.score >= 85) priority = "P1";
    else if (r.score >= 65) priority = "P2";
    else if (r.score >= 35) priority = "P3";
    else priority = "P4";
    const patch = v.patchAvailable !== false;
    const recommendedAction = priority === "P1" ? (patch ? "patch_now" : "mitigate") : priority === "P2" ? (patch ? "patch" : "mitigate") : patch ? "patch" : "monitor";
    const why: string[] = [];
    if (v.knownExploited) why.push("known exploited in the wild");
    if ((v.epss ?? 0) >= 0.5) why.push(`high exploit likelihood (EPSS ${round((v.epss ?? 0) * 100, 0)}%)`);
    if (a.internetFacing) why.push("internet-facing asset");
    if (a.criticality === "crown_jewel" || a.criticality === "high") why.push(`${a.criticality.replace("_", " ")} asset`);
    if (!patch) why.push("no vendor patch");
    const rationale = `${priority}: ${why.length ? why.join(", ") : "limited exploitability and impact"}; ${recommendedAction.replace("_", " ")} within ${this.slaDays[priority]} days.`;
    return { ...r, priority, slaDays: this.slaDays[priority], recommendedAction, rationale };
  }

  // ─── Organization exposure ────────────────────────────────────────────────

  /**
   * Unified exposure score for an organization. Deliberately NOT a vulnerability count:
   * every domain is expressed as *exploitable, reachable, business-relevant* exposure using
   * ratios and saturating functions, then combined with crown-jewel reachability as impact.
   */
  exposureScore(input: ExposureInputs): ExposureAssessment {
    const total = Math.max(1, input.assets.total);
    const drivers: Record<ExposureDomain, string[]> = { external: [], vulnerability: [], identity: [], cloud: [], saas: [], misconfiguration: [], attack_path: [], threat_intel: [] };
    const domain = (key: ExposureDomain, parts: Array<[number, string | null]>) => {
      for (const [v, text] of parts) if (v > 0.001 && text) drivers[key].push(text);
      return noisyOr(parts.map(([v]) => v));
    };

    const ext = input.external ?? {};
    const external = domain("external", [
      [0.7 * saturate(input.assets.internetFacing / total, 0.1), input.assets.internetFacing ? `${input.assets.internetFacing} internet-facing asset(s) (${round((100 * input.assets.internetFacing) / total, 1)}% of estate)` : null],
      [0.6 * saturate(ext.exposedAdminInterfaces ?? 0, 1), ext.exposedAdminInterfaces ? `${ext.exposedAdminInterfaces} exposed admin interface(s)` : null],
      [0.3 * saturate(ext.exposedServices ?? 0, 10), ext.exposedServices ? `${ext.exposedServices} exposed service(s)` : null],
      [0.5 * saturate(ext.unmanagedExternalAssets ?? 0, 2), ext.unmanagedExternalAssets ? `${ext.unmanagedExternalAssets} unmanaged / shadow-IT external asset(s)` : null],
    ]);
    const vu = input.vulnerabilities ?? {};
    const vulnerability = domain("vulnerability", [
      [0.95 * saturate(vu.knownExploitedOnInternetFacing ?? 0, 1), vu.knownExploitedOnInternetFacing ? `${vu.knownExploitedOnInternetFacing} known-exploited vulnerabilit(ies) on internet-facing assets` : null],
      [0.9 * saturate(vu.knownExploitedOnCrownJewels ?? 0, 1), vu.knownExploitedOnCrownJewels ? `${vu.knownExploitedOnCrownJewels} known-exploited vulnerabilit(ies) on crown-jewel assets` : null],
      [0.6 * saturate(vu.knownExploited ?? 0, 3), vu.knownExploited ? `${vu.knownExploited} known-exploited vulnerabilit(ies) overall` : null],
      [0.5 * saturate(vu.highEpss ?? 0, 5), vu.highEpss ? `${vu.highEpss} finding(s) with EPSS ≥ 50%` : null],
      [0.35 * saturate((vu.critical ?? 0) / total, 0.05), vu.critical ? `critical findings on ${round((100 * Math.min(vu.critical, total)) / total, 1)}%-equivalent of assets` : null],
      [0.3 * saturate((vu.overdueSla ?? 0) / Math.max(1, vu.open ?? 0), 0.2), vu.overdueSla ? `${vu.overdueSla} finding(s) past remediation SLA` : null],
    ]);
    const idn = input.identities ?? {};
    const identity = domain("identity", [
      [0.85 * saturate(idn.privilegedWithoutMfa ?? 0, 1), idn.privilegedWithoutMfa ? `${idn.privilegedWithoutMfa} privileged identit(ies) without MFA` : null],
      [0.5 * saturate(idn.dormantPrivileged ?? 0, 2), idn.dormantPrivileged ? `${idn.dormantPrivileged} dormant privileged account(s)` : null],
      [0.45 * saturate(idn.riskyServiceAccounts ?? 0, 3), idn.riskyServiceAccounts ? `${idn.riskyServiceAccounts} risky service account(s)` : null],
      [0.3 * saturate((idn.privileged ?? 0) / Math.max(1, idn.total ?? 0), 0.1), idn.privileged ? `${idn.privileged} privileged of ${idn.total ?? "?"} identities` : null],
    ]);
    const cl = input.cloud ?? {};
    const cloud = domain("cloud", [
      [0.85 * saturate(cl.publicStorage ?? 0, 1), cl.publicStorage ? `${cl.publicStorage} publicly accessible storage resource(s)` : null],
      [0.6 * saturate(cl.failingCriticalControls ?? 0, 2), cl.failingCriticalControls ? `${cl.failingCriticalControls} failing critical cloud control(s)` : null],
      [0.4 * saturate(cl.overPrivilegedRoles ?? 0, 5), cl.overPrivilegedRoles ? `${cl.overPrivilegedRoles} over-privileged cloud role(s)` : null],
      [0.3 * ratio(cl.failingControls, cl.totalControls), cl.failingControls ? `${cl.failingControls}/${cl.totalControls ?? "?"} cloud controls failing` : null],
    ]);
    const sa = input.saas ?? {};
    const saas = domain("saas", [
      [0.6 * saturate(sa.riskyOauthApps ?? 0, 2), sa.riskyOauthApps ? `${sa.riskyOauthApps} risky OAuth application grant(s)` : null],
      [0.4 * ratio(sa.failingControls, sa.totalControls), sa.failingControls ? `${sa.failingControls}/${sa.totalControls ?? "?"} SaaS controls failing` : null],
    ]);
    const mc = input.misconfigurations ?? {};
    const misconfiguration = domain("misconfiguration", [
      [0.6 * saturate(mc.critical ?? 0, 3), mc.critical ? `${mc.critical} critical misconfiguration(s)` : null],
      [0.4 * ratio(mc.failing, mc.total), mc.failing ? `${mc.failing}/${mc.total ?? "?"} configuration checks failing` : null],
    ]);
    const apx = input.attackPaths ?? {};
    const shortest = apx.shortestHopsToCrownJewel ?? null;
    const attackPath = domain("attack_path", [
      [0.9 * saturate(apx.toCrownJewels ?? 0, 1), apx.toCrownJewels ? `${apx.toCrownJewels} attack path(s) to crown-jewel assets` : null],
      [0.4 * saturate(apx.total ?? 0, 5), apx.total ? `${apx.total} attack path(s) in total` : null],
      [shortest !== null && shortest > 0 ? 0.6 * (1 / shortest) : 0, shortest ? `shortest path to a crown jewel is ${shortest} hop(s)` : null],
    ]);
    const ti = input.threatIntel ?? {};
    const threatIntel = domain("threat_intel", [
      [0.8 * saturate(ti.activeCampaignsTargeting ?? 0, 1), ti.activeCampaignsTargeting ? `${ti.activeCampaignsTargeting} active campaign(s) targeting the organization's technology` : null],
      [0.5 * saturate(ti.matchesLast30d ?? 0, 5), ti.matchesLast30d ? `${ti.matchesLast30d} threat-intel match(es) in the last 30 days` : null],
    ]);

    const values: Record<ExposureDomain, number> = { external, vulnerability, identity, cloud, saas, misconfiguration, attack_path: attackPath, threat_intel: threatIntel };
    const labels: Record<ExposureDomain, string> = {
      external: "External attack surface",
      vulnerability: "Exploitable vulnerabilities",
      identity: "Identity exposure",
      cloud: "Cloud exposure",
      saas: "SaaS exposure",
      misconfiguration: "Misconfiguration",
      attack_path: "Attack paths",
      threat_intel: "Active threat",
    };
    const L: FactorInput[] = (Object.keys(values) as ExposureDomain[])
      .filter((k) => values[k] > 0)
      .map((k) => this.f("exposure", k, labels[k], values[k], drivers[k].length ? `${capitalize(drivers[k].join("; "))}.` : `${labels[k]} signals present.`));

    const I: FactorInput[] = [];
    I.push(this.f("exposure", "business_baseline", "Business impact baseline", input.businessImpact ?? 0.5, `Baseline impact of a breach for ${input.organizationName ?? "the organization"} (${round((input.businessImpact ?? 0.5) * 100, 0)}%).`));
    const cjReach = noisyOr([0.9 * saturate(apx.toCrownJewels ?? 0, 1), 0.8 * saturate(vu.knownExploitedOnCrownJewels ?? 0, 1), input.assets.crownJewels > 0 ? 0.2 : 0]);
    if (cjReach > 0) I.push(this.f("exposure", "crown_jewel_reachability", "Crown-jewel reachability", cjReach, `${input.assets.crownJewels} crown-jewel asset(s); ${apx.toCrownJewels ?? 0} attack path(s) and ${vu.knownExploitedOnCrownJewels ?? 0} KEV finding(s) reach them.`));
    if ((idn.privilegedWithoutMfa ?? 0) > 0 || (idn.dormantPrivileged ?? 0) > 0) {
      I.push(this.f("exposure", "privileged_exposure", "Privileged access at risk", noisyOr([saturate(idn.privilegedWithoutMfa ?? 0, 1), 0.6 * saturate(idn.dormantPrivileged ?? 0, 2)]), "Compromise of exposed privileged identities grants broad control."));
    }

    const ctl: FactorInput[] = [];
    const c = input.controls ?? {};
    if (c.edrCoverage !== undefined && c.edrCoverage > 0) ctl.push({ key: "edr_coverage", label: "EDR coverage", value: c.edrCoverage, weight: 0.3, explanation: `${round(c.edrCoverage * 100, 0)}% of endpoints have healthy EDR.` });
    if (c.mfaCoverage !== undefined && c.mfaCoverage > 0) ctl.push({ key: "mfa_coverage", label: "MFA coverage", value: c.mfaCoverage, weight: 0.3, explanation: `${round(c.mfaCoverage * 100, 0)}% of identities enforce MFA.` });
    const seg = typeof c.segmentation === "boolean" ? (c.segmentation ? 1 : 0) : (c.segmentation ?? 0);
    if (seg > 0) ctl.push({ key: "segmentation", label: "Network segmentation", value: seg, weight: 0.25, explanation: `Network segmentation coverage ${round(seg * 100, 0)}%.` });
    if (c.backupCoverage !== undefined && c.backupCoverage > 0) ctl.push({ key: "backup_coverage", label: "Backup coverage", value: c.backupCoverage, weight: 0.1, explanation: `${round(c.backupCoverage * 100, 0)}% of critical assets have tested backups.` });

    const r = computeRisk({ subject: `Exposure of ${input.organizationName ?? "organization"}`, likelihood: L, impact: I, controls: ctl, curve: this.curve, modelVersion: `${RISK_MODEL_VERSION}#exposure` });
    const domains = Object.fromEntries((Object.keys(values) as ExposureDomain[]).map((k) => [k, { score: round(values[k] * 100, 1), drivers: drivers[k] }])) as ExposureAssessment["domains"];
    return { ...r, domains };
  }

  // ─── Attack path ──────────────────────────────────────────────────────────

  scoreAttackPath(input: AttackPathRiskInput): ExplainedRiskAssessment {
    const L: FactorInput[] = [];
    const I: FactorInput[] = [];
    L.push(this.f("path", "exploitability", "Exploitability", input.exploitability, input.exploitedCves.length ? `Requires exploiting ${input.exploitedCves.join(", ")} (exploitability ${round(input.exploitability * 100, 0)}%).` : "No vulnerability exploitation required (credential / rights abuse only)."));
    L.push(this.f("path", "known_exploitation", "Known exploitation", input.knownExploited ? 1 : 0, input.knownExploited ? "At least one step uses a vulnerability exploited in the wild (KEV)." : "No known-exploited vulnerabilities on the path."));
    L.push(this.f("path", "exposure", "Exposure", input.exposure, input.exposure >= 1 ? `Entry point ${input.entryLabel} is reachable from the internet.` : `Entry exposure ${round(input.exposure * 100, 0)}%.`));
    if (input.threatIntel > 0) L.push(this.f("path", "threat_intel", "Threat intelligence", input.threatIntel, "Threat-intel indicators were observed on nodes of this path."));
    if (input.lateralHops > 0) L.push(this.f("path", "lateral_movement", "Lateral movement potential", saturate(input.lateralHops, 2), `${input.lateralHops} lateral movement hop(s) between systems.`));

    I.push(this.f("path", "asset_criticality", "Target criticality", CRITICALITY_VALUE[input.targetCriticality], `Target ${input.targetLabel} is "${input.targetCriticality.replace("_", " ")}".`));
    if (input.identityPrivilege > 0) I.push(this.f("path", "identity_privilege", "Identity privilege", input.identityPrivilege, `Path passes through privileged identit${input.privilegedIdentities.length === 1 ? "y" : "ies"} ${input.privilegedIdentities.slice(0, 3).join(", ")}.`));
    if (input.privilegeEscalation > 0) I.push(this.f("path", "privilege", "Privilege escalation", input.privilegeEscalation, "Path grants administrative / ownership rights."));
    if (input.blastRadius.reachableNodes > 0) I.push(this.f("path", "blast_radius", "Blast radius", noisyOr([saturate(input.blastRadius.reachableNodes, 25), 0.8 * saturate(input.blastRadius.reachableCrownJewels, 1)]), describeBlast(input.blastRadius)));

    const ctl: FactorInput[] = [];
    const feasibility = clamp01(input.chainProbability) ** this.pathExponent;
    const complexity = clamp01(1 - feasibility);
    if (complexity > 0) {
      ctl.push({
        key: "path_complexity",
        label: "Path complexity",
        value: complexity,
        weight: 1,
        explanation: `${input.steps} step(s); combined step success probability ${round(input.chainProbability * 100, 1)}% (complexity-adjusted feasibility ${round(feasibility * 100, 1)}%).`,
      });
    }
    for (const c of input.controls) {
      ctl.push({ key: `control_${c.key}`, label: `${c.label} on ${c.on}`, value: 1, weight: clamp01(c.strength), explanation: `${c.label} on ${c.on} reduces the chance this step succeeds.` });
    }
    return computeRisk({ subject: `Attack path ${input.entryLabel} → ${input.targetLabel}`, likelihood: L, impact: I, controls: ctl, curve: this.curve, modelVersion: `${RISK_MODEL_VERSION}#attack-path` });
  }

  // ─── helpers ──────────────────────────────────────────────────────────────

  private controls(c: CompensatingControls | undefined, opts: { mfaStrength?: number } = {}): FactorInput[] {
    if (!c) return [];
    const out: FactorInput[] = [];
    if (c.isolated) out.push({ key: "isolated", label: "Host isolated", value: 1, weight: 0.9, explanation: "Endpoint is network-isolated by EDR." });
    if (c.edr) out.push({ key: "edr", label: "EDR coverage", value: c.edr === "degraded" ? 0.5 : 1, weight: 0.25, explanation: c.edr === "degraded" ? "EDR agent present but degraded (outdated or unresponsive)." : "Healthy EDR agent with response capability." });
    if (c.mfa) out.push({ key: "mfa", label: c.mfa === "phishing_resistant" ? "Phishing-resistant MFA" : "MFA enforced", value: c.mfa === "phishing_resistant" ? 1 : 0.85, weight: opts.mfaStrength ?? 0.2, explanation: c.mfa === "phishing_resistant" ? "Phishing-resistant MFA (FIDO2 / certificate) enforced." : "MFA enforced for interactive access." });
    if (c.conditionalAccess) out.push({ key: "conditional_access", label: "Conditional access", value: 1, weight: 0.2, explanation: "Conditional-access policies restrict sign-in context." });
    if (c.pam) out.push({ key: "pam", label: "Privileged access management", value: 1, weight: 0.35, explanation: "Privileged access is vaulted / just-in-time." });
    if (c.segmentation) out.push({ key: "segmentation", label: "Network segmentation", value: 1, weight: 0.25, explanation: "Asset sits in a segmented network zone." });
    if (c.virtualPatching) out.push({ key: "virtual_patching", label: "Virtual patching / WAF", value: 1, weight: 0.4, explanation: "A WAF / IPS signature shields the vulnerable service." });
    if (c.firewall) out.push({ key: "firewall", label: "Host firewall", value: 1, weight: 0.1, explanation: "Host firewall enabled." });
    for (const x of c.custom ?? []) out.push({ key: x.key, label: x.label, value: 1, weight: clamp01(x.strength), explanation: x.explanation ?? `${x.label} in place.` });
    return out;
  }
}

// ─── shared helpers ─────────────────────────────────────────────────────────

function openVulns(vulns: VulnerabilitySignal[]): VulnerabilitySignal[] {
  return vulns.filter((v) => v.status === undefined || v.status === "open" || v.status === "in_remediation" || v.status === "accepted");
}

function vulnName(v: VulnerabilitySignal): string {
  return v.cve ?? v.title ?? "unnamed finding";
}

function describeVuln(v: VulnerabilitySignal): string {
  const parts: string[] = [];
  if (v.cvss !== null && v.cvss !== undefined) parts.push(`CVSS ${v.cvss}`);
  if (v.epss !== null && v.epss !== undefined) parts.push(`EPSS ${round(v.epss * 100, 1)}%`);
  if (v.knownExploited) parts.push("KEV");
  return parts.join(", ") || "no scoring data";
}

export function severityFromCvss(cvss: number | null | undefined): Severity {
  if (cvss === null || cvss === undefined) return "medium";
  if (cvss >= 9) return "critical";
  if (cvss >= 7) return "high";
  if (cvss >= 4) return "medium";
  if (cvss > 0) return "low";
  return "info";
}

function countBySeverity(sevs: Severity[]): string {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  return order
    .map((s) => [s, sevs.filter((x) => x === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`)
    .join(", ");
}

function intelValue(intel: IntelSignal[]): number {
  return noisyOr(intel.map((i) => clamp01(i.confidence / 100) * SEVERITY_WEIGHT[i.severity]));
}

function describeIntel(intel: IntelSignal[]): string {
  const actors = [...new Set(intel.flatMap((i) => [i.threatActor, i.campaign]).filter((x): x is string => !!x))];
  const best = intel.reduce((a, b) => (b.confidence * SEVERITY_WEIGHT[b.severity] > a.confidence * SEVERITY_WEIGHT[a.severity] ? b : a));
  return `${intel.length} threat-intel match(es); strongest ${best.value} (${best.severity}, confidence ${best.confidence})${actors.length ? `; associated with ${actors.slice(0, 3).join(", ")}` : ""}.`;
}

/** Noisy-OR over the strongest signal of each distinct rule — volume of repeats adds nothing. */
function detectionValue(dets: DetectionSignal[]): number {
  const best = new Map<string, number>();
  for (const d of dets) {
    const key = d.ruleId ?? d.title ?? `${d.severity}:${d.confidence}`;
    best.set(key, Math.max(best.get(key) ?? 0, clamp01(d.confidence) * SEVERITY_WEIGHT[d.severity]));
  }
  return noisyOr(best.values());
}

function describeDetections(dets: DetectionSignal[]): string {
  const distinct = new Map<string, DetectionSignal>();
  for (const d of dets) {
    const key = d.ruleId ?? d.title ?? `${d.severity}:${d.confidence}`;
    const cur = distinct.get(key);
    if (!cur || SEVERITY_WEIGHT[d.severity] * d.confidence > SEVERITY_WEIGHT[cur.severity] * cur.confidence) distinct.set(key, d);
  }
  const top = [...distinct.values()].sort((a, b) => SEVERITY_WEIGHT[b.severity] * b.confidence - SEVERITY_WEIGHT[a.severity] * a.confidence);
  const lead = top[0]!;
  return `${dets.length} alert(s) from ${distinct.size} distinct detection(s); strongest "${lead.title ?? lead.ruleId ?? "detection"}" (${lead.severity}, confidence ${round(lead.confidence * 100, 0)}%).`;
}

function describeBlast(br: { reachableNodes: number; reachableCrownJewels: number }): string {
  return `Compromise could reach ${br.reachableNodes} further node(s)${br.reachableCrownJewels ? `, including ${br.reachableCrownJewels} crown-jewel asset(s)` : ""}.`;
}

function businessImpactValue(bi: AssetRiskInput["businessImpact"]): { value: number; explanation: string } | null {
  if (bi === undefined) return null;
  if (typeof bi === "number") return { value: clamp01(bi), explanation: `Business impact rated ${round(clamp01(bi) * 100, 0)}%.` };
  const sens = { public: 0.1, internal: 0.35, confidential: 0.7, restricted: 1 } as const;
  let value = bi.dataSensitivity ? sens[bi.dataSensitivity] : 0;
  const parts: string[] = [];
  if (bi.dataSensitivity) parts.push(`${bi.dataSensitivity} data`);
  if (bi.regulated) {
    value = Math.max(value, 0.8);
    parts.push("regulated data (breach notification obligations)");
  }
  if (bi.revenueCritical) {
    value = noisyOr([value, 0.7]);
    parts.push("revenue-critical service");
  }
  if (parts.length === 0) return null;
  return { value, explanation: `${capitalize(parts.join(", "))}.` };
}

function ratio(n: number | undefined, d: number | undefined): number {
  if (!n || !d) return n ? 0.5 : 0;
  return clamp01(n / d);
}

function dedupeTechniques(ts: AttackTechnique[]): AttackTechnique[] {
  const m = new Map<string, AttackTechnique>();
  for (const t of ts) {
    const cur = m.get(t.id);
    if (!cur || (!cur.tactic && t.tactic)) m.set(t.id, t);
  }
  return [...m.values()];
}

function capitalize(s: string): string {
  return s.length ? s[0]!.toUpperCase() + s.slice(1) : s;
}

