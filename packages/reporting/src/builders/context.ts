import type { ReportType, Severity } from "@bloody/contracts";
import type { BrandingInput } from "../branding.js";
import type { OrganizationFact, ReportDataSource, ReportQuery } from "../datasource.js";
import type { Kpi, Recommendation, ReportAudience, ReportPeriod, ReportSection } from "../model.js";
import { mergeSlaTargets, type SlaTargets, DEFAULT_SLA_TARGETS } from "../sla.js";

export interface ReportOptions {
  /** Incident report: produce a post-incident report for this incident. */
  incidentId?: string;
  /** Size of top-N lists (default 10, max 50). */
  topN?: number;
  /** Tenant default SLA targets (organization overrides from the data source win). */
  slaTargets?: Partial<SlaTargets>;
  currency?: string;
  locale?: string;
  timeZone?: string;
  /** Document classification printed on every page (default "Confidential"). */
  classification?: string;
  preparedFor?: string;
  preparedBy?: string;
}

export type PeriodInput = { from: Date | string; to: Date | string } | { days: number; endingAt?: Date | string };

export interface ReportRequest {
  type: ReportType;
  tenantId: string;
  /** Organization scope the caller is authorised for (derived from the principal by the API). */
  organizationIds: readonly string[] | "all";
  period: PeriodInput;
  branding?: Partial<BrandingInput> | null;
  options?: ReportOptions;
}

/** Report-ready aggregates handed to an AI narrative provider (e.g. @bloody/ai). */
export interface NarrativeInput {
  type: ReportType;
  audience: ReportAudience;
  title: string;
  periodLabel: string;
  organizationName: string | null;
  kpis: Kpi[];
  highlights: string[];
  recommendations: Recommendation[];
}

export interface NarrativeOutput {
  headline: string;
  summary: string;
  keyFindings: string[];
  recommendations?: { action: string; priority: "critical" | "high" | "medium" | "low"; owner?: string }[];
  outlook?: string;
  disclaimer?: string;
  model?: string;
}

/** Optional AI commentary. Failures never fail the report (noted under data quality). */
export type NarrativeProvider = (input: NarrativeInput) => Promise<NarrativeOutput>;

export interface ReportBuildDeps {
  dataSource: ReportDataSource;
  clock?: { now(): Date };
  ids?: () => string;
  narrative?: NarrativeProvider;
}

export interface BuildContext {
  type: ReportType;
  ds: ReportDataSource;
  q: ReportQuery;
  prev: ReportQuery;
  from: Date;
  to: Date;
  period: ReportPeriod;
  organizations: OrganizationFact[];
  /** Name of the single organization in scope, else null. */
  scopeName: string | null;
  orgName(id: string): string;
  slaTargetsFor(organizationId: string): SlaTargets;
  topN: number;
  currency: string;
  locale: string;
  timeZone: string;
  options: ReportOptions;
  now: Date;
  /** Data-quality caveats collected while building. */
  notes: string[];
}

export interface BuilderResult {
  title: string;
  subtitle: string;
  summary: { headline: string; highlights: string[]; kpis: Kpi[] };
  sections: ReportSection[];
  /** Glossary terms used by this report (keys of GLOSSARY) plus custom entries. */
  terms: string[];
  recommendations: Recommendation[];
}

export type ReportBuilder = (ctx: BuildContext) => Promise<BuilderResult>;

export class ReportRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReportRequestError";
  }
}

export function toDate(v: Date | string, what: string): Date {
  const d = v instanceof Date ? new Date(v.getTime()) : new Date(v);
  if (Number.isNaN(d.getTime())) throw new ReportRequestError(`invalid ${what}`);
  return d;
}

/** Resolve [from, to) and the immediately preceding period of equal length. */
export function resolvePeriod(input: PeriodInput, now: Date): { from: Date; to: Date; prevFrom: Date } {
  let from: Date;
  let to: Date;
  if ("days" in input) {
    if (!Number.isInteger(input.days) || input.days < 1 || input.days > 366) throw new ReportRequestError("period.days must be 1-366");
    to = input.endingAt ? toDate(input.endingAt, "period.endingAt") : now;
    from = new Date(to.getTime() - input.days * 86_400_000);
  } else {
    from = toDate(input.from, "period.from");
    to = toDate(input.to, "period.to");
  }
  if (to.getTime() <= from.getTime()) throw new ReportRequestError("period end must be after its start");
  if (to.getTime() - from.getTime() > 400 * 86_400_000) throw new ReportRequestError("period may not exceed 400 days");
  const len = to.getTime() - from.getTime();
  return { from, to, prevFrom: new Date(from.getTime() - len) };
}

export function slaResolver(tenantDefault: Partial<SlaTargets> | undefined, organizations: readonly OrganizationFact[]): (organizationId: string) => SlaTargets {
  const base = mergeSlaTargets(DEFAULT_SLA_TARGETS, tenantDefault);
  const byOrg = new Map(organizations.map((o) => [o.id, mergeSlaTargets(base, o.slaTargets)]));
  return (id) => byOrg.get(id) ?? base;
}

export const SEVERITY_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

/** Definitions used in the methodology appendix (explainability). */
export const GLOSSARY: Record<string, string> = {
  MTTD: "Mean time to detect — average time from the first malicious activity linked to an incident to its detection. Only incidents with a known first-activity time are included.",
  MTTA: "Mean time to acknowledge — average time from detection until an analyst acknowledged the incident.",
  MTTC: "Mean time to contain — average time from detection until containment (e.g. host isolation, account disable).",
  MTTR: "Mean time to resolve — average time from detection to closure, for incidents closed during the period.",
  "SLA attainment": "Share of SLA objectives met: acknowledge and resolve targets per severity, evaluated for incidents detected in the period. Objectives not yet due are excluded; overdue open incidents count as breaches.",
  "False-positive rate": "Alerts closed as false positive divided by all alerts in the period.",
  "Risk score": "Risk Engine score (0-100): an explainable likelihood × impact model; each score lists the factors that contributed.",
  "Exposure score": "Aggregate exposure (0-100) from vulnerabilities, internet-facing assets, identity weaknesses and attack paths to crown jewels.",
  KEV: "Known Exploited Vulnerabilities — vulnerabilities with confirmed exploitation in the wild (e.g. the CISA KEV catalogue).",
  EPSS: "Exploit Prediction Scoring System — probability of exploitation in the next 30 days.",
  "Mean time to remediate": "Average days from first detection of a vulnerability to its resolution, for vulnerabilities resolved in the period.",
  "Compliance score": "(passing controls + ½ × partially passing) ÷ applicable controls. Evidence-based indicator from platform telemetry, not a certification.",
  "Workload balance": "Coefficient of variation of incidents assigned per analyst (standard deviation ÷ mean); lower is more evenly balanced.",
  MRR: "Monthly recurring revenue from customer subscriptions at the end of the period. ARR = MRR × 12.",
  "Escalation on-time rate": "Escalations resolved by their due date, divided by escalations resolved or overdue.",
  "Trend vs previous period": "Each change compares the period with the immediately preceding period of equal length.",
};
