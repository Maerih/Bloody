import type { ReportType, RiskFactor, Severity } from "@bloody/contracts";

/**
 * Bloody report model. Builders produce a `ReportData` document — pure data, no presentation —
 * and renderers turn it into HTML, PDF, CSV or JSON. The JSON form is also what the Command
 * Center renders natively in-app, so a report looks the same on screen, on paper and in e-mail.
 */
export type ReportAudience = "business" | "soc" | "mssp" | "customer";

export type ValueUnit = "count" | "percent" | "minutes" | "hours" | "days" | "score" | "currency" | "ratio";

export type Sentiment = "good" | "bad" | "neutral";

export interface KpiDelta {
  previous: number | null;
  absolute: number | null;
  /** Relative change in percent (null when the previous value is 0 / unknown). */
  percent: number | null;
  direction: "up" | "down" | "flat";
  /** Whether the change is good news (depends on whether higher is better). */
  sentiment: Sentiment;
}

export interface Kpi {
  key: string;
  label: string;
  value: number | null;
  unit: ValueUnit;
  currency?: string;
  delta: KpiDelta | null;
  /** Target / objective, e.g. 95 (%) SLA attainment. */
  target: number | null;
  status: "good" | "warn" | "bad" | null;
  /** How the number was computed (explainability; shown as footnote / tooltip / methodology). */
  explanation: string;
}

export interface ChartSeries {
  key: string;
  name: string;
  values: (number | null)[];
  /** Fixed colour (severity charts); otherwise categorical slots are assigned in order. */
  color?: string;
}

export type ChartType = "bar" | "stacked_bar" | "hbar" | "line" | "donut";

export interface ChartSpec {
  id: string;
  type: ChartType;
  title: string;
  subtitle?: string;
  unit: ValueUnit;
  currency?: string;
  categories: string[];
  series: ChartSeries[];
  /** Per-category colours (donut slices / single-series bars by severity). */
  categoryColors?: (string | null)[];
  emptyMessage?: string;
}

export type CellValue = string | number | boolean | null;

export type ColumnFormat = "text" | "number" | "percent" | "minutes" | "days" | "currency" | "severity" | "date" | "datetime" | "status" | "score" | "code";

export interface TableColumn {
  key: string;
  label: string;
  format?: ColumnFormat;
  align?: "left" | "right" | "center";
  /** Relative width hint for PDF/HTML layout. */
  width?: number;
}

export interface TableSpec {
  id: string;
  title: string;
  columns: TableColumn[];
  rows: Record<string, CellValue>[];
  emptyMessage: string;
  /** Total rows available when `rows` was truncated to a top-N. */
  totalRows?: number;
  note?: string;
  currency?: string;
}

export interface RiskItem {
  id: string;
  title: string;
  subject: string | null;
  severity: Severity;
  score: number;
  factors: RiskFactor[];
  recommendation: string | null;
}

export type RecommendationPriority = "critical" | "high" | "medium" | "low";

export interface Recommendation {
  priority: RecommendationPriority;
  title: string;
  rationale: string;
  owner: "customer" | "soc" | "mssp" | "it" | "security_engineering" | "management" | null;
}

export type ReportBlock =
  | { kind: "kpis"; items: Kpi[] }
  | { kind: "chart"; chart: ChartSpec }
  | { kind: "table"; table: TableSpec }
  | { kind: "narrative"; paragraphs: string[]; tone?: "default" | "ai" | "note"; label?: string }
  | { kind: "risks"; title?: string; items: RiskItem[]; emptyMessage?: string }
  | { kind: "recommendations"; title?: string; items: Recommendation[]; emptyMessage?: string }
  | { kind: "callout"; tone: "info" | "success" | "warning" | "critical"; title: string; text: string };

export interface ReportSection {
  id: string;
  title: string;
  description?: string;
  blocks: ReportBlock[];
}

export interface ReportPeriod {
  from: string;
  to: string;
  days: number;
  label: string;
  previousFrom: string;
  previousTo: string;
}

export interface ReportBranding {
  name: string;
  /** #RRGGBB */
  primaryColor: string;
  logoDataUrl: string | null;
  /** "Powered by Bloody" is shown only for white-labelled reports when enabled. */
  poweredBy: boolean;
  footerText: string | null;
}

export interface ReportData {
  schemaVersion: "1.0";
  id: string;
  type: ReportType;
  typeLabel: string;
  title: string;
  subtitle: string;
  audience: ReportAudience;
  generatedAt: string;
  period: ReportPeriod;
  scope: {
    tenantId: string;
    organizationIds: string[] | "all";
    organizationName: string | null;
    organizationCount: number;
  };
  branding: ReportBranding;
  classification: string;
  preparedFor: string | null;
  preparedBy: string | null;
  summary: { headline: string; highlights: string[]; kpis: Kpi[] };
  sections: ReportSection[];
  methodology: { term: string; definition: string }[];
  /** Caveats about missing / partial data (explainability — never silently hidden). */
  dataQuality: string[];
}
