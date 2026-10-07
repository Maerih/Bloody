import { severityFromScore, type Severity } from "@bloody/contracts";

export interface SeverityMeta {
  label: string;
  /** CSS colour usable in SVG / inline styles. */
  color: string;
  text: string;
  bg: string;
  softBg: string;
  border: string;
}

/** Fixed severity semantics: critical red, high orange, medium amber, low purple, info slate. */
export const SEVERITY_META: Record<Severity, SeverityMeta> = {
  critical: {
    label: "Critical",
    color: "rgb(var(--sev-critical))",
    text: "text-sev-critical",
    bg: "bg-sev-critical",
    softBg: "bg-sev-critical/10",
    border: "border-sev-critical",
  },
  high: {
    label: "High",
    color: "rgb(var(--sev-high))",
    text: "text-sev-high",
    bg: "bg-sev-high",
    softBg: "bg-sev-high/10",
    border: "border-sev-high",
  },
  medium: {
    label: "Medium",
    color: "rgb(var(--sev-medium))",
    text: "text-sev-medium",
    bg: "bg-sev-medium",
    softBg: "bg-sev-medium/15",
    border: "border-sev-medium",
  },
  low: {
    label: "Low",
    color: "rgb(var(--sev-low))",
    text: "text-sev-low",
    bg: "bg-sev-low",
    softBg: "bg-sev-low/10",
    border: "border-sev-low",
  },
  info: {
    label: "Info",
    color: "rgb(var(--sev-info))",
    text: "text-sev-info",
    bg: "bg-sev-info",
    softBg: "bg-sev-info/10",
    border: "border-sev-info",
  },
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityMetaForScore(score: number): SeverityMeta & { severity: Severity } {
  const severity = severityFromScore(score);
  return { ...SEVERITY_META[severity], severity };
}

export const CHART_COLORS = {
  healthy: "rgb(var(--healthy))",
  critical: "rgb(var(--sev-critical))",
  high: "rgb(var(--sev-high))",
  medium: "rgb(var(--sev-medium))",
  low: "rgb(var(--sev-low))",
  info: "rgb(var(--sev-info))",
  neutral: "rgb(var(--border-strong))",
  primary: "rgb(var(--primary))",
} as const;
