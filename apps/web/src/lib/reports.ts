import { REPORT_TYPES, type ReportFormat, type ReportType } from "@bloody/contracts";

export const REPORT_FORMATS: { value: ReportFormat; label: string }[] = [
  { value: "pdf", label: "PDF" },
  { value: "html", label: "HTML" },
  { value: "csv", label: "CSV" },
  { value: "json", label: "JSON" },
];

export const REPORT_PERIODS = [7, 30, 90, 180, 365] as const;

export function reportLabel(type: ReportType): string {
  return REPORT_TYPES.find((r) => r.key === type)?.label ?? type;
}

export function reportAudience(type: ReportType): string {
  return REPORT_TYPES.find((r) => r.key === type)?.audience ?? "soc";
}
