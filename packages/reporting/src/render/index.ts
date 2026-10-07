import type { ReportFormat } from "@bloody/contracts";
import { slugify } from "../format.js";
import type { ReportData } from "../model.js";
import { renderCsv } from "./csv.js";
import { renderHtml } from "./html.js";
import { renderPdf } from "./pdf.js";

export interface RenderedReport {
  filename: string;
  contentType: string;
  extension: string;
  content: Buffer;
}

/** Stable, machine-readable JSON form of the report (also what the Command Center renders in-app). */
export function renderJson(report: ReportData, opts: { pretty?: boolean } = {}): string {
  return JSON.stringify(report, null, opts.pretty === false ? 0 : 2);
}

/** "acme-mssp-customer-monthly-2026-09-30.pdf" */
export function reportFilename(report: ReportData, extension: string): string {
  const who = report.scope.organizationName ?? report.branding.name;
  const end = new Date(Date.parse(report.period.to) - 1).toISOString().slice(0, 10);
  return `${slugify(who)}-${report.type.replace(/_/g, "-")}-${end}.${extension}`;
}

/** Render a built report in any supported format. */
export async function renderReport(report: ReportData, format: ReportFormat): Promise<RenderedReport> {
  switch (format) {
    case "html":
      return { filename: reportFilename(report, "html"), extension: "html", contentType: "text/html; charset=utf-8", content: Buffer.from(renderHtml(report), "utf8") };
    case "pdf":
      return { filename: reportFilename(report, "pdf"), extension: "pdf", contentType: "application/pdf", content: await renderPdf(report) };
    case "csv":
      return { filename: reportFilename(report, "csv"), extension: "csv", contentType: "text/csv; charset=utf-8; header=present", content: Buffer.from(renderCsv(report), "utf8") };
    case "json":
      return { filename: reportFilename(report, "json"), extension: "json", contentType: "application/json; charset=utf-8", content: Buffer.from(renderJson(report), "utf8") };
    default: {
      const never: never = format;
      throw new Error(`unsupported format ${String(never)}`);
    }
  }
}
