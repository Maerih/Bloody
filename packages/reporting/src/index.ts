/**
 * @bloody/reporting — modern reporting for every Bloody audience.
 *
 *   Builders   one per REPORT_TYPES entry: executive/CISO, SOC operations, incident (period or
 *              post-incident), vulnerability & exposure, threat intelligence, compliance posture,
 *              SLA performance, analyst activity, customer monthly service review, MSSP portfolio
 *              & revenue. Each takes an injected ReportDataSource + period + organization scope
 *              and computes derived metrics (MTTD/MTTA/MTTC/MTTR, SLA attainment, trends vs the
 *              previous period, top risks with explainable factors, top ATT&CK techniques,
 *              rule-based recommendations).
 *   Renderers  HTML (print-ready, branded, inline SVG charts, cover, TOC), PDF (pdfkit vector
 *              charts, paginated tables, bookmarks), CSV (RFC 4180 + formula-injection
 *              protection), JSON.
 *   Branding   white-label (name, colour, logo) so MSSPs issue reports under their own brand.
 */
export * from "./model.js";
export * from "./datasource.js";
export * from "./sla.js";
export * from "./metrics.js";
export * from "./format.js";
export * from "./branding.js";
export * from "./builders/context.js";
export * from "./builders/recommendations.js";
export { buildReport, REPORT_BUILDERS } from "./builders/index.js";
export { layoutChart, niceScale, type ChartScene, type Primitive } from "./render/chart-scene.js";
export { renderChartSvg, sceneToSvg } from "./render/svg.js";
export { renderHtml, type HtmlRenderOptions } from "./render/html.js";
export { renderPdf, pdfSafe, type PdfRenderOptions } from "./render/pdf.js";
export { renderCsv, renderCsvTables, csvField, csvRow, neutralizeFormula, type CsvOptions } from "./render/csv.js";
export { renderJson, renderReport, reportFilename, type RenderedReport } from "./render/index.js";
export { formatCell, humanize } from "./render/cells.js";
