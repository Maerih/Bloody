import type { Severity } from "@bloody/contracts";
import { brandInk, INK, mix, onColor, SENTIMENT_COLOR, SEVERITY_COLOR, STATUS_COLOR } from "../branding.js";
import { formatDateTime, formatNumber, formatValue } from "../format.js";
import type { ChartSpec, Kpi, Recommendation, ReportBlock, ReportData, RiskItem, TableSpec } from "../model.js";
import { formatCell, humanize, isNumericColumn } from "./cells.js";
import { cssColor, escapeHtml, stripControl } from "./escape.js";
import { renderChartSvg } from "./svg.js";

/**
 * Self-contained, print-ready HTML report: inline CSS, inline SVG charts, cover page, table of
 * contents, numbered sections with page breaks, methodology appendix. No scripts and no
 * external resources — a strict CSP meta tag enforces it, so the file is safe to e-mail,
 * archive or open from the portal. Print to PDF from any modern browser (A4, page numbers).
 */
export interface HtmlRenderOptions {
  /** Expand "View data" tables under charts (useful for screen readers / print). */
  expandChartData?: boolean;
}

const e = (s: string | null | undefined): string => escapeHtml(stripControl(s ?? ""));

function cssString(s: string): string {
  return `"${stripControl(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/[\r\n]+/g, " ")}"`;
}

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function sevPill(value: string): string {
  const sev = (SEV_ORDER as string[]).includes(value) ? (value as Severity) : null;
  if (!sev) return `<span class="pill">${e(humanize(value))}</span>`;
  return `<span class="sev"><i style="background:${SEVERITY_COLOR[sev]}"></i>${e(humanize(sev))}</span>`;
}

function kpiCard(k: Kpi, termIndex: Map<string, number>): string {
  const value = formatValue(k.value, k.unit, { compact: true, ...(k.currency ? { currency: k.currency } : {}) });
  let delta = "";
  if (k.delta) {
    const arrow = k.delta.direction === "up" ? "▲" : k.delta.direction === "down" ? "▼" : "▶";
    const amount = k.delta.percent !== null ? `${Math.abs(k.delta.percent).toFixed(Math.abs(k.delta.percent) < 10 ? 1 : 0)}%` : formatValue(Math.abs(k.delta.absolute ?? 0), k.unit, { compact: true, ...(k.currency ? { currency: k.currency } : {}) });
    delta = `<div class="kpi-delta" style="color:${SENTIMENT_COLOR[k.delta.sentiment]}"><span aria-hidden="true">${arrow}</span> ${k.delta.direction === "flat" ? "No change" : e(amount)} <span class="muted">vs previous period</span></div>`;
  }
  const status = k.status ? `<div class="kpi-status"><i style="background:${STATUS_COLOR[k.status]}"></i>${k.status === "good" ? "On target" : k.status === "warn" ? "Watch" : "Action needed"}${k.target !== null ? ` · target ${e(formatValue(k.target, k.unit, k.currency ? { currency: k.currency } : {}))}` : ""}</div>` : k.target !== null ? `<div class="kpi-status muted">Target ${e(formatValue(k.target, k.unit, k.currency ? { currency: k.currency } : {}))}</div>` : "";
  void termIndex;
  return `<div class="kpi"><div class="kpi-label">${e(k.label)}</div><div class="kpi-value">${e(value)}</div>${delta}${status}<div class="kpi-note">${e(k.explanation)}</div></div>`;
}

function tableHtml(t: TableSpec, opts: { timeZone: string; currency?: string; caption?: boolean }): string {
  if (t.rows.length === 0) return `<div class="empty">${e(t.emptyMessage)}</div>`;
  const head = t.columns.map((c) => `<th scope="col" class="${isNumericColumn(c) ? "num" : ""}">${e(c.label)}</th>`).join("");
  const body = t.rows
    .map(
      (r) =>
        `<tr>${t.columns
          .map((c) => {
            const v = r[c.key] ?? null;
            const text = formatCell(v, c, { timeZone: opts.timeZone, ...(t.currency || opts.currency ? { currency: t.currency ?? opts.currency } : {}) });
            const inner = c.format === "severity" && typeof v === "string" ? sevPill(v) : c.format === "status" && typeof v === "string" ? `<span class="pill">${e(text)}</span>` : c.format === "code" ? `<code>${e(text)}</code>` : e(text);
            return `<td class="${isNumericColumn(c) ? "num" : ""}">${inner}</td>`;
          })
          .join("")}</tr>`,
    )
    .join("");
  const more = t.totalRows !== undefined && t.totalRows > t.rows.length ? `<p class="table-note">Showing ${formatNumber(t.rows.length)} of ${formatNumber(t.totalRows)}. The full list is in the CSV export.</p>` : "";
  const note = t.note ? `<p class="table-note">${e(t.note)}</p>` : "";
  return `<div class="table-wrap"><table class="data">${opts.caption === false ? "" : `<caption>${e(t.title)}</caption>`}<thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>${more}${note}`;
}

function chartHtml(c: ChartSpec, opts: HtmlRenderOptions & { timeZone: string }): string {
  const half = c.type === "donut" || c.type === "hbar";
  const svg = renderChartSvg(c, { width: half ? 420 : 680, height: c.type === "donut" ? 190 : 240 });
  const dataTable: TableSpec = {
    id: `${c.id}-data`,
    title: `${c.title} — data`,
    columns: [{ key: "category", label: "Category" }, ...c.series.map((s) => ({ key: s.key, label: s.name, format: (c.unit === "percent" ? "percent" : c.unit === "minutes" ? "minutes" : c.unit === "currency" ? "currency" : "number") as "percent" | "minutes" | "currency" | "number", align: "right" as const }))],
    rows: c.categories.map((cat, i) => ({ category: cat, ...Object.fromEntries(c.series.map((s) => [s.key, s.values[i] ?? null])) })),
    emptyMessage: c.emptyMessage ?? "No data.",
    ...(c.currency ? { currency: c.currency } : {}),
  };
  return `<figure class="chart${half ? " half" : ""}"><figcaption><strong>${e(c.title)}</strong>${c.subtitle ? `<span>${e(c.subtitle)}</span>` : ""}</figcaption>${svg}<details class="chart-data"${opts.expandChartData ? " open" : ""}><summary>View data</summary>${tableHtml(dataTable, { timeZone: opts.timeZone, caption: false })}</details></figure>`;
}

function risksHtml(items: RiskItem[], emptyMessage: string): string {
  if (items.length === 0) return `<div class="empty">${e(emptyMessage)}</div>`;
  return `<div class="risks">${items
    .map((r) => {
      const max = Math.max(1, ...r.factors.map((f) => Math.abs(f.contribution)));
      const factors = [...r.factors]
        .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution))
        .slice(0, 6)
        .map((f) => `<li><span class="f-label">${e(f.label)}</span><span class="f-bar"><i style="width:${Math.max(2, (Math.abs(f.contribution) / max) * 100).toFixed(1)}%;background:${f.contribution < 0 ? STATUS_COLOR.good : SEVERITY_COLOR[r.severity]}"></i></span><span class="f-val">${f.contribution >= 0 ? "+" : "−"}${e(formatNumber(Math.abs(f.contribution), { digits: 1 }))}</span><span class="f-expl">${e(f.explanation)}</span></li>`)
        .join("");
      return `<article class="risk"><header>${sevPill(r.severity)}<h4>${e(r.title)}</h4><span class="score" title="Risk score">${e(formatNumber(Math.round(r.score)))}</span></header>${r.subject ? `<p class="subject">${e(r.subject)}</p>` : ""}${factors ? `<ul class="factors" aria-label="Contributing factors">${factors}</ul>` : `<p class="muted">No factor breakdown available.</p>`}${r.recommendation ? `<p class="rec"><strong>Recommended:</strong> ${e(r.recommendation)}</p>` : ""}</article>`;
    })
    .join("")}</div>`;
}

const OWNER_LABEL: Record<NonNullable<Recommendation["owner"]>, string> = { customer: "Your team", soc: "SOC", mssp: "Service management", it: "IT operations", security_engineering: "Security engineering", management: "Management" };

function recommendationsHtml(items: Recommendation[], emptyMessage: string): string {
  if (items.length === 0) return `<div class="empty ok">${e(emptyMessage)}</div>`;
  return `<ol class="recs">${items
    .map((r) => `<li><span class="prio prio-${r.priority}">${e(humanize(r.priority))}</span><div><strong>${e(r.title)}</strong><p>${e(r.rationale)}</p>${r.owner ? `<span class="owner">Owner: ${e(OWNER_LABEL[r.owner])}</span>` : ""}</div></li>`)
    .join("")}</ol>`;
}

function blockHtml(b: ReportBlock, ctx: { timeZone: string; currency?: string; opts: HtmlRenderOptions; termIndex: Map<string, number> }): string {
  switch (b.kind) {
    case "kpis":
      return `<div class="kpis">${b.items.map((k) => kpiCard(k, ctx.termIndex)).join("")}</div>`;
    case "chart":
      return chartHtml(b.chart, { ...ctx.opts, timeZone: ctx.timeZone });
    case "table":
      return `<div class="block-table">${tableHtml(b.table, { timeZone: ctx.timeZone, ...(ctx.currency ? { currency: ctx.currency } : {}) })}</div>`;
    case "narrative":
      if (b.paragraphs.length === 0) return "";
      return `<div class="narrative${b.tone ? ` tone-${b.tone}` : ""}">${b.label ? `<span class="narrative-label">${e(b.label)}</span>` : ""}${b.paragraphs.map((p) => `<p>${e(p)}</p>`).join("")}</div>`;
    case "risks":
      return `${b.title ? `<h3>${e(b.title)}</h3>` : ""}${risksHtml(b.items, b.emptyMessage ?? "No risks to report.")}`;
    case "recommendations":
      return `${b.title ? `<h3>${e(b.title)}</h3>` : ""}${recommendationsHtml(b.items, b.emptyMessage ?? "No actions required.")}`;
    case "callout":
      return `<aside class="callout callout-${b.tone}" role="note"><strong>${e(b.title)}</strong><p>${e(b.text)}</p></aside>`;
  }
}

/** Group consecutive "half" charts into a two-column grid. */
function sectionBody(blocks: ReportBlock[], ctx: Parameters<typeof blockHtml>[1]): string {
  const out: string[] = [];
  let grid: string[] = [];
  const flush = (): void => {
    if (grid.length > 0) out.push(`<div class="grid2">${grid.join("")}</div>`);
    grid = [];
  };
  for (const b of blocks) {
    if (b.kind === "chart" && (b.chart.type === "donut" || b.chart.type === "hbar")) grid.push(blockHtml(b, ctx));
    else {
      flush();
      out.push(blockHtml(b, ctx));
    }
  }
  flush();
  return out.join("\n");
}

export function renderHtml(report: ReportData, opts: HtmlRenderOptions = {}): string {
  const brand = cssColor(report.branding.primaryColor, "#B4232C");
  const brandText = brandInk(brand);
  const onBrand = onColor(brand);
  const tint = mix(brand, "#FFFFFF", 0.92);
  const timeZone = "UTC";
  const ctx = { timeZone, opts, termIndex: new Map(report.methodology.map((m, i) => [m.term, i])) };
  const logo = report.branding.logoDataUrl && /^data:image\/(png|jpeg);base64,[A-Za-z0-9+/]+={0,2}$/.test(report.branding.logoDataUrl) ? report.branding.logoDataUrl : null;
  const wordmark = logo ? `<img class="logo" src="${escapeHtml(logo)}" alt="${e(report.branding.name)}">` : `<span class="wordmark">${e(report.branding.name)}</span>`;
  const coverKpis = report.summary.kpis.slice(0, 4);
  const footerLeft = `${report.branding.name} · ${report.classification}`;
  const sections = report.sections
    .map((s, i) => {
      const num = String(i + 1).padStart(2, "0");
      return `<section class="report-section" id="sec-${e(s.id)}" aria-labelledby="h-${e(s.id)}"><header class="section-head"><span class="section-num">${num}</span><div><h2 id="h-${e(s.id)}">${e(s.title)}</h2>${s.description ? `<p class="section-desc">${e(s.description)}</p>` : ""}</div></header>${sectionBody(s.blocks, ctx)}</section>`;
    })
    .join("\n");
  const toc = report.sections.map((s, i) => `<li><a href="#sec-${e(s.id)}"><span class="toc-num">${String(i + 1).padStart(2, "0")}</span><span class="toc-title">${e(s.title)}</span><span class="toc-dots"></span></a></li>`).join("") + `<li><a href="#appendix"><span class="toc-num">A</span><span class="toc-title">Methodology &amp; data notes</span><span class="toc-dots"></span></a></li>`;
  const meta: [string, string | null][] = [
    ["Organization", report.scope.organizationName ?? `${report.scope.organizationCount} organizations`],
    ["Reporting period", report.period.label],
    ["Prepared for", report.preparedFor],
    ["Prepared by", report.preparedBy],
    ["Generated", formatDateTime(report.generatedAt)],
    ["Classification", report.classification],
  ];

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">
<meta name="generator" content="Bloody Reporting">
<meta name="color-scheme" content="light">
<title>${e(report.title)} — ${e(report.period.label)}</title>
<style>
:root{--brand:${brand};--brand-text:${brandText};--on-brand:${onBrand};--brand-tint:${tint};--ink:${INK.primary};--ink-2:${INK.secondary};--muted:${INK.muted};--grid:${INK.grid};--hair:${INK.hairline};--surface:#FFFFFF;--page:#EFEFEB;}
*{box-sizing:border-box}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0;background:var(--page);color:var(--ink);font:13px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
.sheet{max-width:210mm;margin:24px auto;background:var(--surface);box-shadow:0 1px 3px rgba(0,0,0,.08),0 8px 24px rgba(0,0,0,.06);}
.cover{min-height:297mm;display:flex;flex-direction:column;position:relative;}
.cover-band{background:var(--brand);color:var(--on-brand);padding:22mm 18mm 16mm;min-height:118mm;display:flex;flex-direction:column;justify-content:space-between}
.logo{max-height:44px;max-width:220px;display:block}
.wordmark{font-size:22px;font-weight:800;letter-spacing:.3px}
.eyebrow{font-size:11px;font-weight:700;letter-spacing:1.4px;text-transform:uppercase;opacity:.85;margin:28mm 0 8px}
.cover h1{font-size:34px;line-height:1.15;margin:0 0 10px;font-weight:800;letter-spacing:-.3px}
.cover .subtitle{font-size:15px;opacity:.9;margin:0}
.cover-body{padding:14mm 18mm 0;flex:1}
.headline{font-size:17px;line-height:1.5;font-weight:600;margin:0 0 10mm;color:var(--ink);border-left:4px solid var(--brand);padding-left:14px}
.meta{display:grid;grid-template-columns:repeat(3,1fr);gap:12px 18px;margin:0 0 10mm}
.meta div{border-top:1px solid var(--hair);padding-top:8px}
.meta dt{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin:0 0 2px}
.meta dd{margin:0;font-weight:600}
.cover-foot{padding:0 18mm 12mm;display:flex;justify-content:space-between;align-items:center;color:var(--muted);font-size:11px}
.badge{display:inline-block;border:1px solid var(--brand);color:var(--brand-text);border-radius:999px;padding:2px 10px;font-weight:700;font-size:10px;letter-spacing:.8px;text-transform:uppercase}
.toc,.report-section,.appendix{padding:16mm 18mm}
.toc h2,.appendix h2{font-size:22px;margin:0 0 8mm}
.toc ol{list-style:none;margin:0 0 12mm;padding:0}
.toc li a{display:flex;align-items:baseline;gap:12px;color:var(--ink);text-decoration:none;padding:7px 0;border-bottom:1px solid var(--hair);font-size:14px}
.toc-num{color:var(--brand-text);font-weight:700;width:26px}
.toc-dots{flex:1}
.glance h3{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin:0 0 8px}
.glance ul{margin:0;padding-left:18px}
.glance li{margin:0 0 6px}
.section-head{display:flex;gap:14px;align-items:flex-start;margin:0 0 8mm;padding-bottom:5mm;border-bottom:2px solid var(--brand)}
.section-num{font-size:28px;font-weight:800;color:var(--brand-text);line-height:1}
.section-head h2{font-size:22px;margin:0;line-height:1.2}
.section-desc{margin:4px 0 0;color:var(--ink-2)}
h3{font-size:14px;margin:8mm 0 4mm}
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin:0 0 7mm}
.kpi{border:1px solid var(--hair);border-radius:10px;padding:12px 12px 10px;background:#fff;break-inside:avoid}
.kpi-label{font-size:11px;color:var(--ink-2);font-weight:600}
.kpi-value{font-size:26px;font-weight:700;letter-spacing:-.4px;margin:2px 0 2px;line-height:1.2}
.kpi-delta{font-size:11px;font-weight:600}
.kpi-status{font-size:10.5px;color:var(--ink-2);margin-top:4px;display:flex;align-items:center;gap:5px}
.kpi-status i,.sev i{display:inline-block;width:8px;height:8px;border-radius:50%}
.kpi-note{font-size:10px;color:var(--muted);margin-top:6px;line-height:1.35}
.muted{color:var(--muted);font-weight:400}
.narrative{margin:0 0 6mm;max-width:165mm}
.narrative p{margin:0 0 3mm;font-size:13.5px}
.tone-note{color:var(--ink-2);font-size:12px;border-left:3px solid var(--grid);padding-left:10px}
.tone-ai{background:var(--brand-tint);border-radius:10px;padding:12px 14px}
.narrative-label{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--brand-text);margin-bottom:6px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
figure.chart{margin:0 0 7mm;border:1px solid var(--hair);border-radius:10px;padding:12px 14px;background:#fff;break-inside:avoid}
figure.chart figcaption{display:flex;flex-direction:column;margin-bottom:8px}
figure.chart figcaption strong{font-size:13px}
figure.chart figcaption span{font-size:11px;color:var(--muted)}
details.chart-data{margin-top:8px;font-size:11px}
details.chart-data summary{cursor:pointer;color:var(--ink-2)}
.table-wrap{overflow-x:auto}
table.data{width:100%;border-collapse:collapse;margin:0 0 3mm;font-size:11.5px}
table.data caption{text-align:left;font-weight:700;font-size:13px;padding:0 0 6px}
table.data th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--ink-2);border-bottom:1.5px solid var(--ink);padding:6px 8px;white-space:nowrap}
table.data td{padding:6px 8px;border-bottom:1px solid var(--hair);vertical-align:top}
table.data tbody tr:nth-child(even) td{background:#FAFAF8}
table.data .num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
thead{display:table-header-group}
tr{break-inside:avoid}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;word-break:break-all}
.block-table{margin:0 0 7mm}
.table-note{font-size:11px;color:var(--muted);margin:0 0 4mm}
.sev{display:inline-flex;align-items:center;gap:5px;font-weight:600;white-space:nowrap}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;background:#F1F0EC;color:var(--ink-2);font-size:10.5px;white-space:nowrap}
.empty{border:1px dashed var(--grid);border-radius:10px;padding:14px;color:var(--muted);text-align:center;margin:0 0 6mm}
.empty.ok{color:${INK.good};border-color:#BFD8BF}
.risks{display:grid;gap:10px;margin:0 0 7mm}
.risk{border:1px solid var(--hair);border-radius:10px;padding:12px 14px;break-inside:avoid}
.risk header{display:flex;align-items:center;gap:10px}
.risk h4{margin:0;font-size:13.5px;flex:1}
.risk .score{font-size:20px;font-weight:800}
.risk .subject{margin:4px 0 8px;color:var(--ink-2);font-size:11.5px}
.factors{list-style:none;margin:0;padding:0;display:grid;gap:5px}
.factors li{display:grid;grid-template-columns:150px 110px 38px 1fr;gap:8px;align-items:center;font-size:11px}
.f-label{font-weight:600}
.f-bar{background:#F1F0EC;height:6px;border-radius:3px;overflow:hidden}
.f-bar i{display:block;height:6px;border-radius:3px}
.f-val{text-align:right;font-variant-numeric:tabular-nums;font-weight:600}
.f-expl{color:var(--ink-2)}
.rec{margin:8px 0 0;font-size:12px}
.recs{list-style:none;margin:0 0 7mm;padding:0;display:grid;gap:8px}
.recs li{display:flex;gap:12px;border:1px solid var(--hair);border-radius:10px;padding:10px 12px;break-inside:avoid}
.recs p{margin:2px 0 4px;color:var(--ink-2);font-size:12px}
.owner{font-size:10.5px;color:var(--muted)}
.prio{flex:0 0 auto;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;border-radius:6px;padding:3px 8px;height:fit-content;color:#fff}
.prio-critical{background:${SEVERITY_COLOR.critical}}.prio-high{background:#C2410C}.prio-medium{background:#8A6400}.prio-low{background:${SEVERITY_COLOR.low}}
.callout{border-radius:10px;padding:12px 14px;margin:0 0 7mm;border-left:4px solid}
.callout p{margin:4px 0 0}
.callout-info{background:#EEF4FC;border-color:#2A78D6}.callout-success{background:#EEF7EE;border-color:#0CA30C}.callout-warning{background:#FFF7E6;border-color:#E0A100}.callout-critical{background:#FDEEEE;border-color:#D03B3B}
.appendix dl{margin:0 0 8mm}
.appendix dt{font-weight:700;margin-top:8px}
.appendix dd{margin:2px 0 0;color:var(--ink-2)}
.dq li{margin-bottom:4px}
.colophon{font-size:11px;color:var(--muted);border-top:1px solid var(--hair);padding-top:8px;margin-top:10mm}
@media screen and (max-width:820px){.sheet{margin:0;box-shadow:none}.cover{min-height:auto}.toc,.report-section,.appendix,.cover-body{padding:20px 16px}.cover-band{padding:24px 16px;min-height:auto}.meta{grid-template-columns:1fr 1fr}.factors li{grid-template-columns:1fr 60px 34px}.f-expl{grid-column:1/-1}}
@page{size:A4;margin:14mm 0 16mm;@bottom-left{content:${cssString(footerLeft)};font:8pt system-ui,sans-serif;color:#898781;margin-left:18mm}@bottom-right{content:"Page " counter(page) " of " counter(pages);font:8pt system-ui,sans-serif;color:#898781;margin-right:18mm}}
@page:first{margin:0;@bottom-left{content:none}@bottom-right{content:none}}
@media print{body{background:#fff}.sheet{margin:0;box-shadow:none;max-width:none}.cover{height:297mm;min-height:0;break-after:page}.toc{break-after:page}.report-section,.appendix{break-before:page;padding-top:0}details.chart-data:not([open]){display:none}.toc,.report-section,.appendix{padding-left:18mm;padding-right:18mm}a{color:inherit;text-decoration:none}}
</style>
</head>
<body>
<div class="sheet">
<section class="cover" aria-label="Cover">
  <div class="cover-band">
    <div>${wordmark}</div>
    <div>
      <p class="eyebrow">${e(report.typeLabel)} · ${e(humanize(report.audience === "soc" ? "SOC" : report.audience === "mssp" ? "MSSP" : report.audience))}</p>
      <h1>${e(report.title)}</h1>
      <p class="subtitle">${e(report.subtitle)}</p>
    </div>
  </div>
  <div class="cover-body">
    <p class="headline">${e(report.summary.headline)}</p>
    <dl class="meta">${meta.filter(([, v]) => v).map(([k, v]) => `<div><dt>${e(k)}</dt><dd>${e(v)}</dd></div>`).join("")}</dl>
    ${coverKpis.length > 0 ? `<div class="kpis">${coverKpis.map((k) => kpiCard(k, ctx.termIndex)).join("")}</div>` : ""}
  </div>
  <div class="cover-foot"><span class="badge">${e(report.classification)}</span><span>${e(report.branding.footerText ?? `${report.branding.name} Security Operations`)}${report.branding.poweredBy && report.branding.name !== "Bloody" ? " · Powered by Bloody" : ""}</span></div>
</section>
<nav class="toc" aria-label="Contents">
  <h2>Contents</h2>
  <ol>${toc}</ol>
  <div class="glance"><h3>At a glance</h3><ul>${report.summary.highlights.map((h) => `<li>${e(h)}</li>`).join("")}</ul></div>
</nav>
<main>
${sections}
</main>
<section class="appendix" id="appendix" aria-labelledby="h-appendix">
  <h2 id="h-appendix">Methodology &amp; data notes</h2>
  ${report.methodology.length > 0 ? `<dl>${report.methodology.map((m) => `<dt id="m-${e(m.term.replace(/[^A-Za-z0-9]+/g, "-").toLowerCase())}">${e(m.term)}</dt><dd>${e(m.definition)}</dd>`).join("")}</dl>` : ""}
  <h3>Data quality</h3>
  ${report.dataQuality.length > 0 ? `<ul class="dq">${report.dataQuality.map((d) => `<li>${e(d)}</li>`).join("")}</ul>` : `<p class="muted">No data-quality caveats for this report.</p>`}
  <p class="colophon">${e(report.title)} · ${e(report.period.label)} · generated ${e(formatDateTime(report.generatedAt))} · report ${e(report.id)} · schema ${e(report.schemaVersion)}. Every score in this report is explainable: contributing factors are listed with each risk, and every metric states how it was computed.</p>
</section>
</div>
</body>
</html>`;
}
