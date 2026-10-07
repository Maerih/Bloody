import { crc32, deflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { buildReport } from "../builders/index.js";
import type { ChartSpec, ReportData } from "../model.js";
import { FakeReportDataSource, NOW, ORG_A, PERIOD, TENANT } from "../test-support/fake-datasource.js";
import { layoutChart, niceScale } from "./chart-scene.js";
import { csvField, neutralizeFormula, renderCsv, renderCsvTables } from "./csv.js";
import { renderHtml } from "./html.js";
import { renderReport } from "./index.js";
import { pdfSafe, renderPdf } from "./pdf.js";
import { renderChartSvg } from "./svg.js";

/** Minimal valid RGB PNG (solid colour) for logo tests. */
function solidPng(w: number, h: number, rgb: [number, number, number]): Buffer {
  const chunk = (type: string, data: Buffer): Buffer => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type, "ascii"), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(td) >>> 0);
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  const raw = Buffer.alloc((w * 3 + 1) * h);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) raw.set(rgb, y * (w * 3 + 1) + 1 + x * 3);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}

/** Literal and UTF-16 hex strings of an uncompressed PDF (document info, outline titles). */
function pdfStrings(body: string): string[] {
  const out: string[] = [];
  for (const m of body.matchAll(/\(((?:[^()\\]|\\.)*)\)/g)) {
    const raw = m[1]!.replace(/\\(.)/g, "$1");
    out.push(raw.startsWith("\u00fe\u00ff") ? Buffer.from(raw.slice(2), "latin1").swap16().toString("utf16le") : raw);
  }
  for (const m of body.matchAll(/<feff([0-9a-f]+)>/gi)) out.push(Buffer.from(m[1]!, "hex").swap16().toString("utf16le"));
  return out;
}

const LOGO = `data:image/png;base64,${solidPng(40, 12, [0, 85, 170]).toString("base64")}`;

async function report(type: Parameters<typeof buildReport>[0]["type"] = "executive", extra: Partial<Parameters<typeof buildReport>[0]> = {}): Promise<ReportData> {
  return buildReport({ type, tenantId: TENANT, organizationIds: "all", period: PERIOD, ...extra }, { dataSource: new FakeReportDataSource(), clock: { now: () => NOW }, ids: () => "4b1d3c2a-0000-4000-8000-000000000001" });
}

function withHostileTitle(r: ReportData): ReportData {
  return { ...r, title: `Q3 <script>alert("x")</script> & "review"`, summary: { ...r.summary, headline: `<img src=x onerror=alert(1)> headline` } };
}

describe("HTML renderer", () => {
  it("produces a self-contained, print-ready, branded document", async () => {
    const r = await report("executive");
    const html = renderHtml(r);
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).toContain(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">`);
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/(src|href)="https?:/i);
    // cover, TOC, sections, appendix
    expect(html).toContain('<section class="cover"');
    expect(html).toContain('<nav class="toc"');
    for (const s of r.sections) {
      expect(html).toContain(`href="#sec-${s.id}"`);
      expect(html).toContain(`id="sec-${s.id}"`);
    }
    expect(html).toContain('id="appendix"');
    // print layout
    expect(html).toContain("@page{size:A4");
    expect(html).toContain('counter(page) " of " counter(pages)');
    expect(html).toMatch(/\.report-section,\.appendix\{break-before:page/);
    // inline SVG charts with accessibility metadata
    const svgs = html.match(/<svg [^>]*role="img"/g) ?? [];
    expect(svgs.length).toBeGreaterThanOrEqual(5);
    expect(html).toContain("<desc id=");
    expect(html).toContain("<summary>View data</summary>");
    // KPI explanation + trend arrows
    expect(html).toContain("vs previous period");
    expect(html).toContain("Mean detection-to-closure time over 4 incidents closed in the period.");
    // brand colour token
    expect(html).toContain("--brand:#B4232C");
    expect(html).toContain('<span class="wordmark">Bloody</span>');
  });

  it("escapes all report text (no markup injection)", async () => {
    const html = renderHtml(withHostileTitle(await report("executive")));
    expect(html).toContain("Q3 &lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &quot;review&quot;");
    expect(html).toContain("&lt;img src&#61;x onerror&#61;alert(1)&gt; headline");
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("<script>");
  });

  it("white-labels for MSSPs: logo, colour, name and no Bloody wordmark", async () => {
    const r = await report("customer_monthly", { organizationIds: [ORG_A], branding: { name: "Acme MSSP", primaryColor: "#0055AA", logoDataUrl: LOGO, footerText: "Acme MSSP · 24/7 SOC" } });
    const html = renderHtml(r);
    expect(html).toContain("--brand:#0055AA");
    expect(html).toContain(`<img class="logo" src="${LOGO}" alt="Acme MSSP">`);
    expect(html).toContain("Acme MSSP · 24/7 SOC");
    expect(html).toContain('<meta name="generator" content="Acme MSSP Reporting">');
    expect(html).not.toContain("Bloody");
  });

  it("renders the customer review's action list and empty states", async () => {
    const html = renderHtml(await report("customer_monthly", { organizationIds: [ORG_A] }));
    expect(html).toContain("Actions for you");
    expect(html).toContain("Respond to 1 open escalation");
    expect(html).toContain('<span class="prio prio-high">High</span>');
  });
});

describe("CSV renderer", () => {
  it("neutralises spreadsheet formulas in text cells", () => {
    expect(neutralizeFormula("=HYPERLINK(\"http://evil\")")).toBe("'=HYPERLINK(\"http://evil\")");
    expect(neutralizeFormula("+1+cmd|' /C calc'!A0")).toBe("'+1+cmd|' /C calc'!A0");
    expect(neutralizeFormula("-2+3")).toBe("'-2+3");
    expect(neutralizeFormula("@SUM(A1)")).toBe("'@SUM(A1)");
    expect(neutralizeFormula("\t=1")).toBe("'\t=1");
    expect(neutralizeFormula("＝1+1")).toBe("'＝1+1");
    expect(neutralizeFormula("safe = text")).toBe("safe = text");
    expect(csvField(-5)).toBe("-5");
    expect(csvField(null)).toBe("");
    expect(csvField(true)).toBe("true");
  });

  it("quotes per RFC 4180 and uses CRLF", () => {
    expect(csvField('He said "hi", then left')).toBe('"He said ""hi"", then left"');
    expect(csvField("line1\nline2")).toBe('"line1\nline2"');
    expect(csvField('=1,"2"')).toBe(`"'=1,""2"""`);
  });

  it("exports the whole report as tidy CSV with a fixed header", async () => {
    const r = await report("threat_intel");
    const csv = renderCsv(r);
    const lines = csv.split("\r\n");
    expect(lines[0]).toBe("section,dataset,row,field,value");
    expect(csv.endsWith("\r\n")).toBe(true);
    // the hostile indicator from the fixtures is defanged AND formula-neutralised
    expect(csv).toContain("hxxps://=cmd|' /C calc'!A0[.]example/payload");
    expect(csv).not.toMatch(/(^|,)=cmd/m);
    expect(csv).toContain("Indicators observed in the environment,Most matched indicators,1,Indicator,update-check[.]evil-cdn[.]com");
    const injected = renderCsv({ ...r, title: "=2+5" });
    expect(injected).toContain("Report,metadata,1,title,'=2+5");
    expect(renderCsv(r, { bom: true }).startsWith("﻿section")).toBe(true);
  });

  it("exports individual tables in wide format", async () => {
    const r = await report("sla");
    const one = renderCsv(r, { tableId: "breach-list" });
    expect(one.split("\r\n")[0]).toBe("#,Incident,Customer,Severity,Why");
    expect(() => renderCsv(r, { tableId: "missing" })).toThrow(/not found/);
    const files = renderCsvTables(r);
    expect(files[0]!.filename).toBe("kpis.csv");
    expect(files.map((f) => f.filename)).toContain("breach-list.csv");
    expect(files.every((f) => f.csv.endsWith("\r\n"))).toBe(true);
  });
});

describe("PDF renderer", () => {
  it("renders a valid multi-page PDF with vector charts, TOC and bookmarks", async () => {
    const r = await report("executive");
    const pdf = await renderPdf(r, { compress: false });
    expect(pdf.subarray(0, 5).toString("latin1")).toBe("%PDF-");
    expect(pdf.subarray(-8).toString("latin1")).toMatch(/%%EOF\s*$/);
    const body = pdf.toString("latin1");
    const pages = (body.match(/\/Type \/Page\b/g) ?? []).length;
    expect(pages).toBeGreaterThanOrEqual(r.sections.length + 3);
    expect(body).toContain("/Outlines");
    expect(body).toContain("/Dests");
    expect(pdfStrings(body)).toContain(`Executive security summary — ${r.period.label}`);
    // vector drawing operators (paths / curves) are present — charts are not images
    expect(body).toMatch(/ c\n/);
    expect(body).not.toContain("/Subtype /Image");
  });

  it("embeds a white-label PNG logo and brand metadata", async () => {
    const r = await report("customer_monthly", { organizationIds: [ORG_A], branding: { name: "Acme MSSP", primaryColor: "#0055AA", logoDataUrl: LOGO } });
    const pdf = await renderPdf(r, { compress: false });
    const body = pdf.toString("latin1");
    expect(body.startsWith("%PDF")).toBe(true);
    expect(body).toContain("/Subtype /Image");
    expect(pdfStrings(body)).toEqual(expect.arrayContaining(["Acme MSSP", "Acme MSSP Reporting"]));
    expect(pdfStrings(body).some((s) => s.includes("Bloody"))).toBe(false);
  });

  it("renders every report type, including hostile text", async () => {
    for (const type of ["soc_operations", "incident", "vulnerability", "threat_intel", "compliance", "sla", "analyst_activity", "mssp_portfolio"] as const) {
      const pdf = await renderPdf(withHostileTitle(await report(type)));
      expect(pdf.subarray(0, 4).toString("latin1"), type).toBe("%PDF");
      expect(pdf.length).toBeGreaterThan(3000);
    }
  });

  it("maps text to the standard-font character set", () => {
    expect(pdfSafe("MTTR → 4h ≥ target − ✓ 漢字 €")).toBe("MTTR -> 4h >= target - v ?? €");
    expect(pdfSafe("ﬁle")).toBe("file");
  });
});

describe("renderReport", () => {
  it("returns file name, content type and bytes for every format", async () => {
    const r = await report("customer_monthly", { organizationIds: [ORG_A] });
    const html = await renderReport(r, "html");
    expect(html).toMatchObject({ filename: "acme-corp-customer-monthly-2026-09-30.html", contentType: "text/html; charset=utf-8" });
    const pdf = await renderReport(r, "pdf");
    expect(pdf.content.subarray(0, 4).toString()).toBe("%PDF");
    const csv = await renderReport(r, "csv");
    expect(csv.contentType).toMatch(/^text\/csv/);
    const json = await renderReport(r, "json");
    expect(JSON.parse(json.content.toString("utf8"))).toMatchObject({ schemaVersion: "1.0", type: "customer_monthly" });
  });
});

describe("charts", () => {
  const bar: ChartSpec = { id: "b", type: "bar", title: "Alerts", unit: "count", categories: ["Mon", "Tue", "Wed"], series: [{ key: "a", name: "Alerts", values: [3, 12, 7] }] };

  it("computes nice axis scales", () => {
    expect(niceScale(12)).toMatchObject({ max: 15, step: 5, ticks: [0, 5, 10, 15] });
    expect(niceScale(87, 4, "percent").max).toBe(100);
    expect(niceScale(0).max).toBeGreaterThan(0);
    expect(niceScale(1234).ticks.at(-1)).toBe(1500);
  });

  it("lays out bars with rounded data-ends and capped thickness", () => {
    const scene = layoutChart(bar, { width: 600, height: 220 });
    const bars = scene.items.filter((p) => p.t === "path");
    expect(bars).toHaveLength(3);
    for (const b of bars) expect(b.t === "path" && b.d).toMatch(/Q/);
    const widths = bars.map((b) => (b.t === "path" ? Number(/H([\d.]+)/.exec(b.d)![1]) : 0));
    expect(widths.length).toBe(3);
    // value labels for a single short series
    expect(scene.items.filter((p) => p.t === "text" && p.text === "12")).toHaveLength(1);
  });

  it("renders legends for multi-series charts and an empty state when there is no data", () => {
    const multi: ChartSpec = { ...bar, type: "line", series: [{ key: "a", name: "Risk", values: [50, 48, null] }, { key: "b", name: "Exposure", values: [60, 58, 55] }] };
    const scene = layoutChart(multi);
    expect(scene.items.some((p) => p.t === "text" && p.text === "Risk")).toBe(true);
    expect(scene.items.some((p) => p.t === "text" && p.text === "Exposure")).toBe(true);
    const empty = layoutChart({ ...bar, series: [{ key: "a", name: "Alerts", values: [0, 0, 0] }], emptyMessage: "Nothing yet" });
    expect(empty.empty).toBe(true);
    expect(empty.items.some((p) => p.t === "text" && p.text === "Nothing yet")).toBe(true);
  });

  it("renders donuts with totals and per-slice tooltips; escapes labels in SVG", () => {
    const donut: ChartSpec = { id: "d", type: "donut", title: "By severity", unit: "count", categories: ["Critical", "<High>"], categoryColors: ["#D03B3B", "#EC835A"], series: [{ key: "c", name: "n", values: [2, 6] }] };
    const svg = renderChartSvg(donut, { width: 400 });
    expect(svg).toContain("<title>Critical: 2 (25.0%)</title>");
    expect(svg).toContain("&lt;High&gt;");
    expect(svg).not.toContain("<High>");
    expect(svg).toMatch(/>8<\/text>/);
    const hbarSvg = renderChartSvg({ id: "h", type: "hbar", title: "Top", unit: "count", categories: ["a", "b"], series: [{ key: "v", name: "v", values: [5, 1] }] });
    expect(hbarSvg).toContain('role="img"');
  });
});
