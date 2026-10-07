import PDFDocument from "pdfkit";
import type { Severity } from "@bloody/contracts";
import { brandInk, decodeLogo, INK, mix, onColor, SENTIMENT_COLOR, SEVERITY_COLOR, STATUS_COLOR } from "../branding.js";
import { formatDateTime, formatNumber, formatValue } from "../format.js";
import type { ChartSpec, Kpi, Recommendation, ReportBlock, ReportData, RiskItem, TableSpec } from "../model.js";
import { formatCell, humanize, isNumericColumn } from "./cells.js";
import { layoutChart, type ChartScene } from "./chart-scene.js";
import { cssColor } from "./escape.js";

/**
 * PDF renderer (pdfkit, MIT). A4 portrait, standard PDF fonts (no font files shipped), vector
 * charts drawn from the same chart scene as the HTML report, tables paginated with repeated
 * headers, a cover page, a table of contents with real page numbers and internal links, PDF
 * bookmarks (outline), and "Page X of Y" footers with the brand and classification.
 */
export interface PdfRenderOptions {
  compress?: boolean;
}

const PAGE_W = 595.28;
const PAGE_H = 841.89;
const ML = 50;
const MR = 50;
const MT = 56;
const MB = 62;
const CW = PAGE_W - ML - MR;
const FONT = "Helvetica";
const BOLD = "Helvetica-Bold";
const MONO = "Courier";

/** Characters of WinAnsiEncoding beyond Latin-1 that the standard fonts can draw. */
const WIN_ANSI_EXTRA = new Set([0x152, 0x153, 0x160, 0x161, 0x178, 0x17d, 0x17e, 0x192, 0x2c6, 0x2dc, 0x2013, 0x2014, 0x2018, 0x2019, 0x201a, 0x201c, 0x201d, 0x201e, 0x2020, 0x2021, 0x2022, 0x2026, 0x2030, 0x2039, 0x203a, 0x20ac, 0x2122]);
const REPLACE: Record<string, string> = { "\u2192": "->", "\u2190": "<-", "\u2265": ">=", "\u2264": "<=", "\u2260": "!=", "\u2212": "-", "\u25B2": "+", "\u25BC": "-", "\u2713": "v", "\u2714": "v", "\u2717": "x", "\u2026": "...", "\u202F": " ", "\u2009": " " };

/** Make text drawable with the standard PDF fonts (WinAnsi); unknown glyphs become "?". */
export function pdfSafe(input: string): string {
  let out = "";
  for (const ch of input.normalize("NFKC")) {
    const cp = ch.codePointAt(0)!;
    if (cp === 0x09 || cp === 0x0a) out += ch;
    else if (cp < 0x20 || (cp >= 0x7f && cp < 0xa0)) continue;
    else if (cp <= 0xff || WIN_ANSI_EXTRA.has(cp)) out += ch;
    else out += REPLACE[ch] ?? "?";
  }
  return out;
}

type Doc = PDFKit.PDFDocument;

interface TocEntry {
  title: string;
  dest: string;
  page: number;
}

class PdfReport {
  private readonly doc: Doc;
  private readonly r: ReportData;
  private readonly brand: string;
  private readonly brandText: string;
  private readonly onBrand: string;
  private readonly tint: string;
  private readonly toc: TocEntry[] = [];
  private tocPage = 1;

  constructor(doc: Doc, report: ReportData) {
    this.doc = doc;
    this.r = report;
    this.brand = cssColor(report.branding.primaryColor, "#B4232C");
    this.brandText = brandInk(this.brand);
    this.onBrand = onColor(this.brand);
    this.tint = mix(this.brand, "#FFFFFF", 0.92);
  }

  render(): void {
    this.cover();
    this.tocPlaceholder();
    this.r.sections.forEach((s, i) => this.section(s.id, s.title, s.description ?? null, s.blocks, i + 1));
    this.appendix();
    this.fillToc();
    this.decoratePages();
  }

  // ─── primitives ────────────────────────────────────────────────────────────

  private get bottom(): number {
    return PAGE_H - MB;
  }

  private newPage(): void {
    this.doc.addPage({ size: "A4", margins: { top: MT, bottom: MB, left: ML, right: MR } });
    this.doc.x = ML;
    this.doc.y = MT;
  }

  private ensure(height: number): void {
    if (this.doc.y + height > this.bottom) this.newPage();
  }

  private text(s: string, x: number, y: number, opts: { size?: number; font?: string; color?: string; width?: number; align?: "left" | "right" | "center"; lineGap?: number; ellipsis?: boolean; height?: number } = {}): number {
    const d = this.doc;
    d.font(opts.font ?? FONT).fontSize(opts.size ?? 10).fillColor(opts.color ?? INK.primary);
    const str = pdfSafe(s);
    const textOpts: PDFKit.Mixins.TextOptions = { width: opts.width ?? CW, align: opts.align ?? "left", lineGap: opts.lineGap ?? 1.5 };
    if (opts.height !== undefined) {
      textOpts.height = opts.height;
      textOpts.ellipsis = true;
    }
    const h = d.heightOfString(str, textOpts);
    d.text(str, x, y, textOpts);
    return opts.height !== undefined ? Math.min(h, opts.height) : h;
  }

  private measure(s: string, opts: { size?: number; font?: string; width?: number; lineGap?: number }): number {
    this.doc.font(opts.font ?? FONT).fontSize(opts.size ?? 10);
    return this.doc.heightOfString(pdfSafe(s), { width: opts.width ?? CW, lineGap: opts.lineGap ?? 1.5 });
  }

  private textWidth(s: string, size: number, font = FONT): number {
    return this.doc.font(font).fontSize(size).widthOfString(pdfSafe(s));
  }

  private pill(label: string, x: number, y: number, bg: string, fg: string, size = 7): number {
    const w = this.textWidth(label, size, BOLD) + 10;
    this.doc.roundedRect(x, y, w, size + 6, 3).fill(bg);
    this.text(label, x + 5, y + 3, { size, font: BOLD, color: fg, width: w });
    return w;
  }

  private sevMark(sev: string, x: number, y: number, size = 8): number {
    const color = SEVERITY_COLOR[sev as Severity] ?? INK.muted;
    this.doc.circle(x + 3, y + size / 2, 3).fill(color);
    const label = humanize(sev);
    this.text(label, x + 9, y, { size, font: BOLD, color: INK.primary, width: this.textWidth(label, size, BOLD) + 4 });
    return 9 + this.textWidth(label, size, BOLD);
  }

  // ─── pages ─────────────────────────────────────────────────────────────────

  private cover(): void {
    const d = this.doc;
    d.addPage({ size: "A4", margins: { top: 0, bottom: 0, left: 0, right: 0 } });
    d.rect(0, 0, PAGE_W, 330).fill(this.brand);
    const logo = decodeLogo(this.r.branding.logoDataUrl);
    if (logo) {
      try {
        d.image(logo.bytes, ML, 48, { fit: [190, 46] });
      } catch {
        this.text(this.r.branding.name, ML, 56, { size: 20, font: BOLD, color: this.onBrand });
      }
    } else {
      this.text(this.r.branding.name, ML, 56, { size: 20, font: BOLD, color: this.onBrand });
    }
    const audience = this.r.audience === "soc" ? "SOC" : this.r.audience === "mssp" ? "MSSP" : humanize(this.r.audience);
    this.text(`${this.r.typeLabel.toUpperCase()} · ${audience.toUpperCase()}`, ML, 176, { size: 9, font: BOLD, color: this.onBrand, width: CW });
    const titleH = this.text(this.r.title, ML, 194, { size: 28, font: BOLD, color: this.onBrand, width: CW, lineGap: 0 });
    this.text(this.r.subtitle, ML, 194 + titleH + 8, { size: 12, color: this.onBrand, width: CW });

    let y = 370;
    const headlineH = this.measure(this.r.summary.headline, { size: 13, font: BOLD, width: CW - 16 });
    d.rect(ML, y, 3, headlineH).fill(this.brand);
    this.text(this.r.summary.headline, ML + 14, y, { size: 13, font: BOLD, width: CW - 16 });
    y += headlineH + 26;

    const meta: [string, string | null][] = [
      ["ORGANIZATION", this.r.scope.organizationName ?? `${this.r.scope.organizationCount} organizations`],
      ["REPORTING PERIOD", this.r.period.label],
      ["PREPARED FOR", this.r.preparedFor],
      ["PREPARED BY", this.r.preparedBy],
      ["GENERATED", formatDateTime(this.r.generatedAt)],
      ["CLASSIFICATION", this.r.classification],
    ];
    const colW = (CW - 24) / 3;
    meta.forEach(([k, v], i) => {
      const cx = ML + (i % 3) * (colW + 12);
      const cy = y + Math.floor(i / 3) * 48;
      d.moveTo(cx, cy).lineTo(cx + colW, cy).lineWidth(0.6).stroke(INK.hairline);
      this.text(k, cx, cy + 7, { size: 7, font: BOLD, color: INK.muted, width: colW });
      this.text(v ?? "—", cx, cy + 18, { size: 9.5, font: BOLD, width: colW, height: 24 });
    });
    y += 110;
    const kpis = this.r.summary.kpis.slice(0, 4);
    if (kpis.length > 0) this.kpiGrid(kpis, y, 4);

    // classification badge + brand footer
    const badge = this.r.classification.toUpperCase();
    const bw = this.textWidth(badge, 7.5, BOLD) + 16;
    d.roundedRect(ML, PAGE_H - 58, bw, 16, 8).lineWidth(0.8).stroke(this.brand);
    this.text(badge, ML + 8, PAGE_H - 53.5, { size: 7.5, font: BOLD, color: this.brandText, width: bw });
    const foot = `${this.r.branding.footerText ?? `${this.r.branding.name} Security Operations`}${this.r.branding.poweredBy && this.r.branding.name !== "Bloody" ? " · Powered by Bloody" : ""}`;
    this.text(foot, ML, PAGE_H - 53, { size: 8, color: INK.muted, width: CW, align: "right" });
  }

  private tocPlaceholder(): void {
    this.newPage();
    this.tocPage = this.doc.bufferedPageRange().start + this.doc.bufferedPageRange().count - 1;
    this.text("Contents", ML, MT, { size: 20, font: BOLD });
    const rows = this.r.sections.length + 1;
    let y = MT + 44 + rows * 24 + 30;
    this.text("AT A GLANCE", ML, y, { size: 8, font: BOLD, color: INK.muted });
    y += 16;
    for (const h of this.r.summary.highlights) {
      const hh = this.measure(h, { size: 10, width: CW - 14 });
      if (y + hh > this.bottom) break;
      this.doc.circle(ML + 3, y + 5, 1.8).fill(this.brand);
      this.text(h, ML + 14, y, { size: 10, width: CW - 14 });
      y += hh + 6;
    }
  }

  private fillToc(): void {
    this.doc.switchToPage(this.tocPage);
    let y = MT + 44;
    this.toc.forEach((t, i) => {
      const num = i === this.toc.length - 1 && t.dest === "appendix" ? "A" : String(i + 1).padStart(2, "0");
      this.text(num, ML, y, { size: 11, font: BOLD, color: this.brandText, width: 28 });
      this.text(t.title, ML + 30, y, { size: 11, width: CW - 80 });
      this.text(String(t.page), ML, y, { size: 11, width: CW, align: "right", color: INK.secondary });
      this.doc.moveTo(ML, y + 17).lineTo(ML + CW, y + 17).lineWidth(0.5).stroke(INK.hairline);
      this.doc.goTo(ML, y - 2, CW, 18, t.dest);
      y += 24;
    });
  }

  private sectionHeader(num: string, title: string, description: string | null): void {
    const d = this.doc;
    const y = MT;
    this.text(num, ML, y, { size: 22, font: BOLD, color: this.brandText, width: 40 });
    const th = this.text(title, ML + 42, y + 2, { size: 17, font: BOLD, width: CW - 42 });
    let yy = y + Math.max(26, th + 4);
    if (description) yy += this.text(description, ML + 42, yy, { size: 9.5, color: INK.secondary, width: CW - 42 }) + 4;
    d.moveTo(ML, yy + 4).lineTo(ML + CW, yy + 4).lineWidth(1.5).stroke(this.brand);
    d.y = yy + 18;
    d.x = ML;
  }

  private section(id: string, title: string, description: string | null, blocks: ReportBlock[], index: number): void {
    this.newPage();
    const dest = `sec-${id}`;
    this.doc.addNamedDestination(dest);
    this.doc.outline.addItem(pdfSafe(`${index}. ${title}`));
    this.toc.push({ title, dest, page: this.doc.bufferedPageRange().start + this.doc.bufferedPageRange().count });
    this.sectionHeader(String(index).padStart(2, "0"), title, description);
    for (const b of blocks) this.block(b);
  }

  private appendix(): void {
    this.newPage();
    this.doc.addNamedDestination("appendix");
    this.doc.outline.addItem("Methodology & data notes");
    this.toc.push({ title: "Methodology & data notes", dest: "appendix", page: this.doc.bufferedPageRange().start + this.doc.bufferedPageRange().count });
    this.sectionHeader("A", "Methodology & data notes", null);
    for (const m of this.r.methodology) {
      const h = this.measure(m.definition, { size: 9, width: CW });
      this.ensure(h + 18);
      this.text(m.term, ML, this.doc.y, { size: 10, font: BOLD });
      this.doc.y += 13;
      this.doc.y += this.text(m.definition, ML, this.doc.y, { size: 9, color: INK.secondary }) + 8;
    }
    this.ensure(40);
    this.doc.y += 6;
    this.text("Data quality", ML, this.doc.y, { size: 11, font: BOLD });
    this.doc.y += 16;
    const notes = this.r.dataQuality.length > 0 ? this.r.dataQuality : ["No data-quality caveats for this report."];
    for (const n of notes) {
      const h = this.measure(n, { size: 9, width: CW - 12 });
      this.ensure(h + 6);
      this.doc.circle(ML + 3, this.doc.y + 4.5, 1.6).fill(INK.muted);
      this.doc.y += this.text(n, ML + 12, this.doc.y, { size: 9, color: INK.secondary, width: CW - 12 }) + 5;
    }
    this.ensure(50);
    this.doc.y += 12;
    this.text(`${this.r.title} · ${this.r.period.label} · generated ${formatDateTime(this.r.generatedAt)} · report ${this.r.id}. Every score is explainable: contributing factors are listed with each risk, and every metric states how it was computed.`, ML, this.doc.y, { size: 7.5, color: INK.muted });
  }

  private decoratePages(): void {
    const range = this.doc.bufferedPageRange();
    const total = range.count;
    for (let i = range.start; i < range.start + total; i++) {
      if (i === range.start) continue;
      this.doc.switchToPage(i);
      const page = this.doc.page;
      const saved = page.margins.bottom;
      page.margins.bottom = 0;
      const y = PAGE_H - 40;
      this.doc.moveTo(ML, y - 8).lineTo(ML + CW, y - 8).lineWidth(0.5).stroke(INK.hairline);
      this.text(`${this.r.branding.name} · ${this.r.classification}`, ML, y, { size: 7.5, color: INK.muted, width: CW / 2 });
      this.text(`Page ${i - range.start + 1} of ${total}`, ML + CW / 2, y, { size: 7.5, color: INK.muted, width: CW / 2, align: "right" });
      this.text(`${this.r.title} · ${this.r.period.label}`, ML, 26, { size: 7.5, color: INK.muted, width: CW, align: "right", height: 10 });
      page.margins.bottom = saved;
    }
  }

  // ─── blocks ────────────────────────────────────────────────────────────────

  private block(b: ReportBlock): void {
    switch (b.kind) {
      case "kpis":
        this.kpiBlock(b.items);
        break;
      case "chart":
        this.chart(b.chart);
        break;
      case "table":
        this.table(b.table);
        break;
      case "narrative":
        this.narrative(b.paragraphs, b.tone ?? "default", b.label ?? null);
        break;
      case "risks":
        if (b.title) this.subheading(b.title);
        this.risks(b.items, b.emptyMessage ?? "No risks to report.");
        break;
      case "recommendations":
        if (b.title) this.subheading(b.title);
        this.recommendations(b.items, b.emptyMessage ?? "No actions required.");
        break;
      case "callout":
        this.callout(b.tone, b.title, b.text);
        break;
    }
  }

  private subheading(title: string): void {
    this.ensure(40);
    this.text(title, ML, this.doc.y, { size: 11.5, font: BOLD });
    this.doc.y += 18;
  }

  private kpiCardHeight(k: Kpi, w: number): number {
    let h = 10 + 10 + 22;
    if (k.delta) h += 11;
    if (k.status || k.target !== null) h += 11;
    h += Math.min(30, this.measure(k.explanation, { size: 7, width: w - 16, lineGap: 0.5 })) + 10;
    return h;
  }

  private kpiGrid(items: Kpi[], y0: number, cols: number): number {
    const d = this.doc;
    const gap = 8;
    const w = (CW - gap * (cols - 1)) / cols;
    let y = y0;
    for (let i = 0; i < items.length; i += cols) {
      const row = items.slice(i, i + cols);
      const h = Math.max(...row.map((k) => this.kpiCardHeight(k, w)));
      if (y + h > PAGE_H - 30 && d.page.margins.bottom === 0) break;
      row.forEach((k, j) => {
        const x = ML + j * (w + gap);
        d.roundedRect(x, y, w, h, 7).lineWidth(0.7).stroke(INK.hairline);
        let cy = y + 9;
        this.text(k.label, x + 8, cy, { size: 7.5, font: BOLD, color: INK.secondary, width: w - 16, height: 10 });
        cy += 12;
        const value = formatValue(k.value, k.unit, { compact: true, ...(k.currency ? { currency: k.currency } : {}) });
        this.text(value, x + 8, cy, { size: 17, font: BOLD, width: w - 16, height: 22 });
        cy += 22;
        if (k.delta) {
          const color = SENTIMENT_COLOR[k.delta.sentiment];
          const tx = x + 8;
          if (k.delta.direction === "up") d.path(`M${tx} ${cy + 7} L${tx + 3.5} ${cy + 1} L${tx + 7} ${cy + 7} Z`).fill(color);
          else if (k.delta.direction === "down") d.path(`M${tx} ${cy + 1} L${tx + 3.5} ${cy + 7} L${tx + 7} ${cy + 1} Z`).fill(color);
          else d.rect(tx, cy + 3, 7, 1.5).fill(color);
          const amount = k.delta.direction === "flat" ? "No change" : k.delta.percent !== null ? `${Math.abs(k.delta.percent).toFixed(Math.abs(k.delta.percent) < 10 ? 1 : 0)}%` : formatValue(Math.abs(k.delta.absolute ?? 0), k.unit, { compact: true, ...(k.currency ? { currency: k.currency } : {}) });
          this.text(`${amount} vs previous`, tx + 10, cy, { size: 7.5, font: BOLD, color, width: w - 26 });
          cy += 11;
        }
        if (k.status || k.target !== null) {
          if (k.status) d.circle(x + 11.5, cy + 3.5, 2.6).fill(STATUS_COLOR[k.status]);
          const label = `${k.status ? (k.status === "good" ? "On target" : k.status === "warn" ? "Watch" : "Action needed") : ""}${k.target !== null ? `${k.status ? " · " : ""}target ${formatValue(k.target, k.unit, k.currency ? { currency: k.currency } : {})}` : ""}`;
          this.text(label, x + (k.status ? 18 : 8), cy, { size: 7, color: INK.secondary, width: w - 26, height: 9 });
          cy += 11;
        }
        this.text(k.explanation, x + 8, cy + 2, { size: 7, color: INK.muted, width: w - 16, lineGap: 0.5, height: 30 });
      });
      y += h + gap;
    }
    return y;
  }

  private kpiBlock(items: Kpi[]): void {
    const cols = 3;
    const w = (CW - 16) / cols;
    const firstRowH = Math.max(...items.slice(0, cols).map((k) => this.kpiCardHeight(k, w)));
    this.ensure(firstRowH + 8);
    // render row by row so rows can break across pages
    for (let i = 0; i < items.length; i += cols) {
      const row = items.slice(i, i + cols);
      const h = Math.max(...row.map((k) => this.kpiCardHeight(k, w)));
      this.ensure(h + 8);
      this.doc.y = this.kpiGrid(row, this.doc.y, cols);
    }
    this.doc.y += 6;
  }

  private chart(spec: ChartSpec): void {
    const scene = layoutChart(spec, { width: CW - 20, height: spec.type === "donut" ? 170 : 200 });
    const titleH = 14 + (spec.subtitle ? 11 : 0);
    const total = titleH + scene.height + 22;
    this.ensure(total);
    const d = this.doc;
    const y0 = d.y;
    d.roundedRect(ML, y0, CW, total - 6, 7).lineWidth(0.7).stroke(INK.hairline);
    this.text(spec.title, ML + 10, y0 + 9, { size: 10, font: BOLD, width: CW - 20 });
    if (spec.subtitle) this.text(spec.subtitle, ML + 10, y0 + 22, { size: 7.5, color: INK.muted, width: CW - 20 });
    this.drawScene(scene, ML + 10, y0 + 9 + titleH + 4);
    d.y = y0 + total + 4;
    d.x = ML;
  }

  /** Draw a chart scene with pdfkit vector primitives at (x0, y0). */
  private drawScene(scene: ChartScene, x0: number, y0: number): void {
    const d = this.doc;
    d.save();
    d.translate(x0, y0);
    for (const p of scene.items) {
      switch (p.t) {
        case "rect":
          d.rect(p.x, p.y, p.w, p.h).fill(p.fill);
          break;
        case "path":
          if (p.fill && p.fill !== "none" && p.stroke) {
            d.path(p.d).lineWidth(p.strokeWidth ?? 1).fillAndStroke(p.fill, p.stroke);
          } else if (p.fill && p.fill !== "none") {
            if (p.opacity !== undefined) d.fillOpacity(p.opacity);
            d.path(p.d).fill(p.fill);
            if (p.opacity !== undefined) d.fillOpacity(1);
          } else if (p.stroke) {
            d.path(p.d).lineWidth(p.strokeWidth ?? 1).lineJoin("round").lineCap("round").stroke(p.stroke);
          }
          break;
        case "line":
          d.moveTo(p.x1, p.y1).lineTo(p.x2, p.y2).lineWidth(p.width).stroke(p.stroke);
          break;
        case "circle":
          if (p.fill === "transparent") break;
          if (p.stroke) d.circle(p.cx, p.cy, p.r).lineWidth(p.strokeWidth ?? 1).fillAndStroke(p.fill, p.stroke);
          else d.circle(p.cx, p.cy, p.r).fill(p.fill);
          break;
        case "text": {
          const font = p.weight === "bold" ? BOLD : FONT;
          const str = pdfSafe(p.text);
          d.font(font).fontSize(p.size).fillColor(p.fill);
          const w = d.widthOfString(str);
          const x = p.anchor === "middle" ? p.x - w / 2 : p.anchor === "end" ? p.x - w : p.x;
          d.text(str, x, p.y - p.size * 0.78, { lineBreak: false });
          break;
        }
      }
    }
    d.restore();
  }

  private table(t: TableSpec): void {
    const d = this.doc;
    this.ensure(40);
    this.text(t.title, ML, d.y, { size: 10.5, font: BOLD });
    d.y += 16;
    if (t.rows.length === 0) {
      this.empty(t.emptyMessage);
      return;
    }
    const weights = t.columns.map((c) => c.width ?? (isNumericColumn(c) ? 0.8 : 1));
    const sum = weights.reduce((s, w) => s + w, 0);
    const widths = weights.map((w) => (w / sum) * CW);
    const xs = widths.map((_, i) => ML + widths.slice(0, i).reduce((s, w) => s + w, 0));
    const fs = t.columns.length > 7 ? 7 : 7.8;
    const header = (): void => {
      const hh = Math.max(...t.columns.map((c, i) => this.measure(c.label.toUpperCase(), { size: 6.5, font: BOLD, width: widths[i]! - 8, lineGap: 0 }))) + 9;
      d.rect(ML, d.y, CW, hh).fill("#F1F0EC");
      t.columns.forEach((c, i) => this.text(c.label.toUpperCase(), xs[i]! + 4, d.y + 4.5, { size: 6.5, font: BOLD, color: INK.secondary, width: widths[i]! - 8, align: isNumericColumn(c) ? "right" : "left", lineGap: 0 }));
      d.y += hh;
    };
    this.ensure(60);
    header();
    t.rows.forEach((row, ri) => {
      const cells = t.columns.map((c) => formatCell(row[c.key] ?? null, c, { ...(t.currency ? { currency: t.currency } : {}) }));
      const rh = Math.min(48, Math.max(...cells.map((txt, i) => this.measure(txt, { size: fs, font: t.columns[i]!.format === "code" ? MONO : FONT, width: widths[i]! - 8, lineGap: 0.5 })))) + 8;
      if (d.y + rh > this.bottom) {
        this.newPage();
        header();
      }
      if (ri % 2 === 1) d.rect(ML, d.y, CW, rh).fill("#FAFAF8");
      t.columns.forEach((c, i) => {
        const v = row[c.key] ?? null;
        if (c.format === "severity" && typeof v === "string") this.sevMark(v, xs[i]! + 4, d.y + 4, fs);
        else this.text(cells[i]!, xs[i]! + 4, d.y + 4, { size: fs, font: c.format === "code" ? MONO : FONT, width: widths[i]! - 8, align: isNumericColumn(c) ? "right" : "left", lineGap: 0.5, height: rh - 6 });
      });
      d.moveTo(ML, d.y + rh).lineTo(ML + CW, d.y + rh).lineWidth(0.4).stroke(INK.hairline);
      d.y += rh;
    });
    d.y += 6;
    const notes = [t.totalRows !== undefined && t.totalRows > t.rows.length ? `Showing ${formatNumber(t.rows.length)} of ${formatNumber(t.totalRows)}; the full list is in the CSV export.` : null, t.note ?? null].filter((n): n is string => n !== null);
    for (const n of notes) {
      this.ensure(14);
      d.y += this.text(n, ML, d.y, { size: 7.5, color: INK.muted }) + 3;
    }
    d.y += 10;
    d.x = ML;
  }

  private narrative(paragraphs: string[], tone: "default" | "ai" | "note", label: string | null): void {
    if (paragraphs.length === 0) return;
    const d = this.doc;
    const size = tone === "note" ? 8.5 : 10;
    const width = tone === "default" ? CW : CW - 24;
    const color = tone === "note" ? INK.secondary : INK.primary;
    for (let i = 0; i < paragraphs.length; i++) {
      const p = paragraphs[i]!;
      const h = this.measure(p, { size, width });
      const labelH = i === 0 && label ? 13 : 0;
      this.ensure(h + labelH + (tone === "default" ? 6 : 14));
      const x = tone === "default" ? ML : ML + 12;
      const top = d.y;
      if (tone === "ai") d.rect(ML, top, CW, h + labelH + 12).fill(this.tint);
      if (tone === "note") d.rect(ML, top, 2, h + labelH + 4).fill(INK.grid);
      let y = top + (tone === "ai" ? 6 : 0);
      if (labelH) {
        this.text(label!.toUpperCase(), x, y, { size: 6.8, font: BOLD, color: this.brandText, width });
        y += labelH;
      }
      this.text(p, x, y, { size, color, width });
      d.y = top + h + labelH + (tone === "ai" ? 16 : 8);
    }
    d.y += 4;
    d.x = ML;
  }

  private risks(items: RiskItem[], emptyMessage: string): void {
    if (items.length === 0) {
      this.empty(emptyMessage);
      return;
    }
    const d = this.doc;
    for (const r of items) {
      const factors = [...r.factors].sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution)).slice(0, 5);
      const recH = r.recommendation ? this.measure(`Recommended: ${r.recommendation}`, { size: 8, width: CW - 20 }) + 6 : 0;
      const titleH = this.measure(r.title, { size: 9.5, font: BOLD, width: CW - 130 });
      const h = 12 + titleH + (r.subject ? 12 : 0) + Math.max(1, factors.length) * 13 + recH + 10;
      this.ensure(h + 8);
      const y0 = d.y;
      d.roundedRect(ML, y0, CW, h, 7).lineWidth(0.7).stroke(INK.hairline);
      const sw = this.sevMark(r.severity, ML + 10, y0 + 10, 7.5);
      this.text(r.title, ML + 18 + sw, y0 + 9, { size: 9.5, font: BOLD, width: CW - 80 - sw });
      this.text(formatNumber(Math.round(r.score)), ML, y0 + 7, { size: 15, font: BOLD, width: CW - 10, align: "right" });
      let y = y0 + 10 + titleH + 2;
      if (r.subject) {
        this.text(r.subject, ML + 10, y, { size: 7.5, color: INK.secondary, width: CW - 60, height: 10 });
        y += 12;
      }
      const max = Math.max(1, ...factors.map((f) => Math.abs(f.contribution)));
      if (factors.length === 0) {
        this.text("No factor breakdown available.", ML + 10, y, { size: 7.5, color: INK.muted });
        y += 13;
      }
      for (const f of factors) {
        this.text(f.label, ML + 10, y, { size: 7.5, font: BOLD, width: 120, height: 10 });
        d.roundedRect(ML + 135, y + 2, 80, 5, 2.5).fill("#F1F0EC");
        const bw = Math.max(2, (Math.abs(f.contribution) / max) * 80);
        d.roundedRect(ML + 135, y + 2, bw, 5, 2.5).fill(f.contribution < 0 ? STATUS_COLOR.good : (SEVERITY_COLOR[r.severity] ?? INK.muted));
        this.text(`${f.contribution >= 0 ? "+" : "-"}${formatNumber(Math.abs(f.contribution), { digits: 1 })}`, ML + 220, y, { size: 7.5, font: BOLD, width: 30, align: "right" });
        this.text(f.explanation, ML + 258, y, { size: 7.5, color: INK.secondary, width: CW - 268, height: 10 });
        y += 13;
      }
      if (r.recommendation) this.text(`Recommended: ${r.recommendation}`, ML + 10, y + 2, { size: 8, width: CW - 20 });
      d.y = y0 + h + 8;
    }
    d.y += 4;
    d.x = ML;
  }

  private recommendations(items: Recommendation[], emptyMessage: string): void {
    if (items.length === 0) {
      this.empty(emptyMessage, true);
      return;
    }
    const d = this.doc;
    const PRIO: Record<string, string> = { critical: SEVERITY_COLOR.critical, high: "#C2410C", medium: "#8A6400", low: SEVERITY_COLOR.low };
    const OWNER: Record<string, string> = { customer: "Your team", soc: "SOC", mssp: "Service management", it: "IT operations", security_engineering: "Security engineering", management: "Management" };
    for (const r of items) {
      const tx = ML + 74;
      const tw = CW - 84;
      const h = 10 + this.measure(r.title, { size: 9.5, font: BOLD, width: tw }) + this.measure(r.rationale, { size: 8.3, width: tw }) + (r.owner ? 12 : 0) + 8;
      this.ensure(h + 6);
      const y0 = d.y;
      d.roundedRect(ML, y0, CW, h, 7).lineWidth(0.7).stroke(INK.hairline);
      this.pill(r.priority.toUpperCase(), ML + 10, y0 + 9, PRIO[r.priority] ?? INK.secondary, "#FFFFFF", 6.8);
      let y = y0 + 8;
      y += this.text(r.title, tx, y, { size: 9.5, font: BOLD, width: tw }) + 2;
      y += this.text(r.rationale, tx, y, { size: 8.3, color: INK.secondary, width: tw });
      if (r.owner) this.text(`Owner: ${OWNER[r.owner] ?? r.owner}`, tx, y + 2, { size: 7.3, color: INK.muted, width: tw });
      d.y = y0 + h + 6;
    }
    d.y += 6;
    d.x = ML;
  }

  private callout(tone: "info" | "success" | "warning" | "critical", title: string, body: string): void {
    const COLORS = { info: ["#EEF4FC", "#2A78D6"], success: ["#EEF7EE", "#0CA30C"], warning: ["#FFF7E6", "#E0A100"], critical: ["#FDEEEE", "#D03B3B"] } as const;
    const [bg, bar] = COLORS[tone];
    const h = 12 + this.measure(title, { size: 9.5, font: BOLD, width: CW - 28 }) + this.measure(body, { size: 8.8, width: CW - 28 }) + 10;
    this.ensure(h + 8);
    const y0 = this.doc.y;
    this.doc.rect(ML, y0, CW, h).fill(bg);
    this.doc.rect(ML, y0, 3, h).fill(bar);
    let y = y0 + 8;
    y += this.text(title, ML + 14, y, { size: 9.5, font: BOLD, width: CW - 28 }) + 2;
    this.text(body, ML + 14, y, { size: 8.8, color: INK.secondary, width: CW - 28 });
    this.doc.y = y0 + h + 10;
    this.doc.x = ML;
  }

  private empty(message: string, ok = false): void {
    this.ensure(34);
    const y0 = this.doc.y;
    this.doc.roundedRect(ML, y0, CW, 26, 6).dash(3, { space: 3 }).lineWidth(0.7).stroke(ok ? "#BFD8BF" : INK.grid).undash();
    this.text(message, ML, y0 + 8.5, { size: 8.5, color: ok ? INK.good : INK.muted, width: CW, align: "center" });
    this.doc.y = y0 + 36;
    this.doc.x = ML;
  }
}

/** Render a report to a PDF buffer. */
export function renderPdf(report: ReportData, opts: PdfRenderOptions = {}): Promise<Buffer> {
  const doc = new PDFDocument({
    size: "A4",
    autoFirstPage: false,
    bufferPages: true,
    compress: opts.compress ?? true,
    lang: "en",
    displayTitle: true,
    pdfVersion: "1.7",
    info: {
      Title: pdfSafe(`${report.title} — ${report.period.label}`),
      Author: pdfSafe(report.branding.name),
      Subject: pdfSafe(report.typeLabel),
      Keywords: pdfSafe(`${report.type}, security, report, ${report.classification}`),
      Creator: "Bloody Reporting",
      Producer: "Bloody Reporting",
      CreationDate: new Date(report.generatedAt),
      ModDate: new Date(report.generatedAt),
    },
  });
  const chunks: Buffer[] = [];
  const done = new Promise<Buffer>((resolve, reject) => {
    doc.on("data", (c: Buffer) => chunks.push(c));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
  });
  try {
    new PdfReport(doc, report).render();
    doc.end();
  } catch (err) {
    doc.end();
    return Promise.reject(err);
  }
  return done;
}
