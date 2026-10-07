import { CATEGORICAL, INK } from "../branding.js";
import { formatTick, formatValue } from "../format.js";
import type { ChartSpec } from "../model.js";

/**
 * Renderer-neutral chart layout. A chart spec is laid out once into simple vector primitives
 * (rect / path / line / circle / text); the SVG renderer (HTML reports, e-mail) and the
 * pdfkit renderer (PDF reports) draw the same scene, so charts are identical everywhere.
 *
 * Visual rules (house data-viz spec): thin marks (bars ≤ 24px, 2px lines), 4px rounded
 * data-ends anchored square to the baseline, 2px surface gaps between touching marks,
 * hairline recessive gridlines, a legend whenever there are ≥ 2 series, selective direct
 * labels, text always in ink tokens (never the series colour), fixed categorical order.
 */
export type Primitive =
  | { t: "rect"; x: number; y: number; w: number; h: number; fill: string; title?: string }
  | { t: "path"; d: string; fill?: string; stroke?: string; strokeWidth?: number; opacity?: number; title?: string }
  | { t: "line"; x1: number; y1: number; x2: number; y2: number; stroke: string; width: number }
  | { t: "circle"; cx: number; cy: number; r: number; fill: string; stroke?: string; strokeWidth?: number; title?: string }
  | { t: "text"; x: number; y: number; text: string; size: number; fill: string; weight?: "normal" | "bold"; anchor: "start" | "middle" | "end" };

export interface ChartScene {
  width: number;
  height: number;
  items: Primitive[];
  empty: boolean;
  /** Plain-language summary for screen readers (<desc>). */
  description: string;
}

export interface LayoutOptions {
  width?: number;
  height?: number;
  surface?: string;
}

const SURFACE = "#FFFFFF";
const FONT_TICK = 9.5;
const FONT_LABEL = 10;

/** Approximate text width for Helvetica / system sans (good enough for layout decisions). */
export function textWidth(text: string, size: number): number {
  let w = 0;
  for (const ch of text) {
    if ("il.,:;|'!".includes(ch)) w += 0.28;
    else if ("mwMW@%".includes(ch)) w += 0.85;
    else if (ch >= "A" && ch <= "Z") w += 0.66;
    else if (ch === " ") w += 0.28;
    else w += 0.55;
  }
  return w * size;
}

export function fitText(text: string, size: number, maxWidth: number): string {
  if (textWidth(text, size) <= maxWidth) return text;
  let s = text;
  while (s.length > 1 && textWidth(`${s}…`, size) > maxWidth) s = s.slice(0, -1);
  return `${s.trimEnd()}…`;
}

function niceNum(range: number, round: boolean): number {
  const exponent = Math.floor(Math.log10(range));
  const fraction = range / Math.pow(10, exponent);
  let nice: number;
  if (round) nice = fraction < 1.5 ? 1 : fraction < 3 ? 2 : fraction < 7 ? 5 : 10;
  else nice = fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 5 ? 5 : 10;
  return nice * Math.pow(10, exponent);
}

/** "Nice" axis: 0 … niceMax in round steps. */
export function niceScale(max: number, ticks = 4, unit?: string): { max: number; step: number; ticks: number[] } {
  let m = Number.isFinite(max) && max > 0 ? max : 1;
  if (unit === "percent" && m <= 100 && m > 60) m = 100;
  let step = niceNum(niceNum(m, false) / ticks, true);
  // Counts, durations and money never get fractional gridlines.
  if ((unit === "count" || unit === "minutes" || unit === "currency") && step < 1) step = 1;
  const top = Math.max(step, Math.ceil(m / step - 1e-9) * step);
  const out: number[] = [];
  for (let v = 0; v <= top + step / 2; v += step) out.push(Math.round(v * 1e6) / 1e6);
  return { max: top, step, ticks: out };
}

function r2(n: number): number {
  return Math.round(n * 100) / 100;
}

/** Bar rising from a baseline with a rounded data-end (top) and square base. */
export function columnPath(x: number, y: number, w: number, h: number, radius = 4): string {
  if (h <= 0 || w <= 0) return "";
  const r = Math.min(radius, w / 2, h);
  return `M${r2(x)} ${r2(y + h)}V${r2(y + r)}Q${r2(x)} ${r2(y)} ${r2(x + r)} ${r2(y)}H${r2(x + w - r)}Q${r2(x + w)} ${r2(y)} ${r2(x + w)} ${r2(y + r)}V${r2(y + h)}Z`;
}

/** Horizontal bar from the left baseline with a rounded right end. */
export function barPath(x: number, y: number, w: number, h: number, radius = 4): string {
  if (h <= 0 || w <= 0) return "";
  const r = Math.min(radius, h / 2, w);
  return `M${r2(x)} ${r2(y)}H${r2(x + w - r)}Q${r2(x + w)} ${r2(y)} ${r2(x + w)} ${r2(y + r)}V${r2(y + h - r)}Q${r2(x + w)} ${r2(y + h)} ${r2(x + w - r)} ${r2(y + h)}H${r2(x)}Z`;
}

function arcPoint(cx: number, cy: number, r: number, angle: number): [number, number] {
  return [cx + r * Math.cos(angle), cy + r * Math.sin(angle)];
}

/** Donut slice between angles (radians, 0 = 3 o'clock, clockwise). */
export function slicePath(cx: number, cy: number, r: number, ri: number, a0: number, a1: number): string {
  const sweep = a1 - a0;
  if (sweep >= Math.PI * 2 - 1e-6) {
    // full ring: two halves
    return `${slicePath(cx, cy, r, ri, a0, a0 + Math.PI)}${slicePath(cx, cy, r, ri, a0 + Math.PI, a0 + Math.PI * 2 - 1e-4)}`;
  }
  const large = sweep > Math.PI ? 1 : 0;
  const [x0, y0] = arcPoint(cx, cy, r, a0);
  const [x1, y1] = arcPoint(cx, cy, r, a1);
  const [x2, y2] = arcPoint(cx, cy, ri, a1);
  const [x3, y3] = arcPoint(cx, cy, ri, a0);
  return `M${r2(x0)} ${r2(y0)}A${r2(r)} ${r2(r)} 0 ${large} 1 ${r2(x1)} ${r2(y1)}L${r2(x2)} ${r2(y2)}A${r2(ri)} ${r2(ri)} 0 ${large} 0 ${r2(x3)} ${r2(y3)}Z`;
}

function seriesColors(spec: ChartSpec): string[] {
  let slot = 0;
  return spec.series.map((s) => s.color ?? CATEGORICAL[slot++ % CATEGORICAL.length]!);
}

function fmt(spec: ChartSpec, v: number | null): string {
  return formatValue(v, spec.unit, { compact: true, ...(spec.currency ? { currency: spec.currency } : {}) });
}

function legend(items: { name: string; color: string }[], x: number, y: number, maxWidth: number): { prims: Primitive[]; height: number } {
  const prims: Primitive[] = [];
  let cx = x;
  let cy = y;
  for (const it of items) {
    const label = fitText(it.name, FONT_LABEL, 160);
    const w = 14 + textWidth(label, FONT_LABEL) + 14;
    if (cx + w > x + maxWidth && cx > x) {
      cx = x;
      cy += 16;
    }
    prims.push({ t: "rect", x: cx, y: cy + 1, w: 10, h: 10, fill: it.color });
    prims.push({ t: "text", x: cx + 14, y: cy + 10, text: label, size: FONT_LABEL, fill: INK.secondary, anchor: "start" });
    cx += w;
  }
  return { prims, height: items.length > 0 ? cy - y + 16 : 0 };
}

function isEmpty(spec: ChartSpec): boolean {
  return spec.categories.length === 0 || spec.series.length === 0 || spec.series.every((s) => s.values.every((v) => v === null || v === 0));
}

function emptyScene(spec: ChartSpec, width: number, height: number): ChartScene {
  return {
    width,
    height: Math.min(height, 90),
    empty: true,
    description: `${spec.title}: ${spec.emptyMessage ?? "no data"}`,
    items: [
      { t: "rect", x: 0, y: 0, w: width, h: Math.min(height, 90), fill: "#F7F7F5" },
      { t: "text", x: width / 2, y: Math.min(height, 90) / 2 + 4, text: spec.emptyMessage ?? "No data for this period.", size: 11, fill: INK.muted, anchor: "middle" },
    ],
  };
}

export function layoutChart(spec: ChartSpec, opts: LayoutOptions = {}): ChartScene {
  const width = opts.width ?? 640;
  const height = opts.height ?? 240;
  if (isEmpty(spec)) return emptyScene(spec, width, height);
  switch (spec.type) {
    case "donut":
      return layoutDonut(spec, width, height, opts.surface ?? SURFACE);
    case "hbar":
      return layoutHbar(spec, width);
    case "line":
      return layoutLine(spec, width, height, opts.surface ?? SURFACE);
    case "bar":
    case "stacked_bar":
    default:
      return layoutColumns(spec, width, height);
  }
}

function describe(spec: ChartSpec): string {
  const parts = spec.series.map((s) => {
    const vals = s.values.map((v, i) => `${spec.categories[i] ?? i}: ${fmt(spec, v)}`).slice(0, 12);
    return `${s.name} — ${vals.join(", ")}${s.values.length > 12 ? ", …" : ""}`;
  });
  return `${spec.title}. ${parts.join(". ")}`;
}

function layoutColumns(spec: ChartSpec, width: number, height: number): ChartScene {
  const items: Primitive[] = [];
  const colors = seriesColors(spec);
  const stacked = spec.type === "stacked_bar";
  const multi = spec.series.length > 1;
  const lg = multi ? legend(spec.series.map((s, i) => ({ name: s.name, color: colors[i]! })), 0, 0, width) : { prims: [], height: 0 };
  items.push(...lg.prims);
  const n = spec.categories.length;
  const totals = spec.categories.map((_, ci) => (stacked ? spec.series.reduce((s, se) => s + Math.max(0, se.values[ci] ?? 0), 0) : Math.max(0, ...spec.series.map((se) => se.values[ci] ?? 0))));
  const scale = niceScale(Math.max(...totals), 4, spec.unit);
  const tickLabels = scale.ticks.map((t) => formatTick(t, spec.unit, spec.currency));
  const left = Math.ceil(Math.max(...tickLabels.map((l) => textWidth(l, FONT_TICK)))) + 8;
  const top = lg.height + (multi ? 8 : 6) + 10;
  const bottom = height - 22;
  const plotW = width - left - 4;
  const plotH = bottom - top;
  const y = (v: number): number => bottom - (v / scale.max) * plotH;
  scale.ticks.forEach((t, i) => {
    const ty = y(t);
    if (i > 0) items.push({ t: "line", x1: left, y1: ty, x2: width - 4, y2: ty, stroke: INK.grid, width: 1 });
    items.push({ t: "text", x: left - 6, y: ty + 3.5, text: tickLabels[i]!, size: FONT_TICK, fill: INK.muted, anchor: "end" });
  });
  const band = plotW / n;
  const seriesN = stacked ? 1 : spec.series.length;
  const barW = Math.max(2, Math.min(24, (band * 0.72 - (seriesN - 1) * 2) / seriesN));
  const groupW = seriesN * barW + (seriesN - 1) * 2;
  for (let ci = 0; ci < n; ci++) {
    const gx = left + ci * band + (band - groupW) / 2;
    if (stacked) {
      let acc = 0;
      const nonZero = spec.series.map((s, si) => ({ v: Math.max(0, s.values[ci] ?? 0), si })).filter((p) => p.v > 0);
      nonZero.forEach((p, k) => {
        const y0 = y(acc);
        const y1 = y(acc + p.v);
        acc += p.v;
        const isTop = k === nonZero.length - 1;
        const gap = k > 0 ? 2 : 0;
        const h = Math.max(0, y0 - y1 - gap);
        if (h <= 0) return;
        const title = `${spec.categories[ci]} · ${spec.series[p.si]!.name}: ${fmt(spec, p.v)}`;
        if (isTop) items.push({ t: "path", d: columnPath(gx, y1, barW, h), fill: colors[p.si]!, title });
        else items.push({ t: "rect", x: gx, y: y1, w: barW, h, fill: colors[p.si]!, title });
      });
      if (n <= 16 && acc > 0) items.push({ t: "text", x: gx + barW / 2, y: y(acc) - 4, text: fmt(spec, acc), size: FONT_TICK, fill: INK.secondary, anchor: "middle" });
    } else {
      spec.series.forEach((s, si) => {
        const v = s.values[ci];
        if (v === null || v === undefined || v <= 0) return;
        const bx = gx + si * (barW + 2);
        const color = !multi && spec.categoryColors?.[ci] ? spec.categoryColors[ci]! : colors[si]!;
        items.push({ t: "path", d: columnPath(bx, y(v), barW, bottom - y(v)), fill: color, title: `${spec.categories[ci]}${multi ? ` · ${s.name}` : ""}: ${fmt(spec, v)}` });
        if (!multi && n <= 12) items.push({ t: "text", x: bx + barW / 2, y: y(v) - 4, text: fmt(spec, v), size: FONT_TICK, fill: INK.secondary, anchor: "middle" });
      });
    }
  }
  items.push({ t: "line", x1: left, y1: bottom, x2: width - 4, y2: bottom, stroke: INK.axis, width: 1 });
  const maxLabel = Math.max(...spec.categories.map((c) => textWidth(c, FONT_TICK)));
  const step = Math.max(1, Math.ceil((maxLabel + 8) / band));
  for (let ci = 0; ci < n; ci += step) {
    items.push({ t: "text", x: left + ci * band + band / 2, y: bottom + 13, text: fitText(spec.categories[ci]!, FONT_TICK, band * step - 4), size: FONT_TICK, fill: INK.muted, anchor: "middle" });
  }
  return { width, height, items, empty: false, description: describe(spec) };
}

function layoutHbar(spec: ChartSpec, width: number): ChartScene {
  const items: Primitive[] = [];
  const colors = seriesColors(spec);
  const series = spec.series[0]!;
  const n = spec.categories.length;
  const rowH = 22;
  const barH = 12;
  const labelW = Math.min(width * 0.4, Math.max(...spec.categories.map((c) => textWidth(c, FONT_LABEL))) + 10);
  const valueW = Math.max(...series.values.map((v) => textWidth(fmt(spec, v), FONT_TICK))) + 10;
  const plotW = Math.max(40, width - labelW - valueW);
  const max = Math.max(...series.values.map((v) => v ?? 0), 0) || 1;
  const height = n * rowH + 6;
  for (let i = 0; i < n; i++) {
    const v = series.values[i] ?? 0;
    const cy = i * rowH + rowH / 2 + 2;
    items.push({ t: "text", x: labelW - 8, y: cy + 3.5, text: fitText(spec.categories[i]!, FONT_LABEL, labelW - 10), size: FONT_LABEL, fill: INK.secondary, anchor: "end" });
    const w = (v / max) * plotW;
    const color = spec.categoryColors?.[i] ?? colors[0]!;
    if (w > 0) items.push({ t: "path", d: barPath(labelW, cy - barH / 2, w, barH), fill: color, title: `${spec.categories[i]}: ${fmt(spec, v)}` });
    items.push({ t: "text", x: labelW + w + 5, y: cy + 3.5, text: fmt(spec, v), size: FONT_TICK, fill: INK.primary, anchor: "start" });
  }
  items.push({ t: "line", x1: labelW, y1: 2, x2: labelW, y2: height - 4, stroke: INK.axis, width: 1 });
  return { width, height, items, empty: false, description: describe(spec) };
}

function layoutLine(spec: ChartSpec, width: number, height: number, surface: string): ChartScene {
  const items: Primitive[] = [];
  const colors = seriesColors(spec);
  const multi = spec.series.length > 1;
  const lg = multi ? legend(spec.series.map((s, i) => ({ name: s.name, color: colors[i]! })), 0, 0, width) : { prims: [], height: 0 };
  items.push(...lg.prims);
  const n = spec.categories.length;
  const all = spec.series.flatMap((s) => s.values.filter((v): v is number => v !== null && Number.isFinite(v)));
  const scale = niceScale(Math.max(...all, 0), 4, spec.unit);
  const tickLabels = scale.ticks.map((t) => formatTick(t, spec.unit, spec.currency));
  const endLabels = spec.series.length <= 4;
  const endW = endLabels ? Math.max(...spec.series.map((s) => textWidth(fmt(spec, [...s.values].reverse().find((v) => v !== null) ?? null), FONT_TICK))) + 12 : 6;
  const left = Math.ceil(Math.max(...tickLabels.map((l) => textWidth(l, FONT_TICK)))) + 8;
  const top = lg.height + (multi ? 8 : 6) + 6;
  const bottom = height - 22;
  const plotW = width - left - endW;
  const plotH = bottom - top;
  const x = (i: number): number => (n === 1 ? left + plotW / 2 : left + (i / (n - 1)) * plotW);
  const y = (v: number): number => bottom - (v / scale.max) * plotH;
  scale.ticks.forEach((t, i) => {
    const ty = y(t);
    if (i > 0) items.push({ t: "line", x1: left, y1: ty, x2: left + plotW, y2: ty, stroke: INK.grid, width: 1 });
    items.push({ t: "text", x: left - 6, y: ty + 3.5, text: tickLabels[i]!, size: FONT_TICK, fill: INK.muted, anchor: "end" });
  });
  items.push({ t: "line", x1: left, y1: bottom, x2: left + plotW, y2: bottom, stroke: INK.axis, width: 1 });
  const ends: { x: number; y: number; text: string }[] = [];
  spec.series.forEach((s, si) => {
    const color = colors[si]!;
    const segments: [number, number][][] = [];
    let cur: [number, number][] = [];
    s.values.forEach((v, i) => {
      if (v === null || !Number.isFinite(v)) {
        if (cur.length) segments.push(cur);
        cur = [];
      } else cur.push([x(i), y(v)]);
    });
    if (cur.length) segments.push(cur);
    if (!multi) {
      for (const seg of segments) {
        if (seg.length < 2) continue;
        const d = `M${r2(seg[0]![0])} ${r2(bottom)}${seg.map(([px, py]) => `L${r2(px)} ${r2(py)}`).join("")}L${r2(seg[seg.length - 1]![0])} ${r2(bottom)}Z`;
        items.push({ t: "path", d, fill: color, opacity: 0.1 });
      }
    }
    for (const seg of segments) {
      if (seg.length === 1) items.push({ t: "circle", cx: seg[0]![0], cy: seg[0]![1], r: 3, fill: color });
      else items.push({ t: "path", d: seg.map(([px, py], k) => `${k === 0 ? "M" : "L"}${r2(px)} ${r2(py)}`).join(""), stroke: color, strokeWidth: 2 });
    }
    // Hover targets (SVG tooltips) bigger than the mark; invisible in print/PDF.
    s.values.forEach((v, i) => {
      if (v === null || !Number.isFinite(v)) return;
      items.push({ t: "circle", cx: x(i), cy: y(v), r: 7, fill: "transparent", title: `${spec.categories[i]}${multi ? ` · ${s.name}` : ""}: ${fmt(spec, v)}` });
    });
    const lastIdx = s.values.map((v, i) => (v === null ? -1 : i)).filter((i) => i >= 0).pop();
    if (lastIdx !== undefined) {
      const v = s.values[lastIdx]!;
      items.push({ t: "circle", cx: x(lastIdx), cy: y(v), r: 4, fill: color, stroke: surface, strokeWidth: 2 });
      ends.push({ x: x(lastIdx) + 8, y: y(v), text: fmt(spec, v) });
    }
  });
  // Direct end labels only when they do not collide; otherwise the legend carries identity.
  const sortedEnds = [...ends].sort((a, b) => a.y - b.y);
  const collide = sortedEnds.some((p, i) => i > 0 && p.y - sortedEnds[i - 1]!.y < 11);
  if (endLabels && !collide) for (const p of ends) items.push({ t: "text", x: p.x, y: p.y + 3.5, text: p.text, size: FONT_TICK, fill: INK.primary, anchor: "start", weight: "bold" });
  const maxLabel = Math.max(...spec.categories.map((c) => textWidth(c, FONT_TICK)));
  const slot = n > 1 ? plotW / (n - 1) : plotW;
  const step = Math.max(1, Math.ceil((maxLabel + 10) / slot));
  for (let i = 0; i < n; i += step) items.push({ t: "text", x: x(i), y: bottom + 13, text: spec.categories[i]!, size: FONT_TICK, fill: INK.muted, anchor: "middle" });
  return { width, height, items, empty: false, description: describe(spec) };
}

function layoutDonut(spec: ChartSpec, width: number, height: number, surface: string): ChartScene {
  const items: Primitive[] = [];
  const values = spec.series[0]!.values.map((v) => Math.max(0, v ?? 0));
  const total = values.reduce((s, v) => s + v, 0);
  const colors = spec.categories.map((_, i) => spec.categoryColors?.[i] ?? CATEGORICAL[i % CATEGORICAL.length]!);
  const h = Math.min(height, 200);
  const r = Math.min(h / 2 - 6, 84);
  const ri = r * 0.62;
  const cx = r + 6;
  const cy = h / 2;
  let a = -Math.PI / 2;
  values.forEach((v, i) => {
    if (v <= 0) return;
    const sweep = (v / total) * Math.PI * 2;
    items.push({ t: "path", d: slicePath(cx, cy, r, ri, a, a + sweep), fill: colors[i]!, stroke: surface, strokeWidth: 2, title: `${spec.categories[i]}: ${fmt(spec, v)} (${((v / total) * 100).toFixed(1)}%)` });
    a += sweep;
  });
  items.push({ t: "text", x: cx, y: cy + 4, text: fmt(spec, total), size: 18, fill: INK.primary, anchor: "middle", weight: "bold" });
  items.push({ t: "text", x: cx, y: cy + 18, text: "total", size: FONT_TICK, fill: INK.muted, anchor: "middle" });
  const lx = cx + r + 28;
  const rows = spec.categories.length;
  const rowH = Math.min(22, (h - 8) / Math.max(rows, 1));
  const ly0 = cy - (rows * rowH) / 2 + rowH / 2;
  const valueX = width - 4;
  spec.categories.forEach((c, i) => {
    const ly = ly0 + i * rowH;
    const v = values[i]!;
    items.push({ t: "rect", x: lx, y: ly - 5, w: 10, h: 10, fill: colors[i]! });
    items.push({ t: "text", x: lx + 16, y: ly + 3.5, text: fitText(c, FONT_LABEL, valueX - lx - 110), size: FONT_LABEL, fill: INK.secondary, anchor: "start" });
    items.push({ t: "text", x: valueX - 46, y: ly + 3.5, text: fmt(spec, v), size: FONT_LABEL, fill: INK.primary, anchor: "end", weight: "bold" });
    items.push({ t: "text", x: valueX, y: ly + 3.5, text: total > 0 ? `${((v / total) * 100).toFixed(v / total < 0.1 ? 1 : 0)}%` : "—", size: FONT_TICK, fill: INK.muted, anchor: "end" });
  });
  return { width, height: h, items, empty: false, description: describe(spec) };
}
