import type { ChartSpec } from "../model.js";
import { layoutChart, type ChartScene, type LayoutOptions } from "./chart-scene.js";
import { escapeHtml } from "./escape.js";

const FONT = "system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";

function n(v: number): string {
  return (Math.round(v * 100) / 100).toString();
}

/** Serialise a chart scene to an accessible inline SVG (role=img, <title>, <desc>, per-mark tooltips). */
export function sceneToSvg(scene: ChartScene, opts: { id: string; title: string; font?: string }): string {
  const id = opts.id.replace(/[^A-Za-z0-9_-]/g, "-");
  const parts: string[] = [];
  for (const p of scene.items) {
    switch (p.t) {
      case "rect": {
        const el = `<rect x="${n(p.x)}" y="${n(p.y)}" width="${n(p.w)}" height="${n(p.h)}" fill="${escapeHtml(p.fill)}"`;
        parts.push(p.title ? `${el}><title>${escapeHtml(p.title)}</title></rect>` : `${el}/>`);
        break;
      }
      case "path": {
        const attrs = [`d="${escapeHtml(p.d)}"`, `fill="${escapeHtml(p.fill ?? "none")}"`];
        if (p.stroke) attrs.push(`stroke="${escapeHtml(p.stroke)}"`, `stroke-width="${n(p.strokeWidth ?? 1)}"`, `stroke-linejoin="round"`, `stroke-linecap="round"`);
        if (p.opacity !== undefined) attrs.push(`fill-opacity="${n(p.opacity)}"`);
        parts.push(p.title ? `<path ${attrs.join(" ")}><title>${escapeHtml(p.title)}</title></path>` : `<path ${attrs.join(" ")}/>`);
        break;
      }
      case "line":
        parts.push(`<line x1="${n(p.x1)}" y1="${n(p.y1)}" x2="${n(p.x2)}" y2="${n(p.y2)}" stroke="${escapeHtml(p.stroke)}" stroke-width="${n(p.width)}" shape-rendering="crispEdges"/>`);
        break;
      case "circle": {
        const attrs = [`cx="${n(p.cx)}"`, `cy="${n(p.cy)}"`, `r="${n(p.r)}"`, `fill="${escapeHtml(p.fill)}"`];
        if (p.stroke) attrs.push(`stroke="${escapeHtml(p.stroke)}"`, `stroke-width="${n(p.strokeWidth ?? 1)}"`);
        parts.push(p.title ? `<circle ${attrs.join(" ")}><title>${escapeHtml(p.title)}</title></circle>` : `<circle ${attrs.join(" ")}/>`);
        break;
      }
      case "text":
        parts.push(`<text x="${n(p.x)}" y="${n(p.y)}" font-size="${n(p.size)}" fill="${escapeHtml(p.fill)}" text-anchor="${p.anchor}"${p.weight === "bold" ? ' font-weight="600"' : ""}>${escapeHtml(p.text)}</text>`);
        break;
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n(scene.width)} ${n(scene.height)}" width="100%" style="max-width:${n(scene.width)}px;height:auto;display:block" role="img" aria-labelledby="${id}-t ${id}-d" font-family="${escapeHtml(opts.font ?? FONT)}"><title id="${id}-t">${escapeHtml(opts.title)}</title><desc id="${id}-d">${escapeHtml(scene.description)}</desc>${parts.join("")}</svg>`;
}

/** Lay out and render a chart spec as inline SVG. */
export function renderChartSvg(spec: ChartSpec, opts: LayoutOptions & { font?: string } = {}): string {
  return sceneToSvg(layoutChart(spec, opts), { id: `chart-${spec.id}`, title: spec.title, ...(opts.font ? { font: opts.font } : {}) });
}
