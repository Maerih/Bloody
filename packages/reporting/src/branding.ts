import type { Severity } from "@bloody/contracts";
import { z } from "zod";
import type { ReportBranding } from "./model.js";

/**
 * White-labelling. MSSPs issue customer reports under their own name, colour and logo; the
 * default brand is Bloody. Inputs are validated strictly — the logo must be a base64 raster
 * data URL (no SVG: it could carry script), the colour a #RRGGBB hex.
 */
export const BrandingInput = z.object({
  name: z.string().trim().min(1).max(80),
  primaryColor: z.string().regex(/^#[0-9a-fA-F]{6}$/, "primaryColor must be #RRGGBB"),
  logoDataUrl: z
    .string()
    .max(1_400_000)
    .regex(/^data:image\/(png|jpeg);base64,[A-Za-z0-9+/]+={0,2}$/, "logo must be a base64 PNG or JPEG data URL")
    .nullable()
    .optional(),
  poweredBy: z.boolean().optional(),
  footerText: z.string().max(300).nullable().optional(),
});
export type BrandingInput = z.input<typeof BrandingInput>;

export const DEFAULT_REPORT_BRANDING: ReportBranding = {
  name: "Bloody",
  primaryColor: "#B4232C",
  logoDataUrl: null,
  poweredBy: false,
  footerText: null,
};

/** Validate branding; invalid fields fall back to the default (and are reported). */
export function resolveReportBranding(input: Partial<BrandingInput> | null | undefined): { branding: ReportBranding; issues: string[] } {
  if (!input) return { branding: { ...DEFAULT_REPORT_BRANDING }, issues: [] };
  const issues: string[] = [];
  const out: ReportBranding = { ...DEFAULT_REPORT_BRANDING };
  const shape = BrandingInput.shape;
  for (const key of Object.keys(shape) as (keyof typeof shape)[]) {
    const v = (input as Record<string, unknown>)[key];
    if (v === undefined) continue;
    const r = shape[key].safeParse(v);
    if (r.success) (out as unknown as Record<string, unknown>)[key] = r.data ?? (DEFAULT_REPORT_BRANDING as unknown as Record<string, unknown>)[key];
    else issues.push(`branding.${key}: ${r.error.issues[0]?.message ?? "invalid"}`);
  }
  return { branding: out, issues };
}

/** Decode a validated logo data URL to bytes (PDF embedding). */
export function decodeLogo(dataUrl: string | null): { bytes: Buffer; type: "png" | "jpeg" } | null {
  if (!dataUrl) return null;
  const m = /^data:image\/(png|jpeg);base64,([A-Za-z0-9+/]+={0,2})$/.exec(dataUrl);
  if (!m) return null;
  const bytes = Buffer.from(m[2]!, "base64");
  const isPng = bytes.length > 8 && bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  const isJpeg = bytes.length > 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  if (m[1] === "png" && isPng) return { bytes, type: "png" };
  if (m[1] === "jpeg" && isJpeg) return { bytes, type: "jpeg" };
  return null;
}

// ─── colour utilities ───────────────────────────────────────────────────────

function hexToRgb(hex: string): [number, number, number] {
  const m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
  if (!m) return [0, 0, 0];
  return [parseInt(m[1]!, 16), parseInt(m[2]!, 16), parseInt(m[3]!, 16)];
}

function rgbToHex(r: number, g: number, b: number): string {
  const c = (v: number): string => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, "0");
  return `#${c(r)}${c(g)}${c(b)}`.toUpperCase();
}

/** Mix `hex` with `other` (0 = hex, 1 = other). */
export function mix(hex: string, other: string, amount: number): string {
  const a = hexToRgb(hex);
  const b = hexToRgb(other);
  return rgbToHex(a[0] + (b[0] - a[0]) * amount, a[1] + (b[1] - a[1]) * amount, a[2] + (b[2] - a[2]) * amount);
}

export function relativeLuminance(hex: string): number {
  const lin = (v: number): number => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  };
  const [r, g, b] = hexToRgb(hex);
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

export function contrastRatio(a: string, b: string): number {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/** White or ink text on a coloured background, whichever contrasts more. */
export function onColor(hex: string): string {
  return contrastRatio(hex, "#FFFFFF") >= contrastRatio(hex, INK.primary) ? "#FFFFFF" : INK.primary;
}

/** A brand colour safe to use as text on white (darkened until ≥ 4.5:1). */
export function brandInk(hex: string): string {
  let c = hex;
  for (let i = 0; i < 10 && contrastRatio(c, "#FFFFFF") < 4.5; i++) c = mix(c, "#000000", 0.12);
  return c;
}

// ─── chart & document palette (validated reference palette, light mode) ────

export const INK = {
  primary: "#0B0B0B",
  secondary: "#52514E",
  muted: "#898781",
  grid: "#E1E0D9",
  axis: "#C3C2B7",
  surface: "#FCFCFB",
  page: "#F9F9F7",
  hairline: "#E6E5DF",
  good: "#006300",
} as const;

/** Categorical series colours — assigned in this fixed order, never cycled. */
export const CATEGORICAL = ["#2A78D6", "#EB6834", "#1BAF7A", "#EDA100", "#E87BA4", "#008300", "#4A3AA7", "#E34948"] as const;

/** Severity colours (status family; always paired with a text label). */
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#D03B3B",
  high: "#EC835A",
  medium: "#E0A100",
  low: "#4A3AA7",
  info: "#898781",
};

export const STATUS_COLOR = { good: "#0CA30C", warn: "#E0A100", bad: "#D03B3B" } as const;

export const SENTIMENT_COLOR = { good: "#006300", bad: "#B42318", neutral: "#52514E" } as const;
