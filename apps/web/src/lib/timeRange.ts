import type { TimeRange, TimeRangePreset } from "../api/types";

/** Relative windows offered by every time-range picker (SIEM search, module lenses). */
export const TIME_RANGE_PRESETS: { value: TimeRangePreset; label: string; minutes: number }[] = [
  { value: "15m", label: "Last 15 minutes", minutes: 15 },
  { value: "1h", label: "Last hour", minutes: 60 },
  { value: "4h", label: "Last 4 hours", minutes: 240 },
  { value: "24h", label: "Last 24 hours", minutes: 1440 },
  { value: "7d", label: "Last 7 days", minutes: 7 * 1440 },
  { value: "30d", label: "Last 30 days", minutes: 30 * 1440 },
  { value: "90d", label: "Last 90 days", minutes: 90 * 1440 },
];

export function isPreset(value: unknown): value is TimeRangePreset {
  return typeof value === "string" && TIME_RANGE_PRESETS.some((p) => p.value === value);
}

/** Resolve a range to absolute ISO bounds at `now` (relative ranges are evaluated at query time). */
export function resolveTimeRange(range: TimeRange, now: number = Date.now()): { from: string; to: string } {
  if ("preset" in range) {
    const minutes = TIME_RANGE_PRESETS.find((p) => p.value === range.preset)?.minutes ?? 1440;
    return { from: new Date(now - minutes * 60_000).toISOString(), to: new Date(now).toISOString() };
  }
  return { from: range.from, to: range.to };
}

export function describeTimeRange(range: TimeRange): string {
  if ("preset" in range) return TIME_RANGE_PRESETS.find((p) => p.value === range.preset)?.label ?? range.preset;
  const fmt = (iso: string) => iso.replace("T", " ").slice(0, 16);
  return `${fmt(range.from)} → ${fmt(range.to)}`;
}

/** URL encoding: "24h" or "2026-10-01T00:00:00.000Z..2026-10-02T00:00:00.000Z". */
export function encodeTimeRange(range: TimeRange): string {
  return "preset" in range ? range.preset : `${range.from}..${range.to}`;
}

export function decodeTimeRange(value: string | null | undefined, fallback: TimeRange = { preset: "24h" }): TimeRange {
  if (!value) return fallback;
  if (isPreset(value)) return { preset: value };
  const [from, to] = value.split("..");
  if (from && to && !Number.isNaN(Date.parse(from)) && !Number.isNaN(Date.parse(to)) && Date.parse(from) < Date.parse(to)) return { from, to };
  return fallback;
}

/** A window around an anchor time, e.g. ±24h around an incident's detection. */
export function windowAround(anchorIso: string, beforeHours: number, afterHours: number, now: number = Date.now()): TimeRange {
  const anchor = Date.parse(anchorIso);
  if (Number.isNaN(anchor)) return { preset: "7d" };
  const from = new Date(anchor - beforeHours * 3_600_000).toISOString();
  const to = new Date(Math.min(now, anchor + afterHours * 3_600_000)).toISOString();
  return Date.parse(from) < Date.parse(to) ? { from, to } : { preset: "7d" };
}
