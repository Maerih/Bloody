/** Numeric helpers shared by the scoring engines. All pure. */

export function clamp(x: number, min: number, max: number): number {
  if (Number.isNaN(x)) return min;
  return x < min ? min : x > max ? max : x;
}

export function clamp01(x: number): number {
  return clamp(x, 0, 1);
}

/**
 * Hyperbolic saturation of a non-negative count: `n / (n + half)`.
 * Returns 0 for n = 0, exactly 0.5 when n = half and approaches 1 asymptotically.
 * Used everywhere a *count* becomes a signal so that volume can never dominate a score
 * (100 low-confidence alerts must not outweigh one confirmed compromise).
 */
export function saturate(n: number, half: number): number {
  if (!(n > 0)) return 0;
  if (!(half > 0)) return 1;
  return n / (n + half);
}

/** Probabilistic OR of independent signals: 1 − Π(1 − pᵢ). */
export function noisyOr(probabilities: Iterable<number>): number {
  let miss = 1;
  for (const p of probabilities) miss *= 1 - clamp01(p);
  return 1 - miss;
}

export function round(x: number, decimals = 2): number {
  const f = 10 ** decimals;
  return Math.round((x + Number.EPSILON) * f) / f;
}

export function sum(xs: Iterable<number>): number {
  let s = 0;
  for (const x of xs) s += x;
  return s;
}

export function mean(xs: readonly number[]): number {
  return xs.length === 0 ? 0 : sum(xs) / xs.length;
}

export function stddev(xs: readonly number[]): number {
  if (xs.length < 2) return 0;
  const m = mean(xs);
  return Math.sqrt(sum(xs.map((x) => (x - m) ** 2)) / (xs.length - 1));
}

export function pct(x: number): string {
  return `${Math.round(clamp01(x) * 100)}%`;
}

/** Great-circle distance in kilometres. */
export function haversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371.0088;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(a)));
}
