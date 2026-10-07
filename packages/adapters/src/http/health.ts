export type HealthStatus = "healthy" | "degraded" | "unhealthy";

export interface HealthCheckResult {
  engine: string;
  status: HealthStatus;
  ok: boolean;
  checkedAt: string;
  latencyMs: number;
  /** Engine version reported by its API, when available. */
  version?: string;
  /** Short, non-sensitive facts (counts, cluster name, API title). */
  details?: Record<string, string | number | boolean>;
  /** Error code/message when unhealthy — already redacted. */
  error?: { code: string; message: string };
}

/**
 * Run a probe and time it; any thrown error becomes an `unhealthy` result so health
 * endpoints and the integration status dashboard never crash on a misbehaving engine.
 */
export async function runHealthCheck(
  engine: string,
  probe: () => Promise<Omit<HealthCheckResult, "engine" | "checkedAt" | "latencyMs" | "ok"> & { ok?: boolean }>,
  clock: () => number = Date.now,
): Promise<HealthCheckResult> {
  const started = clock();
  try {
    const r = await probe();
    return {
      ...r,
      engine,
      ok: r.ok ?? r.status !== "unhealthy",
      checkedAt: new Date(started).toISOString(),
      latencyMs: Math.max(0, clock() - started),
    };
  } catch (err) {
    const e = err as { code?: unknown; message?: unknown };
    return {
      engine,
      status: "unhealthy",
      ok: false,
      checkedAt: new Date(started).toISOString(),
      latencyMs: Math.max(0, clock() - started),
      error: { code: typeof e.code === "string" ? e.code : "error", message: typeof e.message === "string" ? e.message.slice(0, 300) : "unknown error" },
    };
  }
}
