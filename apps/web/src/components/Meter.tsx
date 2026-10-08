import { clsx } from "clsx";
import { formatNumber, formatPercent } from "../lib/format";

/** Usage vs limit (billing meters, quotas). `limit` null = unlimited. */
export function Meter({ label, used, limit, format = formatNumber, hint }: { label: string; used: number; limit: number | null; format?: (n: number) => string; hint?: string }) {
  const ratio = limit && limit > 0 ? Math.min(1, used / limit) : 0;
  const tone = limit === null ? "bg-primary" : ratio >= 1 ? "bg-sev-critical" : ratio >= 0.8 ? "bg-sev-high" : "bg-healthy";
  return (
    <div>
      <div className="flex items-baseline justify-between gap-2 text-sm">
        <span className="font-medium text-fg">{label}</span>
        <span className="tabular-nums text-fg-muted">
          {format(used)} / {limit === null ? "unlimited" : format(limit)}
          {limit ? <span className="ml-1 text-fg-subtle">({formatPercent(used, limit)})</span> : null}
        </span>
      </div>
      <div className="mt-1 h-2 rounded bg-surface-3" role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={limit ?? undefined} aria-valuenow={used}>
        <div className={clsx("h-2 rounded", tone)} style={{ width: `${limit === null ? 0 : Math.max(ratio * 100, used > 0 ? 2 : 0)}%` }} />
      </div>
      {hint ? <p className="mt-0.5 text-xs text-fg-subtle">{hint}</p> : null}
    </div>
  );
}
