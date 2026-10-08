import type { Alert } from "@bloody/contracts";
import { clsx } from "clsx";
import { useMemo } from "react";
import { useAlerts } from "../../api/hooks";
import type { AlertFilters } from "../../api/types";
import { Skeleton } from "../../components/Skeleton";
import { categorize, type AlertCategory } from "../../lib/classify";
import { formatInteger } from "../../lib/format";
import { SEVERITY_META } from "../../lib/severity";

/**
 * Detection categories (impossible travel, MFA manipulation, beaconing…) with alert counts.
 * Each card explains the category; selecting one filters the alert lens below.
 */
export function CategorySummary({
  categories,
  filters = {},
  predicate,
  selected,
  onSelect,
}: {
  categories: AlertCategory[];
  filters?: AlertFilters;
  predicate?: (a: Alert) => boolean;
  selected: string | null;
  onSelect: (key: string | null) => void;
}) {
  const alerts = useAlerts({ limit: 500, sort: "recent", ...filters });
  const buckets = useMemo(() => categorize((alerts.data?.items ?? []).filter((a) => (predicate ? predicate(a) : true)), categories), [alerts.data, categories, predicate]);
  return (
    <div className="mb-4 grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-5" role="group" aria-label="Detection categories">
      {buckets.map(({ category, alerts: items }) => {
        const open = items.filter((a) => a.status === "new" || a.status === "triaged" || a.status === "promoted");
        const worst = items.reduce<Alert["severity"] | null>((w, a) => (w === null || ["info", "low", "medium", "high", "critical"].indexOf(a.severity) > ["info", "low", "medium", "high", "critical"].indexOf(w) ? a.severity : w), null);
        const active = selected === category.key;
        return (
          <button
            key={category.key}
            type="button"
            aria-pressed={active}
            onClick={() => onSelect(active ? null : category.key)}
            title={category.description}
            className={clsx("rounded border bg-surface p-2.5 text-left shadow-card transition-colors hover:border-line-strong", active ? "border-primary ring-1 ring-primary/30" : "border-line")}
          >
            <span className="block truncate text-sm font-medium text-fg">{category.label}</span>
            {alerts.isPending ? (
              <Skeleton className="mt-1 h-5 w-10" />
            ) : (
              <span className="mt-0.5 flex items-baseline gap-1.5">
                <span className={clsx("text-xl font-semibold tabular-nums", open.length > 0 && worst ? SEVERITY_META[worst].text : "text-fg")}>{formatInteger(items.length)}</span>
                {open.length > 0 ? <span className="text-2xs text-fg-subtle">{formatInteger(open.length)} open</span> : null}
              </span>
            )}
            <span className="mt-0.5 line-clamp-2 block text-2xs text-fg-subtle">{category.description}</span>
          </button>
        );
      })}
    </div>
  );
}
