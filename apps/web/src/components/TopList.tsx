import { Link } from "react-router-dom";
import { formatInteger } from "../lib/format";
import { EmptyState } from "./EmptyState";

export interface TopListItem {
  key: string;
  label: string;
  count: number;
  hint?: string;
  href?: string;
}

/** Ranked horizontal bars ("top talkers", "top processes") over an aggregation. */
export function TopList({ items, emptyText = "No data in this window.", max = 10, ariaLabel }: { items: TopListItem[]; emptyText?: string; max?: number; ariaLabel?: string }) {
  const shown = items.slice(0, max);
  if (shown.length === 0) return <EmptyState compact title={emptyText} />;
  const top = Math.max(1, ...shown.map((i) => i.count));
  return (
    <ol className="space-y-1.5" aria-label={ariaLabel}>
      {shown.map((i) => (
        <li key={i.key} className="text-sm">
          <div className="flex items-center justify-between gap-2">
            {i.href ? (
              <Link to={i.href} className="min-w-0 truncate font-mono text-xs text-heading hover:underline" title={i.label}>
                {i.label}
              </Link>
            ) : (
              <span className="min-w-0 truncate font-mono text-xs text-fg" title={i.label}>
                {i.label}
              </span>
            )}
            <span className="shrink-0 tabular-nums text-fg-muted">{formatInteger(i.count)}</span>
          </div>
          <div className="mt-0.5 h-1 rounded bg-surface-3">
            <div className="h-1 rounded bg-primary/70" style={{ width: `${(i.count / top) * 100}%` }} />
          </div>
          {i.hint ? <div className="text-2xs text-fg-subtle">{i.hint}</div> : null}
        </li>
      ))}
    </ol>
  );
}

/** Count values (skipping empty) and return the top entries. */
export function countBy<T>(rows: T[], key: (row: T) => string | null | undefined, href?: (value: string) => string): TopListItem[] {
  const counts = new Map<string, number>();
  for (const r of rows) {
    const k = key(r);
    if (k === null || k === undefined || k === "") continue;
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([k, count]) => ({ key: k, label: k, count, ...(href ? { href: href(k) } : {}) }));
}
