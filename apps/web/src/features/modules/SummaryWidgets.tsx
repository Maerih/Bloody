import type { ReactNode } from "react";
import { useCommandCenterSummary } from "../../api/hooks";
import { CardSkeleton } from "../../components/Skeleton";
import { ErrorState } from "../../components/ErrorState";
import type { WidgetProps } from "../../pages/command-center/widgets";

/**
 * Command Center widgets reused inside module workspaces, fed by the same summary endpoint —
 * a module dashboard is a lens on the shared data model, not a separate dashboard.
 */
export function SummaryWidgets({ widgets, windowDays = 30, columns = 3 }: { widgets: ((props: WidgetProps) => ReactNode)[]; windowDays?: number; columns?: 2 | 3 | 4 }) {
  const summary = useCommandCenterSummary(windowDays);
  const grid = columns === 2 ? "md:grid-cols-2" : columns === 4 ? "md:grid-cols-2 xl:grid-cols-4" : "md:grid-cols-2 xl:grid-cols-3";
  if (summary.isPending) {
    return (
      <div className={`mb-4 grid grid-cols-1 gap-3 ${grid}`}>
        {widgets.map((_, i) => (
          <CardSkeleton key={i} rows={3} />
        ))}
      </div>
    );
  }
  if (summary.isError) {
    return (
      <div className="mb-4 rounded border border-line bg-surface shadow-card">
        <ErrorState error={summary.error} compact onRetry={() => void summary.refetch()} />
      </div>
    );
  }
  return (
    <div className={`mb-4 grid grid-cols-1 gap-3 ${grid}`}>
      {widgets.map((W, i) => (
        <div key={i} className="min-w-0">
          <W summary={summary.data} windowDays={windowDays} />
        </div>
      ))}
    </div>
  );
}
