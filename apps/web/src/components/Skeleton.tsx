import { clsx } from "clsx";

export function Skeleton({ className, rounded = "rounded" }: { className?: string; rounded?: string }) {
  return <div aria-hidden className={clsx("skeleton", rounded, className ?? "h-4 w-full")} />;
}

export function SkeletonText({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <div className={clsx("space-y-2", className)} aria-hidden>
      {Array.from({ length: lines }, (_, i) => (
        <Skeleton key={i} className={clsx("h-3", i === lines - 1 ? "w-3/5" : "w-full")} />
      ))}
    </div>
  );
}

/** Card-shaped placeholder used while a widget's data loads. */
export function CardSkeleton({ className, rows = 3 }: { className?: string; rows?: number }) {
  return (
    <div role="status" aria-label="Loading" className={clsx("rounded border border-line bg-surface shadow-card", className)}>
      <div className="border-b border-line px-3 py-2.5">
        <Skeleton className="h-3.5 w-40" />
      </div>
      <div className="p-3">
        <SkeletonText lines={rows} />
      </div>
    </div>
  );
}

export function TableSkeleton({ rows = 8, columns = 5 }: { rows?: number; columns?: number }) {
  return (
    <div role="status" aria-label="Loading" className="divide-y divide-line">
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="flex gap-4 px-3 py-2.5">
          {Array.from({ length: columns }, (_, c) => (
            <Skeleton key={c} className={clsx("h-3", c === 1 ? "w-2/5" : "w-1/6")} />
          ))}
        </div>
      ))}
    </div>
  );
}
