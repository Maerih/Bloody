import { clsx } from "clsx";
import type { ReactNode } from "react";

export interface DescriptionItem {
  label: ReactNode;
  value: ReactNode;
  /** Span both columns. */
  wide?: boolean;
}

/** Two-column label/value grid for detail panels. */
export function DescriptionList({ items, className }: { items: DescriptionItem[]; className?: string }) {
  return (
    <dl className={clsx("grid grid-cols-1 gap-x-6 gap-y-2.5 sm:grid-cols-2", className)}>
      {items.map((item, i) => (
        <div key={i} className={clsx("min-w-0", item.wide && "sm:col-span-2")}>
          <dt className="text-xs uppercase tracking-wide text-fg-subtle">{item.label}</dt>
          <dd className="mt-0.5 break-words text-base text-fg">{item.value ?? <span className="text-fg-subtle">—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="kbd">{children}</kbd>;
}
