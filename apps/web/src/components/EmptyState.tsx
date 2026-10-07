import { clsx } from "clsx";
import { Inbox, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export interface EmptyStateProps {
  icon?: LucideIcon;
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  tone?: "neutral" | "success" | "locked";
  compact?: boolean;
  className?: string;
}

/** Real empty state — explains why there is nothing and what to do next. */
export function EmptyState({ icon: Icon = Inbox, title, description, action, tone = "neutral", compact = false, className }: EmptyStateProps) {
  return (
    <div className={clsx("flex flex-col items-center justify-center text-center", compact ? "gap-1.5 py-5" : "gap-2 py-10", className)}>
      <span
        className={clsx(
          "inline-flex items-center justify-center rounded-full",
          compact ? "h-8 w-8" : "h-11 w-11",
          tone === "success" ? "bg-healthy-soft text-healthy" : tone === "locked" ? "bg-surface-3 text-fg-subtle" : "bg-surface-3 text-fg-muted",
        )}
        aria-hidden
      >
        <Icon size={compact ? 16 : 20} />
      </span>
      <div className={clsx("font-medium text-fg", compact ? "text-base" : "text-md")}>{title}</div>
      {description ? <div className="max-w-md text-sm text-fg-muted">{description}</div> : null}
      {action ? <div className="mt-1 flex flex-wrap items-center justify-center gap-2">{action}</div> : null}
    </div>
  );
}
