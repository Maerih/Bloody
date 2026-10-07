import { clsx } from "clsx";
import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { formatNumber } from "../lib/format";
import { Skeleton } from "./Skeleton";

export type StatTone = "default" | "critical" | "high" | "medium" | "low" | "healthy" | "brand" | "primary";

const TONE_TEXT: Record<StatTone, string> = {
  default: "text-fg",
  critical: "text-sev-critical",
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
  healthy: "text-healthy",
  brand: "text-brand",
  primary: "text-primary",
};
const TONE_ICON: Record<StatTone, string> = {
  default: "bg-surface-3 text-fg-muted",
  critical: "bg-sev-critical/10 text-sev-critical",
  high: "bg-sev-high/10 text-sev-high",
  medium: "bg-sev-medium/15 text-sev-medium",
  low: "bg-sev-low/10 text-sev-low",
  healthy: "bg-healthy-soft text-healthy",
  brand: "bg-brand-soft text-brand",
  primary: "bg-primary-soft text-primary",
};

export interface StatTileProps {
  label: string;
  value: number | null | undefined;
  /** Custom formatter; defaults to compact K/M formatting. */
  format?: (value: number | null | undefined) => string;
  hint?: ReactNode;
  icon?: LucideIcon;
  tone?: StatTone;
  href?: string;
  loading?: boolean;
  className?: string;
  /** Render inside a card frame (default) or bare (for use inside an existing card). */
  framed?: boolean;
}

/** Single KPI: label, big number, optional hint and icon; links to its drill-down when given. */
export function StatTile({ label, value, format = formatNumber, hint, icon: Icon, tone = "default", href, loading, className, framed = true }: StatTileProps) {
  const body = (
    <div className="flex items-start gap-3">
      {Icon ? (
        <span className={clsx("mt-0.5 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full", TONE_ICON[tone])}>
          <Icon size={16} aria-hidden />
        </span>
      ) : null}
      <div className="min-w-0">
        <div className="truncate text-sm text-fg-muted">{label}</div>
        {loading ? (
          <Skeleton className="mt-1 h-6 w-16" />
        ) : (
          <div className={clsx("text-2xl font-semibold tabular-nums leading-tight", TONE_TEXT[tone])} title={value === null || value === undefined ? "No data" : String(value)}>
            {format(value)}
          </div>
        )}
        {hint ? <div className="mt-0.5 truncate text-xs text-fg-subtle">{hint}</div> : null}
      </div>
    </div>
  );
  const frame = clsx(framed && "rounded border border-line bg-surface p-3 shadow-card", "block min-w-0", className);
  if (href && !loading) {
    return (
      <Link to={href} className={clsx(frame, "transition-colors hover:border-line-strong hover:bg-surface-2")} aria-label={`${label}: ${format(value)}`}>
        {body}
      </Link>
    );
  }
  return <div className={frame}>{body}</div>;
}
