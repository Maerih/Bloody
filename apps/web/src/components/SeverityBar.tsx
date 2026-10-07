import { clsx } from "clsx";
import { CircleAlert, Fingerprint, Monitor, Wrench, Zap, type LucideIcon } from "lucide-react";
import { Link } from "react-router-dom";
import { formatInteger } from "../lib/format";

export type SeverityBarLevel = "critical" | "high" | "medium" | "low" | "low_medium";

const LEVELS: Record<SeverityBarLevel, { label: string; icon: LucideIcon; bg: string; border: string; text: string }> = {
  critical: { label: "Critical", icon: Zap, bg: "bg-sev-critical", border: "border-sev-critical", text: "text-sev-critical" },
  high: { label: "High", icon: CircleAlert, bg: "bg-sev-high", border: "border-sev-high", text: "text-sev-high" },
  medium: { label: "Medium", icon: Wrench, bg: "bg-sev-medium", border: "border-sev-medium", text: "text-sev-medium" },
  low: { label: "Low", icon: Wrench, bg: "bg-sev-low", border: "border-sev-low", text: "text-sev-low" },
  low_medium: { label: "Low", icon: Wrench, bg: "bg-sev-low", border: "border-sev-low", text: "text-sev-low" },
};

export interface SeverityBarProps {
  level: SeverityBarLevel;
  count: number;
  label?: string;
  /** Incidents involving endpoints; omit (undefined) when unknown — never shown as 0. */
  endpointCount?: number | null;
  /** Incidents involving identities; omit when unknown. */
  identityCount?: number | null;
  href?: string;
  className?: string;
}

/**
 * Severity bar from the Command Center: coloured icon block, "N Critical", and
 * endpoint / identity sub-counts on the right.
 */
export function SeverityBar({ level, count, label, endpointCount, identityCount, href, className }: SeverityBarProps) {
  const meta = LEVELS[level];
  const Icon = meta.icon;
  const text = label ?? meta.label;
  const showSub = endpointCount !== undefined && endpointCount !== null && identityCount !== undefined && identityCount !== null;
  const content = (
    <>
      <span className={clsx("flex w-10 shrink-0 items-center justify-center self-stretch text-white", meta.bg)} aria-hidden>
        <Icon size={15} strokeWidth={2.5} />
      </span>
      <span className="flex min-w-0 flex-1 items-center gap-1 px-2 text-base">
        <span className="font-semibold tabular-nums text-fg" data-testid={`severity-count-${level}`}>
          {formatInteger(count)}
        </span>
        <span className="truncate text-fg-muted">{text}</span>
      </span>
      {showSub ? (
        <span className="flex shrink-0 items-center gap-2 pr-2.5 text-sm text-fg-muted">
          <span className="inline-flex items-center gap-1" title="Incidents involving endpoints">
            <Monitor size={13} aria-hidden />
            <span className="font-semibold tabular-nums text-fg">{formatInteger(endpointCount)}</span>
            <span className="sr-only">endpoint</span>
          </span>
          <span className="h-3.5 w-px bg-line-strong" aria-hidden />
          <span className="inline-flex items-center gap-1" title="Incidents involving identities">
            <Fingerprint size={13} aria-hidden />
            <span className="font-semibold tabular-nums text-fg">{formatInteger(identityCount)}</span>
            <span className="sr-only">identity</span>
          </span>
        </span>
      ) : null}
    </>
  );
  const classes = clsx(
    "flex h-[30px] min-w-0 items-center overflow-hidden rounded border bg-surface",
    meta.border,
    href && "transition-shadow hover:shadow-pop",
    className,
  );
  const aria = `${formatInteger(count)} ${text} incidents${showSub ? `, ${endpointCount} endpoint, ${identityCount} identity` : ""}`;
  return href ? (
    <Link to={href} className={classes} aria-label={aria}>
      {content}
    </Link>
  ) : (
    <div className={classes} role="group" aria-label={aria}>
      {content}
    </div>
  );
}
