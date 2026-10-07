import { clsx } from "clsx";
import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { formatInteger, formatPercent } from "../lib/format";

export interface DonutSegment {
  key: string;
  label: string;
  value: number;
  /** Any CSS colour; prefer theme tokens, e.g. CHART_COLORS.healthy. */
  color: string;
  icon?: LucideIcon;
  href?: string;
}

export interface DonutProps {
  segments: DonutSegment[];
  size?: number;
  thickness?: number;
  /** Content rendered in the hole (e.g. total). */
  center?: ReactNode;
  ariaLabel?: string;
  className?: string;
}

const GAP = 1.5;

/** Dependency-free SVG donut. A zero total renders a neutral ring rather than a fake split. */
export function Donut({ segments, size = 112, thickness = 22, center, ariaLabel, className }: DonutProps) {
  const total = segments.reduce((sum, s) => sum + Math.max(0, s.value), 0);
  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;
  const visible = segments.filter((s) => s.value > 0);
  const gap = visible.length > 1 ? GAP : 0;

  let offset = 0;
  const arcs = visible.map((s) => {
    const length = (s.value / total) * circumference;
    const arc = { key: s.key, color: s.color, dash: Math.max(0, length - gap), offset };
    offset += length;
    return arc;
  });

  const summary =
    ariaLabel ??
    (total === 0
      ? "No data"
      : segments.map((s) => `${s.label}: ${formatInteger(s.value)} (${formatPercent(s.value, total)})`).join(", "));

  return (
    <div className={clsx("relative inline-flex shrink-0", className)} style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={summary}>
        <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="rgb(var(--surface-3))"
            strokeWidth={thickness}
            data-testid="donut-track"
          />
          {arcs.map((a) => (
            <circle
              key={a.key}
              data-testid={`donut-arc-${a.key}`}
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke={a.color}
              strokeWidth={thickness}
              strokeDasharray={`${a.dash} ${circumference - a.dash}`}
              strokeDashoffset={-a.offset}
            />
          ))}
        </g>
      </svg>
      {center !== undefined ? (
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center text-center">{center}</div>
      ) : null}
    </div>
  );
}

export interface DonutLegendProps {
  title?: ReactNode;
  segments: DonutSegment[];
  className?: string;
}

/** Legend rows (icon, label, count) matching a Donut's segments. */
export function DonutLegend({ title, segments, className }: DonutLegendProps) {
  return (
    <div className={clsx("min-w-0 flex-1", className)}>
      {title ? <div className="mb-1 text-sm font-semibold text-fg">{title}</div> : null}
      <ul className="space-y-0.5">
        {segments.map((s) => {
          const Icon = s.icon;
          const label = (
            <span className="flex min-w-0 items-center gap-1.5">
              {Icon ? (
                <Icon size={12} aria-hidden style={{ color: s.color }} className="shrink-0" />
              ) : (
                <span className="h-2 w-2 shrink-0 rounded-sm" style={{ background: s.color }} aria-hidden />
              )}
              <span className="truncate text-heading">{s.label}</span>
            </span>
          );
          return (
            <li key={s.key} className="flex items-center justify-between gap-3 text-sm">
              {s.href ? (
                <Link to={s.href} className="min-w-0 hover:underline">
                  {label}
                </Link>
              ) : (
                label
              )}
              <span className="tabular-nums text-fg-muted">{formatInteger(s.value)}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
