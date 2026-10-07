import { clsx } from "clsx";
import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import type { Severity } from "@bloody/contracts";
import { SEVERITY_META } from "../lib/severity";
import { humanize } from "../lib/format";

export type BadgeTone = "neutral" | "info" | "success" | "warning" | "danger" | "brand" | "purple" | "outline";

const TONES: Record<BadgeTone, string> = {
  neutral: "bg-surface-3 text-fg-muted border-line",
  info: "bg-primary-soft text-primary border-primary/20",
  success: "bg-healthy-soft text-healthy border-healthy/25",
  warning: "bg-sev-high/10 text-sev-high border-sev-high/25",
  danger: "bg-sev-critical/10 text-sev-critical border-sev-critical/25",
  brand: "bg-brand-soft text-brand border-brand/25",
  purple: "bg-sev-low/10 text-sev-low border-sev-low/25",
  outline: "bg-transparent text-fg-muted border-line-strong",
};

export interface BadgeProps {
  tone?: BadgeTone;
  icon?: LucideIcon;
  children: ReactNode;
  className?: string;
  title?: string;
  size?: "xs" | "sm";
}

export function Badge({ tone = "neutral", icon: Icon, children, className, title, size = "sm" }: BadgeProps) {
  return (
    <span
      title={title}
      className={clsx(
        "inline-flex items-center gap-1 whitespace-nowrap rounded border font-medium",
        size === "xs" ? "px-1 py-px text-2xs" : "px-1.5 py-px text-xs",
        TONES[tone],
        className,
      )}
    >
      {Icon ? <Icon size={size === "xs" ? 10 : 11} aria-hidden /> : null}
      {children}
    </span>
  );
}

export function SeverityBadge({ severity, size = "sm", className }: { severity: Severity; size?: "xs" | "sm"; className?: string }) {
  const meta = SEVERITY_META[severity];
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 whitespace-nowrap rounded border font-semibold",
        size === "xs" ? "px-1 py-px text-2xs" : "px-1.5 py-px text-xs",
        meta.softBg,
        meta.text,
        meta.border,
        "border-opacity-30",
        className,
      )}
    >
      <span className={clsx("h-1.5 w-1.5 rounded-full", meta.bg)} aria-hidden />
      {meta.label}
    </span>
  );
}

const STATUS_TONES: Record<string, BadgeTone> = {
  new: "danger",
  open: "danger",
  triage: "warning",
  investigating: "info",
  in_progress: "info",
  acknowledged: "info",
  awaiting_customer: "purple",
  contained: "purple",
  remediated: "success",
  resolved: "success",
  closed: "neutral",
  false_positive: "neutral",
  pending_approval: "warning",
  approved: "info",
  rejected: "neutral",
  queued: "neutral",
  running: "info",
  succeeded: "success",
  failed: "danger",
  cancelled: "neutral",
  active: "success",
  trial: "info",
  trial_ended: "warning",
  available: "neutral",
  locked: "outline",
};

/** Consistent colouring for workflow states (incident, escalation, response action, entitlement). */
export function StatusBadge({ status, size = "sm", className }: { status: string; size?: "xs" | "sm"; className?: string }) {
  return (
    <Badge tone={STATUS_TONES[status] ?? "neutral"} size={size} className={className}>
      {humanize(status)}
    </Badge>
  );
}
