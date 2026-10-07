import { clsx } from "clsx";
import { Info } from "lucide-react";
import type { HTMLAttributes, ReactNode } from "react";
import { formatInteger } from "../lib/format";

export interface CardProps extends Omit<HTMLAttributes<HTMLElement>, "title"> {
  title?: ReactNode;
  /** Rendered as "Title (count)". Pass null to omit while loading. */
  count?: number | null;
  /** Short explanation of how the card's numbers are computed (explainability). */
  info?: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
  footer?: ReactNode;
  /** Pad the body (default true). */
  padded?: boolean;
  bodyClassName?: string;
}

/** White content card with the dense "Title (count)" header used across the Command Center. */
export function Card({ title, count, info, subtitle, actions, footer, padded = true, className, bodyClassName, children, ...rest }: CardProps) {
  const hasHeader = title !== undefined || actions !== undefined;
  return (
    <section className={clsx("flex min-w-0 flex-col rounded border border-line bg-surface shadow-card", className)} {...rest}>
      {hasHeader ? (
        <header className="flex min-h-[38px] items-center gap-2 border-b border-line px-3 py-2">
          <div className="min-w-0 flex-1">
            <h2 className="flex items-center gap-1 truncate text-base font-normal text-heading">
              <span className="truncate">{title}</span>
              {count !== undefined && count !== null ? <span className="font-semibold">({formatInteger(count)})</span> : null}
              {info ? <InfoTip text={info} /> : null}
            </h2>
            {subtitle ? <p className="truncate text-xs text-fg-subtle">{subtitle}</p> : null}
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-1.5">{actions}</div> : null}
        </header>
      ) : null}
      <div className={clsx("min-h-0 flex-1", padded && "p-3", bodyClassName)}>{children}</div>
      {footer ? <footer className="border-t border-line px-3 py-2 text-sm text-fg-muted">{footer}</footer> : null}
    </section>
  );
}

/** Small (i) affordance exposing an explanation to mouse, keyboard and screen readers. */
export function InfoTip({ text, className }: { text: string; className?: string }) {
  return (
    <span className={clsx("group relative inline-flex", className)}>
      <button
        type="button"
        className="inline-flex text-fg-muted hover:text-fg focus-visible:text-fg"
        aria-label={`About: ${text}`}
      >
        <Info size={12} aria-hidden className="fill-current text-fg-muted [&>path]:stroke-surface" />
      </button>
      <span
        role="tooltip"
        className="pointer-events-none absolute left-1/2 top-full z-50 mt-1 hidden w-64 -translate-x-1/2 rounded border border-line bg-surface px-2.5 py-2 text-xs font-normal leading-snug text-fg shadow-pop group-focus-within:block group-hover:block"
      >
        {text}
      </span>
    </span>
  );
}
