import { clsx } from "clsx";
import { ChevronRight } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

export interface Breadcrumb {
  label: string;
  href?: string;
}

export interface PageHeaderProps {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
  breadcrumbs?: Breadcrumb[];
  /** Extra content under the title row (tabs, filters). */
  children?: ReactNode;
  className?: string;
}

export function PageHeader({ title, subtitle, actions, breadcrumbs, children, className }: PageHeaderProps) {
  useDocumentTitle(title);
  return (
    <div className={clsx("mb-4", className)}>
      {breadcrumbs && breadcrumbs.length > 0 ? (
        <nav aria-label="Breadcrumb" className="mb-1 flex items-center gap-1 text-sm text-fg-muted">
          {breadcrumbs.map((b, i) => (
            <span key={`${b.label}-${i}`} className="flex items-center gap-1">
              {b.href ? (
                <Link to={b.href} className="hover:text-fg hover:underline">
                  {b.label}
                </Link>
              ) : (
                <span>{b.label}</span>
              )}
              {i < breadcrumbs.length - 1 ? <ChevronRight size={12} aria-hidden /> : null}
            </span>
          ))}
        </nav>
      ) : null}
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-0 flex-1">
          <h1 className="truncate font-display text-2xl font-bold tracking-tight text-fg">{title}</h1>
          {subtitle ? <div className="mt-0.5 text-base text-fg-muted">{subtitle}</div> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {children ? <div className="mt-3">{children}</div> : null}
    </div>
  );
}
