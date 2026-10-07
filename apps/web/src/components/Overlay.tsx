import { clsx } from "clsx";
import { X } from "lucide-react";
import { useEffect, useId, useRef, type ReactNode, type RefObject } from "react";
import { createPortal } from "react-dom";
import { useFocusTrap } from "../hooks/useFocusTrap";
import { IconButton } from "./Button";

function useEscape(open: boolean, onClose: () => void) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);
}

export interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  headerActions?: ReactNode;
  footer?: ReactNode;
  width?: "md" | "lg" | "xl";
  children: ReactNode;
  initialFocus?: RefObject<HTMLElement | null>;
}

const DRAWER_WIDTHS = { md: "max-w-md", lg: "max-w-2xl", xl: "max-w-4xl" } as const;

/** Right-hand drill-down panel (Alert → Incident → … pivots open here without losing context). */
export function Drawer({ open, onClose, title, subtitle, headerActions, footer, width = "lg", children, initialFocus }: DrawerProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useEscape(open, onClose);
  useFocusTrap(panelRef, open, initialFocus);
  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-[60] flex justify-end">
      <div className="absolute inset-0 animate-fade-in bg-slate-900/30" onClick={onClose} aria-hidden data-testid="drawer-overlay" />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={clsx("relative flex h-full w-full animate-slide-in-right flex-col border-l border-line bg-surface shadow-pop", DRAWER_WIDTHS[width])}
      >
        <header className="flex items-start gap-3 border-b border-line px-4 py-3">
          <div className="min-w-0 flex-1">
            <h2 id={titleId} className="truncate text-lg font-semibold text-fg">
              {title}
            </h2>
            {subtitle ? <div className="mt-0.5 text-sm text-fg-muted">{subtitle}</div> : null}
          </div>
          {headerActions ? <div className="flex items-center gap-1.5">{headerActions}</div> : null}
          <IconButton icon={X} label="Close panel" onClick={onClose} />
        </header>
        <div className="scrollbar-thin min-h-0 flex-1 overflow-y-auto">{children}</div>
        {footer ? <footer className="border-t border-line px-4 py-3">{footer}</footer> : null}
      </div>
    </div>,
    document.body,
  );
}

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  footer?: ReactNode;
  size?: "sm" | "md" | "lg" | "xl";
  children?: ReactNode;
  initialFocus?: RefObject<HTMLElement | null>;
  /** Accessible label override when title is not plain text. */
  ariaLabel?: string;
  className?: string;
  /** Hide the standard header (e.g. command palette renders its own). */
  bare?: boolean;
  align?: "center" | "top";
}

const DIALOG_WIDTHS = { sm: "max-w-sm", md: "max-w-lg", lg: "max-w-2xl", xl: "max-w-4xl" } as const;

export function Dialog({ open, onClose, title, description, footer, size = "md", children, initialFocus, ariaLabel, className, bare = false, align = "center" }: DialogProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useEscape(open, onClose);
  useFocusTrap(panelRef, open, initialFocus);
  if (!open) return null;
  return createPortal(
    <div className={clsx("fixed inset-0 z-[70] flex justify-center px-4", align === "top" ? "items-start pt-[12vh]" : "items-center")}>
      <div className="absolute inset-0 animate-fade-in bg-slate-900/40" onClick={onClose} aria-hidden data-testid="dialog-overlay" />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={ariaLabel ? undefined : titleId}
        aria-label={ariaLabel}
        tabIndex={-1}
        className={clsx("relative flex max-h-[85vh] w-full animate-fade-in flex-col rounded-md border border-line bg-surface shadow-pop", DIALOG_WIDTHS[size], className)}
      >
        {bare ? (
          children
        ) : (
          <>
            <header className="flex items-start gap-3 border-b border-line px-4 py-3">
              <div className="min-w-0 flex-1">
                <h2 id={titleId} className="text-md font-semibold text-fg">
                  {title}
                </h2>
                {description ? <p className="mt-0.5 text-sm text-fg-muted">{description}</p> : null}
              </div>
              <IconButton icon={X} label="Close dialog" onClick={onClose} />
            </header>
            <div className="scrollbar-thin min-h-0 flex-1 overflow-y-auto px-4 py-3">{children}</div>
            {footer ? <footer className="flex items-center justify-end gap-2 border-t border-line px-4 py-3">{footer}</footer> : null}
          </>
        )}
      </div>
    </div>,
    document.body,
  );
}
