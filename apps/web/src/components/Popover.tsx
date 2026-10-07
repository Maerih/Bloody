import { clsx } from "clsx";
import { useCallback, useId, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode, type Ref } from "react";
import { Link } from "react-router-dom";
import type { LucideIcon } from "lucide-react";
import { useDismiss } from "../hooks/useClickOutside";

export interface PopoverTriggerProps {
  ref: Ref<HTMLButtonElement>;
  onClick: () => void;
  "aria-expanded": boolean;
  "aria-haspopup": "dialog" | "menu";
  "aria-controls": string;
}

export interface PopoverProps {
  trigger: (props: PopoverTriggerProps) => ReactNode;
  children: ReactNode | ((close: () => void) => ReactNode);
  align?: "start" | "end";
  /** Open below (default) or above the trigger. */
  side?: "bottom" | "top";
  className?: string;
  panelClassName?: string;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  role?: "dialog" | "menu";
  label?: string;
}

/** Anchored panel with outside-click / Escape dismissal; controlled or uncontrolled. */
export function Popover({ trigger, children, align = "start", side = "bottom", className, panelClassName, open: controlled, onOpenChange, role = "dialog", label }: PopoverProps) {
  const [uncontrolled, setUncontrolled] = useState(false);
  const open = controlled ?? uncontrolled;
  const id = useId();
  const wrapperRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  const setOpen = useCallback(
    (next: boolean) => {
      if (controlled === undefined) setUncontrolled(next);
      onOpenChange?.(next);
    },
    [controlled, onOpenChange],
  );
  const close = useCallback(() => {
    setOpen(false);
  }, [setOpen]);
  const closeAndFocus = useCallback(() => {
    setOpen(false);
    triggerRef.current?.focus({ preventScroll: true });
  }, [setOpen]);

  const refs = useMemo(() => [wrapperRef], []);
  useDismiss(refs, closeAndFocus, open);

  return (
    <div ref={wrapperRef} className={clsx("relative inline-flex", className)}>
      {trigger({ ref: triggerRef, onClick: () => setOpen(!open), "aria-expanded": open, "aria-haspopup": role, "aria-controls": id })}
      {open ? (
        <div
          id={id}
          role={role}
          aria-label={label}
          className={clsx(
            "absolute z-50 animate-fade-in rounded-md border border-line bg-surface text-fg shadow-pop",
            side === "top" ? "bottom-full mb-2" : "top-full mt-1",
            align === "end" ? "right-0" : "left-0",
            panelClassName,
          )}
        >
          {typeof children === "function" ? children(close) : children}
        </div>
      ) : null}
    </div>
  );
}

export interface MenuItemDef {
  key: string;
  label: ReactNode;
  icon?: LucideIcon;
  href?: string;
  external?: boolean;
  onSelect?: () => void;
  disabled?: boolean;
  danger?: boolean;
  hint?: ReactNode;
}

/** Keyboard-navigable list of menu items (arrow keys, Home/End). Used inside a Popover. */
export function MenuList({ items, onClose, className }: { items: MenuItemDef[]; onClose?: () => void; className?: string }) {
  const listRef = useRef<HTMLDivElement>(null);
  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const nodes = Array.from(listRef.current?.querySelectorAll<HTMLElement>('[role="menuitem"]:not([aria-disabled="true"])') ?? []);
    if (nodes.length === 0) return;
    const index = nodes.indexOf(document.activeElement as HTMLElement);
    let next: number | null = null;
    if (event.key === "ArrowDown") next = index < 0 ? 0 : (index + 1) % nodes.length;
    else if (event.key === "ArrowUp") next = index < 0 ? nodes.length - 1 : (index - 1 + nodes.length) % nodes.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = nodes.length - 1;
    if (next !== null) {
      event.preventDefault();
      nodes[next]?.focus();
    }
  };
  return (
    <div ref={listRef} className={clsx("py-1", className)} onKeyDown={onKeyDown}>
      {items.map((item) => {
        const Icon = item.icon;
        const content = (
          <>
            {Icon ? <Icon size={13} aria-hidden className="shrink-0 text-fg-muted" /> : null}
            <span className="min-w-0 flex-1 truncate">{item.label}</span>
            {item.hint ? <span className="text-xs text-fg-subtle">{item.hint}</span> : null}
          </>
        );
        const classes = clsx(
          "flex w-full items-center gap-2 px-3 py-1.5 text-left text-base outline-none",
          item.disabled ? "cursor-not-allowed opacity-50" : "hover:bg-surface-3 focus:bg-surface-3",
          item.danger && "text-sev-critical",
        );
        if (item.href && !item.disabled) {
          return item.external ? (
            <a key={item.key} role="menuitem" href={item.href} target="_blank" rel="noopener noreferrer" className={classes} onClick={onClose}>
              {content}
            </a>
          ) : (
            <Link key={item.key} role="menuitem" to={item.href} className={classes} onClick={onClose}>
              {content}
            </Link>
          );
        }
        return (
          <button
            key={item.key}
            type="button"
            role="menuitem"
            aria-disabled={item.disabled || undefined}
            disabled={item.disabled}
            className={classes}
            onClick={() => {
              item.onSelect?.();
              onClose?.();
            }}
          >
            {content}
          </button>
        );
      })}
    </div>
  );
}
