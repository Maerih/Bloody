import { clsx } from "clsx";
import type { LucideIcon } from "lucide-react";
import { useRef, type KeyboardEvent, type ReactNode } from "react";
import { formatInteger } from "../lib/format";

export interface TabDef<T extends string = string> {
  id: T;
  label: ReactNode;
  count?: number | null;
  icon?: LucideIcon;
  disabled?: boolean;
}

export interface TabsProps<T extends string = string> {
  tabs: TabDef<T>[];
  value: T;
  onChange: (id: T) => void;
  /** "boxed" mirrors the Triage Feed tabs; "underline" for page sections. */
  variant?: "boxed" | "underline";
  className?: string;
  ariaLabel?: string;
  /** id prefix used to link tabs and panels (aria-controls). */
  idPrefix?: string;
}

/** Accessible tablist (roving focus with arrow keys). Render panels with <TabPanel>. */
export function Tabs<T extends string>({ tabs, value, onChange, variant = "underline", className, ariaLabel, idPrefix = "tab" }: TabsProps<T>) {
  const listRef = useRef<HTMLDivElement>(null);
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const enabled = tabs.filter((t) => !t.disabled);
    const index = enabled.findIndex((t) => t.id === value);
    let next: TabDef<T> | undefined;
    if (event.key === "ArrowRight") next = enabled[(index + 1) % enabled.length];
    else if (event.key === "ArrowLeft") next = enabled[(index - 1 + enabled.length) % enabled.length];
    else if (event.key === "Home") next = enabled[0];
    else if (event.key === "End") next = enabled[enabled.length - 1];
    if (next) {
      event.preventDefault();
      onChange(next.id);
      listRef.current?.querySelector<HTMLButtonElement>(`[data-tab-id="${next.id}"]`)?.focus();
    }
  };
  return (
    <div
      ref={listRef}
      role="tablist"
      aria-label={ariaLabel}
      onKeyDown={onKeyDown}
      className={clsx("flex items-end gap-0.5 overflow-x-auto scrollbar-none", variant === "underline" ? "border-b border-line" : "", className)}
    >
      {tabs.map((tab) => {
        const selected = tab.id === value;
        const Icon = tab.icon;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            id={`${idPrefix}-${tab.id}`}
            data-tab-id={tab.id}
            aria-selected={selected}
            aria-controls={`${idPrefix}-panel-${tab.id}`}
            tabIndex={selected ? 0 : -1}
            disabled={tab.disabled}
            onClick={() => onChange(tab.id)}
            className={clsx(
              "inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap text-base transition-colors disabled:opacity-50",
              variant === "boxed"
                ? clsx(
                    "-mb-px rounded-t border px-4 py-2",
                    selected ? "border-line bg-surface text-fg" : "border-transparent text-heading hover:text-fg",
                  )
                : clsx(
                    "-mb-px border-b-2 px-3 py-2",
                    selected ? "border-primary font-medium text-fg" : "border-transparent text-fg-muted hover:text-fg",
                  ),
            )}
          >
            {Icon ? <Icon size={13} aria-hidden /> : null}
            {tab.label}
            {tab.count !== undefined && tab.count !== null ? (
              <span className={clsx("rounded-full px-1.5 text-2xs tabular-nums", selected ? "bg-primary-soft text-primary" : "bg-surface-3 text-fg-muted")}>
                {formatInteger(tab.count)}
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

export function TabPanel({ id, idPrefix = "tab", children, className }: { id: string; idPrefix?: string; children: ReactNode; className?: string }) {
  return (
    <div role="tabpanel" id={`${idPrefix}-panel-${id}`} aria-labelledby={`${idPrefix}-${id}`} className={className}>
      {children}
    </div>
  );
}
