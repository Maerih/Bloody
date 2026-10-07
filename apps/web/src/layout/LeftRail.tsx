import { clsx } from "clsx";
import { Lock } from "lucide-react";
import { forwardRef, useCallback, useEffect, useRef, useState, type KeyboardEvent } from "react";
import { Link, useLocation } from "react-router-dom";
import { activeRailModule, RAIL_MODULES, type NavItem, type RailModule } from "../app/navigation";
import { useSession, type SessionValue } from "../app/session";
import { humanize } from "../lib/format";

const OPEN_DELAY = 60;
const CLOSE_DELAY = 180;

export function railItemsFor(module: RailModule, session: SessionValue): NavItem[] {
  return module.items.filter((item) => {
    if (item.permission && !session.canAnywhere(item.permission)) return false;
    if (item.path === "/mssp") return session.isMssp && session.canSelectAll;
    return true;
  });
}

/**
 * Slim left icon rail: tiny uppercase label above each module icon, hover/focus flyout with the
 * module's sub-pages. Modules the tenant is not entitled to show a lock badge and an upsell.
 */
export function LeftRail() {
  const session = useSession();
  const location = useLocation();
  const active = activeRailModule(location.pathname);
  const [openId, setOpenId] = useState<string | null>(null);
  const [anchorTop, setAnchorTop] = useState(0);
  const openTimer = useRef<ReturnType<typeof setTimeout>>();
  const closeTimer = useRef<ReturnType<typeof setTimeout>>();
  const itemRefs = useRef(new Map<string, HTMLAnchorElement>());
  const flyoutRef = useRef<HTMLDivElement>(null);

  const clearTimers = () => {
    clearTimeout(openTimer.current);
    clearTimeout(closeTimer.current);
  };

  const open = useCallback((id: string, immediate = false) => {
    clearTimeout(closeTimer.current);
    clearTimeout(openTimer.current);
    const run = () => {
      const el = itemRefs.current.get(id);
      if (el) setAnchorTop(el.getBoundingClientRect().top);
      setOpenId(id);
    };
    if (immediate) run();
    else openTimer.current = setTimeout(run, OPEN_DELAY);
  }, []);

  const scheduleClose = useCallback(() => {
    clearTimeout(openTimer.current);
    closeTimer.current = setTimeout(() => setOpenId(null), CLOSE_DELAY);
  }, []);

  useEffect(() => {
    setOpenId(null);
  }, [location.pathname]);
  useEffect(() => clearTimers, []);

  const onItemKeyDown = (event: KeyboardEvent<HTMLAnchorElement>, id: string) => {
    if (event.key === "ArrowRight") {
      event.preventDefault();
      open(id, true);
      requestAnimationFrame(() => flyoutRef.current?.querySelector<HTMLElement>("a,button")?.focus());
    } else if (event.key === "Escape") {
      setOpenId(null);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const ids = RAIL_MODULES.map((m) => m.id);
      const idx = ids.indexOf(id);
      const next = ids[(idx + (event.key === "ArrowDown" ? 1 : -1) + ids.length) % ids.length];
      if (next) itemRefs.current.get(next)?.focus();
    }
  };

  const openModule = RAIL_MODULES.find((m) => m.id === openId) ?? null;

  return (
    <>
      <nav
        aria-label="Security modules"
        className="scrollbar-none fixed bottom-0 left-0 top-11 z-30 w-[60px] overflow-y-auto border-r border-line bg-rail py-2"
        onMouseLeave={scheduleClose}
      >
        <ul className="flex flex-col items-center gap-1">
          {RAIL_MODULES.map((m) => {
            const Icon = m.icon;
            const enabled = m.module === null || session.isModuleEnabled(m.module);
            const isActive = active?.id === m.id;
            return (
              <li key={m.id} className="w-full px-1.5">
                <Link
                  ref={(el) => {
                    if (el) itemRefs.current.set(m.id, el);
                    else itemRefs.current.delete(m.id);
                  }}
                  to={m.path}
                  aria-label={`${m.name}${enabled ? "" : " (not in your plan)"}`}
                  aria-current={isActive ? "page" : undefined}
                  aria-haspopup="menu"
                  aria-expanded={openId === m.id}
                  onMouseEnter={() => open(m.id)}
                  onFocus={() => open(m.id, true)}
                  onKeyDown={(e) => onItemKeyDown(e, m.id)}
                  className={clsx(
                    "relative flex flex-col items-center gap-0.5 rounded-md px-1 py-1.5 transition-colors",
                    isActive ? "bg-rail-active text-[rgb(var(--healthy))]" : "text-rail-fg hover:bg-surface/70 hover:text-fg",
                    openId === m.id && !isActive && "bg-surface/70",
                    !enabled && "opacity-60",
                  )}
                >
                  <span className="text-[8.5px] font-medium uppercase leading-none tracking-wider">{m.short}</span>
                  <span className="relative">
                    <Icon size={19} strokeWidth={1.6} aria-hidden />
                    {!enabled ? (
                      <span className="absolute -bottom-1 -right-1.5 inline-flex h-3 w-3 items-center justify-center rounded-full bg-fg-muted text-white ring-1 ring-rail" data-testid={`rail-lock-${m.id}`}>
                        <Lock size={7} strokeWidth={3} aria-hidden />
                      </span>
                    ) : null}
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>
      {openModule ? (
        <RailFlyout
          ref={flyoutRef}
          module={openModule}
          top={anchorTop}
          session={session}
          onEnter={() => clearTimeout(closeTimer.current)}
          onLeave={scheduleClose}
          onClose={() => {
            setOpenId(null);
            itemRefs.current.get(openModule.id)?.focus();
          }}
        />
      ) : null}
    </>
  );
}

interface RailFlyoutProps {
  module: RailModule;
  top: number;
  session: SessionValue;
  onEnter: () => void;
  onLeave: () => void;
  onClose: () => void;
}

const RailFlyout = forwardRef<HTMLDivElement, RailFlyoutProps>(function RailFlyout({ module, top, session, onEnter, onLeave, onClose }, ref) {
  const enabled = module.module === null || session.isModuleEnabled(module.module);
  const state = module.module ? session.moduleState(module.module) : "active";
  const items = railItemsFor(module, session);
  const maxTop = typeof window !== "undefined" ? Math.max(52, window.innerHeight - 40 - items.length * 26 - 90) : top;
  return (
    <div
      ref={ref}
      role="menu"
      aria-label={module.name}
      onMouseEnter={onEnter}
      onMouseLeave={onLeave}
      onKeyDown={(e) => {
        if (e.key === "Escape" || e.key === "ArrowLeft") {
          e.preventDefault();
          onClose();
        }
      }}
      style={{ top: Math.min(Math.max(top - 6, 52), maxTop) }}
      className="fixed left-[60px] z-50 w-60 animate-fade-in rounded-r-md border border-l-0 border-line bg-surface-3 py-2 shadow-pop"
    >
      <div className="px-3 pb-1 text-2xs text-fg-subtle">{module.name}</div>
      {enabled ? (
        <ul>
          {items.map((item) => {
            const Icon = item.icon;
            return (
              <li key={item.path}>
                <Link role="menuitem" to={item.path} className="flex items-center gap-2.5 px-3 py-1.5 text-sm text-fg hover:bg-surface focus:bg-surface focus:outline-none">
                  <Icon size={15} strokeWidth={1.7} aria-hidden className="text-fg-muted" />
                  {item.label}
                </Link>
              </li>
            );
          })}
        </ul>
      ) : (
        <div className="space-y-2 px-3 pb-1 pt-1">
          <p className="flex items-start gap-1.5 text-sm text-fg-muted">
            <Lock size={13} aria-hidden className="mt-0.5 shrink-0" />
            {state === "trial_ended"
              ? "Your trial of this module has ended."
              : state === "available"
                ? "Available to trial on your plan."
                : "Not included in your current plan."}
          </p>
          <ul className="space-y-0.5 opacity-60" aria-label="Included capabilities">
            {module.items.slice(0, 6).map((item) => (
              <li key={item.path} className="flex items-center gap-2 text-sm text-fg-muted">
                <item.icon size={13} aria-hidden /> {item.label}
              </li>
            ))}
          </ul>
          <Link
            role="menuitem"
            to={`/trials?module=${module.module ?? ""}`}
            className="inline-flex h-7 items-center rounded bg-primary px-2.5 text-sm font-medium text-white hover:bg-primary-hover"
          >
            {state === "available" ? "Start trial" : "Manage modules"}
          </Link>
          <span className="sr-only">Module state: {humanize(state)}</span>
        </div>
      )}
    </div>
  );
});
