import { clsx } from "clsx";
import { Building2, CornerDownLeft, Keyboard, Layers, LoaderCircle, Moon, Search, Sun, type LucideIcon } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useGlobalSearch } from "../api/hooks";
import type { SearchHit } from "../api/types";
import { AUX_PAGES, RAIL_MODULES, TOP_NAV, type NavItem } from "../app/navigation";
import { useSession, type SessionValue } from "../app/session";
import { useTheme } from "../app/theme";
import { useUi } from "../app/ui";
import { SeverityBadge } from "../components/Badge";
import { Dialog } from "../components/Overlay";
import { useDebouncedValue } from "../hooks/useDebouncedValue";
import { humanize } from "../lib/format";
import { railItemsFor } from "./LeftRail";

interface PaletteEntry {
  id: string;
  group: "Pages" | "Actions" | "Results";
  label: string;
  detail?: string;
  icon?: LucideIcon;
  hit?: SearchHit;
  run: () => void;
}

interface PageCandidate {
  item: NavItem;
  context: string;
  keywords: string;
}

/** Pages the principal can actually open (permission + module entitlement aware). */
export function paletteCandidates(session: SessionValue): PageCandidate[] {
  const seen = new Set<string>();
  const out: PageCandidate[] = [];
  const push = (item: NavItem, context: string) => {
    if (seen.has(item.path)) return;
    if (item.permission && !session.canAnywhere(item.permission)) return;
    seen.add(item.path);
    out.push({ item, context, keywords: [item.label, item.description ?? "", context, ...(item.keywords ?? [])].join(" ").toLowerCase() });
  };
  for (const m of RAIL_MODULES) {
    if (m.module && !session.isModuleEnabled(m.module)) continue;
    for (const item of railItemsFor(m, session)) push(item, m.name);
  }
  for (const item of TOP_NAV) push(item, "Navigation");
  for (const item of AUX_PAGES) push(item, "Account");
  return out;
}

export function scorePage(candidate: PageCandidate, query: string): number {
  const q = query.trim().toLowerCase();
  if (!q) return 1;
  const label = candidate.item.label.toLowerCase();
  if (label === q) return 100;
  if (label.startsWith(q)) return 80;
  if (label.split(/\s+/).some((w) => w.startsWith(q))) return 60;
  if (label.includes(q)) return 40;
  const terms = q.split(/\s+/).filter(Boolean);
  if (terms.every((t) => candidate.keywords.includes(t))) return 20;
  return 0;
}

/** ⌘K / Ctrl+K: jump to any page, run shell actions, and search tenant data (/api/v1/search). */
export function CommandPalette() {
  const ui = useUi();
  const open = ui.paletteOpen;
  return open ? <PaletteDialog onClose={() => ui.setPaletteOpen(false)} /> : null;
}

function PaletteDialog({ onClose }: { onClose: () => void }) {
  const session = useSession();
  const theme = useTheme();
  const ui = useUi();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const listId = useId();
  const debounced = useDebouncedValue(query, 180);
  const search = useGlobalSearch(debounced);

  const go = (path: string) => {
    onClose();
    navigate(path);
  };

  const entries = useMemo<PaletteEntry[]>(() => {
    const q = query.trim().toLowerCase();
    const pages = paletteCandidates(session)
      .map((c) => ({ c, score: scorePage(c, q) }))
      .filter((x) => x.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, q ? 8 : 6)
      .map<PaletteEntry>(({ c }) => ({
        id: `page:${c.item.path}`,
        group: "Pages",
        label: c.item.label,
        detail: c.context,
        icon: c.item.icon,
        run: () => go(c.item.path),
      }));

    const actions: PaletteEntry[] = [];
    const matches = (text: string) => !q || text.toLowerCase().includes(q);
    if (session.canSelectAll && session.organizationId !== null && matches("all organizations switch tenant-wide")) {
      actions.push({ id: "org:all", group: "Actions", label: "Switch to All organizations", icon: Layers, run: () => { session.setOrganizationId(null); onClose(); } });
    }
    if (q) {
      for (const org of session.organizations) {
        if (org.id !== session.organizationId && (org.name.toLowerCase().includes(q) || `switch ${org.name}`.toLowerCase().includes(q))) {
          actions.push({ id: `org:${org.id}`, group: "Actions", label: `Switch to ${org.name}`, detail: "Organization", icon: Building2, run: () => { session.setOrganizationId(org.id); onClose(); } });
        }
        if (actions.length >= 6) break;
      }
    }
    const darkLabel = theme.resolved === "dark" ? "Switch to light theme" : "Switch to dark theme";
    if (matches(`${darkLabel} theme dark light mode`)) {
      actions.push({ id: "theme", group: "Actions", label: darkLabel, icon: theme.resolved === "dark" ? Sun : Moon, run: () => { theme.toggle(); onClose(); } });
    }
    if (matches("keyboard shortcuts help")) {
      actions.push({ id: "shortcuts", group: "Actions", label: "Keyboard shortcuts", icon: Keyboard, run: () => { onClose(); ui.setShortcutsOpen(true); } });
    }

    const results: PaletteEntry[] = (debounced.trim().length >= 2 ? (search.data ?? []) : []).map((hit) => ({
      id: `hit:${hit.kind}:${hit.id}`,
      group: "Results",
      label: hit.title,
      detail: [humanize(hit.kind), hit.subtitle, hit.organizationName].filter(Boolean).join(" · "),
      hit,
      run: () => go(hit.href ?? "/"),
    }));
    return [...results, ...pages, ...actions];
  }, [query, debounced, search.data, session, theme.resolved]);

  useEffect(() => setActiveIndex(0), [query, entries.length]);
  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>(`[data-index="${activeIndex}"]`)?.scrollIntoView?.({ block: "nearest" });
  }, [activeIndex]);

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveIndex((i) => (entries.length === 0 ? 0 : (i + 1) % entries.length));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((i) => (entries.length === 0 ? 0 : (i - 1 + entries.length) % entries.length));
    } else if (event.key === "Enter") {
      event.preventDefault();
      entries[activeIndex]?.run();
    }
  };

  const groups: PaletteEntry["group"][] = ["Results", "Pages", "Actions"];
  const searching = debounced.trim().length >= 2 && search.isFetching;
  const activeId = entries[activeIndex] ? `${listId}-${activeIndex}` : undefined;

  return (
    <Dialog open onClose={onClose} title="Command palette" ariaLabel="Command palette" bare size="lg" align="top" initialFocus={inputRef}>
      <div className="flex items-center gap-2 border-b border-line px-3">
        {searching ? <LoaderCircle size={16} className="animate-spin text-fg-subtle" aria-hidden /> : <Search size={16} className="text-fg-subtle" aria-hidden />}
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKeyDown}
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-activedescendant={activeId}
          aria-autocomplete="list"
          aria-label="Search pages, actions, incidents, assets, identities, IOCs…"
          placeholder="Search pages, incidents, assets, identities, IPs, domains, hashes, CVEs…"
          className="h-12 min-w-0 flex-1 bg-transparent text-md text-fg placeholder:text-fg-subtle focus:outline-none"
        />
        <kbd className="kbd">Esc</kbd>
      </div>
      <ul ref={listRef} id={listId} role="listbox" aria-label="Results" className="scrollbar-thin max-h-[60vh] overflow-y-auto py-1">
        {entries.length === 0 ? (
          <li className="px-4 py-6 text-center text-sm text-fg-muted">
            {search.isError ? "Search is unavailable right now." : debounced.trim().length >= 2 && !search.isFetching ? `No results for “${debounced.trim()}”.` : "Type to search."}
          </li>
        ) : (
          groups.map((group) => {
            const groupEntries = entries.map((e, index) => ({ e, index })).filter((x) => x.e.group === group);
            if (groupEntries.length === 0) return null;
            return (
              <li key={group} role="presentation">
                <div className="px-3 pb-1 pt-2 text-2xs font-semibold uppercase tracking-wider text-fg-subtle">{group}</div>
                <ul role="group" aria-label={group}>
                  {groupEntries.map(({ e, index }) => {
                    const Icon = e.icon;
                    const active = index === activeIndex;
                    return (
                      <li
                        key={e.id}
                        id={`${listId}-${index}`}
                        data-index={index}
                        role="option"
                        aria-selected={active}
                        onMouseMove={() => setActiveIndex(index)}
                        onClick={() => e.run()}
                        className={clsx("mx-1 flex cursor-pointer items-center gap-2.5 rounded px-2.5 py-1.5", active ? "bg-primary-soft" : "hover:bg-surface-2")}
                      >
                        {Icon ? <Icon size={14} aria-hidden className="shrink-0 text-fg-muted" /> : <Search size={14} aria-hidden className="shrink-0 text-fg-subtle" />}
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-base text-fg">{e.label}</span>
                          {e.detail ? <span className="block truncate text-xs text-fg-subtle">{e.detail}</span> : null}
                        </span>
                        {e.hit?.severity ? <SeverityBadge severity={e.hit.severity} size="xs" /> : null}
                        {active ? <CornerDownLeft size={13} aria-hidden className="text-fg-subtle" /> : null}
                      </li>
                    );
                  })}
                </ul>
              </li>
            );
          })
        )}
      </ul>
      <div className="flex items-center gap-3 border-t border-line px-3 py-1.5 text-2xs text-fg-subtle">
        <span>
          <kbd className="kbd">↑</kbd> <kbd className="kbd">↓</kbd> navigate
        </span>
        <span>
          <kbd className="kbd">↵</kbd> open
        </span>
        <span className="ml-auto">Searching {session.organization ? session.organization.name : "all organizations"} · results respect your permissions</span>
      </div>
    </Dialog>
  );
}
