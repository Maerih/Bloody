import { clsx } from "clsx";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Bookmark,
  BookmarkPlus,
  ChevronLeft,
  ChevronRight,
  Columns3,
  FileDown,
  ListFilter,
  Search,
  Trash2,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState, type KeyboardEvent, type ReactNode } from "react";
import { downloadCsv } from "../lib/download";
import { formatInteger } from "../lib/format";
import { readStorage, writeStorage } from "../lib/storage";
import { Button } from "./Button";
import { EmptyState } from "./EmptyState";
import { ErrorState } from "./ErrorState";
import { Checkbox, Input, Select } from "./Form";
import { Popover } from "./Popover";
import { TableSkeleton } from "./Skeleton";

export type CellValue = string | number | boolean | Date | null | undefined;

export type ColumnFilter = { kind: "text" } | { kind: "select"; options: { value: string; label: string }[] };

export interface DataTableColumn<T> {
  id: string;
  header: string;
  /** Raw value for sorting, filtering, global search and CSV export. */
  accessor?: (row: T) => CellValue;
  /** Custom rendering; defaults to the accessor value. */
  cell?: (row: T) => ReactNode;
  sortable?: boolean;
  filter?: ColumnFilter;
  align?: "left" | "right" | "center";
  width?: string;
  /** Can be hidden from the Columns menu (default true). */
  hideable?: boolean;
  defaultHidden?: boolean;
  exportable?: boolean;
  className?: string;
}

export interface SortState {
  columnId: string;
  direction: "asc" | "desc";
}

export interface DataTableViewState {
  sort: SortState | null;
  filters: Record<string, string>;
  query: string;
  pageSize: number;
  hidden: string[];
}

export interface SavedView {
  id: string;
  name: string;
  state: DataTableViewState;
  createdAt: string;
}

export interface DataTableProps<T> {
  columns: DataTableColumn<T>[];
  rows: T[] | undefined;
  getRowId: (row: T) => string;
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  onRowClick?: (row: T) => void;
  selectedRowId?: string | null;
  /** Shown when there are no rows at all (before filtering). */
  emptyState?: ReactNode;
  searchable?: boolean;
  searchPlaceholder?: string;
  initialState?: Partial<DataTableViewState>;
  /** Enables saved views persisted per browser under this key. */
  savedViewsKey?: string;
  /** Enables "Export CSV" of the filtered, sorted rows. */
  exportFileName?: string;
  /** Extra toolbar controls (right side). */
  toolbar?: ReactNode;
  /** Footer content (e.g. "Load more" for cursor pagination). */
  footer?: ReactNode;
  pageSizeOptions?: number[];
  caption?: string;
  className?: string;
  rowClassName?: (row: T) => string | undefined;
}

const DEFAULT_PAGE_SIZES = [10, 25, 50, 100];

function toComparable(value: CellValue): string | number | null {
  if (value === null || value === undefined || value === "") return null;
  if (value instanceof Date) return value.getTime();
  if (typeof value === "boolean") return value ? 1 : 0;
  return value;
}

export function compareCells(a: CellValue, b: CellValue): number {
  const x = toComparable(a);
  const y = toComparable(b);
  if (x === null && y === null) return 0;
  if (x === null) return 1; // nulls last regardless of direction
  if (y === null) return -1;
  if (typeof x === "number" && typeof y === "number") return x - y;
  return String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: "base" });
}

function cellText(value: CellValue): string {
  if (value === null || value === undefined) return "";
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function isViewArray(value: unknown): value is SavedView[] {
  return Array.isArray(value) && value.every((v) => typeof v === "object" && v !== null && "id" in v && "name" in v && "state" in v);
}

function newId(): string {
  return typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

/**
 * Dense data grid: global search, per-column filters, sorting, pagination, column visibility,
 * saved views (localStorage) and CSV export (formula-injection safe).
 */
export function DataTable<T>({
  columns,
  rows,
  getRowId,
  loading,
  error,
  onRetry,
  onRowClick,
  selectedRowId,
  emptyState,
  searchable = true,
  searchPlaceholder = "Search…",
  initialState,
  savedViewsKey,
  exportFileName,
  toolbar,
  footer,
  pageSizeOptions = DEFAULT_PAGE_SIZES,
  caption,
  className,
  rowClassName,
}: DataTableProps<T>) {
  const defaultState = useMemo<DataTableViewState>(
    () => ({
      sort: initialState?.sort ?? null,
      filters: initialState?.filters ?? {},
      query: initialState?.query ?? "",
      pageSize: initialState?.pageSize ?? 25,
      hidden: initialState?.hidden ?? columns.filter((c) => c.defaultHidden).map((c) => c.id),
    }),
    // Columns are usually declared inline; only the initial snapshot matters here.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );
  const [state, setState] = useState<DataTableViewState>(defaultState);
  const [pageIndex, setPageIndex] = useState(0);
  const [showFilters, setShowFilters] = useState(Object.keys(defaultState.filters).length > 0);
  const viewsStorageKey = savedViewsKey ? `views.${savedViewsKey}` : null;
  const [views, setViews] = useState<SavedView[]>(() => (viewsStorageKey ? (readStorage(viewsStorageKey, isViewArray) ?? []) : []));
  const [activeViewId, setActiveViewId] = useState<string | null>(null);
  const [newViewName, setNewViewName] = useState("");

  const visibleColumns = columns.filter((c) => !state.hidden.includes(c.id));
  const filterable = columns.filter((c) => c.filter && c.accessor);
  const activeFilterCount = Object.values(state.filters).filter((v) => v !== "").length;

  const processed = useMemo(() => {
    const all = rows ?? [];
    const q = state.query.trim().toLowerCase();
    const searchCols = columns.filter((c) => c.accessor && !state.hidden.includes(c.id));
    let out = all.filter((row) => {
      for (const [colId, raw] of Object.entries(state.filters)) {
        if (!raw) continue;
        const col = columns.find((c) => c.id === colId);
        if (!col?.accessor || !col.filter) continue;
        const text = cellText(col.accessor(row)).toLowerCase();
        if (col.filter.kind === "select" ? text !== raw.toLowerCase() : !text.includes(raw.toLowerCase())) return false;
      }
      if (q) return searchCols.some((c) => cellText(c.accessor!(row)).toLowerCase().includes(q));
      return true;
    });
    if (state.sort) {
      const col = columns.find((c) => c.id === state.sort!.columnId);
      if (col?.accessor) {
        const dir = state.sort.direction === "asc" ? 1 : -1;
        const acc = col.accessor;
        out = [...out].sort((a, b) => {
          const va = acc(a);
          const vb = acc(b);
          const nullA = toComparable(va) === null;
          const nullB = toComparable(vb) === null;
          if (nullA || nullB) return compareCells(va, vb);
          return dir * compareCells(va, vb);
        });
      }
    }
    return out;
  }, [rows, columns, state.filters, state.query, state.sort, state.hidden]);

  const pageCount = Math.max(1, Math.ceil(processed.length / state.pageSize));
  const safePage = Math.min(pageIndex, pageCount - 1);
  useEffect(() => {
    if (pageIndex !== safePage) setPageIndex(safePage);
  }, [pageIndex, safePage]);
  const pageRows = processed.slice(safePage * state.pageSize, safePage * state.pageSize + state.pageSize);

  const update = (patch: Partial<DataTableViewState>) => {
    setState((s) => ({ ...s, ...patch }));
    setPageIndex(0);
    setActiveViewId(null);
  };

  const toggleSort = (col: DataTableColumn<T>) => {
    if (!col.accessor || col.sortable === false) return;
    const current = state.sort?.columnId === col.id ? state.sort.direction : null;
    const next: SortState | null = current === null ? { columnId: col.id, direction: "asc" } : current === "asc" ? { columnId: col.id, direction: "desc" } : null;
    update({ sort: next });
  };

  const persistViews = (next: SavedView[]) => {
    setViews(next);
    if (viewsStorageKey) writeStorage(viewsStorageKey, next);
  };

  const saveView = () => {
    const name = newViewName.trim();
    if (!name) return;
    const existing = views.find((v) => v.name.toLowerCase() === name.toLowerCase());
    const view: SavedView = { id: existing?.id ?? newId(), name, state, createdAt: new Date().toISOString() };
    persistViews(existing ? views.map((v) => (v.id === existing.id ? view : v)) : [...views, view]);
    setActiveViewId(view.id);
    setNewViewName("");
  };

  const applyView = (view: SavedView) => {
    setState({ ...defaultState, ...view.state });
    setPageIndex(0);
    setActiveViewId(view.id);
    setShowFilters(Object.values(view.state.filters).some(Boolean));
  };

  const exportCsv = () => {
    const cols = visibleColumns.filter((c) => c.accessor && c.exportable !== false);
    downloadCsv(
      `${exportFileName ?? "export"}-${new Date().toISOString().slice(0, 10)}.csv`,
      cols.map((c) => c.header),
      processed.map((row) => cols.map((c) => c.accessor!(row))),
    );
  };

  const onRowKey = (event: KeyboardEvent<HTMLTableRowElement>, row: T) => {
    if (onRowClick && (event.key === "Enter" || event.key === " ")) {
      event.preventDefault();
      onRowClick(row);
    }
  };

  const total = rows?.length ?? 0;
  const activeView = views.find((v) => v.id === activeViewId) ?? null;

  return (
    <div className={clsx("flex min-w-0 flex-col rounded border border-line bg-surface shadow-card", className)}>
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
        {searchable ? (
          <div className="relative w-full max-w-xs">
            <Search size={13} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-fg-subtle" aria-hidden />
            <Input
              value={state.query}
              onChange={(e) => update({ query: e.target.value })}
              placeholder={searchPlaceholder}
              aria-label="Search table"
              className="h-7 pl-7"
            />
          </div>
        ) : null}
        {filterable.length > 0 ? (
          <Button size="sm" variant={showFilters ? "primary" : "secondary"} icon={ListFilter} onClick={() => setShowFilters((v) => !v)} aria-pressed={showFilters}>
            Filters{activeFilterCount > 0 ? ` (${activeFilterCount})` : ""}
          </Button>
        ) : null}
        <Popover
          label="Columns"
          panelClassName="w-52 p-2"
          trigger={(props) => (
            <Button {...props} size="sm" icon={Columns3}>
              Columns
            </Button>
          )}
        >
          <div className="space-y-1">
            {columns
              .filter((c) => c.hideable !== false)
              .map((c) => (
                <Checkbox
                  key={c.id}
                  label={c.header}
                  checked={!state.hidden.includes(c.id)}
                  onChange={(e) =>
                    update({ hidden: e.target.checked ? state.hidden.filter((h) => h !== c.id) : [...state.hidden, c.id] })
                  }
                  className="w-full"
                />
              ))}
          </div>
        </Popover>
        {savedViewsKey ? (
          <Popover
            label="Saved views"
            panelClassName="w-64 p-2"
            trigger={(props) => (
              <Button {...props} size="sm" icon={Bookmark}>
                {activeView ? activeView.name : "Views"}
              </Button>
            )}
          >
            {(close) => (
              <div className="space-y-2">
                <ul className="max-h-56 space-y-0.5 overflow-y-auto">
                  <li>
                    <button
                      type="button"
                      className="w-full rounded px-2 py-1 text-left text-base hover:bg-surface-3"
                      onClick={() => {
                        setState(defaultState);
                        setActiveViewId(null);
                        setPageIndex(0);
                        close();
                      }}
                    >
                      Default view
                    </button>
                  </li>
                  {views.map((v) => (
                    <li key={v.id} className="flex items-center gap-1">
                      <button
                        type="button"
                        className={clsx("min-w-0 flex-1 truncate rounded px-2 py-1 text-left text-base hover:bg-surface-3", v.id === activeViewId && "font-semibold text-primary")}
                        onClick={() => {
                          applyView(v);
                          close();
                        }}
                      >
                        {v.name}
                      </button>
                      <button
                        type="button"
                        aria-label={`Delete view ${v.name}`}
                        className="rounded p-1 text-fg-subtle hover:bg-surface-3 hover:text-sev-critical"
                        onClick={() => {
                          persistViews(views.filter((x) => x.id !== v.id));
                          if (activeViewId === v.id) setActiveViewId(null);
                        }}
                      >
                        <Trash2 size={12} aria-hidden />
                      </button>
                    </li>
                  ))}
                </ul>
                <form
                  className="flex gap-1 border-t border-line pt-2"
                  onSubmit={(e) => {
                    e.preventDefault();
                    saveView();
                  }}
                >
                  <Input value={newViewName} onChange={(e) => setNewViewName(e.target.value)} placeholder="Save current as…" aria-label="View name" className="h-7" maxLength={60} />
                  <Button type="submit" size="sm" variant="primary" icon={BookmarkPlus} disabled={!newViewName.trim()} aria-label="Save view" />
                </form>
              </div>
            )}
          </Popover>
        ) : null}
        {exportFileName ? (
          <Button size="sm" icon={FileDown} onClick={exportCsv} disabled={processed.length === 0}>
            Export CSV
          </Button>
        ) : null}
        <div className="ml-auto flex items-center gap-2">{toolbar}</div>
      </div>

      {showFilters && filterable.length > 0 ? (
        <div className="flex flex-wrap items-end gap-2 border-b border-line bg-surface-2 px-3 py-2">
          {filterable.map((c) => (
            <label key={c.id} className="flex flex-col gap-0.5 text-xs text-fg-muted">
              {c.header}
              {c.filter!.kind === "select" ? (
                <Select
                  value={state.filters[c.id] ?? ""}
                  onChange={(e) => update({ filters: { ...state.filters, [c.id]: e.target.value } })}
                  className="h-7 w-40"
                  aria-label={`Filter ${c.header}`}
                >
                  <option value="">All</option>
                  {c.filter!.options.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </Select>
              ) : (
                <Input
                  value={state.filters[c.id] ?? ""}
                  onChange={(e) => update({ filters: { ...state.filters, [c.id]: e.target.value } })}
                  className="h-7 w-40"
                  aria-label={`Filter ${c.header}`}
                />
              )}
            </label>
          ))}
          {activeFilterCount > 0 ? (
            <Button size="sm" variant="ghost" icon={X} onClick={() => update({ filters: {} })}>
              Clear
            </Button>
          ) : null}
        </div>
      ) : null}

      <div className="scrollbar-thin min-w-0 overflow-x-auto">
        {loading && !rows ? (
          <TableSkeleton columns={Math.min(visibleColumns.length, 6)} />
        ) : error && !rows ? (
          <ErrorState error={error} onRetry={onRetry} compact />
        ) : total === 0 ? (
          (emptyState ?? <EmptyState title="Nothing here yet" compact />)
        ) : processed.length === 0 ? (
          <EmptyState
            icon={ListFilter}
            title="No rows match the current filters"
            compact
            action={
              <Button size="sm" onClick={() => update({ filters: {}, query: "" })}>
                Clear filters
              </Button>
            }
          />
        ) : (
          <table className="w-full border-collapse text-base">
            {caption ? <caption className="sr-only">{caption}</caption> : null}
            <thead>
              <tr className="border-b border-line bg-surface-2 text-left">
                {visibleColumns.map((c) => {
                  const sortable = Boolean(c.accessor) && c.sortable !== false;
                  const dir = state.sort?.columnId === c.id ? state.sort.direction : null;
                  const SortIcon = dir === "asc" ? ArrowUp : dir === "desc" ? ArrowDown : ArrowUpDown;
                  return (
                    <th
                      key={c.id}
                      scope="col"
                      style={c.width ? { width: c.width } : undefined}
                      aria-sort={dir === "asc" ? "ascending" : dir === "desc" ? "descending" : undefined}
                      className={clsx(
                        "whitespace-nowrap px-3 py-2 text-xs font-semibold uppercase tracking-wide text-fg-muted",
                        c.align === "right" && "text-right",
                        c.align === "center" && "text-center",
                      )}
                    >
                      {sortable ? (
                        <button type="button" onClick={() => toggleSort(c)} className="inline-flex items-center gap-1 uppercase hover:text-fg">
                          {c.header}
                          <SortIcon size={11} aria-hidden className={dir ? "text-primary" : "opacity-40"} />
                        </button>
                      ) : (
                        c.header
                      )}
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {pageRows.map((row) => {
                const id = getRowId(row);
                const selected = selectedRowId === id;
                return (
                  <tr
                    key={id}
                    data-row-id={id}
                    tabIndex={onRowClick ? 0 : undefined}
                    aria-selected={onRowClick ? selected : undefined}
                    onClick={onRowClick ? () => onRowClick(row) : undefined}
                    onKeyDown={onRowClick ? (e) => onRowKey(e, row) : undefined}
                    className={clsx(
                      "border-b border-line last:border-b-0",
                      onRowClick && "cursor-pointer hover:bg-surface-2 focus:bg-surface-2 focus:outline-none",
                      selected && "bg-primary-soft hover:bg-primary-soft",
                      rowClassName?.(row),
                    )}
                  >
                    {visibleColumns.map((c) => (
                      <td
                        key={c.id}
                        className={clsx("px-3 py-2 align-middle", c.align === "right" && "text-right tabular-nums", c.align === "center" && "text-center", c.className)}
                      >
                        {c.cell ? c.cell(row) : cellText(c.accessor?.(row)) || <span className="text-fg-subtle">—</span>}
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {total > 0 ? (
        <div className="flex flex-wrap items-center gap-3 border-t border-line px-3 py-2 text-sm text-fg-muted">
          <span>
            {processed.length === 0
              ? "0 rows"
              : `${formatInteger(safePage * state.pageSize + 1)}–${formatInteger(Math.min(processed.length, (safePage + 1) * state.pageSize))} of ${formatInteger(processed.length)}`}
            {processed.length !== total ? ` (filtered from ${formatInteger(total)})` : ""}
          </span>
          {footer}
          <div className="ml-auto flex items-center gap-2">
            <label className="flex items-center gap-1">
              Rows
              <Select value={state.pageSize} onChange={(e) => update({ pageSize: Number(e.target.value) })} className="h-6 w-16 text-sm" aria-label="Rows per page">
                {pageSizeOptions.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </Select>
            </label>
            <Button size="xs" icon={ChevronLeft} aria-label="Previous page" disabled={safePage === 0} onClick={() => setPageIndex(safePage - 1)} />
            <span className="tabular-nums">
              {safePage + 1} / {pageCount}
            </span>
            <Button size="xs" icon={ChevronRight} aria-label="Next page" disabled={safePage >= pageCount - 1} onClick={() => setPageIndex(safePage + 1)} />
          </div>
        </div>
      ) : footer ? (
        <div className="border-t border-line px-3 py-2 text-sm">{footer}</div>
      ) : null}
    </div>
  );
}
