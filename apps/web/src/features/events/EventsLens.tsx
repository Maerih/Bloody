import type { CanonicalEvent } from "@bloody/contracts";
import { ExternalLink, ListTree, Rows3 } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { useEventSearch } from "../../api/hooks";
import type { TimeRange } from "../../api/types";
import { Button, ButtonLink } from "../../components/Button";
import { Card } from "../../components/Card";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";
import { ErrorState } from "../../components/ErrorState";
import { ProcessTreeView } from "../../components/ProcessTreeView";
import { SkeletonText } from "../../components/Skeleton";
import { TimeRangePicker } from "../../components/TimeRangePicker";
import { TopList, countBy } from "../../components/TopList";
import { formatInteger } from "../../lib/format";
import { buildProcessTrees } from "../../lib/processTree";
import { encodeTimeRange } from "../../lib/timeRange";
import { EventDrawer } from "./EventDrawer";
import { pivotQuery, searchHref } from "./eventFormat";
import { EventsTable, type EventColumnPreset } from "./EventsTable";

export interface EventAggregation {
  title: string;
  /** Field (dotted path) used for pivots into SIEM search. */
  field: string;
  value: (e: CanonicalEvent) => string | null | undefined;
}

export interface EventsLensProps {
  title: string;
  /** Bloody query that defines the lens. */
  query: string;
  preset?: EventColumnPreset;
  defaultRange?: TimeRange;
  aggregations?: EventAggregation[];
  /** Offer a process-tree view of the loaded events. */
  processTree?: boolean;
  /** Engines that feed this lens (empty-state CTA). */
  engines: string[];
  emptyTitle?: string;
  description?: ReactNode;
  limit?: number;
  organizationId?: string | null;
  defaultView?: "table" | "tree";
  /** Hide the lens heading (when the host page already titles it). */
  hideTitle?: boolean;
}

/**
 * A module "lens" over normalized events: a fixed query + time range, results table, event
 * drawer, optional top-N aggregations and process tree. "Open in SIEM search" carries the exact
 * query so analysts can refine it — every module page reads the same event store.
 */
export function EventsLens({ title, query, preset = "default", defaultRange = { preset: "24h" }, aggregations = [], processTree = false, engines, emptyTitle, description, limit = 200, organizationId, defaultView = "table", hideTitle = false }: EventsLensProps) {
  const [range, setRange] = useState<TimeRange>(defaultRange);
  const [view, setView] = useState<"table" | "tree">(defaultView);
  const [selected, setSelected] = useState<CanonicalEvent | null>(null);
  const search = useEventSearch({ q: query, range, limit, ...(organizationId !== undefined ? { organizationId } : {}) });
  const events = search.items;
  const trees = useMemo(() => (processTree && events ? buildProcessTrees(events) : []), [processTree, events]);
  const aggs = useMemo(
    () => aggregations.map((a) => ({ ...a, items: countBy(events ?? [], a.value, (v) => searchHref(`${query ? `${query} AND ` : ""}${pivotQuery(a.field, v)}`, encodeTimeRange(range))) })),
    [aggregations, events, query, range],
  );

  const loadedLabel = events ? `${formatInteger(events.length)}${search.total !== undefined && search.total > events.length ? ` of ${formatInteger(search.total)}` : ""} events` : null;

  const toolbar = (
    <div className="flex flex-wrap items-center gap-2">
      {processTree ? (
        <div role="group" aria-label="View" className="inline-flex rounded border border-line-strong p-0.5">
          <button type="button" aria-pressed={view === "table"} onClick={() => setView("table")} className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-sm ${view === "table" ? "bg-primary text-white" : "text-fg-muted"}`}>
            <Rows3 size={12} aria-hidden /> Events
          </button>
          <button type="button" aria-pressed={view === "tree"} onClick={() => setView("tree")} className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-sm ${view === "tree" ? "bg-primary text-white" : "text-fg-muted"}`}>
            <ListTree size={12} aria-hidden /> Process tree
          </button>
        </div>
      ) : null}
      <TimeRangePicker value={range} onChange={setRange} />
      <ButtonLink to={searchHref(query, encodeTimeRange(range))} size="sm" icon={ExternalLink}>
        Open in SIEM search
      </ButtonLink>
    </div>
  );

  const empty = <ConnectEngineEmptyState compact title={emptyTitle ?? `No ${title.toLowerCase()} in this time range`} description={description} engines={engines} />;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-0 flex-1">
          {hideTitle ? null : <h2 className="text-md font-semibold text-fg">{title}</h2>}
          <p className="truncate font-mono text-2xs text-fg-subtle" title={query}>
            {query || "(all events)"}
            {loadedLabel ? ` · ${loadedLabel}` : ""}
          </p>
        </div>
        {toolbar}
      </div>

      {aggs.length > 0 && (events?.length ?? 0) > 0 ? (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {aggs.map((a) => (
            <Card key={a.title} title={a.title} info={`Top values among the ${formatInteger(events?.length ?? 0)} most recent matching events.`}>
              <TopList items={a.items} max={8} ariaLabel={a.title} />
            </Card>
          ))}
        </div>
      ) : null}

      {view === "tree" && processTree ? (
        <Card title="Process tree" count={trees.reduce((n, t) => n + t.processCount, 0)}>
          {search.isPending ? <SkeletonText lines={6} /> : search.isError ? <ErrorState error={search.error} onRetry={() => void search.refetch()} compact /> : trees.length === 0 ? empty : <ProcessTreeView trees={trees} onSelectEvent={(id) => setSelected(events?.find((e) => e.id === id) ?? null)} />}
        </Card>
      ) : (
        <EventsTable
          rows={events}
          preset={preset}
          loading={search.isPending}
          error={search.error}
          onRetry={() => void search.refetch()}
          onSelect={setSelected}
          selectedId={selected?.id}
          emptyState={empty}
          footer={
            search.hasNextPage ? (
              <Button size="sm" onClick={() => void search.fetchNextPage()} loading={search.isFetchingNextPage}>
                Load more
              </Button>
            ) : null
          }
        />
      )}
      <EventDrawer event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
