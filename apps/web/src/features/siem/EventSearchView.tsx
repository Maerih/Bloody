import type { CanonicalEvent } from "@bloody/contracts";
import { Bookmark, BookmarkPlus, Lightbulb, Search, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useEventSearch } from "../../api/hooks";
import type { TimeRange } from "../../api/types";
import { useSession } from "../../app/session";
import { Button, IconButton } from "../../components/Button";
import { Card } from "../../components/Card";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";
import { Field, Input } from "../../components/Form";
import { Dialog } from "../../components/Overlay";
import { QueryBuilder } from "../../components/QueryBuilder";
import { RelativeTime } from "../../components/RelativeTime";
import { TimeRangePicker } from "../../components/TimeRangePicker";
import { formatDateTime, formatInteger } from "../../lib/format";
import { decodeTimeRange, describeTimeRange, encodeTimeRange, resolveTimeRange } from "../../lib/timeRange";
import { EventDrawer } from "../events/EventDrawer";
import { EventsTable } from "../events/EventsTable";
import { useSavedSearches } from "./savedSearches";

export interface HuntSuggestion {
  name: string;
  query: string;
  description: string;
  range?: string;
}

const BUCKETS = 48;

/** Result timeline: loaded events per time bucket across the searched window. */
export function EventHistogram({ events, range }: { events: CanonicalEvent[]; range: TimeRange }) {
  const { from, to } = useMemo(() => resolveTimeRange(range), [range]);
  const buckets = useMemo(() => {
    const start = Date.parse(from);
    const end = Date.parse(to);
    const span = Math.max(1, end - start);
    const counts = new Array<number>(BUCKETS).fill(0);
    for (const e of events) {
      const t = Date.parse(e.timestamp);
      if (Number.isNaN(t) || t < start || t > end) continue;
      counts[Math.min(BUCKETS - 1, Math.floor(((t - start) / span) * BUCKETS))]! += 1;
    }
    return { counts, start, step: span / BUCKETS };
  }, [events, from, to]);
  const max = Math.max(1, ...buckets.counts);
  return (
    <div className="flex h-12 items-end gap-px" role="img" aria-label={`Event distribution, ${formatInteger(events.length)} loaded events`} data-testid="event-histogram">
      {buckets.counts.map((c, i) => (
        <div
          key={i}
          className="min-w-0 flex-1 rounded-t-sm bg-primary/60 hover:bg-primary"
          style={{ height: `${c === 0 ? 0 : Math.max(6, (c / max) * 100)}%` }}
          title={`${formatDateTime(new Date(buckets.start + i * buckets.step))}: ${c} event(s)`}
        />
      ))}
    </div>
  );
}

/**
 * SIEM event search: query builder (field/op/value chips) or raw query, time range, results
 * table with the event JSON drawer, result timeline, and saved searches. State lives in the URL
 * (?q=&range=) so searches are shareable and pivots land here pre-filled.
 */
export function EventSearchView({ suggestions = [], savedSearchesPanel = true, defaultRange = "24h" }: { suggestions?: HuntSuggestion[]; savedSearchesPanel?: boolean; defaultRange?: string }) {
  const session = useSession();
  const [params, setParams] = useSearchParams();
  const q = params.get("q") ?? "";
  const range = decodeTimeRange(params.get("range") ?? defaultRange);
  const search = useEventSearch({ q, range, limit: 200 }, { enabled: session.canAnywhere("event:read") });
  const [selected, setSelected] = useState<CanonicalEvent | null>(null);
  const [saving, setSaving] = useState(false);
  const [name, setName] = useState("");
  const saved = useSavedSearches();

  const run = (query: string, nextRange: TimeRange = range) => {
    const next = new URLSearchParams(params);
    if (query) next.set("q", query);
    else next.delete("q");
    next.set("range", encodeTimeRange(nextRange));
    setParams(next);
  };

  const events = search.items;
  const status = events ? `${formatInteger(events.length)}${search.total !== undefined ? ` of ${formatInteger(search.total)}` : ""} events · ${describeTimeRange(range)}${search.truncated ? " · results truncated" : ""}` : null;

  return (
    <div className="grid grid-cols-1 gap-3 2xl:grid-cols-[minmax(0,1fr)_280px]">
      <div className="min-w-0 space-y-3">
        <QueryBuilder
          value={q}
          onSubmit={(query) => run(query)}
          actions={
            <>
              <TimeRangePicker value={range} onChange={(r) => run(q, r)} />
              <Button
                size="sm"
                icon={BookmarkPlus}
                onClick={() => {
                  setName("");
                  setSaving(true);
                }}
              >
                Save
              </Button>
            </>
          }
        />
        <Card
          title="Results"
          subtitle={status ?? undefined}
          info="Events are normalized to the Bloody Canonical Event schema; click a row for the parsed fields, pivots and raw JSON."
          padded={false}
          bodyClassName="space-y-2"
        >
          {events && events.length > 0 ? (
            <div className="px-3 pt-3">
              <EventHistogram events={events} range={range} />
            </div>
          ) : null}
          <EventsTable
            rows={events}
            loading={search.isPending}
            error={search.error}
            onRetry={() => void search.refetch()}
            onSelect={setSelected}
            selectedId={selected?.id}
            savedViewsKey="siem-search-results"
            exportFileName="bloody-event-search"
            emptyState={
              <ConnectEngineEmptyState
                compact
                icon={Search}
                title={q ? "No events match this query" : "No events in this time range"}
                description={q ? "Widen the time range or relax a condition. Field names follow the canonical event schema (e.g. process.name, network.dstIp)." : undefined}
                engines={["wazuh", "zeek", "suricata"]}
              />
            }
            footer={
              search.hasNextPage ? (
                <Button size="sm" onClick={() => void search.fetchNextPage()} loading={search.isFetchingNextPage}>
                  Load more
                </Button>
              ) : null
            }
          />
        </Card>
      </div>
      <div className="space-y-3">
        {savedSearchesPanel ? (
          <Card title="Saved searches" count={saved.searches.length} info="Saved per user in this browser." padded={false}>
            {saved.searches.length === 0 ? (
              <p className="p-3 text-sm text-fg-muted">Save a query and time range to rerun it with one click.</p>
            ) : (
              <ul className="divide-y divide-line" aria-label="Saved searches">
                {saved.searches.slice(0, 20).map((s) => (
                  <li key={s.id} className="group flex items-start gap-2 px-3 py-2">
                    <Bookmark size={13} className="mt-0.5 shrink-0 text-primary" aria-hidden />
                    <button type="button" className="min-w-0 flex-1 text-left" onClick={() => run(s.query, decodeTimeRange(s.range))}>
                      <span className="block truncate text-sm font-medium text-heading hover:underline">{s.name}</span>
                      <span className="block truncate font-mono text-2xs text-fg-subtle" title={s.query}>
                        {s.query || "(all events)"} · {describeTimeRange(decodeTimeRange(s.range))}
                      </span>
                    </button>
                    <IconButton icon={Trash2} size={12} label={`Delete saved search ${s.name}`} onClick={() => saved.remove(s.id)} className="opacity-60 group-hover:opacity-100" />
                  </li>
                ))}
              </ul>
            )}
          </Card>
        ) : null}
        {suggestions.length > 0 ? (
          <Card title="Hunt hypotheses" count={suggestions.length} padded={false} info="Starting queries for common attacker behaviour. They run against your own normalized telemetry.">
            <ul className="divide-y divide-line">
              {suggestions.map((s) => (
                <li key={s.name}>
                  <button type="button" className="flex w-full items-start gap-2 px-3 py-2 text-left hover:bg-surface-2" onClick={() => run(s.query, decodeTimeRange(s.range ?? "7d"))}>
                    <Lightbulb size={13} className="mt-0.5 shrink-0 text-sev-medium" aria-hidden />
                    <span className="min-w-0">
                      <span className="block text-sm font-medium text-fg">{s.name}</span>
                      <span className="block text-xs text-fg-muted">{s.description}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </Card>
        ) : null}
      </div>
      <EventDrawer event={selected} onClose={() => setSelected(null)} />
      {saving ? (
        <Dialog
          open
          onClose={() => setSaving(false)}
          title="Save search"
          description={`${q || "(all events)"} · ${describeTimeRange(range)}`}
          size="sm"
          footer={
            <>
              <Button onClick={() => setSaving(false)}>Cancel</Button>
              <Button
                variant="primary"
                disabled={!name.trim()}
                onClick={() => {
                  saved.save(name, q, encodeTimeRange(range));
                  setSaving(false);
                }}
              >
                Save
              </Button>
            </>
          }
        >
          <Field label="Name" required>
            {(p) => <Input {...p} value={name} onChange={(e) => setName(e.target.value)} maxLength={120} autoFocus placeholder="Encoded PowerShell on servers" />}
          </Field>
        </Dialog>
      ) : null}
    </div>
  );
}

/** Saved searches as a page section (SIEM → Saved Searches). */
export function SavedSearchesList() {
  const saved = useSavedSearches();
  if (saved.searches.length === 0) {
    return <ConnectEngineEmptyState icon={Bookmark} title="No saved searches yet" description="Run a search in Event Search and save it to rerun it later." engines={[]} />;
  }
  return (
    <ul className="divide-y divide-line" aria-label="Saved searches">
      {saved.searches.map((s) => (
        <li key={s.id} className="flex flex-wrap items-center gap-3 px-3 py-2">
          <Bookmark size={14} className="text-primary" aria-hidden />
          <span className="min-w-0 flex-1">
            <Link to={`/siem/search?q=${encodeURIComponent(s.query)}&range=${encodeURIComponent(s.range)}`} className="block font-medium text-heading hover:underline">
              {s.name}
            </Link>
            <span className="block truncate font-mono text-xs text-fg-subtle">{s.query || "(all events)"}</span>
          </span>
          <span className="text-xs text-fg-muted">{describeTimeRange(decodeTimeRange(s.range))}</span>
          <span className="text-xs text-fg-subtle">
            Saved <RelativeTime value={s.createdAt} />
          </span>
          <IconButton icon={Trash2} size={13} label={`Delete saved search ${s.name}`} onClick={() => saved.remove(s.id)} />
        </li>
      ))}
    </ul>
  );
}
