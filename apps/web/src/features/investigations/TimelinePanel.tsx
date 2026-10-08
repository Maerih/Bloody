import type { TimelineEntry } from "@bloody/contracts";
import { clsx } from "clsx";
import { Activity, Archive, Bot, Flag, MessageSquare, ShieldAlert, Terminal, type LucideIcon } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { EmptyState } from "../../components/EmptyState";
import { formatDateTime, humanize } from "../../lib/format";
import { hrefForEntity } from "../../lib/entityLinks";

const KIND_META: Record<TimelineEntry["kind"], { icon: LucideIcon; tone: string; label: string }> = {
  event: { icon: Activity, tone: "bg-surface-3 text-fg-muted", label: "Event" },
  alert: { icon: ShieldAlert, tone: "bg-sev-high/15 text-sev-high", label: "Alert" },
  note: { icon: MessageSquare, tone: "bg-primary-soft text-primary", label: "Note" },
  action: { icon: Terminal, tone: "bg-sev-low/15 text-sev-low", label: "Action" },
  evidence: { icon: Archive, tone: "bg-sev-medium/20 text-sev-medium", label: "Evidence" },
  ai: { icon: Bot, tone: "bg-brand-soft text-brand", label: "AI" },
  status_change: { icon: Flag, tone: "bg-healthy-soft text-healthy", label: "Status" },
};

/** Ordered investigation timeline (events, alerts, notes, actions, evidence, AI, status). */
export function TimelinePanel({ entries, actorName }: { entries: TimelineEntry[]; actorName: (actor: string | null) => string }) {
  const [hidden, setHidden] = useState<Set<TimelineEntry["kind"]>>(new Set());
  const counts = useMemo(() => {
    const c = new Map<TimelineEntry["kind"], number>();
    for (const e of entries) c.set(e.kind, (c.get(e.kind) ?? 0) + 1);
    return c;
  }, [entries]);
  const shown = entries.filter((e) => !hidden.has(e.kind)).sort((a, b) => a.at.localeCompare(b.at));
  if (entries.length === 0) return <EmptyState compact icon={Activity} title="The timeline is empty" description="Alerts, notes, evidence and response actions are added here as the investigation progresses." />;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter timeline">
        {(Object.keys(KIND_META) as TimelineEntry["kind"][])
          .filter((k) => counts.has(k))
          .map((k) => {
            const on = !hidden.has(k);
            return (
              <button
                key={k}
                type="button"
                aria-pressed={on}
                onClick={() => setHidden((h) => {
                  const next = new Set(h);
                  if (next.has(k)) next.delete(k);
                  else next.add(k);
                  return next;
                })}
                className={clsx("rounded-full border px-2 py-0.5 text-xs", on ? "border-primary/40 bg-primary-soft text-primary" : "border-line text-fg-subtle line-through")}
              >
                {KIND_META[k].label} ({counts.get(k)})
              </button>
            );
          })}
      </div>
      <ol className="relative space-y-3 border-l border-line pl-5" aria-label="Investigation timeline">
        {shown.map((e) => {
          const meta = KIND_META[e.kind];
          const Icon = meta.icon;
          const refHref = e.refId && e.kind === "alert" ? hrefForEntity("alert", e.refId) : null;
          return (
            <li key={e.id} className="relative" data-kind={e.kind}>
              <span className={clsx("absolute -left-[31px] top-0 inline-flex h-5 w-5 items-center justify-center rounded-full ring-4 ring-surface", meta.tone)} aria-hidden>
                <Icon size={11} />
              </span>
              <div className="flex flex-wrap items-baseline gap-x-2">
                <span className="font-mono text-2xs text-fg-subtle">{formatDateTime(e.at)}</span>
                <span className="text-2xs uppercase tracking-wide text-fg-subtle">{humanize(e.kind)}</span>
                <span className="text-2xs text-fg-subtle">· {actorName(e.actorId)}</span>
              </div>
              <div className="text-base font-medium text-fg">{refHref ? <Link to={refHref} className="hover:underline">{e.title}</Link> : e.title}</div>
              {e.body ? <p className="whitespace-pre-wrap text-sm text-fg-muted">{e.body}</p> : null}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
