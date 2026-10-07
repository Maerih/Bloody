import type { Severity, TriageItem } from "@bloody/contracts";
import { clsx } from "clsx";
import { CircleCheck, Filter } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { Checkbox } from "../../components/Form";
import { Popover } from "../../components/Popover";
import { RelativeTime } from "../../components/RelativeTime";
import { SkeletonText } from "../../components/Skeleton";
import { StatusBadge } from "../../components/Badge";
import { Tabs, TabPanel } from "../../components/Tabs";
import { hrefForEntity } from "../../lib/entityLinks";
import { SEVERITY_META, SEVERITY_ORDER } from "../../lib/severity";
import { isOneOf, useLocalStorageState } from "../../lib/storage";

type FeedTab = "incidents" | "escalations";
const isSeverityList = (v: unknown): v is Severity[] => Array.isArray(v) && v.every(isOneOf(SEVERITY_ORDER));

export interface TriageFeedProps {
  items: TriageItem[] | undefined;
  loading?: boolean;
  /** Show organization names (All organizations view). */
  showOrganization?: boolean;
  className?: string;
}

/** Right-hand Triage Feed: newest actionable incidents/alerts and escalations, filterable by severity. */
export function TriageFeed({ items, loading, showOrganization, className }: TriageFeedProps) {
  const [tab, setTab] = useState<FeedTab>("incidents");
  const [severities, setSeverities] = useLocalStorageState<Severity[]>("triage.severities", [...SEVERITY_ORDER], isSeverityList);

  const { incidents, escalations } = useMemo(() => {
    const visible = (items ?? []).filter((i) => severities.includes(i.severity));
    const sorted = [...visible].sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime());
    return {
      incidents: sorted.filter((i) => i.kind === "incident" || i.kind === "alert"),
      escalations: sorted.filter((i) => i.kind === "escalation"),
    };
  }, [items, severities]);

  const filtered = severities.length < SEVERITY_ORDER.length;
  const list = tab === "incidents" ? incidents : escalations;

  return (
    <Card
      title="Triage Feed"
      className={clsx("h-full", className)}
      padded={false}
      actions={
        <Popover
          align="end"
          label="Filter triage feed"
          panelClassName="w-48 p-2"
          trigger={(props) => (
            <Button {...props} size="xs" variant="primary" icon={Filter}>
              Filter{filtered ? ` (${severities.length})` : ""}
            </Button>
          )}
        >
          <fieldset className="space-y-1">
            <legend className="mb-1 text-xs font-semibold text-fg-muted">Severity</legend>
            {SEVERITY_ORDER.map((s) => (
              <Checkbox
                key={s}
                label={SEVERITY_META[s].label}
                checked={severities.includes(s)}
                onChange={(e) => setSeverities((prev) => (e.target.checked ? [...prev, s] : prev.filter((x) => x !== s)))}
                className="w-full"
              />
            ))}
            <button type="button" className="mt-1 text-xs text-primary hover:underline" onClick={() => setSeverities([...SEVERITY_ORDER])}>
              Reset
            </button>
          </fieldset>
        </Popover>
      }
    >
      <div className="flex h-full flex-col px-3 pt-3">
        <Tabs<FeedTab>
          variant="boxed"
          idPrefix="triage"
          ariaLabel="Triage feed"
          value={tab}
          onChange={setTab}
          tabs={[
            { id: "incidents", label: "Incidents", count: items ? incidents.length : null },
            { id: "escalations", label: "Escalations", count: items ? escalations.length : null },
          ]}
          className="border-b border-line"
        />
        <TabPanel id={tab} idPrefix="triage" className="scrollbar-thin -mx-3 min-h-[240px] flex-1 overflow-y-auto border-x-0 px-0">
          {loading && !items ? (
            <div className="p-3">
              <SkeletonText lines={6} />
            </div>
          ) : list.length === 0 ? (
            <EmptyState
              compact
              tone="success"
              icon={CircleCheck}
              title={tab === "incidents" ? "All caught up, no active incidents!" : "All caught up, no open escalations!"}
              description={filtered ? "Some severities are hidden by your filter." : undefined}
            />
          ) : (
            <ul className="divide-y divide-line">
              {list.map((item) => (
                <TriageRow key={`${item.kind}:${item.id}`} item={item} showOrganization={showOrganization} />
              ))}
            </ul>
          )}
        </TabPanel>
      </div>
    </Card>
  );
}

function TriageRow({ item, showOrganization }: { item: TriageItem; showOrganization?: boolean }) {
  const meta = SEVERITY_META[item.severity];
  return (
    <li>
      <Link to={hrefForEntity(item.kind, item.id)} className="flex gap-2.5 px-3 py-2 hover:bg-surface-2">
        <span className={clsx("mt-0.5 w-1 shrink-0 self-stretch rounded", meta.bg)} aria-hidden />
        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-1.5">
            <span className={clsx("text-2xs font-semibold uppercase", meta.text)}>{meta.label}</span>
            <span className="text-2xs uppercase text-fg-subtle">{item.kind}</span>
          </span>
          <span className="block truncate text-base text-fg">{item.title}</span>
          <span className="mt-0.5 flex items-center gap-2 text-xs text-fg-subtle">
            <RelativeTime value={item.at} />
            {showOrganization ? <span className="truncate">· {item.organizationName}</span> : null}
          </span>
        </span>
        <StatusBadge status={item.status} size="xs" className="self-start" />
      </Link>
    </li>
  );
}
