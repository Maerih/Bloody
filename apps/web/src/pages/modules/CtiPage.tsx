import { EXCLUDED_KEYED_SERVICES, OPEN_INTEL_SOURCES, type Indicator } from "@bloody/contracts";
import { Crosshair, Radar, Rss, ShieldCheck, Skull, Target } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useIndicators, useIntelMatches, useIntelSources, useRetroHunt } from "../../api/hooks";
import type { IntelSource } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge, SeverityBadge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Card } from "../../components/Card";
import { ConnectEngineEmptyState } from "../../components/ConnectEngine";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { Select } from "../../components/Form";
import { RelativeTime } from "../../components/RelativeTime";
import { StatTile } from "../../components/StatTile";
import { IndicatorsTable, IntelMatchesTable } from "../../features/intel/IntelTables";
import { IntegrationStatusList } from "../../features/integrations/IntegrationStatusList";
import { KpiGrid, ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { SummaryWidgets } from "../../features/modules/SummaryWidgets";
import { formatInteger } from "../../lib/format";
import { groupIndicators, indicatorInGroup, type IntelGroup, type IntelGroupBy } from "../../lib/intelGroups";
import { SEVERITY_ORDER } from "../../lib/severity";
import { IntelMatchesWidget } from "../command-center/widgets";

/** Retro-hunt: re-match the indicator corpus against stored telemetry (writes environment matches). */
function RetroHunt() {
  const session = useSession();
  const hunt = useRetroHunt();
  const [days, setDays] = useState(30);
  const orgId = session.organizationId;
  const allowed = orgId ? session.can("intel:write", orgId) : session.can("intel:write", null);
  if (!allowed) return null;
  return (
    <span className="flex flex-wrap items-center gap-2 text-sm">
      <Select value={days} onChange={(e) => setDays(Number(e.target.value))} className="h-7 w-32" aria-label="Retro-hunt lookback">
        {[7, 30, 90].map((d) => (
          <option key={d} value={d}>
            Last {d} days
          </option>
        ))}
      </Select>
      <Button size="sm" icon={Radar} loading={hunt.isPending} onClick={() => hunt.mutate({ organizationId: orgId, lookbackDays: days })}>
        Retro-hunt
      </Button>
      {hunt.isSuccess ? (
        <span role="status" className="text-xs text-healthy">
          {hunt.data.matches !== undefined ? `${formatInteger(hunt.data.matches)} match(es) recorded` : "Retro-hunt complete"}
          {hunt.data.indicators !== undefined ? ` from ${formatInteger(hunt.data.indicators)} indicators` : ""}
        </span>
      ) : hunt.isError ? (
        <span role="alert" className="text-xs text-sev-critical">
          {errorMessage(hunt.error)}
        </span>
      ) : null}
    </span>
  );
}

/** Actors or campaigns rolled up from indicators, with environment matches; selecting one lists its IOCs. */
function IntelGroups({ by, initialKey }: { by: IntelGroupBy; initialKey: string | null }) {
  const indicators = useIndicators({ limit: 500 });
  const matches = useIntelMatches({ limit: 500 });
  const [selected, setSelected] = useState<string | null>(initialKey?.toLowerCase() ?? null);
  const groups = useMemo(() => (indicators.items ? groupIndicators(indicators.items, matches.data?.items ?? [], by) : undefined), [indicators.items, matches.data, by]);
  const label = by === "actor" ? "Threat actor" : "Campaign / malware";
  const sel = groups?.find((g) => g.key === selected) ?? null;
  const predicate = useMemo(() => (sel ? (i: Indicator) => indicatorInGroup(i, by, sel.key) : undefined), [sel, by]);

  const columns: DataTableColumn<IntelGroup>[] = [
    { id: "name", header: label, accessor: (g) => g.name, hideable: false, cell: (g) => <span className="font-medium text-heading">{g.name}</span> },
    { id: "severity", header: "Max severity", accessor: (g) => SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(g.maxSeverity), cell: (g) => <SeverityBadge severity={g.maxSeverity} size="xs" /> },
    { id: "indicators", header: "Indicators", accessor: (g) => g.indicators, align: "right" },
    {
      id: "matches",
      header: "Seen in environment",
      accessor: (g) => g.matches,
      align: "right",
      cell: (g) => (g.matches > 0 ? <span className="font-semibold text-sev-critical">{formatInteger(g.matches)} match(es) · {g.matchedIndicators} IOC(s)</span> : <span className="text-fg-subtle">No</span>),
    },
    { id: "related", header: by === "actor" ? "Campaigns & malware" : "Attributed actors", accessor: (g) => g.related.join(", "), cell: (g) => <span className="line-clamp-1 max-w-[260px] text-xs text-fg-muted">{g.related.join(", ") || "—"}</span> },
    { id: "types", header: "IOC types", accessor: (g) => g.types.join(", "), cell: (g) => <span className="text-xs">{g.types.join(", ")}</span> },
    { id: "sources", header: "Sources", accessor: (g) => g.sources.join(", "), defaultHidden: true },
    { id: "lastMatched", header: "Last matched", accessor: (g) => (g.lastMatchedAt ? new Date(g.lastMatchedAt) : null), cell: (g) => (g.lastMatchedAt ? <RelativeTime value={g.lastMatchedAt} /> : <span className="text-fg-subtle">—</span>) },
    { id: "lastSeen", header: "Last seen (intel)", accessor: (g) => new Date(g.lastSeenAt), cell: (g) => <RelativeTime value={g.lastSeenAt} /> },
  ];

  return (
    <div className="space-y-3">
      <DataTable
        caption={by === "actor" ? "Threat actors" : "Campaigns and malware"}
        columns={columns}
        rows={groups}
        getRowId={(g) => g.key}
        loading={indicators.isPending}
        error={indicators.error}
        onRetry={() => void indicators.refetch()}
        onRowClick={(g) => setSelected((cur) => (cur === g.key ? null : g.key))}
        selectedRowId={selected}
        initialState={{ sort: { columnId: "matches", direction: "desc" } }}
        savedViewsKey={`cti-${by}`}
        exportFileName={by === "actor" ? "bloody-threat-actors" : "bloody-campaigns"}
        footer={
          indicators.hasNextPage ? (
            <span className="flex items-center gap-2 text-xs text-fg-muted">
              Rolled up from the first {formatInteger(indicators.items?.length ?? 0)} indicators.
              <Button size="xs" onClick={() => void indicators.fetchNextPage()} loading={indicators.isFetchingNextPage}>
                Load more
              </Button>
            </span>
          ) : null
        }
        emptyState={
          <ConnectEngineEmptyState
            compact
            icon={by === "actor" ? Skull : Target}
            title={by === "actor" ? "No indicators are attributed to a threat actor" : "No indicators are linked to a campaign or malware family"}
            description="Attribution comes from intelligence feeds (MISP events, OpenCTI STIX relationships) or from analysts when adding IOCs."
            engines={["misp", "opencti"]}
          />
        }
      />
      {sel ? (
        <div>
          <h2 className="mb-2 text-md font-semibold text-fg">
            Indicators · {sel.name} <span className="font-normal text-fg-muted">({sel.indicators})</span>
          </h2>
          <IndicatorsTable key={sel.key} predicate={predicate} emptyTitle={`No indicators for ${sel.name}`} />
        </div>
      ) : null}
    </div>
  );
}

function Feeds() {
  const sources = useIntelSources();
  const columns: DataTableColumn<IntelSource>[] = [
    { id: "source", header: "Source", accessor: (s) => s.source, hideable: false, cell: (s) => <span className="font-medium text-heading">{s.source}</span> },
    { id: "indicators", header: "Indicators", accessor: (s) => s.indicators, align: "right" },
    { id: "active", header: "Active", accessor: (s) => s.active, align: "right", cell: (s) => <span title="Not revoked and not expired">{formatInteger(s.active)}</span> },
    { id: "types", header: "IOC types", accessor: (s) => s.types, align: "right" },
    { id: "updated", header: "Last updated", accessor: (s) => (s.lastUpdatedAt ? new Date(s.lastUpdatedAt) : null), cell: (s) => <RelativeTime value={s.lastUpdatedAt} /> },
  ];
  return (
    <div className="space-y-3">
      <DataTable
        caption="Indicator sources"
        columns={columns}
        rows={sources.data}
        getRowId={(s) => s.source}
        loading={sources.isPending}
        error={sources.error}
        onRetry={() => void sources.refetch()}
        initialState={{ sort: { columnId: "indicators", direction: "desc" } }}
        exportFileName="bloody-intel-sources"
        emptyState={<ConnectEngineEmptyState compact icon={Rss} title="No intelligence feeds have contributed indicators yet" engines={["misp", "opencti"]} />}
      />
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        <Card title="Feed connections" padded={false} info="MISP and OpenCTI run as separate services; Bloody syncs indicators over their REST / GraphQL APIs.">
          <IntegrationStatusList engines={["misp", "opencti"]} />
        </Card>
        <Card title="Key-less open sources" info="Free sources enabled by default. Commercial API-keyed services are not part of the default stack.">
          <ul className="space-y-1.5">
            {OPEN_INTEL_SOURCES.map((s) => (
              <li key={s.key} className="flex items-start gap-2 text-sm">
                <ShieldCheck size={13} className="mt-0.5 shrink-0 text-healthy" aria-hidden />
                <span>
                  <a href={s.url} target="_blank" rel="noopener noreferrer" className="font-medium text-heading hover:underline">
                    {s.name}
                  </a>
                  <span className="block text-2xs text-fg-subtle">{s.license}</span>
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-fg-muted">Excluded (paid API keys): {EXCLUDED_KEYED_SERVICES.join(", ")}.</p>
        </Card>
      </div>
    </div>
  );
}

function CtiOverview() {
  const indicators = useIndicators({ limit: 500 });
  const matches = useIntelMatches({ limit: 500 });
  const sources = useIntelSources();
  const actors = useMemo(() => (indicators.items ? groupIndicators(indicators.items, matches.data?.items ?? [], "actor") : null), [indicators.items, matches.data]);
  const activeActors = actors?.filter((a) => a.matches > 0).length ?? null;
  const loaded = indicators.items?.length ?? 0;
  return (
    <div className="space-y-4">
      <KpiGrid>
        <StatTile label="Indicators" value={indicators.items ? loaded : null} loading={indicators.isPending} icon={Target} href="/cti/indicators" hint={indicators.hasNextPage ? `First ${formatInteger(loaded)} loaded` : undefined} />
        <StatTile label="Environment matches" value={matches.data?.items.length} loading={matches.isPending} icon={Crosshair} tone={(matches.data?.items.length ?? 0) > 0 ? "critical" : "healthy"} href="/cti/matches" hint={matches.data?.nextCursor ? "First page" : undefined} />
        <StatTile label="Threat actors" value={actors?.length} loading={indicators.isPending} icon={Skull} href="/cti/actors" />
        <StatTile label="Actors seen here" value={activeActors} loading={indicators.isPending || matches.isPending} icon={Skull} tone={(activeActors ?? 0) > 0 ? "critical" : "healthy"} href="/cti/actors" />
        <StatTile label="Feeds" value={sources.data?.length} loading={sources.isPending} icon={Rss} href="/cti/feeds" />
      </KpiGrid>
      <SummaryWidgets widgets={[IntelMatchesWidget]} columns={2} />
      <div>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <h2 className="text-md font-semibold text-fg">Recent environment matches</h2>
          <span className="ml-auto">
            <RetroHunt />
          </span>
        </div>
        <IntelMatchesTable />
      </div>
      {actors && actors.some((a) => a.matches > 0) ? (
        <Card title="Actors active in this environment" padded={false}>
          <ul className="divide-y divide-line">
            {actors
              .filter((a) => a.matches > 0)
              .slice(0, 8)
              .map((a) => (
                <li key={a.key} className="flex items-center gap-2 px-3 py-2 text-sm">
                  <SeverityBadge severity={a.maxSeverity} size="xs" />
                  <Link to={`/cti/actors?id=${encodeURIComponent(a.name)}`} className="min-w-0 flex-1 truncate font-medium text-heading hover:underline">
                    {a.name}
                  </Link>
                  <Badge size="xs" tone="danger">
                    {a.matches} match(es)
                  </Badge>
                  <span className="text-xs text-fg-subtle">{a.related.slice(0, 2).join(", ")}</span>
                </li>
              ))}
          </ul>
        </Card>
      ) : null}
    </div>
  );
}

/** CTI workspace: indicators (add IOC), environment matches, actors, campaigns and feeds. */
export default function CtiPage() {
  const [params] = useSearchParams();
  const id = params.get("id");
  const q = params.get("q") ?? "";
  return (
    <ModuleWorkspace
      moduleId="cti"
      aliases={{ "/intel": "" }}
      sections={{
        "": () => <CtiOverview />,
        indicators: () => <IndicatorsTable key={q} initialQuery={q} initialId={id} emptyTitle={q ? `No indicator matches “${q}”` : "No indicators yet"} />,
        matches: () => (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <p className="min-w-0 flex-1 text-sm text-fg-muted">Indicators from your feeds observed in endpoint, network, identity and cloud telemetry. Each match links to the entity and incident it touches.</p>
              <RetroHunt />
            </div>
            <IntelMatchesTable filters={params.get("indicator") ? { indicatorId: params.get("indicator")! } : {}} />
          </div>
        ),
        actors: () => <IntelGroups by="actor" initialKey={id} />,
        campaigns: () => <IntelGroups by="campaign" initialKey={id ?? (q || null)} />,
        feeds: () => <Feeds />,
      }}
    />
  );
}
