import type { Alert, Indicator } from "@bloody/contracts";
import { Ghost, KeyRound, Radar, Siren } from "lucide-react";
import { useMemo } from "react";
import { useAlerts, useEventSearch } from "../../api/hooks";
import { Card } from "../../components/Card";
import { StatTile } from "../../components/StatTile";
import { TopList, countBy } from "../../components/TopList";
import { AlertsLens } from "../../features/alerts/AlertsLens";
import { AssetsTable } from "../../features/assets/AssetsTable";
import { EventsLens } from "../../features/events/EventsLens";
import { pivotQuery, searchHref } from "../../features/events/eventFormat";
import { IndicatorsTable } from "../../features/intel/IntelTables";
import { IntegrationStatusList } from "../../features/integrations/IntegrationStatusList";
import { KpiGrid, ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { alertDomain } from "../../lib/domains";

const ENGINES = ["opencanary"];
const DECOY_QUERY = "source.product:opencanary";
const DECOY_TAG = /^(decoy|honeypot|canary)$/i;
const HONEYTOKEN_TAG = /^(honeytoken|canarytoken|canary[-_]?token)$/i;
const isDecoyAlert = (a: Alert) => alertDomain(a) === "deception";
const label = (e: { labels?: Record<string, string> }, key: string) => e.labels?.[key] ?? null;

function DeceptionOverview() {
  const alerts = useAlerts({ limit: 500, sort: "recent" });
  const events = useEventSearch({ q: DECOY_QUERY, range: { preset: "7d" }, limit: 500 });
  const decoyAlerts = useMemo(() => (alerts.data?.items ?? []).filter(isDecoyAlert), [alerts.data]);
  const attackers = useMemo(() => countBy(events.items ?? [], (e) => e.network?.srcIp, (v) => searchHref(`${DECOY_QUERY} AND ${pivotQuery("network.srcIp", v)}`, "7d")), [events.items]);
  const decoys = useMemo(() => countBy(events.items ?? [], (e) => label(e, "canary.node") ?? e.source.sensorId ?? null), [events.items]);
  return (
    <div className="space-y-4">
      <KpiGrid>
        <StatTile label="Decoy alerts" value={alerts.data ? decoyAlerts.length : null} loading={alerts.isPending} icon={Siren} tone={decoyAlerts.length > 0 ? "critical" : "healthy"} href="/decoy/alerts" hint="No legitimate use — every hit matters" />
        <StatTile label="Interactions (7 days)" value={events.items?.length} loading={events.isPending} icon={Radar} hint={events.hasNextPage ? "First 500" : undefined} />
        <StatTile label="Decoys touched" value={events.items ? decoys.length : null} loading={events.isPending} icon={Ghost} href="/decoy/decoys" />
        <StatTile label="Source addresses" value={events.items ? attackers.length : null} loading={events.isPending} icon={KeyRound} />
      </KpiGrid>
      <AlertsLens title="Decoy alerts" predicate={isDecoyAlert} engines={ENGINES} emptyTitle="No decoy has been touched" description="Decoys and honeytokens have no legitimate use, so any interaction is a high-confidence signal of reconnaissance or lateral movement." savedViewsKey="decoy-overview-alerts" />
      {(events.items?.length ?? 0) > 0 ? (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <Card title="Who touched the decoys" info="Source addresses of interactions in the last 7 days.">
            <TopList items={attackers} ariaLabel="Source addresses" />
          </Card>
          <Card title="Decoys touched">
            <TopList items={decoys} ariaLabel="Decoys touched" />
          </Card>
        </div>
      ) : null}
    </div>
  );
}

/** Deception workspace: decoys (honeypots), honeytokens, interactions and zero-false-positive alerts. */
export default function DeceptionPage() {
  return (
    <ModuleWorkspace
      moduleId="decoy"
      aliases={{ "/deception": "" }}
      sections={{
        "": () => <DeceptionOverview />,
        decoys: () => (
          <div className="space-y-4">
            <Card title="Decoy sensors" padded={false} info="OpenCanary honeypots run as separate services and report every interaction over webhook / syslog.">
              <IntegrationStatusList engines={ENGINES} />
            </Card>
            <EventsLens
              title="Decoy services"
              query={DECOY_QUERY}
              engines={ENGINES}
              defaultRange={{ preset: "30d" }}
              aggregations={[
                { title: "Decoys", field: "source.sensorId", value: (e) => label(e, "canary.node") ?? e.source.sensorId ?? null },
                { title: "Services", field: "labels.canary.service", value: (e) => label(e, "canary.service") },
                { title: "Sources", field: "network.srcIp", value: (e) => e.network?.srcIp ?? null },
              ]}
            />
            <div>
              <h2 className="mb-2 text-md font-semibold text-fg">Decoy assets in the inventory</h2>
              <AssetsTable predicate={(a) => a.tags.some((t) => DECOY_TAG.test(t))} engines={ENGINES} emptyTitle="No assets tagged as decoys" description="Tag decoy hosts with “decoy” or “honeypot” so attack paths and exposure analysis treat them as bait, not assets." savedViewsKey="decoy-assets" />
            </div>
          </div>
        ),
        tokens: () => (
          <div className="space-y-4">
            <p className="text-sm text-fg-muted">Honeytokens are planted credentials, keys and documents tracked as indicators tagged “honeytoken”. Any use of one — a sign-in with a decoy credential, a DNS lookup of a canary hostname — matches the indicator and raises an alert.</p>
            <IndicatorsTable predicate={(i: Indicator) => i.tags.some((t) => HONEYTOKEN_TAG.test(t))} emptyTitle="No honeytokens registered" description="Add an indicator (credential user name, canary domain, document hash) with the tag “honeytoken”." />
            <EventsLens title="Decoy credential use" query={`${DECOY_QUERY} AND category:authentication`} preset="auth" engines={ENGINES} defaultRange={{ preset: "30d" }} aggregations={[{ title: "Usernames tried", field: "identity.principal", value: (e) => e.identity?.principal ?? null }, { title: "Sources", field: "identity.sourceIp", value: (e) => e.identity?.sourceIp ?? null }]} />
          </div>
        ),
        alerts: () => <AlertsLens predicate={isDecoyAlert} engines={ENGINES} emptyTitle="No decoy alerts" savedViewsKey="decoy-alerts" />,
      }}
    />
  );
}
