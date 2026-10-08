import type { Alert } from "@bloody/contracts";
import { HardDrive } from "lucide-react";
import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { ButtonLink } from "../../components/Button";
import { Card } from "../../components/Card";
import { AlertsLens } from "../../features/alerts/AlertsLens";
import { CategorySummary } from "../../features/alerts/CategorySummary";
import { EventsLens } from "../../features/events/EventsLens";
import { IntegrationStatusList } from "../../features/integrations/IntegrationStatusList";
import { ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { SummaryWidgets } from "../../features/modules/SummaryWidgets";
import { matchCategory, NETWORK_DETECTIONS } from "../../lib/classify";
import { IntelMatchesWidget, NetworkHealthWidget } from "../command-center/widgets";

const NET_ENGINES = ["zeek", "suricata", "arkime"];
const isNetworkAlert = (a: Alert) => matchCategory(a, NETWORK_DETECTIONS) !== null || /zeek|suricata|arkime|network/i.test(a.source);
const inCategory = (key: string) => (a: Alert) => matchCategory(a, NETWORK_DETECTIONS)?.category.key === key;

function NetworkDetections() {
  const [params, setParams] = useSearchParams();
  const category = NETWORK_DETECTIONS.some((c) => c.key === params.get("category")) ? params.get("category") : null;
  const select = useCallback(
    (k: string | null) => {
      const next = new URLSearchParams(params);
      if (k) next.set("category", k);
      else next.delete("category");
      setParams(next, { replace: true });
    },
    [params, setParams],
  );
  const predicate = useMemo(() => (category ? inCategory(category) : isNetworkAlert), [category]);
  return (
    <>
      <CategorySummary categories={NETWORK_DETECTIONS} predicate={isNetworkAlert} selected={category} onSelect={select} />
      <AlertsLens title="Network detections" predicate={predicate} categories={NETWORK_DETECTIONS} engines={NET_ENGINES} emptyTitle="No network detections" savedViewsKey="ndr-alerts" />
    </>
  );
}

/** NDR workspace: flows, DNS / TLS / HTTP analytics, beaconing & C2, exfiltration, PCAP and sensors. */
export default function NdrPage() {
  return (
    <ModuleWorkspace
      moduleId="ndr"
      sections={{
        "": () => (
          <div className="space-y-4">
            <SummaryWidgets widgets={[NetworkHealthWidget, IntelMatchesWidget]} columns={2} />
            <NetworkDetections />
            <EventsLens
              title="Suspicious connections"
              query="category:network AND indicators.value:*"
              preset="network"
              engines={NET_ENGINES}
              description="Connections whose source or destination matched threat intelligence or a detection."
              aggregations={[{ title: "Destinations", field: "network.dstIp", value: (e) => e.network?.dstIp }, { title: "Internal hosts", field: "network.srcIp", value: (e) => e.network?.srcIp }]}
            />
          </div>
        ),
        flows: () => (
          <EventsLens
            title="Network flows"
            query="category:network"
            preset="network"
            engines={["zeek", "suricata"]}
            aggregations={[
              { title: "Top destinations", field: "network.dstIp", value: (e) => e.network?.dstIp },
              { title: "Destination ports", field: "network.dstPort", value: (e) => (e.network?.dstPort !== undefined ? String(e.network.dstPort) : null) },
              { title: "Direction", field: "network.direction", value: (e) => e.network?.direction },
            ]}
          />
        ),
        dns: () => (
          <EventsLens
            title="DNS analytics"
            query="category:dns"
            preset="dns"
            engines={["zeek", "suricata"]}
            aggregations={[
              { title: "Queried domains", field: "network.dnsQuery", value: (e) => e.network?.dnsQuery },
              { title: "Clients", field: "network.srcIp", value: (e) => e.network?.srcIp },
              { title: "Resolvers", field: "network.dstIp", value: (e) => e.network?.dstIp },
            ]}
          />
        ),
        "tls-http": () => (
          <div className="space-y-6">
            <EventsLens
              title="TLS analytics"
              query="category:tls"
              preset="web"
              engines={["zeek", "suricata"]}
              aggregations={[
                { title: "Server names (SNI)", field: "network.tlsSni", value: (e) => e.network?.tlsSni },
                { title: "JA3 fingerprints", field: "network.ja3", value: (e) => e.network?.ja3 },
              ]}
            />
            <EventsLens
              title="HTTP analytics"
              query="category:http"
              preset="web"
              engines={["zeek", "suricata"]}
              aggregations={[
                { title: "Hosts", field: "network.httpHost", value: (e) => e.network?.httpHost },
                { title: "User agents", field: "labels.user_agent", value: (e) => e.labels?.["http.user_agent"] ?? e.labels?.user_agent },
              ]}
            />
          </div>
        ),
        beaconing: () => (
          <div className="space-y-4">
            <AlertsLens title="Beaconing & command-and-control" predicate={inCategory("beaconing")} categories={NETWORK_DETECTIONS} engines={["zeek", "suricata"]} emptyTitle="No beaconing detected" description="Periodic callbacks are detected by threshold rules with timing regularity over connection logs." savedViewsKey="ndr-beaconing" />
            <AlertsLens title="DNS abuse (tunnelling, DGA)" predicate={inCategory("dns_abuse")} categories={NETWORK_DETECTIONS} engines={["zeek"]} emptyTitle="No DNS abuse detected" savedViewsKey="ndr-dns-abuse" />
          </div>
        ),
        exfiltration: () => (
          <div className="space-y-4">
            <AlertsLens title="Exfiltration detections" predicate={inCategory("exfiltration")} categories={NETWORK_DETECTIONS} engines={["zeek", "suricata"]} emptyTitle="No exfiltration indicators" savedViewsKey="ndr-exfil" />
            <EventsLens
              title="Large outbound transfers (≥ 10 MB)"
              query="category:network AND network.direction:outbound AND network.bytesOut:>=10000000"
              preset="network"
              engines={["zeek"]}
              defaultRange={{ preset: "7d" }}
              aggregations={[{ title: "Destinations", field: "network.dstIp", value: (e) => e.network?.dstIp }, { title: "Internal sources", field: "network.srcIp", value: (e) => e.network?.srcIp }]}
            />
          </div>
        ),
        pcap: () => (
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            <Card title="Packet capture" padded={false} info="Full-packet capture runs in Arkime as a separate service; Bloody retrieves session PCAPs as evidence.">
              <IntegrationStatusList engines={["arkime"]} />
            </Card>
            <Card title="Retrieve PCAP as evidence">
              <p className="text-sm text-fg-muted">From an investigation, request a “Collect evidence” action on the host or register an Arkime session as external evidence (arkime://…). The PCAP's SHA-256 starts its chain of custody.</p>
              <div className="mt-3 flex gap-2">
                <ButtonLink to="/investigations" size="sm" icon={HardDrive}>
                  Investigations
                </ButtonLink>
                <ButtonLink to="/dfir/evidence" size="sm">
                  Evidence locker
                </ButtonLink>
              </div>
            </Card>
          </div>
        ),
        sensors: () => (
          <div className="space-y-4">
            <SummaryWidgets widgets={[NetworkHealthWidget]} columns={2} />
            <Card title="Network sensors" padded={false} info="Health, last sync and 24h volume of every network sensor connection.">
              <IntegrationStatusList engines={["zeek", "suricata", "arkime"]} />
            </Card>
          </div>
        ),
      }}
    />
  );
}
