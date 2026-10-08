import { Card } from "../../components/Card";
import { AssetsTable } from "../../features/assets/AssetsTable";
import { EventsLens } from "../../features/events/EventsLens";
import { ScanScopes } from "../../features/integrations/ScanScopes";
import { ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { VulnerabilitiesTable } from "../../features/vulns/VulnerabilitiesTable";

const ASM_ENGINES = ["nuclei", "subfinder", "amass"];
const label = (e: { labels?: Record<string, string> }, key: string) => e.labels?.[key] ?? null;

/** ASM workspace: external assets, exposed services & technologies, certificates, findings, scan scopes. */
export default function AsmPage() {
  return (
    <ModuleWorkspace
      moduleId="asm"
      sections={{
        "": () => (
          <div className="space-y-4">
            <Card title="Scan scope controls" info="Active scanning runs only against authorized targets, inside the configured rate limit, until the authorization expires. Every scan and scope change is audited." padded={false} bodyClassName="p-3">
              <ScanScopes />
            </Card>
            <div>
              <h2 className="mb-2 text-md font-semibold text-fg">External assets</h2>
              <AssetsTable filters={{ internetFacing: true }} engines={ASM_ENGINES} emptyTitle="No internet-facing assets discovered" description="Domains, subdomains, IPs and services discovered by passive and authorized active scanning." savedViewsKey="asm-assets" />
            </div>
          </div>
        ),
        inventory: () => (
          <div className="space-y-6">
            <AssetsTable filters={{ internetFacing: true }} engines={ASM_ENGINES} emptyTitle="No external assets discovered" savedViewsKey="asm-inventory" />
            <EventsLens
              title="Discovered names & addresses"
              query="source.product:(subfinder OR amass OR nuclei)"
              engines={["subfinder", "amass"]}
              defaultRange={{ preset: "30d" }}
              aggregations={[
                { title: "Hostnames & subdomains", field: "asset.hostname", value: (e) => e.asset?.hostname ?? e.network?.httpHost },
                { title: "IP addresses", field: "network.dstIp", value: (e) => e.network?.dstIp ?? e.asset?.ip?.[0] },
              ]}
            />
          </div>
        ),
        services: () => (
          <EventsLens
            title="Exposed services & technologies"
            query="source.product:nuclei"
            preset="web"
            engines={["nuclei"]}
            defaultRange={{ preset: "30d" }}
            aggregations={[
              { title: "Open ports", field: "network.dstPort", value: (e) => (e.network?.dstPort !== undefined ? `${e.network.dstPort}/${e.network.protocol ?? "tcp"}` : null) },
              { title: "Technologies", field: "labels.nuclei.tags", value: (e) => label(e, "nuclei.tags")?.split(",")[0] ?? null },
              { title: "Hosts", field: "network.httpHost", value: (e) => e.network?.httpHost ?? e.asset?.hostname },
            ]}
          />
        ),
        certificates: () => (
          <EventsLens
            title="Certificates & TLS endpoints"
            query="category:tls"
            preset="web"
            engines={["zeek", "nuclei"]}
            defaultRange={{ preset: "30d" }}
            aggregations={[
              { title: "Server names", field: "network.tlsSni", value: (e) => e.network?.tlsSni },
              { title: "Issuers", field: "labels.tls.issuer", value: (e) => label(e, "tls.issuer") ?? label(e, "ssl.issuer") },
            ]}
          />
        ),
        findings: () => (
          <div className="space-y-6">
            <VulnerabilitiesTable filters={{ internetFacing: true }} engines={["nuclei", "greenbone"]} emptyTitle="No findings on internet-facing assets" savedViewsKey="asm-findings" />
            <EventsLens title="Exposure findings (misconfigurations, panels, takeovers)" query="eventType:nuclei.exposure" engines={["nuclei"]} defaultRange={{ preset: "30d" }} aggregations={[{ title: "Templates", field: "detection.ruleName", value: (e) => e.detection?.ruleName }]} />
          </div>
        ),
        scopes: () => <ScanScopes />,
      }}
    />
  );
}
