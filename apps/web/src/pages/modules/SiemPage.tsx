import { ENGINES } from "@bloody/contracts";
import { Code2 } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { API_BASE } from "../../api/client";
import { Card } from "../../components/Card";
import { AlertsLens } from "../../features/alerts/AlertsLens";
import { IntegrationStatusList } from "../../features/integrations/IntegrationStatusList";
import { ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { SummaryWidgets } from "../../features/modules/SummaryWidgets";
import { RetentionPanel } from "../../features/settings/RetentionPanel";
import { DetectionRulesView } from "../../features/siem/DetectionRulesView";
import { EventSearchView, SavedSearchesList } from "../../features/siem/EventSearchView";
import { MttrWidget, SocActionsWidget } from "../command-center/widgets";

const SIEM_ENGINES = ENGINES.filter((e) => e.powers.includes("siem") && e.layer !== "storage" && e.layer !== "detection").map((e) => e.key);

function LogSources() {
  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_380px]">
      <Card title="Log sources" padded={false} info="Health, last sync and 24-hour volume per connected source. Parsing failures surface as degraded status with the last error.">
        <IntegrationStatusList engines={SIEM_ENGINES} />
      </Card>
      <Card title="Send events" actions={<Code2 size={14} className="text-fg-muted" aria-hidden />}>
        <div className="space-y-2 text-sm text-fg-muted">
          <p>Collectors (Vector or the OpenTelemetry Collector) forward raw vendor records with an ingestion API key; normalization into the canonical event schema happens server-side.</p>
          <pre className="overflow-x-auto rounded border border-line bg-surface-2 p-2 font-mono text-2xs text-fg">{`POST ${API_BASE}/ingest/<adapter>   # wazuh, zeek, suricata, keycloak…\nPOST ${API_BASE}/ingest/events      # canonical events\nAuthorization: Bearer bk_…`}</pre>
          <p className="text-xs">Create a service API key with the api_service role in Settings → API credentials.</p>
        </div>
      </Card>
    </div>
  );
}

/** SIEM workspace: search, alerts, detection-as-code, saved searches, log sources, retention. */
export default function SiemPage() {
  const [params] = useSearchParams();
  return (
    <ModuleWorkspace
      moduleId="siem"
      sections={{
        "": () => (
          <div className="space-y-4">
            <SummaryWidgets widgets={[SocActionsWidget, MttrWidget]} columns={2} />
            <AlertsLens title="Recent alerts" engines={["wazuh", "suricata", "zeek"]} savedViewsKey="siem-overview-alerts" />
            <Card title="Log source health" padded={false}>
              <IntegrationStatusList engines={SIEM_ENGINES} showUnconfigured={false} />
            </Card>
          </div>
        ),
        search: () => <EventSearchView />,
        alerts: () => <AlertsLens engines={["wazuh", "suricata", "zeek"]} initialAlertId={params.get("id")} savedViewsKey="siem-alerts" />,
        detections: () => <DetectionRulesView initialId={params.get("id")} />,
        saved: () => (
          <Card title="Saved searches" padded={false} info="Saved per user in this browser.">
            <SavedSearchesList />
          </Card>
        ),
        sources: () => <LogSources />,
        retention: () => <RetentionPanel />,
      }}
    />
  );
}
