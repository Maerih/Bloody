import { AgentStatus, RESPONSE_ACTIONS, type Agent, type Alert } from "@bloody/contracts";
import { ShieldAlert, ShieldCheck, Workflow } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { useResponseActions } from "../../api/hooks";
import { Badge } from "../../components/Badge";
import { ButtonLink } from "../../components/Button";
import { Card } from "../../components/Card";
import { AgentsTable } from "../../features/agents/AgentsTable";
import { AlertsLens } from "../../features/alerts/AlertsLens";
import { AssetsTable } from "../../features/assets/AssetsTable";
import { EventsLens } from "../../features/events/EventsLens";
import { ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { SummaryWidgets } from "../../features/modules/SummaryWidgets";
import { ResponseActionsTable } from "../../features/response/ResponseActionsTable";
import { hasTechnique, PERSISTENCE_TECHNIQUES } from "../../lib/classify";
import { AgentsWidget, AntivirusWidget, FirewallWidget } from "../command-center/widgets";

const ENDPOINT_ENGINES = ["wazuh", "velociraptor", "osquery"];
const LIVE_ACTIONS = ["collect_evidence", "run_yara_scan", "kill_process", "quarantine_file"] as const;
const AV_STATES: Agent["antivirusStatus"][] = ["protected", "unhealthy", "unmanaged", "incompatible"];

const isEndpointAlert = (a: Alert) => a.assetId !== null;
const isPersistence = (a: Alert) => hasTechnique(a, PERSISTENCE_TECHNIQUES, "persistence");
const isMalware = (a: Alert) => /malware|virus|trojan|defender|antivirus|quarantin|ransom/i.test(`${a.title} ${a.ruleId ?? ""}`) || hasTechnique(a, ["T1486", "T1204"]);
const isRansomware = (a: Alert) => hasTechnique(a, ["T1486", "T1490"]) || /ransom|canary|mass[\s_-]?(encrypt|rename)/i.test(`${a.title} ${a.ruleId ?? ""}`);

function LiveResponse() {
  const actions = useResponseActions({ limit: 200 });
  const rows = actions.data?.items.filter((a) => (LIVE_ACTIONS as readonly string[]).includes(a.action) || a.action === "isolate_endpoint" || a.action === "release_endpoint");
  return (
    <div className="space-y-4">
      <AgentsTable mode="live-response" engines={["velociraptor", "wazuh"]} savedViewsKey="edr-live-response" />
      <div>
        <h2 className="mb-2 text-md font-semibold text-fg">Endpoint response log</h2>
        <ResponseActionsTable rows={rows} loading={actions.isPending} error={actions.error} onRetry={() => void actions.refetch()} emptyTitle="No endpoint response actions yet" savedViewsKey="edr-response-log" exportFileName="bloody-endpoint-response" />
      </div>
    </div>
  );
}

function EndpointPolicies() {
  const endpointActions = RESPONSE_ACTIONS.filter((a) => a.target === "asset");
  return (
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
      <Card title="Response approval policy" info="Enforced server-side: high-risk endpoint actions always pass an approval gate (four-eyes) and are audited.">
        <ul className="divide-y divide-line">
          {endpointActions.map((a) => (
            <li key={a.key} className="flex items-center gap-2 py-1.5 text-sm">
              <span className="flex-1">{a.label}</span>
              <Badge size="xs" tone={a.risk === "high" ? "danger" : a.risk === "medium" ? "warning" : "success"}>
                {a.risk} risk
              </Badge>
              {a.risk === "high" ? (
                <Badge size="xs" tone="warning" icon={ShieldAlert}>
                  Approval required
                </Badge>
              ) : (
                <Badge size="xs" icon={ShieldCheck}>
                  Executes with response:execute
                </Badge>
              )}
            </li>
          ))}
        </ul>
      </Card>
      <Card title="Automated containment" info="Containment and collection run from SOAR playbooks (trigger → conditions → steps) with the same approval gates.">
        <p className="text-sm text-fg-muted">Detection, isolation and collection behaviour is defined as versioned playbooks and detection rules, so every change is reviewed, audited and reversible.</p>
        <div className="mt-3 flex flex-wrap gap-2">
          <ButtonLink to="/soar/playbooks" size="sm" icon={Workflow}>
            Endpoint playbooks
          </ButtonLink>
          <ButtonLink to="/siem/detections" size="sm">
            Endpoint detection rules
          </ButtonLink>
          <ButtonLink to="/soar/approvals" size="sm">
            Approval queue
          </ButtonLink>
        </div>
      </Card>
    </div>
  );
}

/** EDR workspace: endpoint fleet & containment, detections, process insights, persistence, AV, canaries. */
export default function EdrPage() {
  const [params] = useSearchParams();
  const avStatus = AV_STATES.find((s) => s === params.get("status"));
  const agentStatus = AgentStatus.options.find((s) => s === params.get("agent"));
  return (
    <ModuleWorkspace
      moduleId="edr"
      sections={{
        "": () => (
          <div className="space-y-4">
            <SummaryWidgets widgets={[AgentsWidget, AntivirusWidget, FirewallWidget]} />
            <AlertsLens title="Endpoint detections" predicate={isEndpointAlert} engines={ENDPOINT_ENGINES} emptyTitle="No endpoint detections" savedViewsKey="edr-alerts" />
            <div>
              <h2 className="mb-2 text-md font-semibold text-fg">Endpoints & agents</h2>
              <AgentsTable mode="containment" filters={agentStatus ? { status: [agentStatus] } : {}} savedViewsKey="edr-agents" />
            </div>
          </div>
        ),
        processes: () => (
          <EventsLens
            title="Process insights"
            query="category:process"
            preset="process"
            processTree
            engines={ENDPOINT_ENGINES}
            description="Process creation telemetry from endpoint agents (Wazuh/Sysmon, osquery, Velociraptor)."
            aggregations={[
              { title: "Top processes", field: "process.name", value: (e) => e.process?.name },
              { title: "Parent processes", field: "process.parent.name", value: (e) => e.process?.parent?.name },
              { title: "Users", field: "process.user", value: (e) => e.process?.user ?? e.user?.name },
            ]}
          />
        ),
        persistence: () => (
          <div className="space-y-4">
            <AlertsLens title="Persistence detections" predicate={isPersistence} engines={ENDPOINT_ENGINES} emptyTitle="No persistence techniques detected" description="Autoruns, services, scheduled tasks, account creation and other ATT&CK persistence techniques." savedViewsKey="edr-persistence" />
            <EventsLens
              title="Autoruns, services & scheduled tasks"
              query="category:registry OR action:(service-install OR scheduled-task-create OR user-create)"
              engines={ENDPOINT_ENGINES}
              defaultRange={{ preset: "7d" }}
              aggregations={[{ title: "Hosts", field: "asset.hostname", value: (e) => e.asset?.hostname }, { title: "Actions", field: "action", value: (e) => e.action }]}
            />
          </div>
        ),
        antivirus: () => (
          <div className="space-y-4">
            <SummaryWidgets widgets={[AntivirusWidget]} columns={2} />
            <AgentsTable mode="none" filters={avStatus ? { antivirusStatus: avStatus } : {}} emptyTitle={avStatus ? `No endpoints with antivirus ${avStatus}` : "No agents reporting antivirus status"} savedViewsKey="edr-antivirus" />
            <AlertsLens title="Malware detections" predicate={isMalware} engines={["wazuh", "yara"]} emptyTitle="No malware detections" savedViewsKey="edr-malware" />
          </div>
        ),
        "ransomware-canaries": () => (
          <div className="space-y-4">
            <AlertsLens title="Ransomware & canary alerts" predicate={isRansomware} engines={["wazuh", "opencanary"]} emptyTitle="No ransomware behaviour or canary trips" description="Canary files trip when encryption or mass-rename behaviour touches them (file-integrity monitoring on canary paths)." savedViewsKey="edr-ransomware" />
            <EventsLens title="Canary file activity" query="category:file AND file.path:*canary*" preset="file" engines={["wazuh"]} defaultRange={{ preset: "30d" }} emptyTitle="No canary file was touched" />
          </div>
        ),
        "external-recon": () => (
          <AssetsTable
            filters={{ internetFacing: true, kind: ["endpoint", "server", "domain_controller"] }}
            engines={["nuclei", "amass"]}
            emptyTitle="No internet-facing endpoints"
            description="Endpoints whose public IPs expose services (RDP, SMB, SSH…) found by authorized external scans."
            savedViewsKey="edr-external"
          />
        ),
        "live-response": () => <LiveResponse />,
        policies: () => <EndpointPolicies />,
      }}
    />
  );
}
