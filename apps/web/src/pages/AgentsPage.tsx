import { AgentStatus } from "@bloody/contracts";
import { Download } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { useSession } from "../app/session";
import { ButtonLink } from "../components/Button";
import { PageHeader } from "../components/PageHeader";
import { AgentsTable } from "../features/agents/AgentsTable";
import { SummaryWidgets } from "../features/modules/SummaryWidgets";
import { AgentsWidget, AntivirusWidget, FirewallWidget } from "./command-center/widgets";

/** /agents — agent fleet health, versions, antivirus and isolation state with approval-gated isolate / release. */
export default function AgentsPage() {
  const session = useSession();
  const [params] = useSearchParams();
  const status = AgentStatus.options.find((s) => s === params.get("status"));
  return (
    <div>
      <PageHeader
        title="Agents"
        subtitle="Endpoint agents across every organization: health, version, antivirus and firewall state. Isolation and release go through the approval gate."
        actions={
          session.canAnywhere("asset:write") ? (
            <ButtonLink size="sm" icon={Download} to="/agents/download">
              Download agent
            </ButtonLink>
          ) : null
        }
      />
      <SummaryWidgets widgets={[AgentsWidget, AntivirusWidget, FirewallWidget]} />
      <AgentsTable key={status ?? "all"} mode="containment" filters={status ? { status: [status] } : {}} emptyTitle={status ? `No ${status} agents` : "No agents reporting"} savedViewsKey="agents" />
    </div>
  );
}
