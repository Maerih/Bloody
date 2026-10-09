import { ClipboardCheck, CircleX, PlayCircle, ShieldAlert, Workflow } from "lucide-react";
import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { usePlaybooks, useResponseActions } from "../../api/hooks";
import { ButtonLink } from "../../components/Button";
import { StatTile } from "../../components/StatTile";
import { KpiGrid, ModuleWorkspace } from "../../features/modules/ModuleWorkspace";
import { SummaryWidgets } from "../../features/modules/SummaryWidgets";
import { ResponseActionsTable } from "../../features/response/ResponseActionsTable";
import { PlaybooksView } from "../../features/soar/PlaybooksView";
import { AutomationRulesView } from "../automation/AutomationRulesPage";
import { NotificationChannelsView } from "../automation/NotificationChannelsPage";
import { AiActivityWidget, AutomationWidget } from "../command-center/widgets";

function ApprovalQueue({ selectedId, showDecided = true }: { selectedId?: string | null; showDecided?: boolean }) {
  const actions = useResponseActions({ limit: 200 }, { refetchIntervalMs: 30_000 });
  const pending = useMemo(() => actions.data?.items.filter((a) => a.status === "pending_approval"), [actions.data]);
  const decided = useMemo(() => actions.data?.items.filter((a) => a.status !== "pending_approval" && a.approvedBy !== null).slice(0, 50), [actions.data]);
  return (
    <div className="space-y-4">
      <div>
        <h2 className="mb-1 text-md font-semibold text-fg">Pending approvals</h2>
        <p className="mb-2 text-sm text-fg-muted">High-risk actions requested by analysts, playbooks or the AI analyst. A different person holding response:approve must decide; the requester never can.</p>
        <ResponseActionsTable
          rows={pending}
          loading={actions.isPending}
          error={actions.error}
          onRetry={() => void actions.refetch()}
          selectedId={selectedId}
          emptyTitle="No action is waiting for approval"
          emptyDescription="Isolate, block, disable identity and revoke actions appear here until a second approver decides."
          savedViewsKey="soar-approvals"
          exportFileName="bloody-pending-approvals"
        />
      </div>
      {showDecided ? (
        <div>
          <h2 className="mb-2 text-md font-semibold text-fg">Recent decisions</h2>
          <ResponseActionsTable rows={decided} loading={actions.isPending} error={actions.error} emptyTitle="No approval decisions yet" savedViewsKey="soar-decided" exportFileName="bloody-approval-decisions" />
        </div>
      ) : null}
    </div>
  );
}

function SoarOverview() {
  const playbooks = usePlaybooks();
  const actions = useResponseActions({ limit: 200 }, { refetchIntervalMs: 30_000 });
  const items = actions.data?.items;
  const pending = items?.filter((a) => a.status === "pending_approval").length;
  const failed = items?.filter((a) => a.status === "failed").length;
  const viaPlaybook = useMemo(() => items?.filter((a) => a.requestedVia === "playbook"), [items]);
  const enabled = playbooks.data?.items.filter((p) => p.enabled).length;
  return (
    <div className="space-y-4">
      <KpiGrid>
        <StatTile label="Playbooks" value={playbooks.data?.items.length} loading={playbooks.isPending} icon={Workflow} href="/soar/playbooks" hint={enabled !== undefined ? `${enabled} active` : undefined} />
        <StatTile label="Pending approvals" value={pending} loading={actions.isPending} icon={ClipboardCheck} tone={(pending ?? 0) > 0 ? "high" : "healthy"} href="/soar/approvals" />
        <StatTile label="Playbook actions" value={viaPlaybook?.length} loading={actions.isPending} icon={PlayCircle} href="/soar/actions" hint="Recent executions" />
        <StatTile label="Failed actions" value={failed} loading={actions.isPending} icon={CircleX} tone={(failed ?? 0) > 0 ? "critical" : "healthy"} href="/soar/actions" />
      </KpiGrid>
      <SummaryWidgets widgets={[AutomationWidget, AiActivityWidget]} columns={2} />
      <ApprovalQueue showDecided={false} />
      <div>
        <h2 className="mb-2 text-md font-semibold text-fg">Playbook executions</h2>
        <ResponseActionsTable rows={viaPlaybook} loading={actions.isPending} error={actions.error} onRetry={() => void actions.refetch()} emptyTitle="No playbook has executed an action yet" savedViewsKey="soar-playbook-runs" exportFileName="bloody-playbook-executions" />
      </div>
    </div>
  );
}

function ExecutionLog({ selectedId }: { selectedId: string | null }) {
  const actions = useResponseActions({ limit: 500 }, { refetchIntervalMs: 30_000 });
  return (
    <div className="space-y-2">
      <p className="text-sm text-fg-muted">Every response action — requested by an analyst, a playbook or the AI analyst — with its approval, executor and result. Filter by status, risk or origin in the column headers.</p>
      <ResponseActionsTable rows={actions.data?.items} loading={actions.isPending} error={actions.error} onRetry={() => void actions.refetch()} selectedId={selectedId} emptyTitle="No response actions yet" savedViewsKey="soar-actions" exportFileName="bloody-response-actions" />
    </div>
  );
}

/** SOAR workspace: playbooks (visual editor), approval queue, execution log, automation rules, channels. */
export default function SoarPage() {
  const [params] = useSearchParams();
  const id = params.get("id");
  return (
    <ModuleWorkspace
      moduleId="soar"
      actions={
        <ButtonLink size="sm" icon={ShieldAlert} to="/soar/approvals">
          Approval queue
        </ButtonLink>
      }
      sections={{
        "": () => <SoarOverview />,
        playbooks: () => <PlaybooksView initialId={id} />,
        approvals: () => <ApprovalQueue selectedId={id} />,
        actions: () => <ExecutionLog selectedId={id} />,
        automations: () => <AutomationRulesView />,
        channels: () => <NotificationChannelsView />,
      }}
    />
  );
}
