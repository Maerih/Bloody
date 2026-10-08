import type { Playbook } from "@bloody/contracts";
import { ChevronRight, Plus, ShieldAlert, Workflow } from "lucide-react";
import { useMemo, useState } from "react";
import { usePlaybooks } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge, StatusBadge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { EmptyState } from "../../components/EmptyState";
import { CONDITION_OP_LABELS, conditionValueText } from "../../lib/conditions";
import { describeCron } from "../../lib/format";
import { TRIGGER_LABELS, actionLabelOf, isHighRisk } from "../../lib/playbooks";
import { PlaybookEditor } from "./PlaybookEditor";

function StepChain({ playbook }: { playbook: Playbook }) {
  return (
    <span className="flex flex-wrap items-center gap-0.5">
      {playbook.steps.map((s, i) => (
        <span key={s.id} className="inline-flex items-center gap-0.5">
          {i > 0 ? <ChevronRight size={11} className="text-fg-subtle" aria-hidden /> : null}
          <Badge size="xs" tone={isHighRisk(s.action) ? "danger" : s.requireApproval ? "warning" : "neutral"} icon={isHighRisk(s.action) || s.requireApproval ? ShieldAlert : undefined}>
            {actionLabelOf(s.action)}
          </Badge>
        </span>
      ))}
    </span>
  );
}

/** SOAR playbooks (organization and global) with the visual editor. `library`: global ones only. */
export function PlaybooksView({ library = false, initialId = null }: { library?: boolean; initialId?: string | null }) {
  const session = useSession();
  const playbooks = usePlaybooks();
  const [editing, setEditing] = useState<Playbook | "new" | null>(null);
  const [initialDismissed, setInitialDismissed] = useState(false);
  const rows = useMemo(() => playbooks.data?.items.filter((p) => !library || p.organizationId === null), [playbooks.data, library]);
  const initial = initialId && !initialDismissed ? rows?.find((p) => p.id === initialId) : undefined;
  const open = editing ?? initial ?? null;
  const canWrite = session.canAnywhere("playbook:write");

  const columns: DataTableColumn<Playbook>[] = [
    { id: "name", header: "Playbook", accessor: (p) => p.name, hideable: false, cell: (p) => <span><span className="block font-medium text-heading">{p.name}</span>{p.description ? <span className="block max-w-[360px] truncate text-xs text-fg-subtle">{p.description}</span> : null}</span> },
    { id: "trigger", header: "Trigger", accessor: (p) => TRIGGER_LABELS[p.trigger.on], cell: (p) => <span>{TRIGGER_LABELS[p.trigger.on]}{p.trigger.on === "schedule" && p.trigger.cron ? <span className="block text-2xs text-fg-subtle">{describeCron(p.trigger.cron)}</span> : null}</span> },
    {
      id: "conditions",
      header: "Conditions",
      accessor: (p) => p.conditions.map((c) => `${c.field} ${c.op} ${conditionValueText(c.value)}`).join("; "),
      cell: (p) => (p.conditions.length === 0 ? <span className="text-fg-subtle">Always</span> : <span className="font-mono text-xs">{p.conditions.map((c) => `${c.field} ${CONDITION_OP_LABELS[c.op]}${c.op === "exists" ? "" : ` ${conditionValueText(c.value)}`}`).join(" AND ")}</span>),
    },
    { id: "steps", header: "Steps", accessor: (p) => p.steps.length, cell: (p) => <StepChain playbook={p} /> },
    { id: "approvals", header: "Approval gates", accessor: (p) => p.steps.filter((s) => s.requireApproval || isHighRisk(s.action)).length, align: "right" },
    { id: "scope", header: "Scope", accessor: (p) => (p.organizationId ? (session.organizationName(p.organizationId) ?? "Organization") : "Global") },
    { id: "version", header: "Version", accessor: (p) => p.version, align: "right", cell: (p) => `v${p.version}` },
    { id: "enabled", header: "State", accessor: (p) => (p.enabled ? "active" : "paused"), cell: (p) => (p.enabled ? <StatusBadge status="active" size="xs" /> : <Badge size="xs">Paused</Badge>) },
  ];

  return (
    <>
      <DataTable
        caption="Playbooks"
        columns={columns}
        rows={rows}
        getRowId={(p) => p.id}
        loading={playbooks.isPending}
        error={playbooks.error}
        onRetry={() => void playbooks.refetch()}
        onRowClick={(p) => setEditing(p)}
        initialState={{ sort: { columnId: "name", direction: "asc" } }}
        savedViewsKey={library ? "playbook-library" : "playbooks"}
        exportFileName="bloody-playbooks"
        toolbar={
          canWrite ? (
            <Button size="sm" variant="primary" icon={Plus} onClick={() => setEditing("new")}>
              New playbook
            </Button>
          ) : null
        }
        emptyState={
          <EmptyState
            icon={Workflow}
            title={library ? "No global playbooks yet" : "No playbooks yet"}
            description={library ? "Global playbooks apply to every organization unless an organization overrides them." : "Automate triage and containment: trigger → conditions → steps, with approval gates for high-risk actions."}
            action={canWrite ? <Button size="sm" variant="primary" icon={Plus} onClick={() => setEditing("new")}>New playbook</Button> : undefined}
          />
        }
      />
      {open ? (
        <PlaybookEditor
          key={open === "new" ? "new" : open.id}
          playbook={open === "new" ? null : open}
          onClose={() => {
            setEditing(null);
            setInitialDismissed(true);
          }}
        />
      ) : null}
    </>
  );
}
