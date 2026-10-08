import { RESPONSE_ACTIONS, actionRisk, type ResponseActionRecord } from "@bloody/contracts";
import { Check, ShieldAlert, X } from "lucide-react";
import { useState } from "react";
import { errorMessage } from "../../api/client";
import { useApproveResponseAction, useRejectResponseAction } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge, StatusBadge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { DescriptionList } from "../../components/DescriptionList";
import { EmptyState } from "../../components/EmptyState";
import { Field, Textarea } from "../../components/Form";
import { JsonView } from "../../components/JsonView";
import { Dialog } from "../../components/Overlay";
import { RelativeTime } from "../../components/RelativeTime";
import { formatDateTime, humanize } from "../../lib/format";

const RISK_TONE = { low: "success", medium: "warning", high: "danger" } as const;

export function actionLabel(key: string): string {
  return RESPONSE_ACTIONS.find((a) => a.key === key)?.label ?? humanize(key);
}

/** "user:<id>" / "<id>" → whether the record was requested by this principal (four-eyes rule). */
export function isOwnRequest(record: Pick<ResponseActionRecord, "requestedBy">, principalId: string): boolean {
  return record.requestedBy === principalId || record.requestedBy.endsWith(`:${principalId}`);
}

/** Approve / reject with a comment. The requester can never approve their own action. */
export function ApprovalDialog({ record, decision, onClose }: { record: ResponseActionRecord; decision: "approve" | "reject"; onClose: () => void }) {
  const approve = useApproveResponseAction();
  const reject = useRejectResponseAction();
  const m = decision === "approve" ? approve : reject;
  const [comment, setComment] = useState("");
  const risk = actionRisk(record.action);
  const needsComment = decision === "reject";
  const valid = !needsComment || comment.trim().length >= 3;
  return (
    <Dialog
      open
      onClose={onClose}
      title={decision === "approve" ? "Approve response action" : "Reject response action"}
      description="Your decision is attributed to you and recorded in the audit log."
      footer={
        m.isSuccess ? (
          <span role="status" className="mr-auto text-sm text-healthy">
            {decision === "approve" ? "Approved — handed to the executor." : "Rejected."}
          </span>
        ) : (
          <>
            {m.isError ? (
              <span role="alert" className="mr-auto text-sm text-sev-critical">
                {errorMessage(m.error)}
              </span>
            ) : null}
            <Button onClick={onClose}>Cancel</Button>
            <Button
              variant={decision === "approve" ? (risk === "high" ? "danger" : "primary") : "secondary"}
              icon={decision === "approve" ? Check : X}
              loading={m.isPending}
              disabled={!valid}
              onClick={() => m.mutate({ id: record.id, ...(comment.trim() ? { comment: comment.trim() } : {}) }, { onSuccess: () => setTimeout(onClose, 700) })}
            >
              {decision === "approve" ? "Approve & execute" : "Reject"}
            </Button>
          </>
        )
      }
    >
      <div className="space-y-3">
        {risk === "high" && decision === "approve" ? (
          <p className="flex items-start gap-2 rounded border border-sev-critical/30 bg-sev-critical/5 p-2 text-sm">
            <ShieldAlert size={14} className="mt-0.5 shrink-0 text-sev-critical" aria-hidden />
            This is a high-risk action. Confirm the target and the business impact before approving.
          </p>
        ) : null}
        <DescriptionList
          items={[
            { label: "Action", value: <span className="font-medium">{actionLabel(record.action)}</span> },
            { label: "Risk", value: <Badge tone={RISK_TONE[risk]}>{risk}</Badge> },
            { label: "Target", value: `${record.target.label ?? record.target.id} (${record.target.kind})` },
            { label: "Requested", value: `${formatDateTime(record.createdAt)} via ${record.requestedVia}` },
            { label: "Requested by", value: record.requestedBy },
            { label: "Reason", value: record.reason, wide: true },
          ]}
        />
        {Object.keys(record.parameters ?? {}).length > 0 ? <JsonView value={record.parameters} maxHeight="8rem" /> : null}
        <Field label={needsComment ? "Reason for rejection" : "Comment (optional)"} required={needsComment} error={needsComment && comment.length > 0 && !valid ? "At least 3 characters" : null}>
          {(p) => <Textarea {...p} value={comment} maxLength={2000} onChange={(e) => setComment(e.target.value)} />}
        </Field>
      </div>
    </Dialog>
  );
}

/**
 * Response actions with the approval gate: pending high-risk actions show Approve / Reject to
 * users holding `response:approve` for the action's organization — never to the requester.
 */
export function ResponseActionsTable({
  rows,
  loading,
  error,
  onRetry,
  emptyTitle = "No response actions",
  emptyDescription,
  selectedId,
  savedViewsKey,
  exportFileName,
}: {
  rows: ResponseActionRecord[] | undefined;
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  emptyTitle?: string;
  emptyDescription?: string;
  selectedId?: string | null;
  savedViewsKey?: string;
  exportFileName?: string;
}) {
  const session = useSession();
  const [decision, setDecision] = useState<{ record: ResponseActionRecord; decision: "approve" | "reject" } | null>(null);
  const [detail, setDetail] = useState<ResponseActionRecord | null>(null);

  const columns: DataTableColumn<ResponseActionRecord>[] = [
    { id: "action", header: "Action", accessor: (a) => actionLabel(a.action), hideable: false, cell: (a) => <span className="font-medium text-heading">{actionLabel(a.action)}</span> },
    { id: "risk", header: "Risk", accessor: (a) => actionRisk(a.action), cell: (a) => <Badge size="xs" tone={RISK_TONE[actionRisk(a.action)]}>{actionRisk(a.action)}</Badge>, filter: { kind: "select", options: ["low", "medium", "high"].map((r) => ({ value: r, label: humanize(r) })) } },
    { id: "target", header: "Target", accessor: (a) => a.target.label ?? a.target.id },
    { id: "status", header: "Status", accessor: (a) => a.status, cell: (a) => <StatusBadge status={a.status} size="xs" />, filter: { kind: "select", options: ["pending_approval", "approved", "rejected", "queued", "running", "succeeded", "failed", "cancelled"].map((s) => ({ value: s, label: humanize(s) })) } },
    { id: "via", header: "Via", accessor: (a) => a.requestedVia, cell: (a) => <Badge size="xs" tone="outline">{a.requestedVia}</Badge>, filter: { kind: "select", options: ["user", "playbook", "ai"].map((v) => ({ value: v, label: v })) } },
    { id: "org", header: "Organization", accessor: (a) => session.organizationName(a.organizationId) ?? a.organizationId, defaultHidden: session.organizationId !== null },
    { id: "reason", header: "Reason", accessor: (a) => a.reason, cell: (a) => <span className="line-clamp-1 max-w-[280px] text-fg-muted" title={a.reason}>{a.reason}</span> },
    { id: "requested", header: "Requested", accessor: (a) => new Date(a.createdAt), cell: (a) => <RelativeTime value={a.createdAt} /> },
    {
      id: "decision",
      header: "Approval",
      exportable: false,
      sortable: false,
      cell: (a) => {
        if (a.status !== "pending_approval") return a.approvedBy ? <span className="text-xs text-fg-muted">by {a.approvedBy}</span> : null;
        if (!session.can("response:approve", a.organizationId)) return <span className="text-xs text-fg-subtle">Awaiting approver</span>;
        if (isOwnRequest(a, session.principal.id)) return <span className="text-xs text-fg-subtle" title="Four-eyes rule: another approver must decide">Requested by you</span>;
        return (
          <span className="flex gap-1" onClick={(e) => e.stopPropagation()}>
            <Button size="xs" variant="success" icon={Check} onClick={() => setDecision({ record: a, decision: "approve" })}>
              Approve
            </Button>
            <Button size="xs" icon={X} onClick={() => setDecision({ record: a, decision: "reject" })}>
              Reject
            </Button>
          </span>
        );
      },
    },
  ];

  return (
    <>
      <DataTable
        caption="Response actions"
        columns={columns}
        rows={rows}
        getRowId={(a) => a.id}
        loading={loading}
        error={error}
        onRetry={onRetry}
        onRowClick={setDetail}
        selectedRowId={selectedId ?? detail?.id ?? null}
        initialState={{ sort: { columnId: "requested", direction: "desc" } }}
        savedViewsKey={savedViewsKey}
        exportFileName={exportFileName}
        emptyState={<EmptyState icon={ShieldAlert} title={emptyTitle} description={emptyDescription} />}
      />
      {decision ? <ApprovalDialog record={decision.record} decision={decision.decision} onClose={() => setDecision(null)} /> : null}
      {detail ? (
        <Dialog open onClose={() => setDetail(null)} title={actionLabel(detail.action)} description={`${detail.target.label ?? detail.target.id} · ${humanize(detail.status)}`} size="lg">
          <div className="space-y-3">
            <DescriptionList
              items={[
                { label: "Status", value: <StatusBadge status={detail.status} /> },
                { label: "Risk", value: actionRisk(detail.action) },
                { label: "Requested via", value: detail.requestedVia },
                { label: "Requested by", value: detail.requestedBy },
                { label: "Approved by", value: detail.approvedBy },
                { label: "Executor", value: detail.executor },
                { label: "Created", value: formatDateTime(detail.createdAt) },
                { label: "Updated", value: formatDateTime(detail.updatedAt) },
                { label: "Reason", value: detail.reason, wide: true },
              ]}
            />
            <div>
              <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-fg-muted">Parameters</h4>
              <JsonView value={detail.parameters} maxHeight="10rem" />
            </div>
            {detail.result !== null && detail.result !== undefined ? (
              <div>
                <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-fg-muted">Result</h4>
                <JsonView value={detail.result} maxHeight="14rem" />
              </div>
            ) : null}
          </div>
        </Dialog>
      ) : null}
    </>
  );
}
