import type { ResponseActionRecord } from "@bloody/contracts";
import { Check } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useApproveResponseAction, useApprovers, useResponseActions } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Field, Textarea } from "../../components/Form";
import { Dialog } from "../../components/Overlay";

const CONTAINMENT = new Set(["isolate_endpoint", "release_endpoint"]);
const IN_FLIGHT = new Set(["pending_approval", "approved", "queued", "running"]);

/** Latest isolate / release request per asset that still needs attention (in flight or failed). */
export function useContainmentState(enabled: boolean): Map<string, ResponseActionRecord> {
  const actions = useResponseActions({ limit: 200 }, { enabled, refetchIntervalMs: 10_000 });
  return useMemo(() => {
    const latest = new Map<string, ResponseActionRecord>();
    for (const a of actions.data?.items ?? []) {
      if (!CONTAINMENT.has(a.action) || a.target.kind !== "asset") continue;
      const cur = latest.get(a.target.id);
      if (!cur || a.createdAt > cur.createdAt) latest.set(a.target.id, a);
    }
    for (const [k, a] of latest) if (!IN_FLIGHT.has(a.status) && a.status !== "failed") latest.delete(k);
    return latest;
  }, [actions.data]);
}

export const isInFlight = (a: ResponseActionRecord | undefined) => Boolean(a && IN_FLIGHT.has(a.status));

/** Under the agent status: what happened to the last isolate / release request, with approval inline. */
export function ContainmentNote({ record }: { record: ResponseActionRecord }) {
  const session = useSession();
  const [approving, setApproving] = useState(false);
  const verb = record.action === "release_endpoint" ? "Release" : "Isolation";
  const own = record.requestedBy === session.principal.id;
  const canApprove = record.status === "pending_approval" && session.can("response:approve", record.organizationId);
  const approvers = useApprovers(record.organizationId, { enabled: canApprove && own });
  const showApprove = canApprove && (!own || approvers.data?.selfApprovalAllowed === true);
  const error = (record.error as { message?: string } | null)?.message;
  return (
    <div className="mt-1 flex flex-wrap items-center gap-1" onClick={(e) => e.stopPropagation()}>
      {record.status === "pending_approval" ? (
        <>
          <Badge size="xs" tone="warning">{verb} awaiting approval</Badge>
          {showApprove ? (
            <Button size="xs" variant="success" icon={Check} onClick={() => setApproving(true)}>
              Approve
            </Button>
          ) : (
            <Link to="/soar/approvals" className="text-xs text-brand hover:underline" title={own ? "Four-eyes rule: another approver must decide" : undefined}>
              {own ? "Needs another approver" : "Open approvals"}
            </Link>
          )}
        </>
      ) : record.status === "failed" ? (
        <Badge size="xs" tone="danger" title={error}>
          {verb} failed{error ? `: ${error.length > 70 ? `${error.slice(0, 70)}…` : error}` : ""}
        </Badge>
      ) : (
        <Badge size="xs" tone="info">{record.executor === "sciat:agent" ? `${verb} sent to agent…` : `${verb} in progress…`}</Badge>
      )}
      {approving ? <ApproveDialog record={record} sole={own} minJustification={approvers.data?.minJustification ?? 20} onClose={() => setApproving(false)} /> : null}
    </div>
  );
}

function ApproveDialog({ record, sole, minJustification, onClose }: { record: ResponseActionRecord; sole: boolean; minJustification: number; onClose: () => void }) {
  const approve = useApproveResponseAction();
  const [comment, setComment] = useState("");
  const short = sole && comment.trim().length < minJustification;
  return (
    <Dialog
      open
      onClose={onClose}
      title={`Approve: ${record.action === "release_endpoint" ? "release" : "isolate"} ${record.target.label ?? record.target.id}`}
      description={
        sole
          ? "You are the only approver for this organization, so you may approve your own request. Your justification is recorded as a self-approval in the audit log."
          : `Requested by ${record.requestedBy}: ${record.reason}`
      }
      footer={
        approve.isSuccess ? (
          <span role="status" className="mr-auto text-sm text-healthy">
            Approved — {approve.data?.executor === "sciat:agent" ? "sent to the SCIAT Agent." : "handed to the executor."}
          </span>
        ) : (
          <>
            {approve.error ? (
              <span role="alert" className="mr-auto text-sm text-sev-critical">
                {approve.error.message}
              </span>
            ) : null}
            <Button variant="secondary" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="success" icon={Check} disabled={short} loading={approve.isPending} onClick={() => approve.mutate({ id: record.id, comment: comment.trim() || undefined })}>
              Approve &amp; execute
            </Button>
          </>
        )
      }
    >
      <Field label={sole ? `Justification (at least ${minJustification} characters)` : "Comment (optional)"}>
        {(f) => <Textarea {...f} rows={3} value={comment} onChange={(e) => setComment(e.target.value)} maxLength={2000} />}
      </Field>
    </Dialog>
  );
}
