import { RESPONSE_ACTIONS, ResponseActionRequest, actionRisk, type ResponseActionKey } from "@bloody/contracts";
import { ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";
import { errorMessage } from "../../api/client";
import { useRequestResponseAction } from "../../api/hooks";
import type { IncidentDetail } from "../../api/types";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Field, Input, Select, Textarea } from "../../components/Form";
import { Dialog } from "../../components/Overlay";

interface TargetOption {
  id: string;
  label: string;
}

const RISK_TONE = { low: "success", medium: "warning", high: "danger" } as const;

/**
 * Request a SOAR response action scoped to an incident. High-risk actions are queued for
 * approval by a user holding `response:approve`; every request is audited server-side.
 */
export function RequestResponseActionDialog({ incident, open, onClose }: { incident: IncidentDetail; open: boolean; onClose: () => void }) {
  const request = useRequestResponseAction();
  const [action, setAction] = useState<ResponseActionKey>("collect_evidence");
  const [targetId, setTargetId] = useState("");
  const [indicator, setIndicator] = useState("");
  const [reason, setReason] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const def = RESPONSE_ACTIONS.find((a) => a.key === action)!;
  const risk = actionRisk(action);

  const targets = useMemo<TargetOption[]>(() => {
    if (def.target === "asset") {
      const embedded = incident.assets?.map((a) => ({ id: a.id, label: a.hostname ?? a.name }));
      return embedded ?? incident.assetIds.map((id) => ({ id, label: id }));
    }
    if (def.target === "identity") {
      const embedded = incident.identities?.map((i) => ({ id: i.id, label: i.displayName ?? i.principal }));
      return embedded ?? incident.identityIds.map((id) => ({ id, label: id }));
    }
    if (def.target === "incident") return [{ id: incident.id, label: `#${incident.number} ${incident.title}` }];
    return [];
  }, [def.target, incident]);

  const effectiveTarget = def.target === "indicator" ? indicator.trim() : (targets.find((t) => t.id === targetId) ?? targets[0])?.id ?? "";
  const targetLabel = def.target === "indicator" ? indicator.trim() : targets.find((t) => t.id === effectiveTarget)?.label;

  const payload = {
    action,
    organizationId: incident.organizationId,
    incidentId: incident.id,
    target: { kind: def.target, id: effectiveTarget, ...(targetLabel ? { label: targetLabel } : {}) },
    parameters: {},
    reason: reason.trim(),
  };
  const parsed = ResponseActionRequest.safeParse(payload);
  const errors = {
    target: effectiveTarget ? null : def.target === "indicator" ? "Enter the IP, domain or hash to block" : `This incident has no linked ${def.target}s`,
    reason: reason.trim().length >= 3 ? null : "Explain why this action is needed (min. 3 characters)",
  };

  const submit = () => {
    setSubmitted(true);
    if (!parsed.success || errors.target || errors.reason) return;
    request.mutate(payload, { onSuccess: () => setTimeout(onClose, 900) });
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Request response action"
      description={`Incident #${incident.number} · requests are audited and attributed to you.`}
      footer={
        request.isSuccess ? (
          <span className="mr-auto text-sm text-healthy">
            {request.data?.status === "pending_approval" ? "Submitted — awaiting approval." : "Action submitted."}
          </span>
        ) : (
          <>
            {request.isError ? (
              <span role="alert" className="mr-auto text-sm text-sev-critical">
                {errorMessage(request.error)}
              </span>
            ) : null}
            <Button onClick={onClose}>Cancel</Button>
            <Button variant={risk === "high" ? "danger" : "primary"} onClick={submit} loading={request.isPending}>
              {risk === "high" ? "Request approval" : "Submit action"}
            </Button>
          </>
        )
      }
    >
      <div className="space-y-3">
        <Field label="Action" required>
          {(p) => (
            <Select
              {...p}
              value={action}
              onChange={(e) => {
                setAction(e.target.value as ResponseActionKey);
                setTargetId("");
              }}
            >
              {(["low", "medium", "high"] as const).map((r) => (
                <optgroup key={r} label={`${r[0]!.toUpperCase()}${r.slice(1)} risk`}>
                  {RESPONSE_ACTIONS.filter((a) => a.risk === r).map((a) => (
                    <option key={a.key} value={a.key}>
                      {a.label}
                    </option>
                  ))}
                </optgroup>
              ))}
            </Select>
          )}
        </Field>
        <div className="flex items-center gap-2 text-sm">
          <Badge tone={RISK_TONE[risk]}>{risk} risk</Badge>
          <span className="text-fg-muted">Target: {def.target}</span>
        </div>
        {risk === "high" ? (
          <p className="flex items-start gap-2 rounded border border-sev-critical/30 bg-sev-critical/5 p-2 text-sm text-fg">
            <ShieldAlert size={14} className="mt-0.5 shrink-0 text-sev-critical" aria-hidden />
            High-risk actions are never executed directly: they wait in the approval queue for a user with the response-approval permission.
          </p>
        ) : null}
        {def.target === "indicator" ? (
          <Field label="Indicator" required error={submitted ? errors.target : null}>
            {(p) => <Input {...p} value={indicator} onChange={(e) => setIndicator(e.target.value)} placeholder="203.0.113.10 or evil.example" />}
          </Field>
        ) : (
          <Field label="Target" required error={submitted ? errors.target : null}>
            {(p) => (
              <Select {...p} value={effectiveTarget} onChange={(e) => setTargetId(e.target.value)} disabled={targets.length === 0}>
                {targets.length === 0 ? <option value="">No linked {def.target}s</option> : null}
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.label}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}
        <Field label="Reason" required error={submitted ? errors.reason : null} hint="Recorded in the audit log and shown to approvers.">
          {(p) => <Textarea {...p} value={reason} maxLength={2000} onChange={(e) => setReason(e.target.value)} />}
        </Field>
      </div>
    </Dialog>
  );
}
