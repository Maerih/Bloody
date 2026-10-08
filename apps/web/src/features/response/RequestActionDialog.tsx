import { RESPONSE_ACTIONS, ResponseActionRequest, actionRisk, type ResponseActionKey } from "@bloody/contracts";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { errorMessage } from "../../api/client";
import { useRequestResponseAction } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { Field, Input, Select, Textarea } from "../../components/Form";
import { Dialog } from "../../components/Overlay";

export type ActionTargetKind = "asset" | "identity" | "indicator" | "incident";

export interface ActionTarget {
  id: string;
  label?: string;
}

const RISK_TONE = { low: "success", medium: "warning", high: "danger" } as const;

interface ParamField {
  key: string;
  label: string;
  placeholder?: string;
  numeric?: boolean;
  hint?: string;
}

/** Action-specific parameters collected before submission (validated server-side again). */
const PARAMS: Partial<Record<ResponseActionKey, { fields: ParamField[]; validate: (p: Record<string, string>) => string | null }>> = {
  kill_process: {
    fields: [
      { key: "pid", label: "Process ID", numeric: true, placeholder: "4242" },
      { key: "processName", label: "Process name", placeholder: "rundll32.exe" },
    ],
    validate: (p) => (p.pid || p.processName ? (p.pid && !/^\d+$/.test(p.pid) ? "PID must be a number" : null) : "Provide a PID or a process name"),
  },
  quarantine_file: {
    fields: [
      { key: "path", label: "File path", placeholder: "C:\\Users\\Public\\payload.dll" },
      { key: "sha256", label: "SHA-256", placeholder: "64 hex characters" },
    ],
    validate: (p) => (p.path || p.sha256 ? (p.sha256 && !/^[0-9a-f]{64}$/i.test(p.sha256) ? "SHA-256 must be 64 hex characters" : null) : "Provide a file path or SHA-256"),
  },
  run_yara_scan: {
    fields: [{ key: "ruleset", label: "YARA ruleset", placeholder: "ransomware-core", hint: "Name of a ruleset deployed to the scanner." }],
    validate: (p) => (p.ruleset ? null : "Choose the YARA ruleset to run"),
  },
  collect_evidence: {
    fields: [{ key: "artifacts", label: "Artifacts", placeholder: "Windows.KapeFiles.Targets, memory", hint: "Comma-separated collection artifacts (empty = default triage set)." }],
    validate: () => null,
  },
  block_ip: { fields: [{ key: "durationHours", label: "Block for (hours)", numeric: true, placeholder: "empty = until removed" }], validate: (p) => (p.durationHours && !/^\d+$/.test(p.durationHours) ? "Duration must be whole hours" : null) },
  block_domain: { fields: [{ key: "durationHours", label: "Block for (hours)", numeric: true, placeholder: "empty = until removed" }], validate: (p) => (p.durationHours && !/^\d+$/.test(p.durationHours) ? "Duration must be whole hours" : null) },
};

function buildParameters(action: ResponseActionKey, values: Record<string, string>): Record<string, unknown> {
  const spec = PARAMS[action];
  if (!spec) return {};
  const out: Record<string, unknown> = {};
  for (const f of spec.fields) {
    const v = values[f.key]?.trim();
    if (!v) continue;
    if (f.key === "artifacts") out.artifacts = v.split(",").map((s) => s.trim()).filter(Boolean);
    else out[f.key] = f.numeric ? Number(v) : v;
  }
  return out;
}

export interface RequestActionDialogProps {
  open: boolean;
  onClose: () => void;
  organizationId: string;
  incidentId?: string;
  /** Candidate targets per kind (e.g. the incident's assets and identities). */
  targets?: Partial<Record<ActionTargetKind, ActionTarget[]>>;
  /** Restrict the offered actions (e.g. only isolate/release for an endpoint row). */
  actions?: ResponseActionKey[];
  defaultAction?: ResponseActionKey;
  /** Prefill for indicator actions (block IP / domain). */
  indicatorValue?: string;
  description?: string;
  onSubmitted?: () => void;
}

/**
 * Request a SOAR response action. Every request is attributed and audited; high-risk actions
 * (isolate, block, disable identity, revoke) always wait in the approval queue for a second
 * person holding `response:approve`.
 */
export function RequestActionDialog({ open, onClose, organizationId, incidentId, targets = {}, actions, defaultAction, indicatorValue = "", description, onSubmitted }: RequestActionDialogProps) {
  const session = useSession();
  const request = useRequestResponseAction();
  const offered = useMemo(() => RESPONSE_ACTIONS.filter((a) => !actions || actions.includes(a.key)), [actions]);
  const [action, setAction] = useState<ResponseActionKey>(defaultAction ?? offered[0]?.key ?? "collect_evidence");
  const [targetId, setTargetId] = useState("");
  const [indicator, setIndicator] = useState(indicatorValue);
  const [reason, setReason] = useState("");
  const [params, setParams] = useState<Record<string, string>>({});
  const [submitted, setSubmitted] = useState(false);

  const def = RESPONSE_ACTIONS.find((a) => a.key === action)!;
  const risk = actionRisk(action);
  const list = def.target === "indicator" ? [] : (targets[def.target] ?? []);
  const effectiveTarget = def.target === "indicator" ? indicator.trim() : (list.find((t) => t.id === targetId) ?? list[0])?.id ?? "";
  const targetLabel = def.target === "indicator" ? indicator.trim() : list.find((t) => t.id === effectiveTarget)?.label;
  const spec = PARAMS[action];
  const paramError = spec ? spec.validate(params) : null;

  const payload = {
    action,
    organizationId,
    ...(incidentId ? { incidentId } : {}),
    target: { kind: def.target, id: effectiveTarget, ...(targetLabel ? { label: targetLabel } : {}) },
    parameters: buildParameters(action, params),
    reason: reason.trim(),
  };
  const parsed = ResponseActionRequest.safeParse(payload);
  const errors = {
    target: effectiveTarget ? null : def.target === "indicator" ? "Enter the IP address or domain" : `No ${def.target} available for this action`,
    reason: reason.trim().length >= 3 ? null : "Explain why this action is needed (min. 3 characters)",
  };
  const canRequest = session.can("response:request", organizationId);

  const submit = () => {
    setSubmitted(true);
    if (!canRequest || !parsed.success || errors.target || errors.reason || paramError) return;
    request.mutate(payload, {
      onSuccess: () => {
        onSubmitted?.();
        setTimeout(onClose, 900);
      },
    });
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Request response action"
      description={description ?? "Requests are attributed to you and recorded in the audit log."}
      footer={
        request.isSuccess ? (
          <span role="status" className="mr-auto text-sm text-healthy">
            {request.data?.status === "pending_approval" ? "Submitted — waiting in the approval queue." : "Action submitted."}
          </span>
        ) : (
          <>
            {request.isError ? (
              <span role="alert" className="mr-auto text-sm text-sev-critical">
                {errorMessage(request.error)}
              </span>
            ) : !canRequest ? (
              <span className="mr-auto text-sm text-fg-muted">You don't have permission to request response actions here.</span>
            ) : null}
            <Button onClick={onClose}>Cancel</Button>
            <Button variant={risk === "high" ? "danger" : "primary"} onClick={submit} loading={request.isPending} disabled={!canRequest}>
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
                setParams({});
              }}
            >
              {(["low", "medium", "high"] as const).map((r) => {
                const group = offered.filter((a) => a.risk === r);
                return group.length === 0 ? null : (
                  <optgroup key={r} label={`${r[0]!.toUpperCase()}${r.slice(1)} risk`}>
                    {group.map((a) => (
                      <option key={a.key} value={a.key}>
                        {a.label}
                      </option>
                    ))}
                  </optgroup>
                );
              })}
            </Select>
          )}
        </Field>
        <div className="flex items-center gap-2 text-sm">
          <Badge tone={RISK_TONE[risk]}>{risk} risk</Badge>
          <span className="text-fg-muted">Target: {def.target}</span>
        </div>
        {risk === "high" ? (
          <p className="flex items-start gap-2 rounded border border-sev-critical/30 bg-sev-critical/5 p-2 text-sm text-fg" data-testid="approval-gate">
            <ShieldAlert size={14} className="mt-0.5 shrink-0 text-sev-critical" aria-hidden />
            Approval gate: high-risk actions are never executed directly. They wait in the approval queue until a different user with the response-approval permission approves them.
          </p>
        ) : (
          <p className="flex items-start gap-2 rounded border border-line bg-surface-2 p-2 text-sm text-fg-muted">
            <ShieldCheck size={14} className="mt-0.5 shrink-0 text-healthy" aria-hidden />
            Low/medium-risk actions run once submitted if your role may execute them; otherwise they are queued for approval.
          </p>
        )}
        {def.target === "indicator" ? (
          <Field label={action === "block_domain" ? "Domain" : "IP address"} required error={submitted ? errors.target : null}>
            {(p) => <Input {...p} value={indicator} onChange={(e) => setIndicator(e.target.value)} placeholder={action === "block_domain" ? "evil.example" : "203.0.113.10"} />}
          </Field>
        ) : (
          <Field label="Target" required error={submitted ? errors.target : null}>
            {(p) => (
              <Select {...p} value={effectiveTarget} onChange={(e) => setTargetId(e.target.value)} disabled={list.length === 0}>
                {list.length === 0 ? <option value="">No {def.target}s available</option> : null}
                {list.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.label ?? t.id}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}
        {spec
          ? spec.fields.map((f) => (
              <Field key={f.key} label={f.label} hint={f.hint}>
                {(p) => <Input {...p} value={params[f.key] ?? ""} inputMode={f.numeric ? "numeric" : undefined} placeholder={f.placeholder} onChange={(e) => setParams((cur) => ({ ...cur, [f.key]: e.target.value }))} />}
              </Field>
            ))
          : null}
        {submitted && paramError ? (
          <p role="alert" className="text-xs text-sev-critical">
            {paramError}
          </p>
        ) : null}
        <Field label="Reason" required error={submitted ? errors.reason : null} hint="Recorded in the audit log and shown to approvers.">
          {(p) => <Textarea {...p} value={reason} maxLength={2000} onChange={(e) => setReason(e.target.value)} />}
        </Field>
      </div>
    </Dialog>
  );
}
