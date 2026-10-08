import { RESPONSE_ACTIONS, type Playbook, type ResponseActionKey } from "@bloody/contracts";
import { clsx } from "clsx";
import { ArrowDown, ArrowUp, CircleStop, Filter, Plus, ShieldAlert, Trash2, Zap, type LucideIcon } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { errorMessage } from "../../api/client";
import { useSavePlaybook } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge } from "../../components/Badge";
import { Button, IconButton } from "../../components/Button";
import { Checkbox, Field, Input, Select, Textarea } from "../../components/Form";
import { OrganizationSelect, useDefaultOrganization } from "../../components/OrganizationSelect";
import { Drawer } from "../../components/Overlay";
import { CONDITION_OPS, CONDITION_OP_LABELS, type ConditionOp } from "../../lib/conditions";
import { describeCron } from "../../lib/format";
import { TRIGGERS, TRIGGER_LABELS, actionLabelOf, draftFromPlaybook, emptyPlaybookDraft, isHighRisk, newStep, validatePlaybookDraft, type PlaybookDraft, type StepDraft, type TriggerOn } from "../../lib/playbooks";

const RISK_TONE = { low: "success", medium: "warning", high: "danger" } as const;
const FIELD_HINTS = ["severity", "status", "riskScore", "organizationId", "alertCount", "asset.criticality", "asset.internetFacing", "identity.privileged", "indicator.type", "indicator.confidence", "attack.id"];

function FlowNode({ icon: Icon, title, tone, children, testId }: { icon: LucideIcon; title: ReactNode; tone: string; children: ReactNode; testId?: string }) {
  return (
    <section className="relative rounded border border-line bg-surface shadow-card" data-testid={testId}>
      <header className="flex items-center gap-2 border-b border-line px-3 py-2">
        <span className={clsx("inline-flex h-6 w-6 items-center justify-center rounded-full text-white", tone)} aria-hidden>
          <Icon size={13} />
        </span>
        <h3 className="flex-1 text-sm font-semibold text-fg">{title}</h3>
      </header>
      <div className="space-y-2 p-3">{children}</div>
    </section>
  );
}

function Connector() {
  return (
    <div className="flex justify-center py-1" aria-hidden>
      <div className="h-5 w-px bg-line-strong" />
    </div>
  );
}

/**
 * Visual playbook editor: trigger → conditions → ordered steps (reorder, add, remove).
 * High-risk steps always wait for approval; the toggle is locked on for them.
 */
export function PlaybookEditor({ playbook, onClose }: { playbook: Playbook | null; onClose: () => void }) {
  const session = useSession();
  const defaultOrg = useDefaultOrganization("playbook:write", true);
  const save = useSavePlaybook();
  const [draft, setDraft] = useState<PlaybookDraft>(() => (playbook ? draftFromPlaybook(playbook) : emptyPlaybookDraft(defaultOrg)));
  const [submitted, setSubmitted] = useState(false);
  const { errors, input } = useMemo(() => validatePlaybookDraft(draft), [draft]);
  const canWrite = session.can("playbook:write", draft.organizationId);
  const approvals = draft.steps.filter((s) => s.requireApproval || isHighRisk(s.action)).length;

  const setStep = (i: number, patch: Partial<StepDraft>) => setDraft((d) => ({ ...d, steps: d.steps.map((s, j) => (j === i ? { ...s, ...patch } : s)) }));
  const move = (i: number, delta: number) =>
    setDraft((d) => {
      const steps = [...d.steps];
      const j = i + delta;
      if (j < 0 || j >= steps.length) return d;
      [steps[i], steps[j]] = [steps[j]!, steps[i]!];
      return { ...d, steps };
    });

  const submit = () => {
    setSubmitted(true);
    if (!input || !canWrite) return;
    save.mutate({ ...(playbook ? { id: playbook.id } : {}), input }, { onSuccess: onClose });
  };

  return (
    <Drawer
      open
      onClose={onClose}
      width="xl"
      title={playbook ? `Edit playbook · v${playbook.version}` : "New playbook"}
      subtitle="Trigger → conditions → steps. Saving creates a new version; every run and approval is audited."
      footer={
        <div className="flex flex-wrap items-center gap-2">
          {save.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(save.error)}
            </span>
          ) : submitted && !input ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              Fix the highlighted fields before saving.
            </span>
          ) : (
            <span className="mr-auto text-xs text-fg-muted">
              {approvals > 0 ? `${approvals} step(s) will wait for human approval.` : "All steps run automatically once conditions match."}
            </span>
          )}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} loading={save.isPending} disabled={!canWrite}>
            Save playbook
          </Button>
        </div>
      }
    >
      <div className="space-y-3 p-4" data-testid="playbook-editor">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <Field label="Name" required error={submitted ? (errors.name ?? null) : null}>
            {(p) => <Input {...p} value={draft.name} onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))} maxLength={200} placeholder="Contain ransomware on critical endpoints" />}
          </Field>
          <Field label="Scope" hint="Tenant-wide playbooks apply to every organization unless overridden.">
            {(p) => <OrganizationSelect {...p} value={draft.organizationId} onChange={(v) => setDraft((d) => ({ ...d, organizationId: v }))} permission="playbook:write" allowTenantWide tenantWideLabel="All organizations (global playbook)" />}
          </Field>
          <Field label="Description" className="md:col-span-2">
            {(p) => <Textarea {...p} value={draft.description} onChange={(e) => setDraft((d) => ({ ...d, description: e.target.value }))} maxLength={4000} className="min-h-[48px]" />}
          </Field>
          <Checkbox label="Enabled" checked={draft.enabled} onChange={(e) => setDraft((d) => ({ ...d, enabled: e.target.checked }))} />
        </div>

        <div className="mx-auto max-w-3xl">
          <FlowNode icon={Zap} title="Trigger" tone="bg-primary" testId="flow-trigger">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <Select value={draft.trigger.on} onChange={(e) => setDraft((d) => ({ ...d, trigger: { ...d.trigger, on: e.target.value as TriggerOn } }))} aria-label="Trigger event">
                {TRIGGERS.map((t) => (
                  <option key={t} value={t}>
                    {TRIGGER_LABELS[t]}
                  </option>
                ))}
              </Select>
              {draft.trigger.on === "schedule" ? (
                <div>
                  <Input value={draft.trigger.cron} onChange={(e) => setDraft((d) => ({ ...d, trigger: { ...d.trigger, cron: e.target.value } }))} className="font-mono text-xs" aria-label="Cron schedule" aria-invalid={Boolean(errors.cron)} />
                  <p className={clsx("mt-0.5 text-2xs", errors.cron ? "text-sev-critical" : "text-fg-subtle")}>{errors.cron ?? describeCron(draft.trigger.cron)}</p>
                </div>
              ) : null}
            </div>
          </FlowNode>
          <Connector />
          <FlowNode icon={Filter} title={`Conditions (${draft.conditions.length === 0 ? "always" : `all ${draft.conditions.length} must match`})`} tone="bg-sev-medium" testId="flow-conditions">
            {draft.conditions.length === 0 ? <p className="text-sm text-fg-muted">No conditions — the playbook runs for every trigger event.</p> : null}
            {draft.conditions.map((c, i) => (
              <div key={i} className="grid grid-cols-[minmax(0,1fr)_130px_minmax(0,1fr)_28px] items-start gap-1.5">
                <div>
                  <Input
                    list="playbook-fields"
                    value={c.field}
                    onChange={(e) => setDraft((d) => ({ ...d, conditions: d.conditions.map((x, j) => (j === i ? { ...x, field: e.target.value } : x)) }))}
                    className="h-7 font-mono text-xs"
                    aria-label={`Condition ${i + 1} field`}
                    aria-invalid={Boolean(errors.conditions?.[i])}
                  />
                  {errors.conditions?.[i] ? <p className="text-2xs text-sev-critical">{errors.conditions[i]}</p> : null}
                </div>
                <Select value={c.op} onChange={(e) => setDraft((d) => ({ ...d, conditions: d.conditions.map((x, j) => (j === i ? { ...x, op: e.target.value as ConditionOp } : x)) }))} className="h-7" aria-label={`Condition ${i + 1} operator`}>
                  {CONDITION_OPS.map((op) => (
                    <option key={op} value={op}>
                      {CONDITION_OP_LABELS[op]}
                    </option>
                  ))}
                </Select>
                <Input
                  value={c.value}
                  onChange={(e) => setDraft((d) => ({ ...d, conditions: d.conditions.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)) }))}
                  disabled={c.op === "exists"}
                  placeholder={c.op === "in" ? "a, b, c" : "value"}
                  className="h-7"
                  aria-label={`Condition ${i + 1} value`}
                />
                <IconButton icon={Trash2} size={12} label={`Remove condition ${i + 1}`} onClick={() => setDraft((d) => ({ ...d, conditions: d.conditions.filter((_, j) => j !== i) }))} />
              </div>
            ))}
            <datalist id="playbook-fields">
              {FIELD_HINTS.map((f) => (
                <option key={f} value={f} />
              ))}
            </datalist>
            <Button size="xs" icon={Plus} onClick={() => setDraft((d) => ({ ...d, conditions: [...d.conditions, { field: "", op: "eq", value: "" }] }))}>
              Add condition
            </Button>
          </FlowNode>

          {draft.steps.map((s, i) => {
            const high = isHighRisk(s.action);
            const risk = RESPONSE_ACTIONS.find((a) => a.key === s.action)?.risk ?? "low";
            return (
              <div key={s.id}>
                <Connector />
                <FlowNode
                  icon={high ? ShieldAlert : Zap}
                  tone={high ? "bg-sev-critical" : "bg-healthy"}
                  testId="flow-step"
                  title={
                    <span className="flex flex-wrap items-center gap-2">
                      Step {i + 1}: {actionLabelOf(s.action)}
                      <Badge size="xs" tone={RISK_TONE[risk]}>
                        {risk} risk
                      </Badge>
                      {s.requireApproval || high ? (
                        <Badge size="xs" tone="warning" icon={ShieldAlert}>
                          approval gate
                        </Badge>
                      ) : null}
                      <span className="ml-auto flex gap-0.5">
                        <IconButton icon={ArrowUp} size={12} label={`Move step ${i + 1} up`} disabled={i === 0} onClick={() => move(i, -1)} />
                        <IconButton icon={ArrowDown} size={12} label={`Move step ${i + 1} down`} disabled={i === draft.steps.length - 1} onClick={() => move(i, 1)} />
                        <IconButton icon={Trash2} size={12} label={`Remove step ${i + 1}`} onClick={() => setDraft((d) => ({ ...d, steps: d.steps.filter((_, j) => j !== i) }))} />
                      </span>
                    </span>
                  }
                >
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    <Select
                      value={s.action}
                      onChange={(e) => {
                        const action = e.target.value as ResponseActionKey;
                        setStep(i, { action, requireApproval: isHighRisk(action) ? true : s.requireApproval });
                      }}
                      aria-label={`Step ${i + 1} action`}
                    >
                      {(["low", "medium", "high"] as const).map((r) => (
                        <optgroup key={r} label={`${r} risk`}>
                          {RESPONSE_ACTIONS.filter((a) => a.risk === r).map((a) => (
                            <option key={a.key} value={a.key}>
                              {a.label}
                            </option>
                          ))}
                        </optgroup>
                      ))}
                    </Select>
                    <div className="flex flex-wrap items-center gap-3">
                      <Checkbox label="Require approval" checked={s.requireApproval || high} disabled={high} onChange={(e) => setStep(i, { requireApproval: e.target.checked })} title={high ? "High-risk actions always require approval" : undefined} />
                      <Checkbox label="Continue on error" checked={s.continueOnError} onChange={(e) => setStep(i, { continueOnError: e.target.checked })} />
                    </div>
                  </div>
                  <Field label="Parameters (JSON)" error={errors.steps?.[i] ?? null}>
                    {(p) => <Textarea {...p} value={s.parameters} onChange={(e) => setStep(i, { parameters: e.target.value })} spellCheck={false} className="min-h-[48px] font-mono text-xs" placeholder='{"channel": "soc-oncall"}' />}
                  </Field>
                </FlowNode>
              </div>
            );
          })}
          <Connector />
          <div className="flex flex-wrap items-center justify-center gap-2">
            <Button size="sm" icon={Plus} onClick={() => setDraft((d) => ({ ...d, steps: [...d.steps, newStep()] }))}>
              Add step
            </Button>
            <span className="inline-flex items-center gap-1 text-xs text-fg-subtle">
              <CircleStop size={12} aria-hidden /> End
            </span>
          </div>
          {errors.general && submitted ? (
            <p role="alert" className="mt-2 text-center text-sm text-sev-critical">
              {errors.general}
            </p>
          ) : null}
        </div>
      </div>
    </Drawer>
  );
}
