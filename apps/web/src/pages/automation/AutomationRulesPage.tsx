import { AUTOMATION_EVENTS, PlaybookCondition, type AutomationEvent, type AutomationRule } from "@bloody/contracts";
import { CalendarClock, Eye, FileText, Pencil, Plus, Power, Trash2, TriangleAlert, WandSparkles } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { errorMessage } from "../../api/client";
import {
  useAutomationRules,
  useAutomationTemplates,
  useCreateAutomationRule,
  useDeleteAutomationRule,
  useNotificationChannels,
  usePreviewAutomation,
  useUpdateAutomationRule,
} from "../../api/hooks";
import type { AutomationTemplatePreset, CreateAutomationRuleInput } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge, StatusBadge } from "../../components/Badge";
import { Button, ButtonLink, IconButton } from "../../components/Button";
import { Card } from "../../components/Card";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { EmptyState } from "../../components/EmptyState";
import { Checkbox, Field, Input, Select, Textarea } from "../../components/Form";
import { Dialog } from "../../components/Overlay";
import { PageHeader } from "../../components/PageHeader";
import { CHANNEL_ICONS } from "../../components/ScheduleReportDialog";
import { coerceConditionValue, conditionValueText } from "../../lib/conditions";
import { insertVariable, parseTemplate, samplePayload, templateVariables, unknownVariables } from "../../lib/template";

export const EVENT_LABELS: Record<AutomationEvent, string> = {
  "incident.created": "Incident created",
  "incident.severity_changed": "Incident severity changed",
  "incident.closed": "Incident closed",
  "escalation.created": "Escalation created",
  "escalation.overdue": "Escalation overdue",
  "response.pending_approval": "Response action awaiting approval",
  "agent.unresponsive": "Agent unresponsive",
  "indicator.matched": "Threat-intel indicator matched",
  "vulnerability.kev_detected": "Known-exploited vulnerability detected",
  "report.generated": "Report generated",
  "trial.ending": "Trial ending",
  "usage.quota_exceeded": "Usage quota exceeded",
};

/** Field suggestions for conditions (free text is still allowed). */
const FIELD_SUGGESTIONS: string[] = ["severity", "organization.id", "incident.riskScore", "incident.status", "asset.criticality", "asset.internetFacing", "identity.privileged", "indicator.type", "indicator.confidence", "vulnerability.cvss", "vulnerability.epss", "action.key", "module"];

const OPS = PlaybookCondition.shape.op.options;
const OP_LABELS: Record<(typeof OPS)[number], string> = { eq: "equals", neq: "not equal", gte: "≥", lte: "≤", in: "is one of", contains: "contains", exists: "exists" };

interface ConditionDraft {
  field: string;
  op: (typeof OPS)[number];
  value: string;
}

export { coerceConditionValue };

interface RuleTemplate {
  name: string;
  event: AutomationEvent;
  conditions: ConditionDraft[];
  subject: string;
  body: string;
  throttleMinutes: number;
}

/** Curated starting points (product content, not data): event + conditions + wording. */
const RECOMMENDED: RuleTemplate[] = [
  {
    name: "Email on-call for critical incidents",
    event: "incident.created",
    conditions: [{ field: "severity", op: "eq", value: "critical" }],
    subject: "[{{severity | upper}}] Incident #{{incident.number}}: {{incident.title}}",
    body: "A critical incident was opened for {{organization.name}}.\n\n{{incident.summary | default:\"No summary yet.\"}}\n\nOpen: {{link.url}}",
    throttleMinutes: 0,
  },
  {
    name: "Notify customer when an escalation is overdue",
    event: "escalation.overdue",
    conditions: [],
    subject: "Action required: {{escalation.title}}",
    body: "An escalation for {{organization.name}} is past its due time ({{escalation.dueAt | datetime}}).\n\nPlease review: {{link.url}}",
    throttleMinutes: 240,
  },
  {
    name: "Approvers: response action pending",
    event: "response.pending_approval",
    conditions: [],
    subject: "Approval needed: {{action.label}} on {{action.target}}",
    body: "A high-risk response action is waiting for approval.\n\nReason: {{action.reason}}\nRequested by: {{action.requestedBy}}\nReview: {{link.url}}",
    throttleMinutes: 0,
  },
  {
    name: "KEV vulnerability on a crown jewel",
    event: "vulnerability.kev_detected",
    conditions: [{ field: "asset.criticality", op: "eq", value: "crown_jewel" }],
    subject: "Known-exploited {{vulnerability.cve}} on {{asset.name}}",
    body: "{{vulnerability.cve}} (CISA KEV, CVSS {{vulnerability.cvss}}) was detected on {{asset.name}}.\n\nRemediation: {{link.url}}",
    throttleMinutes: 1440,
  },
];

const BLANK: RuleTemplate = { name: "", event: "incident.created", conditions: [], subject: "[{{severity | upper}}] {{subject.label}}", body: "{{subject.label}} — {{organization.name}}\n\nOpen: {{link.url}}", throttleMinutes: 0 };

function canManageRules(session: ReturnType<typeof useSession>): boolean {
  return session.canAnywhere("playbook:write") || session.canAnywhere("settings:write");
}

function draftFromRule(r: AutomationRule): RuleTemplate {
  return {
    name: r.name,
    event: r.event,
    conditions: r.conditions.map((c) => ({ field: c.field, op: c.op, value: conditionValueText(c.value) })),
    subject: r.template.subject,
    body: r.template.body,
    throttleMinutes: r.throttleMinutes,
  };
}

/**
 * Automation rules shared by /automations and /soar/automations: "when <event> and <conditions>,
 * notify <channels> using <template>", with enable / disable, edit and delete.
 */
export function AutomationRulesView() {
  const session = useSession();
  const rules = useAutomationRules();
  const channels = useNotificationChannels();
  const update = useUpdateAutomationRule();
  const remove = useDeleteAutomationRule();
  const canManage = canManageRules(session);
  const [editor, setEditor] = useState<{ template: RuleTemplate; existing: AutomationRule | null } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<AutomationRule | null>(null);
  const channelName = useMemo(() => new Map((channels.data ?? []).map((c) => [c.id, c.name])), [channels.data]);

  const columns: DataTableColumn<AutomationRule>[] = [
    { id: "name", header: "Rule", accessor: (r) => r.name, hideable: false, cell: (r) => <span className="font-medium text-heading">{r.name}</span> },
    { id: "event", header: "When", accessor: (r) => EVENT_LABELS[r.event] ?? r.event, filter: { kind: "select", options: AUTOMATION_EVENTS.map((e) => ({ value: EVENT_LABELS[e], label: EVENT_LABELS[e] })) } },
    {
      id: "conditions",
      header: "Conditions",
      accessor: (r) => r.conditions.map((c) => `${c.field} ${c.op} ${conditionValueText(c.value)}`).join("; "),
      cell: (r) =>
        r.conditions.length === 0 ? (
          <span className="text-fg-subtle">Always</span>
        ) : (
          <span className="font-mono text-xs">{r.conditions.map((c) => `${c.field} ${OP_LABELS[c.op]}${c.op === "exists" ? "" : ` ${conditionValueText(c.value)}`}`).join(" AND ")}</span>
        ),
    },
    { id: "channels", header: "Notify", accessor: (r) => r.channelIds.map((id) => channelName.get(id) ?? id).join(", "), cell: (r) => <span>{r.channelIds.map((id) => channelName.get(id) ?? "Unknown channel").join(", ") || "—"}</span> },
    { id: "throttle", header: "Throttle", accessor: (r) => r.throttleMinutes, cell: (r) => (r.throttleMinutes > 0 ? `${r.throttleMinutes} min` : "None") },
    { id: "scope", header: "Scope", accessor: (r) => (r.organizationId ? (session.organizationName(r.organizationId) ?? r.organizationId) : "All organizations") },
    { id: "enabled", header: "State", accessor: (r) => (r.enabled ? "active" : "paused"), cell: (r) => (r.enabled ? <StatusBadge status="active" /> : <Badge>Paused</Badge>) },
    {
      id: "actions",
      header: "",
      sortable: false,
      hideable: false,
      exportable: false,
      cell: (r) =>
        canManage ? (
          <span className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
            <IconButton icon={Power} label={r.enabled ? `Pause ${r.name}` : `Enable ${r.name}`} onClick={() => update.mutate({ id: r.id, patch: { enabled: !r.enabled } })} />
            <IconButton icon={Pencil} label={`Edit ${r.name}`} onClick={() => setEditor({ template: draftFromRule(r), existing: r })} />
            <IconButton icon={Trash2} label={`Delete ${r.name}`} onClick={() => setConfirmDelete(r)} />
          </span>
        ) : null,
    },
  ];

  return (
    <>
      {canManage ? (
        <Card title="Recommended rules" info="Start from a proven rule and adjust conditions, channels and wording." className="mb-3">
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2 2xl:grid-cols-4">
            {RECOMMENDED.map((t) => (
              <button key={t.name} type="button" onClick={() => setEditor({ template: t, existing: null })} className="flex items-start gap-2 rounded border border-line p-2.5 text-left hover:border-primary hover:bg-primary-soft/40">
                <WandSparkles size={14} aria-hidden className="mt-0.5 shrink-0 text-primary" />
                <span>
                  <span className="block text-base font-medium text-fg">{t.name}</span>
                  <span className="block text-xs text-fg-muted">{EVENT_LABELS[t.event]}</span>
                </span>
              </button>
            ))}
          </div>
        </Card>
      ) : null}
      {update.isError ? (
        <p role="alert" className="mb-2 text-sm text-sev-critical">
          {errorMessage(update.error)}
        </p>
      ) : null}
      <DataTable
        caption="Automation rules"
        columns={columns}
        rows={rules.data}
        getRowId={(r) => r.id}
        loading={rules.isPending}
        error={rules.error}
        onRetry={() => void rules.refetch()}
        onRowClick={canManage ? (r) => setEditor({ template: draftFromRule(r), existing: r }) : undefined}
        initialState={{ sort: { columnId: "name", direction: "asc" } }}
        savedViewsKey="automation-rules"
        exportFileName="bloody-automation-rules"
        toolbar={
          canManage ? (
            <Button size="sm" variant="primary" icon={Plus} onClick={() => setEditor({ template: BLANK, existing: null })}>
              New rule
            </Button>
          ) : null
        }
        emptyState={<EmptyState icon={CalendarClock} title="No automation rules yet" description="Use a recommended rule to start emailing your team on critical events." />}
      />
      {editor ? <RuleEditorDialog key={editor.existing?.id ?? editor.template.name} initial={editor.template} existing={editor.existing} onClose={() => setEditor(null)} /> : null}
      {confirmDelete ? (
        <Dialog
          open
          size="sm"
          onClose={() => setConfirmDelete(null)}
          title={`Delete ${confirmDelete.name}?`}
          description="Matching events stop notifying these channels. This is audited and cannot be undone."
          footer={
            <>
              {remove.isError ? (
                <span role="alert" className="mr-auto text-sm text-sev-critical">
                  {errorMessage(remove.error)}
                </span>
              ) : null}
              <Button onClick={() => setConfirmDelete(null)}>Cancel</Button>
              <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate(confirmDelete.id, { onSuccess: () => setConfirmDelete(null) })}>
                Delete rule
              </Button>
            </>
          }
        />
      ) : null}
    </>
  );
}

/** Automation rules (/soar/automations). */
export default function AutomationRulesPage() {
  return (
    <div>
      <PageHeader
        title="Automation Rules"
        subtitle="When an event happens and its conditions match, notify the right people by email, Slack, Teams, webhook or syslog."
        breadcrumbs={[{ label: "SOAR", href: "/soar" }, { label: "Automation Rules" }]}
        actions={
          <ButtonLink to="/soar/channels" size="sm">
            Notification channels
          </ButtonLink>
        }
      />
      <AutomationRulesView />
    </div>
  );
}

/** Highlighted template preview: variables in purple, unknown variables in red. */
function TemplatePreview({ text, variables }: { text: string; variables: ReturnType<typeof templateVariables> }) {
  const segments = parseTemplate(text, variables);
  return (
    <span className="whitespace-pre-wrap break-words">
      {segments.map((s, i) =>
        s.kind === "text" ? (
          <span key={i}>{s.text}</span>
        ) : (
          <mark key={i} className={s.known ? "rounded bg-sev-low/10 px-0.5 text-sev-low" : "rounded bg-sev-critical/10 px-0.5 text-sev-critical"} title={s.description ?? "Not provided by this event"}>
            ‹{s.name}
            {s.filters ? ` | ${s.filters}` : ""}›
          </mark>
        ),
      )}
    </span>
  );
}

function RuleEditorDialog({ initial, existing, onClose }: { initial: RuleTemplate; existing: AutomationRule | null; onClose: () => void }) {
  const session = useSession();
  const channels = useNotificationChannels();
  const presets = useAutomationTemplates();
  const create = useCreateAutomationRule();
  const update = useUpdateAutomationRule();
  const preview = usePreviewAutomation();
  const [name, setName] = useState(initial.name);
  const [event, setEvent] = useState<AutomationEvent>(initial.event);
  const [conditions, setConditions] = useState<ConditionDraft[]>(initial.conditions);
  const [channelIds, setChannelIds] = useState<string[]>(existing?.channelIds ?? []);
  const [subject, setSubject] = useState(initial.subject);
  const [body, setBody] = useState(initial.body);
  const [throttle, setThrottle] = useState(initial.throttleMinutes);
  const [scope, setScope] = useState<string>(existing ? (existing.organizationId ?? "") : (session.organizationId ?? ""));
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [submitted, setSubmitted] = useState(false);
  const [focused, setFocused] = useState<"subject" | "body">("body");
  const subjectRef = useRef<HTMLInputElement>(null);
  const bodyRef = useRef<HTMLTextAreaElement>(null);
  const m = existing ? update : create;
  const resetPreview = preview.reset;
  // A rendered preview is only valid for the template it was rendered from.
  useEffect(() => resetPreview(), [subject, body, event, resetPreview]);

  const preset: AutomationTemplatePreset | null = presets.data?.find((p) => p.event === event) ?? null;
  const variables = useMemo(() => templateVariables(event, preset), [event, preset]);
  const unknown = useMemo(() => unknownVariables(`${subject}\n${body}`, variables), [subject, body, variables]);
  const usable = (channels.data ?? []).filter((c) => (c.enabled || channelIds.includes(c.id)) && (c.organizationId === null || c.organizationId === (scope || null)));

  const builtConditions = conditions
    .filter((c) => c.field.trim())
    .map((c) => {
      const value = coerceConditionValue(c.op, c.value);
      return PlaybookCondition.parse({ field: c.field.trim(), op: c.op, ...(value === undefined ? {} : { value }) });
    });

  const errors = {
    name: name.trim() ? null : "Name is required",
    channels: channelIds.length > 0 ? (channelIds.length > 20 ? "At most 20 channels per rule" : null) : "Choose at least one channel",
    subject: subject.trim() ? (subject.length > 300 ? "Subject must be at most 300 characters" : null) : "Subject is required",
    conditions: conditions.some((c) => c.field.trim() && c.op !== "exists" && !c.value.trim()) ? "Every condition needs a value" : null,
  };
  const valid = Object.values(errors).every((e) => e === null);

  const insert = (variable: string) => {
    if (focused === "subject") {
      const el = subjectRef.current;
      const r = insertVariable(subject, variable, el?.selectionStart ?? null, el?.selectionEnd ?? null);
      setSubject(r.value);
      requestAnimationFrame(() => el?.setSelectionRange(r.cursor, r.cursor));
    } else {
      const el = bodyRef.current;
      const r = insertVariable(body, variable, el?.selectionStart ?? null, el?.selectionEnd ?? null);
      setBody(r.value);
      requestAnimationFrame(() => el?.setSelectionRange(r.cursor, r.cursor));
    }
  };

  const submit = () => {
    setSubmitted(true);
    if (!valid) return;
    const common = {
      name: name.trim(),
      conditions: builtConditions,
      channelIds,
      template: { subject: subject.trim(), body },
      throttleMinutes: Math.max(0, Math.min(10_080, throttle)),
      enabled,
    };
    if (existing) {
      update.mutate({ id: existing.id, patch: common }, { onSuccess: () => onClose() });
    } else {
      const input: CreateAutomationRuleInput = { ...common, organizationId: scope || null, event };
      create.mutate(input, { onSuccess: () => onClose() });
    }
  };

  const err = (k: keyof typeof errors) => (submitted ? errors[k] : null);

  return (
    <Dialog
      open
      onClose={onClose}
      size="xl"
      title={existing ? `Edit rule: ${existing.name}` : initial.name ? `New rule: ${initial.name}` : "New automation rule"}
      description="Rules run on the server for every matching event; repeats for the same subject are suppressed during the throttle window."
      footer={
        <>
          {m.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(m.error)}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} loading={m.isPending}>
            {existing ? "Save rule" : "Create rule"}
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_300px]">
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Field label="Name" required error={err("name")}>
              {(p) => <Input {...p} value={name} maxLength={200} onChange={(e) => setName(e.target.value)} />}
            </Field>
            <Field label="When" required hint={existing ? "The event of an existing rule cannot change." : undefined}>
              {(p) => (
                <Select {...p} value={event} disabled={Boolean(existing)} onChange={(e) => setEvent(e.target.value as AutomationEvent)}>
                  {AUTOMATION_EVENTS.map((ev) => (
                    <option key={ev} value={ev}>
                      {EVENT_LABELS[ev]}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          </div>

          <fieldset className="space-y-1.5">
            <legend className="text-sm font-medium text-fg">Conditions (all must match)</legend>
            <datalist id="automation-fields">
              {FIELD_SUGGESTIONS.map((f) => (
                <option key={f} value={f} />
              ))}
            </datalist>
            {conditions.length === 0 ? <p className="text-xs text-fg-subtle">No conditions — the rule fires for every {EVENT_LABELS[event].toLowerCase()} event.</p> : null}
            {conditions.map((c, i) => (
              <div key={i} className="grid grid-cols-[minmax(0,1fr)_130px_minmax(0,1fr)_28px] items-center gap-2">
                <Input list="automation-fields" value={c.field} aria-label={`Condition ${i + 1} field`} onChange={(e) => setConditions((cs) => cs.map((x, j) => (j === i ? { ...x, field: e.target.value } : x)))} placeholder="field (e.g. severity)" />
                <Select value={c.op} aria-label={`Condition ${i + 1} operator`} onChange={(e) => setConditions((cs) => cs.map((x, j) => (j === i ? { ...x, op: e.target.value as ConditionDraft["op"] } : x)))}>
                  {OPS.map((op) => (
                    <option key={op} value={op}>
                      {OP_LABELS[op]}
                    </option>
                  ))}
                </Select>
                <Input value={c.value} disabled={c.op === "exists"} aria-label={`Condition ${i + 1} value`} onChange={(e) => setConditions((cs) => cs.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))} placeholder={c.op === "in" ? "critical, high" : "value"} />
                <IconButton icon={Trash2} label={`Remove condition ${i + 1}`} onClick={() => setConditions((cs) => cs.filter((_, j) => j !== i))} />
              </div>
            ))}
            {err("conditions") ? <p className="text-xs text-sev-critical">{err("conditions")}</p> : null}
            <Button size="xs" icon={Plus} onClick={() => setConditions((cs) => [...cs, { field: "", op: "eq", value: "" }])}>
              Add condition
            </Button>
          </fieldset>

          <fieldset className="space-y-1.5">
            <legend className="text-sm font-medium text-fg">
              Notify<span className="ml-0.5 text-sev-critical">*</span>
            </legend>
            {usable.length === 0 ? (
              <p className="text-sm text-fg-muted">
                No enabled channels for this scope.{" "}
                <ButtonLink to="/soar/channels?create=1" size="xs" variant="link" onClick={onClose}>
                  Add a channel
                </ButtonLink>
              </p>
            ) : (
              <div className="flex flex-wrap gap-x-4 gap-y-1">
                {usable.map((c) => {
                  const Icon = CHANNEL_ICONS[c.kind];
                  return (
                    <Checkbox
                      key={c.id}
                      label={
                        <span className="inline-flex items-center gap-1">
                          <Icon size={12} aria-hidden className="text-fg-muted" /> {c.name}
                          {!c.enabled ? <Badge size="xs">disabled</Badge> : null}
                        </span>
                      }
                      checked={channelIds.includes(c.id)}
                      onChange={(e) => setChannelIds((ids) => (e.target.checked ? [...ids, c.id] : ids.filter((x) => x !== c.id)))}
                    />
                  );
                })}
              </div>
            )}
            {err("channels") && usable.length > 0 ? <p className="text-xs text-sev-critical">{err("channels")}</p> : null}
          </fieldset>

          <div className="flex items-center gap-2">
            <h3 className="text-sm font-medium text-fg">Message template</h3>
            {preset ? (
              <Button
                size="xs"
                icon={FileText}
                className="ml-auto"
                onClick={() => {
                  setSubject(preset.subject);
                  setBody(preset.body);
                  setThrottle(preset.throttleMinutes);
                }}
              >
                Use “{preset.name}” wording
              </Button>
            ) : null}
          </div>
          <Field label="Subject" required error={err("subject")}>
            {(p) => <Input {...p} ref={subjectRef} value={subject} maxLength={300} onFocus={() => setFocused("subject")} onChange={(e) => setSubject(e.target.value)} className="font-mono text-sm" />}
          </Field>
          <Field label="Message" hint="Variables like {{incident.title}} or {{severity | upper}} are filled from the triggering event. Click a variable on the right to insert it.">
            {(p) => <Textarea {...p} ref={bodyRef} value={body} rows={6} onFocus={() => setFocused("body")} onChange={(e) => setBody(e.target.value)} className="font-mono text-sm" />}
          </Field>
          {unknown.length > 0 ? (
            <p className="flex items-start gap-1.5 text-xs text-sev-high" role="status">
              <TriangleAlert size={12} className="mt-0.5 shrink-0" aria-hidden /> Not provided by “{EVENT_LABELS[event]}”: {unknown.map((u) => `{{${u}}}`).join(", ")} — these render empty.
            </p>
          ) : null}
          <div className="grid grid-cols-3 gap-3">
            <Field label="Throttle (minutes)" hint="0 = no suppression; max 7 days">
              {(p) => <Input {...p} inputMode="numeric" value={String(throttle)} onChange={(e) => setThrottle(Math.min(10_080, Number(e.target.value.replace(/\D/g, "")) || 0))} />}
            </Field>
            <Field label="Scope" className="col-span-2" hint={existing ? "Scope is fixed after creation." : undefined}>
              {(p) => (
                <Select {...p} value={scope} disabled={Boolean(existing)} onChange={(e) => setScope(e.target.value)}>
                  <option value="">All organizations</option>
                  {session.organizations.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          </div>
          <Checkbox label="Enabled" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        </div>

        <aside className="space-y-3">
          <section aria-label="Template variables" className="rounded border border-line">
            <h3 className="border-b border-line px-2.5 py-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted">Variables</h3>
            <ul className="max-h-56 overflow-y-auto p-1 scrollbar-thin">
              {variables.map((v) => (
                <li key={v.name}>
                  <button type="button" onClick={() => insert(v.name)} className="block w-full rounded px-1.5 py-1 text-left hover:bg-surface-2" title={`Insert {{${v.name}}} into the ${focused}`}>
                    <span className="block font-mono text-2xs text-sev-low">{`{{${v.name}}}`}</span>
                    <span className="block text-2xs text-fg-subtle">{v.description}</span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
          <section aria-label="Preview" className="rounded border border-line" data-testid="template-preview">
            <div className="flex items-center gap-2 border-b border-line px-2.5 py-1.5">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-fg-muted">Preview</h3>
              <Button
                size="xs"
                icon={Eye}
                className="ml-auto"
                loading={preview.isPending}
                disabled={!subject.trim() || !body.trim()}
                onClick={() => preview.mutate({ event, template: { subject, body }, data: samplePayload(variables), organizationId: scope || null })}
              >
                Render
              </Button>
            </div>
            <div className="space-y-2 p-2.5 text-xs">
              {preview.data ? (
                <>
                  <p className="font-semibold text-fg">{preview.data.subject}</p>
                  <p className="whitespace-pre-wrap text-fg-muted">{preview.data.text}</p>
                  {preview.data.missing.length > 0 ? <p className="text-sev-high">Missing: {preview.data.missing.join(", ")}</p> : null}
                  {preview.data.warnings.map((w) => (
                    <p key={w} className="text-sev-high">
                      {w}
                    </p>
                  ))}
                  <p className="text-2xs text-fg-subtle">Rendered by the automation engine with placeholder values — nothing was sent.</p>
                </>
              ) : (
                <>
                  <p className="font-semibold text-fg">
                    <TemplatePreview text={subject} variables={variables} />
                  </p>
                  <p className="text-fg-muted">
                    <TemplatePreview text={body} variables={variables} />
                  </p>
                </>
              )}
              {preview.isError ? <p className="text-sev-critical">{errorMessage(preview.error)}</p> : null}
            </div>
          </section>
        </aside>
      </div>
    </Dialog>
  );
}
