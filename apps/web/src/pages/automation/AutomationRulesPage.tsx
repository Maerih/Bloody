import { AUTOMATION_EVENTS, PlaybookCondition, type AutomationEvent, type AutomationRule } from "@bloody/contracts";
import { CalendarClock, Plus, Trash2, WandSparkles } from "lucide-react";
import { useMemo, useState } from "react";
import { errorMessage } from "../../api/client";
import { useAutomationRules, useCreateAutomationRule, useNotificationChannels } from "../../api/hooks";
import type { CreateAutomationRuleInput } from "../../api/types";
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

const EVENT_LABELS: Record<AutomationEvent, string> = {
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

/** Field suggestions for conditions, per event (free text is still allowed). */
const FIELD_SUGGESTIONS: string[] = ["severity", "organizationId", "status", "riskScore", "asset.criticality", "asset.internetFacing", "identity.privileged", "indicator.type", "vulnerability.cvss", "vulnerability.epss", "action", "module"];

const OPS = PlaybookCondition.shape.op.options;
const OP_LABELS: Record<(typeof OPS)[number], string> = { eq: "equals", neq: "not equal", gte: "≥", lte: "≤", in: "is one of", contains: "contains", exists: "exists" };

interface ConditionDraft {
  field: string;
  op: (typeof OPS)[number];
  value: string;
}

/** Turn the text value into the typed condition value the engine compares against. */
export function coerceConditionValue(op: ConditionDraft["op"], raw: string): unknown {
  if (op === "exists") return undefined;
  const text = raw.trim();
  if (op === "in") return text.split(",").map((v) => coerceScalar(v.trim())).filter((v) => v !== "");
  return coerceScalar(text);
}
function coerceScalar(text: string): unknown {
  if (text === "true") return true;
  if (text === "false") return false;
  if (text !== "" && !Number.isNaN(Number(text))) return Number(text);
  return text;
}

interface RuleTemplate {
  name: string;
  event: AutomationEvent;
  conditions: ConditionDraft[];
  subject: string;
  body: string;
  throttleMinutes: number;
}

/** Starting points offered in the editor (templates, not data). */
const RECOMMENDED: RuleTemplate[] = [
  {
    name: "Email on-call for critical incidents",
    event: "incident.created",
    conditions: [{ field: "severity", op: "eq", value: "critical" }],
    subject: "[Bloody] Critical incident: {{title}}",
    body: "A critical incident was created for {{organization}}.\n\nSeverity: {{severity}}\nOpen: {{link}}",
    throttleMinutes: 0,
  },
  {
    name: "Notify customer when an escalation is overdue",
    event: "escalation.overdue",
    conditions: [],
    subject: "[Bloody] Action required: {{title}}",
    body: "An escalation for {{organization}} is past its due time.\n\nPlease review: {{link}}",
    throttleMinutes: 240,
  },
  {
    name: "Approvers: response action pending",
    event: "response.pending_approval",
    conditions: [],
    subject: "[Bloody] Approval needed: {{action}}",
    body: "A high-risk response action is waiting for approval.\n\nReason: {{reason}}\nReview: {{link}}",
    throttleMinutes: 0,
  },
  {
    name: "KEV vulnerability on a crown jewel",
    event: "vulnerability.kev_detected",
    conditions: [{ field: "asset.criticality", op: "eq", value: "crown_jewel" }],
    subject: "[Bloody] Known-exploited vulnerability on {{asset}}",
    body: "{{cve}} (known exploited) was detected on {{asset}}.\n\nRemediation: {{link}}",
    throttleMinutes: 1440,
  },
];

/** Automation rules (/soar/automations): event-driven email / Slack / Teams / webhook notifications. */
export default function AutomationRulesPage() {
  const session = useSession();
  const rules = useAutomationRules();
  const channels = useNotificationChannels();
  const canManage = session.canAnywhere("playbook:write") || session.canAnywhere("settings:write");
  const [editor, setEditor] = useState<RuleTemplate | null>(null);
  const channelName = useMemo(() => new Map((channels.data ?? []).map((c) => [c.id, c.name])), [channels.data]);

  const blank: RuleTemplate = { name: "", event: "incident.created", conditions: [], subject: "[Bloody] {{title}}", body: "{{title}}\n\nOpen: {{link}}", throttleMinutes: 0 };

  const columns: DataTableColumn<AutomationRule>[] = [
    { id: "name", header: "Rule", accessor: (r) => r.name, hideable: false, cell: (r) => <span className="font-medium text-heading">{r.name}</span> },
    { id: "event", header: "When", accessor: (r) => EVENT_LABELS[r.event] ?? r.event, filter: { kind: "select", options: AUTOMATION_EVENTS.map((e) => ({ value: EVENT_LABELS[e], label: EVENT_LABELS[e] })) } },
    {
      id: "conditions",
      header: "Conditions",
      accessor: (r) => r.conditions.map((c) => `${c.field} ${c.op} ${JSON.stringify(c.value ?? "")}`).join("; "),
      cell: (r) =>
        r.conditions.length === 0 ? (
          <span className="text-fg-subtle">Always</span>
        ) : (
          <span className="font-mono text-xs">{r.conditions.map((c) => `${c.field} ${OP_LABELS[c.op]} ${c.op === "exists" ? "" : JSON.stringify(c.value)}`).join(" AND ")}</span>
        ),
    },
    { id: "channels", header: "Notify", accessor: (r) => r.channelIds.map((id) => channelName.get(id) ?? id).join(", "), cell: (r) => <span>{r.channelIds.map((id) => channelName.get(id) ?? "Unknown channel").join(", ") || "—"}</span> },
    { id: "throttle", header: "Throttle", accessor: (r) => r.throttleMinutes, cell: (r) => (r.throttleMinutes > 0 ? `${r.throttleMinutes} min` : "None") },
    { id: "scope", header: "Scope", accessor: (r) => (r.organizationId ? (session.organizationName(r.organizationId) ?? r.organizationId) : "All organizations") },
    { id: "enabled", header: "State", accessor: (r) => (r.enabled ? "active" : "paused"), cell: (r) => (r.enabled ? <StatusBadge status="active" /> : <Badge>Paused</Badge>) },
  ];

  return (
    <div>
      <PageHeader
        title="Automation Rules"
        subtitle="When an event happens and its conditions match, notify the right people by email, Slack, Teams or webhook."
        breadcrumbs={[{ label: "SOAR", href: "/soar" }, { label: "Automation Rules" }]}
        actions={
          <>
            <ButtonLink to="/soar/channels" size="sm">
              Notification channels
            </ButtonLink>
            {canManage ? (
              <Button variant="primary" icon={Plus} onClick={() => setEditor(blank)}>
                New rule
              </Button>
            ) : null}
          </>
        }
      />
      {canManage ? (
        <Card title="Recommended rules" info="Start from a proven template and adjust conditions, channels and wording." className="mb-3">
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2 2xl:grid-cols-4">
            {RECOMMENDED.map((t) => (
              <button key={t.name} type="button" onClick={() => setEditor(t)} className="flex items-start gap-2 rounded border border-line p-2.5 text-left hover:border-primary hover:bg-primary-soft/40">
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
      <DataTable
        caption="Automation rules"
        columns={columns}
        rows={rules.data}
        getRowId={(r) => r.id}
        loading={rules.isPending}
        error={rules.error}
        onRetry={() => void rules.refetch()}
        initialState={{ sort: { columnId: "name", direction: "asc" } }}
        savedViewsKey="automation-rules"
        exportFileName="bloody-automation-rules"
        emptyState={<EmptyState icon={CalendarClock} title="No automation rules yet" description="Use a recommended rule to start emailing your team on critical events." />}
      />
      {editor ? <RuleEditorDialog initial={editor} onClose={() => setEditor(null)} /> : null}
    </div>
  );
}

function RuleEditorDialog({ initial, onClose }: { initial: RuleTemplate; onClose: () => void }) {
  const session = useSession();
  const channels = useNotificationChannels();
  const create = useCreateAutomationRule();
  const [name, setName] = useState(initial.name);
  const [event, setEvent] = useState<AutomationEvent>(initial.event);
  const [conditions, setConditions] = useState<ConditionDraft[]>(initial.conditions);
  const [channelIds, setChannelIds] = useState<string[]>([]);
  const [subject, setSubject] = useState(initial.subject);
  const [body, setBody] = useState(initial.body);
  const [throttle, setThrottle] = useState(initial.throttleMinutes);
  const [scope, setScope] = useState<string>(session.organizationId ?? "");
  const [enabled, setEnabled] = useState(true);
  const [submitted, setSubmitted] = useState(false);

  const usable = (channels.data ?? []).filter((c) => c.enabled && (c.organizationId === null || c.organizationId === (scope || null)));
  const builtConditions = conditions
    .filter((c) => c.field.trim())
    .map((c) => {
      const value = coerceConditionValue(c.op, c.value);
      return PlaybookCondition.parse({ field: c.field.trim(), op: c.op, ...(value === undefined ? {} : { value }) });
    });

  const errors = {
    name: name.trim() ? null : "Name is required",
    channels: channelIds.length > 0 ? null : "Choose at least one channel",
    subject: subject.trim() ? null : "Subject is required",
    conditions: conditions.some((c) => c.field.trim() && c.op !== "exists" && !c.value.trim()) ? "Every condition needs a value" : null,
  };
  const valid = Object.values(errors).every((e) => e === null);

  const submit = () => {
    setSubmitted(true);
    if (!valid) return;
    const input: CreateAutomationRuleInput = {
      name: name.trim(),
      organizationId: scope || null,
      event,
      conditions: builtConditions,
      channelIds,
      template: { subject: subject.trim(), body },
      throttleMinutes: Math.max(0, Math.min(10_080, throttle)),
      enabled,
    };
    create.mutate(input, { onSuccess: () => onClose() });
  };

  const err = (k: keyof typeof errors) => (submitted ? errors[k] : null);

  return (
    <Dialog
      open
      onClose={onClose}
      size="lg"
      title={initial.name ? `New rule: ${initial.name}` : "New automation rule"}
      description="Rules run on the server for every matching event; repeats for the same subject are suppressed during the throttle window."
      footer={
        <>
          {create.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(create.error)}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} loading={create.isPending}>
            Create rule
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name" required error={err("name")}>
            {(p) => <Input {...p} value={name} maxLength={200} onChange={(e) => setName(e.target.value)} />}
          </Field>
          <Field label="When" required>
            {(p) => (
              <Select {...p} value={event} onChange={(e) => setEvent(e.target.value as AutomationEvent)}>
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

        <Field label="Subject" required error={err("subject")}>
          {(p) => <Input {...p} value={subject} maxLength={300} onChange={(e) => setSubject(e.target.value)} />}
        </Field>
        <Field label="Message" hint="Placeholders like {{title}}, {{severity}}, {{organization}} and {{link}} are filled from the triggering event.">
          {(p) => <Textarea {...p} value={body} rows={5} onChange={(e) => setBody(e.target.value)} className="font-mono text-sm" />}
        </Field>
        <div className="grid grid-cols-3 gap-3">
          <Field label="Throttle (minutes)" hint="0 = no suppression">
            {(p) => <Input {...p} inputMode="numeric" value={String(throttle)} onChange={(e) => setThrottle(Number(e.target.value.replace(/\D/g, "")) || 0)} />}
          </Field>
          <Field label="Scope" className="col-span-2">
            {(p) => (
              <Select {...p} value={scope} onChange={(e) => setScope(e.target.value)}>
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
    </Dialog>
  );
}
