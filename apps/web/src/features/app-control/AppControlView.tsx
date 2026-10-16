import type { AppControlEvent, AppControlMode, AppControlRule, AppInventoryItem, AppMatchKind, AppPlatform, AppRuleAction } from "@bloody/contracts";
import { Ban, CheckCircle2, Eye, Plus, ShieldOff, Trash2 } from "lucide-react";
import { useState } from "react";
import { errorMessage } from "../../api/client";
import { useAddAppControlRule, useAppControlEvents, useAppControlInventory, useAppControlOverview, useDeleteAppControlRule, useSetAppControlMode } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge, Button, Card, DataTable, Dialog, EmptyState, ErrorState, Field, Input, OrganizationSelect, RelativeTime, Select, StatTile, Tabs, useDefaultOrganization, type DataTableColumn } from "../../components";

type Tab = "rules" | "applications" | "activity";
type Draft = { action: AppRuleAction; kind: AppMatchKind; value: string; platform: AppPlatform; scope: "org" | "account"; note: string };

const MODES: Array<{ mode: AppControlMode; label: string; help: string; icon: typeof Eye }> = [
  { mode: "off", label: "Off", help: "Nothing is checked.", icon: ShieldOff },
  { mode: "audit", label: "Audit", help: "Programs matching a block rule are reported, not stopped.", icon: Eye },
  { mode: "enforce", label: "Enforce", help: "Programs matching a block rule are stopped and reported.", icon: Ban },
];
const KIND_LABEL: Record<AppMatchKind, string> = { name: "Program name", path: "File path", sha256: "SHA-256 hash", publisher: "Publisher (Windows)" };
const VERDICT_TONE = { blocked: "danger", audited: "warning", allowed: "success", none: "neutral" } as const;

function RuleDialog({ organizationId, initial, onClose }: { organizationId: string; initial: Partial<Draft>; onClose: () => void }) {
  const session = useSession();
  const add = useAddAppControlRule();
  const [d, setD] = useState<Draft>({ action: "block", kind: "name", value: "", platform: "any", scope: "org", note: "", ...initial });
  const canAccount = session.can("asset:write", null);
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD((x) => ({ ...x, [k]: v }));
  const submit = () =>
    add.mutate(
      { organizationId: d.scope === "account" ? null : organizationId, action: d.action, kind: d.kind, value: d.value.trim(), platform: d.platform, ...(d.note.trim() ? { note: d.note.trim() } : {}) },
      { onSuccess: onClose },
    );
  return (
    <Dialog
      open
      onClose={onClose}
      title="Add App Control rule"
      description="Allow rules always win over block rules. Use * as a wildcard. Core system processes and the SCIAT Agent can never be blocked."
      footer={
        <>
          {add.error ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(add.error)}
            </span>
          ) : null}
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant={d.action === "block" ? "danger" : "success"} loading={add.isPending} disabled={!d.value.trim()} onClick={submit}>
            {d.action === "block" ? "Add block rule" : "Add allow rule"}
          </Button>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Action">
          {(f) => (
            <Select {...f} value={d.action} onChange={(e) => set("action", e.target.value as AppRuleAction)}>
              <option value="block">Block</option>
              <option value="allow">Allow (exception)</option>
            </Select>
          )}
        </Field>
        <Field label="Match on">
          {(f) => (
            <Select {...f} value={d.kind} onChange={(e) => set("kind", e.target.value as AppMatchKind)}>
              {(Object.keys(KIND_LABEL) as AppMatchKind[]).map((k) => (
                <option key={k} value={k}>
                  {KIND_LABEL[k]}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Value" className="sm:col-span-2" hint={d.kind === "name" ? "e.g. anydesk.exe or team*.exe" : d.kind === "path" ? "e.g. C:\\Users\\*\\Downloads\\*" : d.kind === "publisher" ? "e.g. AnyDesk Software GmbH" : "64 hex characters"}>
          {(f) => <Input {...f} value={d.value} onChange={(e) => set("value", e.target.value)} maxLength={500} />}
        </Field>
        <Field label="Platform">
          {(f) => (
            <Select {...f} value={d.platform} onChange={(e) => set("platform", e.target.value as AppPlatform)}>
              <option value="any">Any</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="macos">macOS</option>
            </Select>
          )}
        </Field>
        <Field label="Applies to">
          {(f) => (
            <Select {...f} value={d.scope} onChange={(e) => set("scope", e.target.value as Draft["scope"])}>
              <option value="org">This organization</option>
              {canAccount ? <option value="account">Every organization (account-wide)</option> : null}
            </Select>
          )}
        </Field>
        <Field label="Note (optional)" className="sm:col-span-2">
          {(f) => <Input {...f} value={d.note} onChange={(e) => set("note", e.target.value)} maxLength={300} />}
        </Field>
      </div>
    </Dialog>
  );
}

function ModeSwitch({ organizationId, mode, canWrite }: { organizationId: string; mode: AppControlMode; canWrite: boolean }) {
  const setMode = useSetAppControlMode();
  const [confirm, setConfirm] = useState(false);
  const choose = (m: AppControlMode) => (m === "enforce" ? setConfirm(true) : setMode.mutate({ organizationId, mode: m }));
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2" role="radiogroup" aria-label="App Control mode">
        {MODES.map((m) => (
          <Button
            key={m.mode}
            role="radio"
            aria-checked={mode === m.mode}
            size="sm"
            icon={m.icon}
            variant={mode === m.mode ? (m.mode === "enforce" ? "danger" : "primary") : "secondary"}
            disabled={!canWrite || setMode.isPending}
            onClick={() => mode !== m.mode && choose(m.mode)}
          >
            {m.label}
          </Button>
        ))}
      </div>
      <p className="text-sm text-fg-muted">{MODES.find((m) => m.mode === mode)?.help} Agents pick up changes at their next check-in (within a minute).</p>
      {setMode.error ? <p className="text-sm text-sev-critical">{errorMessage(setMode.error)}</p> : null}
      <Dialog
        open={confirm}
        onClose={() => setConfirm(false)}
        title="Start enforcing?"
        description="The SCIAT Agent will stop every program that matches a block rule on this organization's computers. Run in Audit first to check what would be stopped."
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirm(false)}>
              Cancel
            </Button>
            <Button variant="danger" icon={Ban} loading={setMode.isPending} onClick={() => setMode.mutate({ organizationId, mode: "enforce" }, { onSuccess: () => setConfirm(false) })}>
              Enforce
            </Button>
          </>
        }
      />
    </div>
  );
}

/** ESPM → App Control: decide which programs may run; the SCIAT Agent applies it on endpoints. */
export function AppControlView() {
  const session = useSession();
  const [organizationId, setOrganizationId] = useState<string | null>(useDefaultOrganization("asset:read"));
  const [tab, setTab] = useState<Tab>("rules");
  const [draft, setDraft] = useState<Partial<Draft> | null>(null);
  const overview = useAppControlOverview(organizationId);
  const inventory = useAppControlInventory(tab === "applications" ? organizationId : null);
  const events = useAppControlEvents(tab === "activity" ? organizationId : null);
  const remove = useDeleteAppControlRule();
  const canWrite = organizationId ? session.can("asset:write", organizationId) : false;

  const ruleCols: DataTableColumn<AppControlRule>[] = [
    { id: "action", header: "Action", accessor: (r) => r.action, cell: (r) => <Badge size="xs" tone={r.action === "block" ? "danger" : "success"}>{r.action}</Badge> },
    { id: "kind", header: "Match on", accessor: (r) => KIND_LABEL[r.kind] },
    { id: "value", header: "Value", accessor: (r) => r.value, hideable: false, cell: (r) => <span className="break-all font-mono text-xs">{r.value}</span> },
    { id: "platform", header: "Platform", accessor: (r) => r.platform },
    { id: "scope", header: "Applies to", accessor: (r) => (r.organizationId ? "This organization" : "Every organization") },
    { id: "note", header: "Note", accessor: (r) => r.note },
    { id: "created", header: "Added", accessor: (r) => new Date(r.createdAt), cell: (r) => <RelativeTime value={r.createdAt} /> },
    {
      id: "remove",
      header: "",
      exportable: false,
      sortable: false,
      cell: (r) =>
        session.can("asset:write", r.organizationId) ? (
          <Button size="xs" variant="ghost" icon={Trash2} aria-label={`Remove rule ${r.value}`} loading={remove.isPending && remove.variables === r.id} onClick={() => remove.mutate(r.id)} />
        ) : null,
    },
  ];
  const appCols: DataTableColumn<AppInventoryItem>[] = [
    { id: "name", header: "Program", accessor: (a) => a.name, hideable: false, cell: (a) => <span className="font-medium">{a.name}</span> },
    { id: "path", header: "Path", accessor: (a) => a.path, cell: (a) => <span className="break-all font-mono text-xs">{a.path}</span> },
    { id: "endpoints", header: "Endpoints", accessor: (a) => a.endpoints },
    { id: "verdict", header: "Policy", accessor: (a) => a.verdict, cell: (a) => <Badge size="xs" tone={VERDICT_TONE[a.verdict]}>{a.verdict === "none" ? "no rule" : a.verdict}</Badge>, filter: { kind: "select", options: ["blocked", "audited", "allowed", "none"].map((v) => ({ value: v, label: v })) } },
    { id: "seen", header: "Last seen", accessor: (a) => new Date(a.lastSeenAt), cell: (a) => <RelativeTime value={a.lastSeenAt} /> },
    {
      id: "act",
      header: "",
      exportable: false,
      sortable: false,
      cell: (a) =>
        canWrite ? (
          <span className="flex gap-1">
            <Button size="xs" variant="danger" icon={Ban} onClick={() => setDraft({ action: "block", kind: "name", value: a.name })}>
              Block
            </Button>
            <Button size="xs" icon={CheckCircle2} onClick={() => setDraft({ action: "allow", kind: "path", value: a.path })}>
              Allow
            </Button>
          </span>
        ) : null,
    },
  ];
  const eventCols: DataTableColumn<AppControlEvent>[] = [
    { id: "at", header: "When", accessor: (e) => new Date(e.occurredAt), cell: (e) => <RelativeTime value={e.occurredAt} /> },
    { id: "verdict", header: "Result", accessor: (e) => e.verdict, cell: (e) => <Badge size="xs" tone={VERDICT_TONE[e.verdict]}>{e.verdict === "blocked" ? "stopped" : "would stop"}</Badge> },
    { id: "host", header: "Endpoint", accessor: (e) => e.hostname },
    { id: "name", header: "Program", accessor: (e) => e.name, hideable: false },
    { id: "path", header: "Path", accessor: (e) => e.path, cell: (e) => <span className="break-all font-mono text-xs">{e.path ?? "—"}</span> },
    { id: "rule", header: "Rule", accessor: (e) => overview.data?.rules.find((r) => r.id === e.ruleId)?.value ?? (e.ruleId ? "removed rule" : "—") },
  ];

  const o = overview.data;
  return (
    <div className="space-y-4">
      <Card title="App Control">
        <div className="space-y-4">
          <div className="max-w-sm">
            <OrganizationSelect value={organizationId} onChange={setOrganizationId} permission="asset:read" aria-label="Organization" />
          </div>
          {!organizationId ? (
            <EmptyState compact title="Pick an organization" />
          ) : overview.isError ? (
            <ErrorState compact error={overview.error} onRetry={() => void overview.refetch()} />
          ) : o ? (
            <>
              <ModeSwitch organizationId={organizationId} mode={o.mode} canWrite={canWrite} />
              <div className="grid gap-3 sm:grid-cols-4">
                <StatTile label="Endpoints with SCIAT Agent" value={o.stats.agents} />
                <StatTile label="Programs seen" value={o.stats.programs} />
                <StatTile label="Stopped (24 h)" value={o.stats.blocked24h} tone={o.stats.blocked24h > 0 ? "high" : "healthy"} />
                <StatTile label="Would stop (24 h)" value={o.stats.audited24h} tone={o.stats.audited24h > 0 ? "medium" : "healthy"} />
              </div>
              {o.stats.agents === 0 ? <p className="text-sm text-fg-muted">No SCIAT Agent is enrolled in this organization yet — App Control runs on computers with the agent (Windows and Linux).</p> : null}
            </>
          ) : null}
        </div>
      </Card>
      {organizationId && o ? (
        <Card>
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <Tabs
                ariaLabel="App Control"
                idPrefix="appctl"
                tabs={[
                  { id: "rules" as const, label: "Rules", count: o.rules.length },
                  { id: "applications" as const, label: "Applications", count: o.stats.programs },
                  { id: "activity" as const, label: "Activity", count: o.stats.blocked24h + o.stats.audited24h || null },
                ]}
                value={tab}
                onChange={setTab}
              />
              {canWrite ? (
                <Button size="sm" variant="primary" icon={Plus} onClick={() => setDraft({})}>
                  Add rule
                </Button>
              ) : null}
            </div>
            {tab === "rules" ? (
              <DataTable caption="App Control rules" columns={ruleCols} rows={o.rules} getRowId={(r) => r.id} emptyState={<EmptyState compact title="No rules yet" description="Block programs such as unapproved remote-access tools; add allow rules for the exceptions your helpdesk needs." />} />
            ) : null}
            {tab === "applications" ? (
              <DataTable caption="Programs seen" columns={appCols} rows={inventory.data?.items} loading={inventory.isPending} error={inventory.error} getRowId={(a) => a.path} searchable searchPlaceholder="Search programs" exportFileName="app-control-programs" emptyState={<EmptyState compact title="No programs reported yet" description="SCIAT Agents report the programs running on each computer every 30 minutes." />} />
            ) : null}
            {tab === "activity" ? (
              <DataTable caption="App Control activity" columns={eventCols} rows={events.data?.items} loading={events.isPending} error={events.error} getRowId={(e) => e.id} searchable exportFileName="app-control-activity" emptyState={<EmptyState compact title="Nothing blocked or audited yet" />} />
            ) : null}
          </div>
        </Card>
      ) : null}
      {draft && organizationId ? <RuleDialog organizationId={organizationId} initial={draft} onClose={() => setDraft(null)} /> : null}
    </div>
  );
}
