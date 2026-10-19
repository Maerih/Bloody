import { NotificationChannelKind, type NotificationChannel } from "@bloody/contracts";
import { Pencil, Plus, Power, Send, Trash2, Webhook } from "lucide-react";
import { useState } from "react";
import { useLocation, useSearchParams } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useCreateNotificationChannel, useDeleteNotificationChannel, useNotificationChannels, useTestNotificationChannel, useUpdateNotificationChannel } from "../../api/hooks";
import type { CreateNotificationChannelInput } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge, StatusBadge } from "../../components/Badge";
import { Button, ButtonLink, IconButton } from "../../components/Button";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { EmptyState } from "../../components/EmptyState";
import { Checkbox, Field, Input, Select } from "../../components/Form";
import { Dialog } from "../../components/Overlay";
import { CopyButton } from "../../components/CopyButton";
import { ChannelSettingsFields, buildConfig, initialSettings, validateSettings, type ChannelSettingsState } from "../../features/notifications/ChannelSettings";
import { PageHeader } from "../../components/PageHeader";
import { CHANNEL_ICONS } from "../../components/ScheduleReportDialog";

const KIND_LABELS: Record<NotificationChannelKind, string> = {
  email: "Email",
  slack: "Slack",
  teams: "Microsoft Teams",
  webhook: "Webhook",
  syslog: "Syslog",
  in_app: "In-app",
};
const CREATABLE: NotificationChannelKind[] = ["email", "slack", "teams", "webhook", "syslog"];

export { isSafeWebhookUrl, parseRecipients } from "../../features/notifications/ChannelSettings";

function targetSummary(c: NotificationChannel): string {
  const cfg = c.config as Record<string, unknown>;
  if (c.kind === "email" && Array.isArray(cfg.to)) {
    const smtp = cfg.smtp as { host?: string } | undefined;
    return `${(cfg.to as unknown[]).map(String).join(", ")}${smtp?.host ? ` · via ${smtp.host}` : ""}`;
  }
  if (c.kind === "syslog" && typeof cfg.host === "string") return `${String(cfg.protocol ?? "tls").toUpperCase()} ${cfg.host}:${String(cfg.port ?? 514)}`;
  if (c.kind === "slack" || c.kind === "teams" || c.kind === "webhook") return "Endpoint configured (stored as secret)";
  return "—";
}

export function canManageChannels(session: ReturnType<typeof useSession>): boolean {
  return session.canAnywhere("settings:write") || session.canAnywhere("playbook:write");
}

/**
 * Channel management shared by /soar/channels, /settings/notifications and /automations:
 * create, edit (secrets stay write-only), enable / disable, delete and send a test message.
 */
export function NotificationChannelsView() {
  const session = useSession();
  const [params, setParams] = useSearchParams();
  const channels = useNotificationChannels();
  const test = useTestNotificationChannel();
  const update = useUpdateNotificationChannel();
  const remove = useDeleteNotificationChannel();
  const canManage = canManageChannels(session);
  const [dialog, setDialog] = useState<NotificationChannel | "new" | null>(params.get("create") === "1" && canManage ? "new" : null);
  const [confirmDelete, setConfirmDelete] = useState<NotificationChannel | null>(null);

  const closeDialog = () => {
    setDialog(null);
    if (params.get("create")) {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.delete("create");
          return next;
        },
        { replace: true },
      );
    }
  };

  const columns: DataTableColumn<NotificationChannel>[] = [
    {
      id: "name",
      header: "Channel",
      accessor: (c) => c.name,
      hideable: false,
      cell: (c) => {
        const Icon = CHANNEL_ICONS[c.kind];
        return (
          <span className="flex items-center gap-2">
            <Icon size={14} aria-hidden className="text-fg-muted" />
            <span className="font-medium text-heading">{c.name}</span>
          </span>
        );
      },
    },
    { id: "kind", header: "Type", accessor: (c) => KIND_LABELS[c.kind], filter: { kind: "select", options: CREATABLE.map((k) => ({ value: KIND_LABELS[k], label: KIND_LABELS[k] })) } },
    { id: "target", header: "Destination", accessor: (c) => targetSummary(c), cell: (c) => <span className="block max-w-[340px] truncate text-fg-muted">{targetSummary(c)}</span> },
    { id: "scope", header: "Scope", accessor: (c) => (c.organizationId ? (session.organizationName(c.organizationId) ?? c.organizationId) : "All organizations") },
    { id: "enabled", header: "State", accessor: (c) => (c.enabled ? "active" : "disabled"), cell: (c) => (c.enabled ? <StatusBadge status="active" /> : <Badge>Disabled</Badge>) },
    {
      id: "actions",
      header: "",
      sortable: false,
      hideable: false,
      exportable: false,
      cell: (c) => (
        <span className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          <Button size="xs" icon={Send} disabled={!c.enabled} loading={test.isPending && test.variables === c.id} onClick={() => test.mutate(c.id)}>
            Send test
          </Button>
          {canManage ? (
            <>
              <IconButton icon={Power} label={c.enabled ? `Disable ${c.name}` : `Enable ${c.name}`} onClick={() => update.mutate({ id: c.id, patch: { enabled: !c.enabled } })} />
              <IconButton icon={Pencil} label={`Edit ${c.name}`} onClick={() => setDialog(c)} />
              <IconButton icon={Trash2} label={`Delete ${c.name}`} onClick={() => setConfirmDelete(c)} />
            </>
          ) : null}
        </span>
      ),
    },
  ];

  return (
    <>
      {test.isSuccess ? (
        <p role="status" className="mb-2 text-sm text-healthy">
          {test.data?.message ?? "Test notification sent."}
        </p>
      ) : test.isError ? (
        <p role="alert" className="mb-2 text-sm text-sev-critical">
          {errorMessage(test.error)}
        </p>
      ) : null}
      {update.isError ? (
        <p role="alert" className="mb-2 text-sm text-sev-critical">
          {errorMessage(update.error)}
        </p>
      ) : null}
      <DataTable
        caption="Notification channels"
        columns={columns}
        rows={channels.data}
        getRowId={(c) => c.id}
        loading={channels.isPending}
        error={channels.error}
        onRetry={() => void channels.refetch()}
        onRowClick={canManage ? (c) => setDialog(c) : undefined}
        initialState={{ sort: { columnId: "name", direction: "asc" } }}
        savedViewsKey="notification-channels"
        exportFileName="bloody-notification-channels"
        toolbar={
          canManage ? (
            <Button size="sm" variant="primary" icon={Plus} onClick={() => setDialog("new")}>
              Add channel
            </Button>
          ) : null
        }
        emptyState={
          <EmptyState
            icon={Webhook}
            title="No notification channels yet"
            description="Add an email distribution list (SMTP), Slack or Teams channel, webhook or syslog target."
            action={canManage ? <Button variant="primary" size="sm" icon={Plus} onClick={() => setDialog("new")}>Add channel</Button> : undefined}
          />
        }
      />
      {dialog ? <ChannelDialog key={dialog === "new" ? "new" : dialog.id} existing={dialog === "new" ? null : dialog} onClose={closeDialog} /> : null}
      {confirmDelete ? (
        <Dialog
          open
          size="sm"
          onClose={() => setConfirmDelete(null)}
          title={`Delete ${confirmDelete.name}?`}
          description="Automation rules and report schedules that use this channel stop delivering to it. Stored secrets are destroyed."
          footer={
            <>
              {remove.isError ? (
                <span role="alert" className="mr-auto text-sm text-sev-critical">
                  {errorMessage(remove.error)}
                </span>
              ) : null}
              <Button onClick={() => setConfirmDelete(null)}>Cancel</Button>
              <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate(confirmDelete.id, { onSuccess: () => setConfirmDelete(null) })}>
                Delete channel
              </Button>
            </>
          }
        />
      ) : null}
    </>
  );
}

/** Notification channels (/soar/channels, /settings/notifications). */
export default function NotificationChannelsPage() {
  const location = useLocation();
  const inSettings = location.pathname.startsWith("/settings");
  return (
    <div>
      <PageHeader
        title="Notification Channels"
        subtitle="Where alerts, escalations, approvals and scheduled reports are delivered. Every change and test send is audited."
        breadcrumbs={[inSettings ? { label: "Settings", href: "/settings" } : { label: "SOAR", href: "/soar" }, { label: "Notification Channels" }]}
        actions={
          <ButtonLink to="/automations" size="sm">
            Automation rules
          </ButtonLink>
        }
      />
      <NotificationChannelsView />
    </div>
  );
}

function ChannelDialog({ existing, onClose }: { existing: NotificationChannel | null; onClose: () => void }) {
  const session = useSession();
  const create = useCreateNotificationChannel();
  const update = useUpdateNotificationChannel();
  const initial = useState(() => initialSettings(existing))[0];
  const [name, setName] = useState(existing?.name ?? "");
  const [kind, setKind] = useState<NotificationChannelKind>(existing?.kind ?? "email");
  const [scope, setScope] = useState<string>(existing ? (existing.organizationId ?? "") : (session.organizationId ?? ""));
  const [settings, setSettings] = useState<ChannelSettingsState>(initial.state);
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [submitted, setSubmitted] = useState(false);
  const [signingSecret, setSigningSecret] = useState<string | null>(null);
  const m = existing ? update : create;
  const set = <K extends keyof ChannelSettingsState>(k: K, v: ChannelSettingsState[K]) => setSettings((cur) => ({ ...cur, [k]: v }));

  const tenantWideAllowed = session.can("settings:write", null) || session.can("playbook:write", null);
  const settingErrors = validateSettings(kind, settings, initial.stored, Boolean(existing));
  const errors = {
    name: name.trim() ? null : "Name is required",
    scope: !existing && scope === "" && !tenantWideAllowed ? "Choose an organization" : null,
  };
  const valid = Object.values(errors).every((e) => e === null) && Object.values(settingErrors).every((e) => !e);

  const submit = () => {
    setSubmitted(true);
    if (!valid) return;
    const config = buildConfig(kind, settings);
    if (existing) {
      update.mutate({ id: existing.id, patch: { name: name.trim(), enabled, config } }, { onSuccess: () => onClose() });
    } else {
      const input: CreateNotificationChannelInput = { name: name.trim(), kind, organizationId: scope || null, config, enabled };
      create.mutate(input, {
        onSuccess: (res) => {
          // A generated webhook signing secret is shown once, for the receiving system.
          const generated = (res as { signingSecret?: string }).signingSecret;
          if (generated) setSigningSecret(generated);
          else onClose();
        },
      });
    }
  };

  const err = (k: keyof typeof errors) => (submitted ? errors[k] : null);

  if (signingSecret) {
    return (
      <Dialog
        open
        onClose={onClose}
        title="Webhook signing secret"
        description="Give this secret to the receiving system to verify the X-Bloody-Signature header (HMAC-SHA256 over “timestamp.body”). It is shown only once."
        footer={
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        }
      >
        <div className="flex items-center gap-2">
          <code className="min-w-0 flex-1 break-all rounded border border-line bg-canvas px-2 py-1.5 font-mono text-xs">{signingSecret}</code>
          <CopyButton value={signingSecret} label="Copy signing secret" />
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title={existing ? `Edit ${existing.name}` : "Add notification channel"}
      size="lg"
      description="URLs, passwords, signing secrets and certificates are stored encrypted and never shown again."
      footer={
        <>
          {m.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(m.error)}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} loading={m.isPending}>
            {existing ? "Save channel" : "Add channel"}
          </Button>
        </>
      }
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name" required error={err("name")}>
            {(p) => <Input {...p} autoFocus value={name} maxLength={120} onChange={(e) => setName(e.target.value)} placeholder="SOC on-call" />}
          </Field>
          <Field label="Type" required hint={existing ? "The type of an existing channel cannot change." : undefined}>
            {(p) => (
              <Select {...p} value={kind} disabled={Boolean(existing)} onChange={(e) => setKind(NotificationChannelKind.parse(e.target.value))}>
                {CREATABLE.map((k) => (
                  <option key={k} value={k}>
                    {KIND_LABELS[k]}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <ChannelSettingsFields kind={kind} state={settings} set={set} stored={initial.stored} editing={Boolean(existing)} errors={submitted ? settingErrors : {}} />
        <Field label="Scope" error={err("scope")} hint={existing ? "Scope is fixed after creation." : "Organization channels only receive that organization's notifications."}>
          {(p) => (
            <Select {...p} value={scope} disabled={Boolean(existing)} onChange={(e) => setScope(e.target.value)}>
              {tenantWideAllowed || (existing && existing.organizationId === null) ? <option value="">All organizations (tenant-wide)</option> : <option value="">Select an organization…</option>}
              {session.organizations.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Checkbox label="Enabled" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
