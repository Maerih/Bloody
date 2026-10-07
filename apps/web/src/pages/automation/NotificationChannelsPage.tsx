import { NotificationChannelKind, type NotificationChannel } from "@bloody/contracts";
import { Plus, Send, Webhook } from "lucide-react";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { errorMessage } from "../../api/client";
import { useCreateNotificationChannel, useNotificationChannels, useTestNotificationChannel } from "../../api/hooks";
import type { CreateNotificationChannelInput } from "../../api/types";
import { useSession } from "../../app/session";
import { Badge, StatusBadge } from "../../components/Badge";
import { Button, ButtonLink } from "../../components/Button";
import { DataTable, type DataTableColumn } from "../../components/DataTable";
import { EmptyState } from "../../components/EmptyState";
import { Checkbox, Field, Input, Select, Textarea } from "../../components/Form";
import { Dialog } from "../../components/Overlay";
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

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function parseRecipients(text: string): { valid: string[]; invalid: string[] } {
  const parts = text
    .split(/[\s,;]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  const unique = [...new Set(parts.map((p) => p.toLowerCase()))];
  return { valid: unique.filter((p) => EMAIL_RE.test(p)), invalid: unique.filter((p) => !EMAIL_RE.test(p)) };
}

/** Only https endpoints; the API additionally applies its SSRF guard. */
export function isSafeWebhookUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname.length > 0 && !url.username && !url.password;
  } catch {
    return false;
  }
}

function targetSummary(c: NotificationChannel): string {
  const cfg = c.config as Record<string, unknown>;
  if (c.kind === "email" && Array.isArray(cfg.to)) return (cfg.to as unknown[]).map(String).join(", ");
  if (c.kind === "syslog" && typeof cfg.host === "string") return `${cfg.host}:${String(cfg.port ?? 514)}`;
  if (c.kind === "slack" || c.kind === "teams" || c.kind === "webhook") return "Endpoint configured (stored as secret)";
  return "—";
}

function canManageChannels(session: ReturnType<typeof useSession>): boolean {
  return session.canAnywhere("settings:write") || session.canAnywhere("playbook:write");
}

/** Notification channels (/soar/channels): email lists, Slack, Teams, webhooks and syslog. */
export default function NotificationChannelsPage() {
  const session = useSession();
  const [params, setParams] = useSearchParams();
  const channels = useNotificationChannels();
  const test = useTestNotificationChannel();
  const canManage = canManageChannels(session);
  const [createOpen, setCreateOpen] = useState(params.get("create") === "1" && canManage);

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
      id: "test",
      header: "",
      sortable: false,
      hideable: false,
      cell: (c) => (
        <Button size="xs" icon={Send} disabled={!c.enabled} loading={test.isPending && test.variables === c.id} onClick={(e) => { e.stopPropagation(); test.mutate(c.id); }}>
          Send test
        </Button>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Notification Channels"
        subtitle="Where alerts, escalations, approvals and scheduled reports are delivered. Every change and test send is audited."
        breadcrumbs={[{ label: "SOAR", href: "/soar" }, { label: "Notification Channels" }]}
        actions={
          <>
            <ButtonLink to="/soar/automations" size="sm">
              Automation rules
            </ButtonLink>
            {canManage ? (
              <Button variant="primary" icon={Plus} onClick={() => setCreateOpen(true)}>
                Add channel
              </Button>
            ) : null}
          </>
        }
      />
      {test.isSuccess ? (
        <p role="status" className="mb-2 text-sm text-healthy">
          {test.data?.message ?? "Test notification sent."}
        </p>
      ) : test.isError ? (
        <p role="alert" className="mb-2 text-sm text-sev-critical">
          {errorMessage(test.error)}
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
        initialState={{ sort: { columnId: "name", direction: "asc" } }}
        savedViewsKey="notification-channels"
        exportFileName="bloody-notification-channels"
        emptyState={
          <EmptyState
            icon={Webhook}
            title="No notification channels yet"
            description="Add an email distribution list, Slack or Teams channel, webhook or syslog target."
            action={canManage ? <Button variant="primary" size="sm" icon={Plus} onClick={() => setCreateOpen(true)}>Add channel</Button> : undefined}
          />
        }
      />
      {createOpen ? (
        <CreateChannelDialog
          onClose={() => {
            setCreateOpen(false);
            setParams((prev) => {
              const next = new URLSearchParams(prev);
              next.delete("create");
              return next;
            });
          }}
        />
      ) : null}
    </div>
  );
}

function CreateChannelDialog({ onClose }: { onClose: () => void }) {
  const session = useSession();
  const create = useCreateNotificationChannel();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<NotificationChannelKind>("email");
  const [scope, setScope] = useState<string>(session.organizationId ?? "");
  const [recipients, setRecipients] = useState("");
  const [url, setUrl] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("514");
  const [enabled, setEnabled] = useState(true);
  const [submitted, setSubmitted] = useState(false);

  const tenantWideAllowed = session.can("settings:write", null) || session.can("playbook:write", null);
  const parsedRecipients = parseRecipients(recipients);
  const portNum = Number(port);
  const errors = {
    name: name.trim() ? null : "Name is required",
    recipients:
      kind !== "email" ? null : parsedRecipients.invalid.length > 0 ? `Invalid address: ${parsedRecipients.invalid[0]}` : parsedRecipients.valid.length === 0 ? "Add at least one recipient" : null,
    url: kind === "slack" || kind === "teams" || kind === "webhook" ? (isSafeWebhookUrl(url.trim()) ? null : "Enter an https:// URL") : null,
    host: kind === "syslog" ? (/^[a-zA-Z0-9.-]+$/.test(host.trim()) ? null : "Enter a hostname or IP") : null,
    port: kind === "syslog" ? (Number.isInteger(portNum) && portNum > 0 && portNum < 65536 ? null : "Port 1–65535") : null,
    scope: scope === "" && !tenantWideAllowed ? "Choose an organization" : null,
  };
  const valid = Object.values(errors).every((e) => e === null);

  const config = (): Record<string, unknown> => {
    switch (kind) {
      case "email":
        return { to: parsedRecipients.valid };
      case "syslog":
        return { host: host.trim(), port: portNum };
      default:
        return { url: url.trim() };
    }
  };

  const submit = () => {
    setSubmitted(true);
    if (!valid) return;
    const input: CreateNotificationChannelInput = { name: name.trim(), kind, organizationId: scope || null, config: config(), enabled };
    create.mutate(input, { onSuccess: () => onClose() });
  };

  const err = (k: keyof typeof errors) => (submitted ? errors[k] : null);

  return (
    <Dialog
      open
      onClose={onClose}
      title="Add notification channel"
      description="Webhook, Slack and Teams URLs are stored encrypted and never shown again."
      footer={
        <>
          {create.isError ? (
            <span role="alert" className="mr-auto text-sm text-sev-critical">
              {errorMessage(create.error)}
            </span>
          ) : null}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} loading={create.isPending}>
            Add channel
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
          <Field label="Type" required>
            {(p) => (
              <Select {...p} value={kind} onChange={(e) => setKind(NotificationChannelKind.parse(e.target.value))}>
                {CREATABLE.map((k) => (
                  <option key={k} value={k}>
                    {KIND_LABELS[k]}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        {kind === "email" ? (
          <Field label="Recipients" required error={err("recipients")} hint="Separate addresses with commas or new lines.">
            {(p) => <Textarea {...p} value={recipients} onChange={(e) => setRecipients(e.target.value)} placeholder="soc@example.com, ciso@example.com" />}
          </Field>
        ) : kind === "syslog" ? (
          <div className="grid grid-cols-[minmax(0,1fr)_120px] gap-3">
            <Field label="Host" required error={err("host")}>
              {(p) => <Input {...p} value={host} onChange={(e) => setHost(e.target.value)} placeholder="siem.example.internal" />}
            </Field>
            <Field label="Port" required error={err("port")}>
              {(p) => <Input {...p} inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))} />}
            </Field>
          </div>
        ) : (
          <Field label={`${KIND_LABELS[kind]} URL`} required error={err("url")} hint="Write-only. Private and link-local addresses are rejected by the server.">
            {(p) => <Input {...p} type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://" autoComplete="off" />}
          </Field>
        )}
        <Field label="Scope" error={err("scope")} hint="Organization channels only receive that organization's notifications.">
          {(p) => (
            <Select {...p} value={scope} onChange={(e) => setScope(e.target.value)}>
              {tenantWideAllowed ? <option value="">All organizations (tenant-wide)</option> : <option value="">Select an organization…</option>}
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
