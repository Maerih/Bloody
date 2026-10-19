import type { MailEncryption, MailServerView } from "@bloody/contracts";
import { Mail, Save, Send, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { errorMessage } from "../../api/client";
import { useMailServer, useRemoveMailServer, useSaveMailServer, useTestMailServer } from "../../api/hooks";
import { useSession } from "../../app/session";
import { Badge, Button, Card, Checkbox, Dialog, EmptyState, ErrorState, Field, Input, Select, Skeleton } from "../../components";
import { PageHeader } from "../../components/PageHeader";

const ENCRYPTION_LABEL: Record<MailEncryption, string> = { starttls: "STARTTLS (usually port 587)", tls: "SSL/TLS (usually port 465)" };
const DEFAULT_PORT: Record<MailEncryption, number> = { starttls: 587, tls: 465 };

/** Common providers: fill in the server and port; the person still enters their own account. */
const PRESETS: Array<{ key: string; label: string; host: string; port: number; encryption: MailEncryption; hint: string }> = [
  { key: "m365", label: "Microsoft 365 / Outlook", host: "smtp.office365.com", port: 587, encryption: "starttls", hint: "Sign in with a mailbox that has SMTP AUTH enabled." },
  { key: "google", label: "Google Workspace / Gmail", host: "smtp.gmail.com", port: 587, encryption: "starttls", hint: "Use an app password (2-step verification must be on)." },
  { key: "ses", label: "Amazon SES", host: "email-smtp.eu-west-1.amazonaws.com", port: 587, encryption: "starttls", hint: "Change the region in the server name; use SES SMTP credentials." },
  { key: "sendgrid", label: "SendGrid", host: "smtp.sendgrid.net", port: 587, encryption: "starttls", hint: "User name is “apikey”; the password is the API key." },
  { key: "mailgun", label: "Mailgun", host: "smtp.mailgun.org", port: 587, encryption: "starttls", hint: "Use the SMTP credentials of your sending domain." },
];

interface FormState {
  host: string;
  port: string;
  encryption: MailEncryption;
  signIn: boolean;
  username: string;
  password: string;
  fromAddress: string;
  fromName: string;
}

function initialForm(view: MailServerView): FormState {
  const a = view.account;
  return {
    host: a?.host ?? "",
    port: String(a?.port ?? 587),
    encryption: a?.encryption ?? "starttls",
    signIn: a ? a.username !== null : true,
    username: a?.username ?? "",
    password: "",
    fromAddress: a?.fromAddress ?? "",
    fromName: a?.fromName ?? "SCIAT Security Operations",
  };
}

function CurrentServer({ view }: { view: MailServerView }) {
  if (view.source === "account" && view.account) {
    const a = view.account;
    return (
      <p className="text-sm">
        <Badge size="xs" tone="success">
          Your mail server
        </Badge>{" "}
        Mail is sent through <span className="font-medium">{a.host}:{a.port}</span> as <span className="font-medium">{a.fromName ? `${a.fromName} <${a.fromAddress}>` : a.fromAddress}</span>.
      </p>
    );
  }
  if (view.source === "platform") {
    return (
      <p className="text-sm">
        <Badge size="xs" tone="info">
          Platform default
        </Badge>{" "}
        {view.platform ? (
          <>
            Mail is sent through the platform's server <span className="font-medium">{view.platform.host}:{view.platform.port}</span> as <span className="font-medium">{view.platform.fromAddress}</span>. Set your own below to send from your domain.
          </>
        ) : (
          "Mail is sent through the platform's default server."
        )}
      </p>
    );
  }
  return (
    <p className="text-sm">
      <Badge size="xs" tone="warning">
        Not set up
      </Badge>{" "}
      No mail server yet: e-mail notifications, scheduled reports, training invitations and phishing simulations cannot be sent until you add one.
    </p>
  );
}

function ServerForm({ view, save }: { view: MailServerView; save: ReturnType<typeof useSaveMailServer> }) {
  const [f, setF] = useState<FormState>(() => initialForm(view));
  const [submitted, setSubmitted] = useState(false);
  const [preset, setPreset] = useState("");
  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setF((cur) => ({ ...cur, [k]: v }));
  const a = view.account;
  // The stored password is kept unless the server or user changes (then it must be entered again).
  const keepsPassword = Boolean(a?.hasPassword && f.signIn && a.host === f.host.trim().toLowerCase() && a.username === f.username.trim());
  const port = Number(f.port);
  const errors = {
    host: /^[A-Za-z0-9.-]+$/.test(f.host.trim()) ? null : "Enter the server name, e.g. smtp.office365.com (no http:// or port)",
    port: Number.isInteger(port) && port > 0 && port < 65536 ? null : "Port 1–65535",
    username: f.signIn && !f.username.trim() ? "Enter the user name" : null,
    password: f.signIn && !keepsPassword && !f.password ? (a?.hasPassword ? "Enter the password again (the server or user changed)" : "Enter the password") : null,
    fromAddress: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(f.fromAddress.trim()) ? null : "Enter the address mail is sent from",
  };
  const err = (k: keyof typeof errors) => (submitted ? errors[k] : null);
  const presetHint = PRESETS.find((p) => p.key === preset)?.hint;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setSubmitted(true);
    if (Object.values(errors).some(Boolean)) return;
    save.mutate(
      {
        host: f.host.trim(),
        port,
        encryption: f.encryption,
        username: f.signIn ? f.username.trim() : null,
        ...(f.signIn && f.password ? { password: f.password } : {}),
        fromAddress: f.fromAddress.trim(),
        fromName: f.fromName.trim() || null,
      },
      { onSuccess: () => (setF((cur) => ({ ...cur, password: "" })), setSubmitted(false)) },
    );
  };

  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      <div className="grid gap-4 md:grid-cols-2">
        <Field label="Provider" hint={presetHint ?? "Fills in the server and port. Choose “Other” for any SMTP server."}>
          {(p) => (
            <Select
              {...p}
              value={preset}
              onChange={(e) => {
                setPreset(e.target.value);
                const pr = PRESETS.find((x) => x.key === e.target.value);
                if (pr) setF((cur) => ({ ...cur, host: pr.host, port: String(pr.port), encryption: pr.encryption, signIn: true, ...(pr.key === "sendgrid" ? { username: "apikey" } : {}) }));
              }}
            >
              <option value="">Other / my own server</option>
              {PRESETS.map((p) => (
                <option key={p.key} value={p.key}>
                  {p.label}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <div />
        <Field label="SMTP server" required error={err("host")}>
          {(p) => <Input {...p} value={f.host} placeholder="smtp.example.com" autoComplete="off" onChange={(e) => set("host", e.target.value)} />}
        </Field>
        <div className="grid grid-cols-[1fr_7rem] gap-3">
          <Field label="Encryption" required hint="Connections always use TLS with certificate checks.">
            {(p) => (
              <Select
                {...p}
                value={f.encryption}
                onChange={(e) => {
                  const next = e.target.value as MailEncryption;
                  // Follow the usual port unless a custom one was entered.
                  setF((cur) => ({ ...cur, encryption: next, port: cur.port === String(DEFAULT_PORT[cur.encryption]) ? String(DEFAULT_PORT[next]) : cur.port }));
                }}
              >
                {(Object.keys(ENCRYPTION_LABEL) as MailEncryption[]).map((k) => (
                  <option key={k} value={k}>
                    {ENCRYPTION_LABEL[k]}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Port" required error={err("port")}>
            {(p) => <Input {...p} inputMode="numeric" value={f.port} onChange={(e) => set("port", e.target.value.replace(/\D/g, "").slice(0, 5))} />}
          </Field>
        </div>
      </div>
      <Checkbox label="The server requires signing in (user name and password)" checked={f.signIn} onChange={(e) => set("signIn", e.target.checked)} />
      {f.signIn ? (
        <div className="grid gap-4 md:grid-cols-2">
          <Field label="User name" required error={err("username")}>
            {(p) => <Input {...p} value={f.username} autoComplete="off" onChange={(e) => set("username", e.target.value)} />}
          </Field>
          <Field label="Password" required={!keepsPassword} error={err("password")} hint={keepsPassword ? "Saved and encrypted. Leave empty to keep it." : "Stored encrypted; it is never shown again."}>
            {(p) => <Input {...p} type="password" value={f.password} autoComplete="new-password" placeholder={keepsPassword ? "••••••••" : ""} onChange={(e) => set("password", e.target.value)} />}
          </Field>
        </div>
      ) : null}
      <div className="grid gap-4 md:grid-cols-2">
        <Field label="From address" required error={err("fromAddress")} hint="Must be an address the server is allowed to send as.">
          {(p) => <Input {...p} type="email" value={f.fromAddress} placeholder="soc@yourcompany.com" onChange={(e) => set("fromAddress", e.target.value)} />}
        </Field>
        <Field label="From name" hint="What recipients see as the sender.">
          {(p) => <Input {...p} value={f.fromName} maxLength={120} onChange={(e) => set("fromName", e.target.value)} />}
        </Field>
      </div>
      {save.error ? (
        <p role="alert" className="text-sm text-sev-critical">
          {errorMessage(save.error)}
        </p>
      ) : save.isSuccess ? (
        <p role="status" className="text-sm text-healthy">
          Saved. Send a test message to check it.
        </p>
      ) : null}
      <div className="flex justify-end">
        <Button type="submit" variant="primary" icon={Save} loading={save.isPending}>
          Save mail server
        </Button>
      </div>
    </form>
  );
}

function TestSend({ disabled }: { disabled: boolean }) {
  const session = useSession();
  const test = useTestMailServer();
  const [to, setTo] = useState(session.principal.email ?? "");
  return (
    <form
      className="flex flex-wrap items-end gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (to.trim()) test.mutate(to.trim());
      }}
    >
      <Field label="Send a test message to" className="min-w-64 flex-1">
        {(p) => <Input {...p} type="email" value={to} onChange={(e) => setTo(e.target.value)} />}
      </Field>
      <Button type="submit" icon={Send} loading={test.isPending} disabled={disabled || !to.trim()}>
        Send test
      </Button>
      {test.error ? (
        <p role="alert" className="w-full text-sm text-sev-critical">
          {errorMessage(test.error)}
        </p>
      ) : test.data ? (
        <p role="status" className="w-full text-sm text-healthy">
          {test.data.message}. Check the inbox (and spam folder).
        </p>
      ) : null}
    </form>
  );
}

/** Settings → Email server: the account's outgoing mail (SMTP) server. */
export default function EmailServerPage() {
  const session = useSession();
  const canManage = session.can("settings:write", null);
  const view = useMailServer({ enabled: canManage });
  const remove = useRemoveMailServer();
  // Held here so the result stays visible when the form resets after the first save.
  const save = useSaveMailServer();
  const [confirmRemove, setConfirmRemove] = useState(false);
  const header = (
    <PageHeader
      title="Email server"
      subtitle="The SMTP server SCIAT sends mail through: e-mail notifications, scheduled reports, training invitations and phishing simulations."
      breadcrumbs={[{ label: "Settings", href: "/settings" }, { label: "Email server" }]}
    />
  );
  if (!canManage) {
    return (
      <div>
        {header}
        <div className="rounded border border-line bg-surface shadow-card">
          <EmptyState icon={Mail} title="You don't have access to the email server" description="Changing it needs account-wide settings permission (settings:write)." />
        </div>
      </div>
    );
  }
  return (
    <div className="space-y-3">
      {header}
      {view.isPending ? (
        <Skeleton className="h-64" />
      ) : view.isError ? (
        <ErrorState error={view.error} onRetry={() => void view.refetch()} />
      ) : (
        <>
          <Card
            title="Mail server"
            actions={
              view.data.account ? (
                <Button size="sm" variant="ghost" icon={Trash2} onClick={() => setConfirmRemove(true)}>
                  {view.data.platform ? "Use platform default" : "Remove"}
                </Button>
              ) : undefined
            }
          >
            <div className="space-y-4">
              <CurrentServer view={view.data} />
              <ServerForm key={view.data.account ? "account" : "new"} view={view.data} save={save} />
            </div>
          </Card>
          <Card title="Test">
            <TestSend disabled={view.data.source === "none"} />
          </Card>
          <p className="text-xs text-fg-muted">
            A notification channel can use a different server: edit the channel under Notification Channels. Mail servers on this machine or cloud metadata addresses are refused.
          </p>
        </>
      )}
      <Dialog
        open={confirmRemove}
        onClose={() => setConfirmRemove(false)}
        size="sm"
        title={view.data?.platform ? "Go back to the platform default?" : "Remove the mail server?"}
        description={view.data?.platform ? "Mail will be sent through the platform's server and address again. The saved password is deleted." : "SCIAT will not be able to send e-mail until a mail server is added again. The saved password is deleted."}
        footer={
          <>
            <Button onClick={() => setConfirmRemove(false)}>Cancel</Button>
            <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate(undefined, { onSuccess: () => setConfirmRemove(false) })}>
              {view.data?.platform ? "Use platform default" : "Remove"}
            </Button>
          </>
        }
      >
        {remove.error ? <p className="text-sm text-sev-critical">{errorMessage(remove.error)}</p> : null}
      </Dialog>
    </div>
  );
}
