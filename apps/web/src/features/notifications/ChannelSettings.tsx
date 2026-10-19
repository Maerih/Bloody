import type { NotificationChannel, NotificationChannelKind } from "@bloody/contracts";
import { Checkbox, Field, Input, Select, Textarea } from "../../components/Form";

/**
 * Every setting of a notification channel, per type. Secrets (URLs, signing secret,
 * Authorization header, SMTP password, CA bundle) are write-only: left empty they keep the
 * stored value; the server re-asks for a credential when the destination changes.
 */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HOST_RE = /^[A-Za-z0-9.:-]+$/;
const HEADER_NAME_RE = /^[A-Za-z0-9-]{1,64}$/;
const RESERVED_HEADERS = new Set(["host", "content-type", "content-length", "authorization", "user-agent", "connection", "transfer-encoding", "cookie"]);

export const SYSLOG_FACILITIES = [
  "kernel",
  "user",
  "mail",
  "system daemons",
  "security / auth",
  "syslogd",
  "printer",
  "news",
  "UUCP",
  "cron",
  "security / authpriv",
  "FTP",
  "NTP",
  "log audit",
  "log alert",
  "clock",
  ...Array.from({ length: 8 }, (_, i) => `local${i}`),
];

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

/** "Name: value" per line → headers; errors name the first bad line. */
export function parseHeaders(text: string): { headers: Record<string, string>; error: string | null } {
  const headers: Record<string, string> = {};
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const i = line.indexOf(":");
    const name = i > 0 ? line.slice(0, i).trim() : "";
    const value = i > 0 ? line.slice(i + 1).trim() : "";
    if (!HEADER_NAME_RE.test(name)) return { headers, error: `“${line.slice(0, 40)}” is not “Name: value”` };
    if (RESERVED_HEADERS.has(name.toLowerCase()) || name.toLowerCase().startsWith("x-bloody-")) return { headers, error: `${name} is set by SCIAT and cannot be changed${name.toLowerCase() === "authorization" ? " here (use the Authorization field)" : ""}` };
    headers[name] = value;
  }
  if (Object.keys(headers).length > 20) return { headers, error: "At most 20 headers" };
  return { headers, error: null };
}

export interface ChannelSettingsState {
  // email
  to: string;
  cc: string;
  bcc: string;
  replyTo: string;
  subjectPrefix: string;
  ownServer: boolean;
  smtpHost: string;
  smtpPort: string;
  smtpEncryption: "starttls" | "tls";
  smtpSignIn: boolean;
  smtpUser: string;
  smtpPassword: string;
  smtpFromAddress: string;
  smtpFromName: string;
  // slack / teams / webhook
  url: string;
  mentionOnCritical: "" | "here" | "channel";
  signingSecret: string;
  authorization: string;
  removeAuthorization: boolean;
  headers: string;
  includeData: boolean;
  // syslog
  host: string;
  port: string;
  protocol: "tls" | "tcp" | "udp";
  facility: string;
  appName: string;
  ca: string;
  removeCa: boolean;
}

/** What the stored channel already holds (secrets only as "is set"). */
export interface StoredSecrets {
  url: boolean;
  signingSecret: boolean;
  authorization: boolean;
  smtpPassword: boolean;
  ca: boolean;
  smtpHost: string | null;
  smtpUser: string | null;
}

const str = (v: unknown, d = "") => (typeof v === "string" ? v : d);
const list = (v: unknown) => (Array.isArray(v) ? v.map(String).join(", ") : "");

export function initialSettings(c: NotificationChannel | null): { state: ChannelSettingsState; stored: StoredSecrets } {
  const cfg = (c?.config ?? {}) as Record<string, unknown>;
  const smtp = (cfg.smtp ?? null) as Record<string, unknown> | null;
  const protocol = (["tls", "tcp", "udp"].includes(str(cfg.protocol)) ? cfg.protocol : "tls") as ChannelSettingsState["protocol"];
  const headers = cfg.headers && typeof cfg.headers === "object" ? Object.entries(cfg.headers as Record<string, string>).map(([k, v]) => `${k}: ${v}`).join("\n") : "";
  return {
    state: {
      to: list(cfg.to),
      cc: list(cfg.cc),
      bcc: list(cfg.bcc),
      replyTo: str(cfg.replyTo),
      subjectPrefix: str(cfg.subjectPrefix),
      ownServer: smtp !== null,
      smtpHost: str(smtp?.host),
      smtpPort: smtp?.port !== undefined ? String(smtp.port) : "587",
      smtpEncryption: smtp?.secure === true ? "tls" : "starttls",
      smtpSignIn: smtp ? typeof smtp.user === "string" && smtp.user.length > 0 : true,
      smtpUser: str(smtp?.user),
      smtpPassword: "",
      smtpFromAddress: str(smtp?.fromAddress),
      smtpFromName: str(smtp?.fromName),
      url: "",
      mentionOnCritical: (cfg.mentionOnCritical === "here" || cfg.mentionOnCritical === "channel" ? cfg.mentionOnCritical : "") as ChannelSettingsState["mentionOnCritical"],
      signingSecret: "",
      authorization: "",
      removeAuthorization: false,
      headers,
      includeData: cfg.includeData !== false,
      host: str(cfg.host),
      port: cfg.port !== undefined ? String(cfg.port) : protocol === "tls" ? "6514" : "514",
      protocol,
      facility: typeof cfg.facility === "number" ? String(cfg.facility) : "13",
      appName: str(cfg.appName, "sciat"),
      ca: "",
      removeCa: false,
    },
    stored: {
      url: cfg.hasUrl === true,
      signingSecret: cfg.hasSecret === true,
      authorization: cfg.hasAuthorization === true,
      smtpPassword: smtp?.hasPassword === true,
      ca: cfg.hasCa === true,
      smtpHost: smtp ? str(smtp.host) : null,
      smtpUser: smtp ? str(smtp.user) || null : null,
    },
  };
}

type Errors = Partial<Record<keyof ChannelSettingsState, string | null>>;

export function validateSettings(kind: NotificationChannelKind, s: ChannelSettingsState, stored: StoredSecrets, editing: boolean): Errors {
  const e: Errors = {};
  const port = (v: string) => (Number.isInteger(Number(v)) && Number(v) > 0 && Number(v) < 65536 ? null : "Port 1–65535");
  if (kind === "email") {
    const to = parseRecipients(s.to);
    e.to = to.invalid.length ? `Invalid address: ${to.invalid[0]}` : to.valid.length === 0 ? "Add at least one recipient" : null;
    for (const k of ["cc", "bcc"] as const) {
      const p = parseRecipients(s[k]);
      e[k] = p.invalid.length ? `Invalid address: ${p.invalid[0]}` : null;
    }
    e.replyTo = s.replyTo.trim() && !EMAIL_RE.test(s.replyTo.trim()) ? "Enter one e-mail address" : null;
    if (s.ownServer) {
      e.smtpHost = /^[A-Za-z0-9.-]+$/.test(s.smtpHost.trim()) ? null : "Enter the server name (no http:// or port)";
      e.smtpPort = port(s.smtpPort);
      e.smtpUser = s.smtpSignIn && !s.smtpUser.trim() ? "Enter the user name" : null;
      const keeps = stored.smtpPassword && stored.smtpHost === s.smtpHost.trim() && stored.smtpUser === s.smtpUser.trim();
      e.smtpPassword = s.smtpSignIn && !s.smtpPassword && !keeps ? (stored.smtpPassword ? "Enter the password again (server or user changed)" : "Enter the password") : null;
      e.smtpFromAddress = EMAIL_RE.test(s.smtpFromAddress.trim()) ? null : "Enter the address mail is sent from";
    }
  }
  if (kind === "slack" || kind === "teams" || kind === "webhook") {
    const keepUrl = editing && stored.url && s.url.trim() === "";
    e.url = keepUrl ? null : isSafeWebhookUrl(s.url.trim()) ? null : "Enter an https:// URL";
  }
  if (kind === "webhook") {
    e.headers = parseHeaders(s.headers).error;
    if (editing && stored.authorization && s.url.trim() && !s.authorization && !s.removeAuthorization) e.authorization = "Enter the Authorization value again for the new URL, or remove it";
  }
  if (kind === "syslog") {
    e.host = HOST_RE.test(s.host.trim()) ? null : "Enter a hostname or IP address";
    e.port = port(s.port);
    e.appName = /^[\x21-\x7e]{1,48}$/.test(s.appName) ? null : "1–48 characters, no spaces";
    e.ca = s.ca.trim() && !s.ca.includes("-----BEGIN CERTIFICATE-----") ? "Paste a PEM certificate (-----BEGIN CERTIFICATE-----)" : null;
  }
  return e;
}

/** The config to send. Secrets are included only when typed (null removes one). */
export function buildConfig(kind: NotificationChannelKind, s: ChannelSettingsState): Record<string, unknown> {
  switch (kind) {
    case "email":
      return {
        to: parseRecipients(s.to).valid,
        cc: parseRecipients(s.cc).valid,
        bcc: parseRecipients(s.bcc).valid,
        ...(s.replyTo.trim() ? { replyTo: s.replyTo.trim() } : {}),
        ...(s.subjectPrefix.trim() ? { subjectPrefix: s.subjectPrefix.trim() } : {}),
        smtp: s.ownServer
          ? {
              host: s.smtpHost.trim().toLowerCase(),
              port: Number(s.smtpPort),
              secure: s.smtpEncryption === "tls",
              ...(s.smtpSignIn ? { user: s.smtpUser.trim() } : {}),
              ...(s.smtpSignIn && s.smtpPassword ? { password: s.smtpPassword } : !s.smtpSignIn ? { password: null } : {}),
              fromAddress: s.smtpFromAddress.trim(),
              ...(s.smtpFromName.trim() ? { fromName: s.smtpFromName.trim() } : {}),
            }
          : null,
      };
    case "slack":
      return { ...(s.url.trim() ? { url: s.url.trim() } : {}), mentionOnCritical: s.mentionOnCritical || null };
    case "teams":
      return s.url.trim() ? { url: s.url.trim() } : {};
    case "webhook": {
      const { headers } = parseHeaders(s.headers);
      return {
        ...(s.url.trim() ? { url: s.url.trim() } : {}),
        ...(s.signingSecret ? { secret: s.signingSecret } : {}),
        ...(s.removeAuthorization ? { authorization: null } : s.authorization ? { authorization: s.authorization } : {}),
        ...(Object.keys(headers).length ? { headers } : {}),
        includeData: s.includeData,
      };
    }
    case "syslog":
      return {
        host: s.host.trim(),
        port: Number(s.port),
        protocol: s.protocol,
        facility: Number(s.facility),
        appName: s.appName,
        ...(s.removeCa ? { ca: null } : s.ca.trim() ? { ca: s.ca.trim() } : {}),
      };
    default:
      return {};
  }
}

const URL_HINT: Partial<Record<NotificationChannelKind, string>> = {
  slack: "Slack → Apps → Incoming Webhooks → Add New Webhook (https://hooks.slack.com/…).",
  teams: "Teams channel → Workflows → “Post to a channel when a webhook request is received”, or a Power Automate URL.",
  webhook: "Any https endpoint. SCIAT POSTs JSON signed with HMAC-SHA256 (header X-Bloody-Signature).",
};

export function ChannelSettingsFields({
  kind,
  state: s,
  set,
  stored,
  editing,
  errors,
}: {
  kind: NotificationChannelKind;
  state: ChannelSettingsState;
  set: <K extends keyof ChannelSettingsState>(k: K, v: ChannelSettingsState[K]) => void;
  stored: StoredSecrets;
  editing: boolean;
  errors: Errors;
}) {
  const err = (k: keyof ChannelSettingsState) => errors[k] ?? null;
  const secretHint = (has: boolean, what: string) => (editing && has ? `Stored encrypted. Leave empty to keep the current ${what}.` : undefined);

  if (kind === "email") {
    return (
      <div className="space-y-3">
        <Field label="To" required error={err("to")} hint="Separate addresses with commas or new lines.">
          {(p) => <Textarea {...p} rows={2} value={s.to} onChange={(e) => set("to", e.target.value)} placeholder="soc@example.com, ciso@example.com" />}
        </Field>
        <div className="grid gap-3 md:grid-cols-2">
          <Field label="Cc" error={err("cc")}>
            {(p) => <Input {...p} value={s.cc} onChange={(e) => set("cc", e.target.value)} />}
          </Field>
          <Field label="Bcc" error={err("bcc")}>
            {(p) => <Input {...p} value={s.bcc} onChange={(e) => set("bcc", e.target.value)} />}
          </Field>
          <Field label="Reply-to" error={err("replyTo")}>
            {(p) => <Input {...p} type="email" value={s.replyTo} onChange={(e) => set("replyTo", e.target.value)} placeholder="soc-desk@example.com" />}
          </Field>
          <Field label="Subject prefix" hint="e.g. [SOC]">
            {(p) => <Input {...p} value={s.subjectPrefix} maxLength={40} onChange={(e) => set("subjectPrefix", e.target.value)} />}
          </Field>
        </div>
        <Field label="Send through">
          {(p) => (
            <Select {...p} value={s.ownServer ? "own" : "account"} onChange={(e) => set("ownServer", e.target.value === "own")}>
              <option value="account">The account's email server (Settings → Email server)</option>
              <option value="own">A different mail server for this channel</option>
            </Select>
          )}
        </Field>
        {s.ownServer ? (
          <div className="space-y-3 rounded border border-line p-3">
            <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_11rem_6rem]">
              <Field label="SMTP server" required error={err("smtpHost")}>
                {(p) => <Input {...p} value={s.smtpHost} placeholder="smtp.example.com" autoComplete="off" onChange={(e) => set("smtpHost", e.target.value)} />}
              </Field>
              <Field label="Encryption" required>
                {(p) => (
                  <Select
                    {...p}
                    value={s.smtpEncryption}
                    onChange={(e) => {
                      const next = e.target.value as "starttls" | "tls";
                      set("smtpEncryption", next);
                      if (s.smtpPort === (next === "tls" ? "587" : "465")) set("smtpPort", next === "tls" ? "465" : "587");
                    }}
                  >
                    <option value="starttls">STARTTLS</option>
                    <option value="tls">SSL/TLS</option>
                  </Select>
                )}
              </Field>
              <Field label="Port" required error={err("smtpPort")}>
                {(p) => <Input {...p} inputMode="numeric" value={s.smtpPort} onChange={(e) => set("smtpPort", e.target.value.replace(/\D/g, "").slice(0, 5))} />}
              </Field>
            </div>
            <Checkbox label="The server requires signing in" checked={s.smtpSignIn} onChange={(e) => set("smtpSignIn", e.target.checked)} />
            {s.smtpSignIn ? (
              <div className="grid gap-3 md:grid-cols-2">
                <Field label="User name" required error={err("smtpUser")}>
                  {(p) => <Input {...p} value={s.smtpUser} autoComplete="off" onChange={(e) => set("smtpUser", e.target.value)} />}
                </Field>
                <Field label="Password" error={err("smtpPassword")} hint={secretHint(stored.smtpPassword, "password")}>
                  {(p) => <Input {...p} type="password" value={s.smtpPassword} autoComplete="new-password" placeholder={editing && stored.smtpPassword ? "••••••••" : ""} onChange={(e) => set("smtpPassword", e.target.value)} />}
                </Field>
              </div>
            ) : null}
            <div className="grid gap-3 md:grid-cols-2">
              <Field label="From address" required error={err("smtpFromAddress")}>
                {(p) => <Input {...p} type="email" value={s.smtpFromAddress} onChange={(e) => set("smtpFromAddress", e.target.value)} />}
              </Field>
              <Field label="From name">
                {(p) => <Input {...p} value={s.smtpFromName} maxLength={120} onChange={(e) => set("smtpFromName", e.target.value)} />}
              </Field>
            </div>
          </div>
        ) : null}
      </div>
    );
  }

  if (kind === "syslog") {
    return (
      <div className="space-y-3">
        <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_11rem_6rem]">
          <Field label="Collector host" required error={err("host")}>
            {(p) => <Input {...p} value={s.host} onChange={(e) => set("host", e.target.value)} placeholder="siem.example.com" />}
          </Field>
          <Field label="Protocol" required>
            {(p) => (
              <Select
                {...p}
                value={s.protocol}
                onChange={(e) => {
                  const next = e.target.value as ChannelSettingsState["protocol"];
                  set("protocol", next);
                  if (s.port === "514" || s.port === "6514") set("port", next === "tls" ? "6514" : "514");
                }}
              >
                <option value="tls">TLS (encrypted)</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </Select>
            )}
          </Field>
          <Field label="Port" required error={err("port")}>
            {(p) => <Input {...p} inputMode="numeric" value={s.port} onChange={(e) => set("port", e.target.value.replace(/\D/g, "").slice(0, 5))} />}
          </Field>
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          <Field label="Facility">
            {(p) => (
              <Select {...p} value={s.facility} onChange={(e) => set("facility", e.target.value)}>
                {SYSLOG_FACILITIES.map((f, i) => (
                  <option key={f} value={String(i)}>
                    {i} — {f}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="App name" error={err("appName")} hint="APP-NAME field of each RFC 5424 message.">
            {(p) => <Input {...p} value={s.appName} maxLength={48} onChange={(e) => set("appName", e.target.value)} />}
          </Field>
        </div>
        {s.protocol === "tls" ? (
          <Field label="CA certificate (optional)" error={err("ca")} hint={secretHint(stored.ca, "certificate") ?? "Only for a collector with a private certificate authority. PEM format."}>
            {(p) => <Textarea {...p} rows={3} className="font-mono text-xs" value={s.ca} disabled={s.removeCa} onChange={(e) => set("ca", e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />}
          </Field>
        ) : (
          <p className="text-xs text-sev-medium">TCP and UDP send alerts unencrypted. Use them only on a trusted network.</p>
        )}
        {editing && stored.ca && s.protocol === "tls" ? <Checkbox label="Remove the stored CA certificate" checked={s.removeCa} onChange={(e) => set("removeCa", e.target.checked)} /> : null}
      </div>
    );
  }

  // slack / teams / webhook
  return (
    <div className="space-y-3">
      <Field
        label={kind === "webhook" ? "URL" : `${kind === "slack" ? "Slack" : "Teams"} webhook URL`}
        required={!editing || !stored.url}
        error={err("url")}
        hint={secretHint(stored.url, "URL") ?? URL_HINT[kind]}
      >
        {(p) => <Input {...p} type="url" value={s.url} onChange={(e) => set("url", e.target.value)} placeholder={editing && stored.url ? "••• stored" : "https://"} autoComplete="off" />}
      </Field>
      {kind === "slack" ? (
        <Field label="Mention on critical alerts">
          {(p) => (
            <Select {...p} value={s.mentionOnCritical} onChange={(e) => set("mentionOnCritical", e.target.value as ChannelSettingsState["mentionOnCritical"])}>
              <option value="">No mention</option>
              <option value="here">@here</option>
              <option value="channel">@channel</option>
            </Select>
          )}
        </Field>
      ) : null}
      {kind === "webhook" ? (
        <>
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="Signing secret" hint={secretHint(stored.signingSecret, "secret") ?? "Leave empty to have SCIAT generate one (shown once)."}>
              {(p) => <Input {...p} type="password" value={s.signingSecret} autoComplete="new-password" onChange={(e) => set("signingSecret", e.target.value)} />}
            </Field>
            <Field label="Authorization header (optional)" error={err("authorization")} hint={secretHint(stored.authorization, "value") ?? "e.g. Bearer <token> for the receiving system."}>
              {(p) => <Input {...p} type="password" value={s.authorization} disabled={s.removeAuthorization} autoComplete="new-password" onChange={(e) => set("authorization", e.target.value)} />}
            </Field>
          </div>
          {editing && stored.authorization ? <Checkbox label="Remove the Authorization header" checked={s.removeAuthorization} onChange={(e) => set("removeAuthorization", e.target.checked)} /> : null}
          <Field label="Extra headers (optional)" error={err("headers")} hint="One per line: Name: value. Not secret — use the Authorization field for credentials.">
            {(p) => <Textarea {...p} rows={2} className="font-mono text-xs" value={s.headers} onChange={(e) => set("headers", e.target.value)} placeholder="X-Tenant: acme" />}
          </Field>
          <Checkbox label="Include the event details (data) in the payload" checked={s.includeData} onChange={(e) => set("includeData", e.target.checked)} />
        </>
      ) : null}
    </div>
  );
}
