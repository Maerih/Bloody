import { checkHostname, createGuardedLookup, createSmtpTransport, type LookupFunction, type SsrfPolicy } from "@bloody/automation";
import { MailServerInput, type MailEncryption, type MailServerSettings, type MailServerView } from "@bloody/contracts";
import type { SmtpConfig } from "../config.js";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError, badRequest } from "../http/errors.js";
import type { SecretStore } from "./secret-store.js";
import type { EmailTransport } from "./notifications.js";

/** Stored in accounts.settings.mailServer (the password lives in the secret store). */
interface StoredMailServer {
  host: string;
  port: number;
  encryption: MailEncryption;
  username: string | null;
  passwordRef: string | null;
  fromAddress: string;
  fromName: string | null;
  updatedAt: string;
  updatedBy: string | null;
}

export interface ResolvedMailer {
  transport: EmailTransport;
  from: { address: string; name?: string };
}

/** Connection settings for {@link MailServerService.transportFor} (account, channel or platform). */
export interface SmtpTarget {
  host: string;
  port: number;
  secure: boolean;
  user?: string | undefined;
  password?: string | undefined;
  fromAddress: string;
}

export class MailServerUnavailableError extends HttpError {
  constructor(message = "No mail server is set up: add one under Settings → Email server") {
    super(409, "smtp_not_configured", message);
  }
}

/**
 * The account's outgoing mail server, set from Settings → Email server, falling back to the
 * platform default (SMTP_* in the server environment). Servers entered in the app never point at
 * this machine (loopback) or cloud metadata, and at internal addresses only when the operator
 * allows private networks (INTEGRATIONS_ALLOW_PRIVATE_NETWORKS); the address is checked when
 * saving and again when connecting.
 */
export class MailServerService {
  private readonly transports = new Map<string, EmailTransport>();
  private readonly policy: SsrfPolicy;
  private readonly lookup: (host: string) => Promise<string>;

  constructor(
    private readonly deps: {
      db: Database;
      secretStore: SecretStore;
      platform: SmtpConfig | null;
      /** Tests: every message goes here instead of an SMTP server. */
      override: EmailTransport | null;
      allowPrivateNetworks: boolean;
      lookup?: LookupFunction;
    },
  ) {
    // Internal relays follow the operator's private-network switch; loopback never.
    this.policy = { allowPrivateNetworks: deps.allowPrivateNetworks, allowLoopback: false };
    const guarded = createGuardedLookup(this.policy, deps.lookup);
    this.lookup = (host) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`no answer when looking up ${host}`)), 10_000);
        guarded(host, {}, (err, address) => {
          clearTimeout(timer);
          if (err) reject(err);
          else resolve(typeof address === "string" ? address : address[0]!.address);
        });
      });
  }

  private async stored(tx: Queryable, tenantId: string): Promise<StoredMailServer | null> {
    const { rows } = await tx.query<{ m: StoredMailServer | null }>("SELECT settings->'mailServer' AS m FROM accounts WHERE id = $1", [tenantId]);
    return rows[0]?.m ?? null;
  }

  async view(tx: Queryable, tenantId: string): Promise<MailServerView> {
    const m = await this.stored(tx, tenantId);
    let account: MailServerSettings | null = null;
    if (m) {
      const by = m.updatedBy ? (await tx.query<{ n: string }>("SELECT coalesce(display_name, email) AS n FROM users WHERE id::text = $1", [m.updatedBy])).rows[0]?.n ?? null : null;
      account = { host: m.host, port: m.port, encryption: m.encryption, username: m.username, hasPassword: m.passwordRef !== null, fromAddress: m.fromAddress, fromName: m.fromName, updatedAt: m.updatedAt, updatedBy: by };
    }
    const p = this.deps.platform;
    return {
      source: m ? "account" : p || this.deps.override ? "platform" : "none",
      account,
      platform: p ? { host: p.host, port: p.port, encryption: p.secure ? "tls" : "starttls", fromAddress: p.from } : null,
    };
  }

  /** Static destination check (the address is checked again when connecting). */
  checkHost(host: string): void {
    const v = checkHostname(host, this.policy);
    if (v.blocked) throw badRequest(`This mail server address is not allowed: ${v.reason ?? "blocked"}`);
  }

  async save(tx: Queryable, tenantId: string, body: unknown, actor: string | null): Promise<void> {
    const input = MailServerInput.parse(body);
    this.checkHost(input.host);
    const prior = await this.stored(tx, tenantId);
    let passwordRef = prior?.passwordRef ?? null;
    const username = input.username ? input.username : null;
    if (!username) {
      // No sign-in: drop a stored password.
      if (passwordRef) await this.deps.secretStore.delete(tx, passwordRef);
      passwordRef = null;
    } else if (input.password !== undefined) {
      if (passwordRef) await this.deps.secretStore.replace(tx, tenantId, passwordRef, input.password);
      else passwordRef = (await this.deps.secretStore.put(tx, tenantId, { value: input.password, name: "Email server password", purpose: "account.smtp_password", createdBy: actor })).ref;
    } else if (!passwordRef) {
      throw badRequest("Enter the password for the mail server user");
    } else if (prior && (prior.host !== input.host || prior.username !== username)) {
      // A stored credential is never sent to a new destination.
      throw badRequest("Enter the password again when changing the mail server or user");
    }
    const next: StoredMailServer = {
      host: input.host.toLowerCase(),
      port: input.port,
      encryption: input.encryption,
      username,
      passwordRef,
      fromAddress: input.fromAddress,
      fromName: input.fromName ? input.fromName : null,
      updatedAt: new Date().toISOString(),
      updatedBy: actor,
    };
    await tx.query("UPDATE accounts SET settings = settings || jsonb_build_object('mailServer', $2::jsonb) WHERE id = $1", [tenantId, JSON.stringify(next)]);
  }

  /** Back to the platform default. */
  async clear(tx: Queryable, tenantId: string): Promise<boolean> {
    const prior = await this.stored(tx, tenantId);
    if (!prior) return false;
    if (prior.passwordRef) await this.deps.secretStore.delete(tx, prior.passwordRef);
    await tx.query("UPDATE accounts SET settings = settings - 'mailServer' WHERE id = $1", [tenantId]);
    return true;
  }

  /**
   * A transport for a customer-entered server: the host is resolved here, checked, and the
   * connection goes to that exact address (verifying the certificate against the host name).
   */
  async transportFor(target: SmtpTarget, pool: boolean): Promise<EmailTransport> {
    if (this.deps.override) return this.deps.override;
    this.checkHost(target.host);
    let address: string;
    try {
      address = await this.lookup(target.host);
    } catch (err) {
      throw new HttpError(400, "smtp_host_blocked", `Cannot use mail server ${target.host}: ${err instanceof Error ? err.message : "lookup failed"}`);
    }
    const key = JSON.stringify([target, address, pool]);
    let transport = this.transports.get(key);
    if (!transport) {
      transport = createSmtpTransport({ ...target, host: address, servername: target.host, pool });
      this.transports.set(key, transport);
    }
    return transport;
  }

  /** The transport and sender address for the account's mail, or null when none is set up. */
  async resolve(tenantId: string): Promise<ResolvedMailer | null> {
    const found = await this.deps.db.withTenant(tenantId, async (tx) => {
      const m = await this.stored(tx, tenantId);
      if (!m) return null;
      const password = m.passwordRef ? ((await this.deps.secretStore.resolve(tx, tenantId, m.passwordRef)) ?? undefined) : undefined;
      return { m, password };
    });
    if (found) {
      const { m, password } = found;
      const transport = await this.transportFor({ host: m.host, port: m.port, secure: m.encryption === "tls", user: m.username ?? undefined, password, fromAddress: m.fromAddress }, true);
      return { transport, from: { address: m.fromAddress, ...(m.fromName ? { name: m.fromName } : {}) } };
    }
    const p = this.deps.platform;
    if (this.deps.override) return { transport: this.deps.override, from: { address: p?.from ?? "notifications@sciat.local", name: p?.fromName ?? "SCIAT AFRICA Security Operations" } };
    if (!p) return null;
    // The operator's own relay may be internal: not subject to the customer network rules.
    const key = JSON.stringify(["platform", p.host, p.port]);
    let transport = this.transports.get(key);
    if (!transport) {
      transport = createSmtpTransport({ host: p.host, port: p.port, secure: p.secure, ...(p.user ? { user: p.user } : {}), ...(p.password ? { password: p.password } : {}), fromAddress: p.from, pool: true });
      this.transports.set(key, transport);
    }
    return { transport, from: { address: p.from, name: p.fromName } };
  }

  async configured(tenantId: string): Promise<boolean> {
    if (this.deps.platform || this.deps.override) return true;
    return this.deps.db.withTenant(tenantId, async (tx) => (await this.stored(tx, tenantId)) !== null);
  }

  /** Send a short test message; errors carry the mail server's own answer. */
  async sendTest(tenantId: string, to: string): Promise<{ messageId: string | null }> {
    const mailer = await this.resolve(tenantId);
    if (!mailer) throw new MailServerUnavailableError();
    try {
      const info = (await mailer.transport.sendMail({
        from: mailer.from,
        to,
        subject: "SCIAT test message",
        text: "This test message was sent from SCIAT Settings → Email server. Your mail server is working.",
        headers: { "Auto-Submitted": "auto-generated" },
      })) as { messageId?: string } | undefined;
      return { messageId: info?.messageId ?? null };
    } catch (err) {
      throw new HttpError(502, "smtp_send_failed", `The mail server did not accept the message: ${err instanceof Error ? err.message.slice(0, 300) : "unknown error"}`);
    }
  }
}
