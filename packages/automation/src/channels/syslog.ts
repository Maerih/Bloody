import { createSocket } from "node:dgram";
import { connect as netConnect, isIP } from "node:net";
import { hostname as osHostname } from "node:os";
import { connect as tlsConnect } from "node:tls";
import type { NotificationChannel, Severity } from "@bloody/contracts";
import { z } from "zod";
import { DeliveryError, SsrfBlockedError } from "../util/errors.js";
import { systemClock, uuidIds, type Clock, type IdGenerator } from "../util/runtime.js";
import { checkAddress, checkHostname, createGuardedLookup, type LookupFunction, type SsrfPolicy } from "./ssrf.js";
import {
  buildTestMessage,
  checkConfig,
  defaultBrandingResolver,
  parseConfig,
  type BrandingResolver,
  type ConfigCheck,
  type DeliveryResult,
  type NotificationMessage,
  type NotificationSender,
  type SecretResolver,
} from "./types.js";

/**
 * Syslog (RFC 5424) forwarding to SIEMs / log collectors over UDP (RFC 5426), TCP with
 * octet-counting framing (RFC 6587) or TLS (RFC 5425).
 */
export const SyslogConfig = z.object({
  host: z
    .string()
    .min(1)
    .max(253)
    .regex(/^[A-Za-z0-9.:-]+$/, "host must be a hostname or IP address"),
  port: z.number().int().min(1).max(65535).optional(),
  protocol: z.enum(["udp", "tcp", "tls"]).default("tls"),
  /** Syslog facility 0-23 (default 13 = log audit). */
  facility: z.number().int().min(0).max(23).default(13),
  appName: z
    .string()
    .regex(/^[\x21-\x7e]{1,48}$/)
    .default("bloody"),
  /** Private Enterprise Number used in the structured-data id (default 32473, RFC 5612 example PEN). */
  enterpriseId: z
    .string()
    .regex(/^\d+(\.\d+)*$/)
    .max(32)
    .default("32473"),
  /** Secret-store ref to a PEM CA bundle for private TLS collectors. */
  caRef: z.string().min(1).max(256).optional(),
});
export type SyslogConfig = z.output<typeof SyslogConfig>;

/** RFC 5424 severity: emerg 0 … debug 7. */
export const SYSLOG_SEVERITY: Record<Severity, number> = { critical: 2, high: 3, medium: 4, low: 5, info: 6 };

const NILVALUE = "-";

function printUsAscii(value: string | undefined | null, max: number): string {
  if (!value) return NILVALUE;
  const clean = value.replace(/[^\x21-\x7e]/g, "_").slice(0, max);
  return clean.length > 0 ? clean : NILVALUE;
}

/** SD-PARAM value escaping: '"', '\' and ']' MUST be escaped (RFC 5424 §6.3.3). */
export function escapeSdValue(value: string): string {
  return value.replace(/[\\"\]]/g, (c) => `\\${c}`).replace(/[\r\n]+/g, " ");
}

function sdName(name: string): string {
  return name.replace(/[^\x21-\x7e]|[= \]"]/g, "_").slice(0, 32);
}

export interface Rfc5424Fields {
  facility: number;
  severity: number;
  timestamp: Date;
  hostname?: string | null;
  appName?: string | null;
  procId?: string | null;
  msgId?: string | null;
  structuredData?: { id: string; params: Record<string, string | number | null | undefined> }[];
  message: string;
}

/** Format one RFC 5424 syslog line (no trailing newline / framing). MSG is UTF-8 with BOM. */
export function formatRfc5424(f: Rfc5424Fields): string {
  if (f.facility < 0 || f.facility > 23 || f.severity < 0 || f.severity > 7) throw new RangeError("invalid facility/severity");
  const pri = f.facility * 8 + f.severity;
  const ts = f.timestamp.toISOString();
  const sd =
    f.structuredData && f.structuredData.length > 0
      ? f.structuredData
          .map((el) => {
            const params = Object.entries(el.params)
              .filter(([, v]) => v !== null && v !== undefined && String(v) !== "")
              .map(([k, v]) => `${sdName(k)}="${escapeSdValue(String(v))}"`)
              .join(" ");
            return `[${sdName(el.id)}${params ? ` ${params}` : ""}]`;
          })
          .join("")
      : NILVALUE;
  const msg = f.message.replace(/[\r\n]+/g, " ").trim();
  return `<${pri}>1 ${ts} ${printUsAscii(f.hostname, 255)} ${printUsAscii(f.appName, 48)} ${printUsAscii(f.procId, 128)} ${printUsAscii(f.msgId, 32)} ${sd}${msg ? ` ﻿${msg}` : ""}`;
}

/** Map a notification onto an RFC 5424 record. */
export function buildSyslogMessage(message: NotificationMessage, cfg: Pick<SyslogConfig, "facility" | "appName" | "enterpriseId">, hostname: string): string {
  const params: Record<string, string | number | null | undefined> = {
    tenant: message.tenantId,
    org: message.organizationId,
    orgName: message.organizationName,
    event: message.event,
    severity: message.severity,
    id: message.id,
    dedup: message.dedupKey,
    link: message.link?.url,
  };
  for (const fact of message.facts.slice(0, 12)) {
    const key = `f_${fact.label.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "")}`.slice(0, 32);
    if (!(key in params)) params[key] = fact.value.slice(0, 256);
  }
  const body = `${message.subject} — ${message.text.replace(/\s+/g, " ")}`.slice(0, 4000);
  return formatRfc5424({
    facility: cfg.facility,
    severity: SYSLOG_SEVERITY[message.severity],
    timestamp: new Date(message.occurredAt),
    hostname,
    appName: cfg.appName,
    procId: null,
    msgId: message.event,
    structuredData: [{ id: `bloody@${cfg.enterpriseId}`, params }],
    message: body,
  });
}

/** Cut a UTF-8 buffer to at most `max` bytes without splitting a code point. */
export function truncateUtf8(buf: Buffer, max: number): Buffer {
  if (buf.length <= max) return buf;
  let end = max;
  while (end > 0 && (buf[end]! & 0xc0) === 0x80) end--;
  return buf.subarray(0, end);
}

export interface SyslogTarget {
  host: string;
  port: number;
  protocol: "udp" | "tcp" | "tls";
  ca?: string;
}

/** Transport port — tests inject a recorder; production uses {@link NodeSyslogTransport}. */
export interface SyslogTransport {
  send(target: SyslogTarget, payload: Buffer): Promise<void>;
}

/**
 * Production transport. Destinations pass the SSRF guard with private networks allowed
 * (collectors are usually internal) but metadata / link-local / multicast always blocked.
 */
export class NodeSyslogTransport implements SyslogTransport {
  private readonly timeoutMs: number;
  private readonly policy: SsrfPolicy;
  private readonly lookup: LookupFunction;

  constructor(opts: { timeoutMs?: number; ssrf?: SsrfPolicy; lookup?: LookupFunction } = {}) {
    this.timeoutMs = opts.timeoutMs ?? 5_000;
    this.policy = { allowPrivateNetworks: true, ...opts.ssrf };
    this.lookup = createGuardedLookup(this.policy, opts.lookup);
  }

  async send(target: SyslogTarget, payload: Buffer): Promise<void> {
    const v = checkHostname(target.host, this.policy);
    if (v.blocked) throw new SsrfBlockedError(v.reason ?? "syslog destination blocked", { host: target.host });
    if (target.protocol === "udp") return this.sendUdp(target, payload);
    return this.sendStream(target, payload);
  }

  private resolve(host: string): Promise<{ address: string; family: number }> {
    if (isIP(host)) {
      const v = checkAddress(host, this.policy);
      if (v.blocked) return Promise.reject(new SsrfBlockedError(v.reason ?? "blocked", { host }));
      return Promise.resolve({ address: host, family: isIP(host) });
    }
    return new Promise((resolve, reject) => {
      this.lookup(host, {}, (err, address, family) => {
        if (err) reject(err instanceof DeliveryError ? err : new DeliveryError("dns_error", err.message, { retryable: true }));
        else resolve({ address: address as string, family: family ?? 4 });
      });
    });
  }

  private async sendUdp(target: SyslogTarget, payload: Buffer): Promise<void> {
    const { address, family } = await this.resolve(target.host);
    await new Promise<void>((resolve, reject) => {
      const socket = createSocket(family === 6 ? "udp6" : "udp4");
      const timer = setTimeout(() => {
        socket.close();
        reject(new DeliveryError("timeout", "syslog UDP send timed out", { retryable: true }));
      }, this.timeoutMs);
      socket.send(payload, target.port, address, (err) => {
        clearTimeout(timer);
        socket.close();
        if (err) reject(new DeliveryError("network_error", err.message, { retryable: true }));
        else resolve();
      });
    });
  }

  private async sendStream(target: SyslogTarget, payload: Buffer): Promise<void> {
    const framed = Buffer.concat([Buffer.from(`${payload.length} `, "ascii"), payload]);
    const { address } = await this.resolve(target.host);
    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error): void => {
        clearTimeout(timer);
        socket.destroy();
        reject(err instanceof DeliveryError ? err : new DeliveryError("network_error", err.message, { retryable: true }));
      };
      const socket =
        target.protocol === "tls"
          ? tlsConnect({ host: address, port: target.port, servername: isIP(target.host) ? undefined : target.host, rejectUnauthorized: true, minVersion: "TLSv1.2", ...(target.ca ? { ca: target.ca } : {}) }, () => write())
          : netConnect({ host: address, port: target.port }, () => write());
      const timer = setTimeout(() => onError(new DeliveryError("timeout", "syslog connection timed out", { retryable: true })), this.timeoutMs);
      const write = (): void => {
        socket.end(framed, () => {
          clearTimeout(timer);
          resolve();
        });
      };
      socket.on("error", onError);
    });
  }
}

export interface SyslogSenderDeps {
  transport: SyslogTransport;
  secrets: SecretResolver;
  branding?: BrandingResolver;
  clock?: Clock;
  ids?: IdGenerator;
  /** HOSTNAME field (default: this host's name). */
  hostname?: string;
  /** Max datagram size for UDP (default 2048 bytes, RFC 5426 guidance). */
  maxUdpBytes?: number;
}

export class SyslogSender implements NotificationSender {
  readonly kind = "syslog" as const;
  private readonly deps: SyslogSenderDeps;

  constructor(deps: SyslogSenderDeps) {
    this.deps = deps;
  }

  validateConfig(config: unknown): ConfigCheck {
    const check = checkConfig(SyslogConfig, config);
    if (!check.ok) return check;
    const host = (config as { host: string }).host;
    const v = checkHostname(host, { allowPrivateNetworks: true });
    return v.blocked ? { ok: false, issues: [{ path: "host", message: v.reason ?? "destination not allowed" }] } : check;
  }

  async send(channel: NotificationChannel, message: NotificationMessage): Promise<DeliveryResult> {
    const cfg = parseConfig(SyslogConfig, channel);
    const line = buildSyslogMessage(message, cfg, this.deps.hostname ?? osHostname());
    let payload = Buffer.from(line, "utf8");
    const warnings: string[] = [];
    if (cfg.protocol === "udp") {
      const max = this.deps.maxUdpBytes ?? 2048;
      if (payload.length > max) {
        payload = truncateUtf8(payload, max);
        warnings.push(`message truncated to ${max} bytes for UDP`);
      }
    }
    const port = cfg.port ?? (cfg.protocol === "tls" ? 6514 : 514);
    const ca = cfg.caRef ? await this.deps.secrets.resolve(channel.tenantId, cfg.caRef) : undefined;
    await this.deps.transport.send({ host: cfg.host, port, protocol: cfg.protocol, ...(ca ? { ca } : {}) }, payload);
    return { ok: true, channelId: channel.id, kind: "syslog", detail: `${cfg.protocol}://${cfg.host}:${port}`, ...(warnings.length ? { warnings } : {}) };
  }

  async test(channel: NotificationChannel, opts: { requestedBy?: string; now?: Date } = {}): Promise<DeliveryResult> {
    const brand = await (this.deps.branding ?? defaultBrandingResolver)(channel.tenantId, channel.organizationId);
    return this.send(channel, buildTestMessage(channel, brand, { ...opts, id: (this.deps.ids ?? uuidIds)(), now: opts.now ?? (this.deps.clock ?? systemClock).now() }));
  }
}
