import { connect as http2Connect } from "node:http2";

/**
 * Apple Push Notification service client for MDM (proprietary). An MDM push is an empty
 * notification: the server POSTs `{"mdm": "<PushMagic>"}` to api.push.apple.com with the device's
 * push token, authenticated by the MDM push certificate (TLS client certificate). The device then
 * connects back to the server to pick up queued commands.
 */

export const APNS_HOST = "https://api.push.apple.com";

export class ApnsError extends Error {
  constructor(
    readonly status: number,
    readonly reason: string,
  ) {
    super(`APNs push failed (${status}): ${reason}`);
  }
  /** The device's push token is no longer valid — it has un-enrolled or been wiped. */
  get deviceGone(): boolean {
    return this.status === 410 || this.reason === "BadDeviceToken" || this.reason === "Unregistered";
  }
}

export interface ApnsPush {
  pushToken: string;
  pushMagic: string;
  topic: string;
}

/** Low-level transport: send one push, resolve on 200, throw ApnsError otherwise. */
export type ApnsTransport = (push: ApnsPush) => Promise<void>;

export interface ApnsClientOptions {
  /** PEM certificate + key for the MDM push certificate (from the Apple Push Certificates Portal). */
  cert: string;
  key: string;
  host?: string;
  /** Injected transport for tests; production uses the built-in HTTP/2 + mTLS transport. */
  transport?: ApnsTransport;
  timeoutMs?: number;
}

const TOKEN_RE = /^[0-9a-fA-F]{8,200}$/;

/** Built-in APNs transport over HTTP/2 with the push certificate as the TLS client certificate. */
export function http2ApnsTransport(opts: { cert: string; key: string; host?: string; timeoutMs?: number }): ApnsTransport {
  const host = opts.host ?? APNS_HOST;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  return (push) =>
    new Promise<void>((resolve, reject) => {
      const session = http2Connect(host, { cert: opts.cert, key: opts.key });
      const done = (err?: Error) => {
        try {
          session.close();
        } catch {
          /* already closed */
        }
        if (err) reject(err);
        else resolve();
      };
      session.on("error", (err) => done(err instanceof Error ? err : new Error(String(err))));
      const body = JSON.stringify({ mdm: push.pushMagic });
      const req = session.request({ ":method": "POST", ":path": `/3/device/${push.pushToken}`, "apns-topic": push.topic, "apns-push-type": "mdm", "content-type": "application/json", "content-length": Buffer.byteLength(body) });
      req.setTimeout(timeoutMs, () => req.close());
      let status = 0;
      let payload = "";
      req.on("response", (headers) => {
        status = Number(headers[":status"]) || 0;
      });
      req.on("data", (chunk) => (payload += chunk));
      req.on("end", () => {
        if (status === 200) done();
        else {
          let reason = `HTTP ${status}`;
          try {
            reason = (JSON.parse(payload) as { reason?: string }).reason ?? reason;
          } catch {
            /* non-JSON body */
          }
          done(new ApnsError(status, reason));
        }
      });
      req.on("error", (err) => done(err instanceof Error ? err : new Error(String(err))));
      req.end(body);
    });
}

export interface ApnsClient {
  push(push: ApnsPush): Promise<void>;
}

export function createApnsClient(opts: ApnsClientOptions): ApnsClient {
  const transport = opts.transport ?? http2ApnsTransport({ cert: opts.cert, key: opts.key, host: opts.host, timeoutMs: opts.timeoutMs });
  return {
    async push(push) {
      if (!TOKEN_RE.test(push.pushToken)) throw new ApnsError(400, "BadDeviceToken");
      if (!push.topic.startsWith("com.apple.mgmt.")) throw new ApnsError(400, "TopicDisallowed");
      await transport(push);
    },
  };
}

/** The APNs topic is the UID (or CN) of the MDM push certificate subject. */
export function topicFromSubject(subject: string): string | null {
  const m = subject.match(/(?:UID|userId|0\.9\.2342\.19200300\.100\.1\.1)=([^,/\n]+)/i);
  const topic = m?.[1]?.trim();
  return topic && topic.startsWith("com.apple.mgmt.") ? topic : null;
}
