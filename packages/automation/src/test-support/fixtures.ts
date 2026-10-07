/**
 * Test fixtures and fakes (no real network, no real clock). Used only by *.test.ts files.
 */
import type { NotificationChannel, NotificationChannelKind, Principal, RoleKey } from "@bloody/contracts";
import type { HttpRequest, HttpResponse, HttpTransport } from "../channels/http.js";
import type { SecretResolver } from "../channels/types.js";
import type { SyslogTarget, SyslogTransport } from "../channels/syslog.js";
import type { Clock, IdGenerator } from "../util/runtime.js";

export const TENANT = "11111111-1111-4111-8111-111111111111";
export const OTHER_TENANT = "22222222-2222-4222-8222-222222222222";
export const ORG_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const ORG_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

export class FakeClock implements Clock {
  private t: number;

  constructor(iso = "2026-10-07T12:00:00.000Z") {
    this.t = Date.parse(iso);
  }

  now(): Date {
    return new Date(this.t);
  }

  advance(ms: number): void {
    this.t += ms;
  }

  set(iso: string): void {
    this.t = Date.parse(iso);
  }
}

/** Deterministic UUID-shaped ids. */
export function sequentialIds(prefix = "00000000"): IdGenerator {
  let n = 0;
  return () => {
    n += 1;
    return `${prefix}-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;
  };
}

export function principal(id: string, role: RoleKey, opts: { tenantId?: string; organizationId?: string | null; kind?: "user" | "service" } = {}): Principal {
  return {
    kind: opts.kind ?? "user",
    id,
    tenantId: opts.tenantId ?? TENANT,
    displayName: id,
    bindings: [{ role, organizationId: opts.organizationId === undefined ? null : opts.organizationId }],
  };
}

export class FakeHttp implements HttpTransport {
  readonly requests: HttpRequest[] = [];
  private readonly responses: (HttpResponse | Error)[];

  constructor(responses: (HttpResponse | Error)[] = []) {
    this.responses = responses;
  }

  async request(req: HttpRequest): Promise<HttpResponse> {
    this.requests.push(req);
    const next = this.responses.length > 1 ? this.responses.shift()! : (this.responses[0] ?? { status: 200, headers: {}, body: "ok" });
    if (next instanceof Error) throw next;
    return next;
  }
}

export class FakeSecrets implements SecretResolver {
  constructor(private readonly values: Record<string, string>) {}

  async resolve(tenantId: string, ref: string): Promise<string> {
    const v = this.values[`${tenantId}:${ref}`] ?? this.values[ref];
    if (v === undefined) throw new Error(`secret ${ref} not found`);
    return v;
  }
}

export class RecordingSyslogTransport implements SyslogTransport {
  readonly sent: { target: SyslogTarget; payload: Buffer }[] = [];

  async send(target: SyslogTarget, payload: Buffer): Promise<void> {
    this.sent.push({ target, payload });
  }
}

export function channel(kind: NotificationChannelKind, config: Record<string, unknown>, opts: { id?: string; organizationId?: string | null; tenantId?: string; enabled?: boolean; name?: string } = {}): NotificationChannel {
  return {
    id: opts.id ?? "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    tenantId: opts.tenantId ?? TENANT,
    organizationId: opts.organizationId === undefined ? null : opts.organizationId,
    name: opts.name ?? `${kind} channel`,
    kind,
    config,
    enabled: opts.enabled ?? true,
  };
}
