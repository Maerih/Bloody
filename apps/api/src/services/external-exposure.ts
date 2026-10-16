import { Socket } from "node:net";
import {
  EXPOSURE_PORTS,
  SEVERITY_ORDER,
  exposurePort,
  isPublicAddress,
  normalizeAddress,
  type ExposureAuthorization,
  type ExposureFinding,
  type ExposureScan,
  type ExposureTarget,
  type ExposureTargetStatus,
} from "@bloody/contracts";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError, notFound } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";
import type { DomainEventBus } from "./domain-events.js";

/** True when a TCP connection to ip:port completes within the timeout. */
export type PortProbe = (ip: string, port: number, timeoutMs: number) => Promise<boolean>;

export const tcpProbe: PortProbe = (ip, port, timeoutMs) =>
  new Promise((resolve) => {
    const socket = new Socket();
    const done = (open: boolean) => {
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
    socket.connect(port, ip);
  });

export const EXPOSURE_RESCAN_HOURS = 24;
export const MAX_TARGETS = 64;
const PROBE_TIMEOUT_MS = 2500;
const CONCURRENCY = 32;
const STALE_SCAN_MINUTES = 30;
/** Addresses an agent has not come from for this long no longer list it as "behind" them. */
const HOST_WINDOW_DAYS = 30;

const iso = (v: unknown) => (v ? new Date(String(v)).toISOString() : null);

function toScan(r: Row): ExposureScan {
  return {
    id: String(r.id),
    status: r.status as ExposureScan["status"],
    trigger: r.trigger as ExposureScan["trigger"],
    startedAt: iso(r.started_at)!,
    finishedAt: iso(r.finished_at),
    addresses: Number(r.addresses),
    openPorts: Number(r.open_ports),
    error: (r.error as string | null) ?? null,
  };
}

async function pool<T>(items: T[], size: number, fn: (item: T) => Promise<void>): Promise<void> {
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(size, items.length) }, async () => {
      while (i < items.length) await fn(items[i++]!);
    }),
  );
}

/** External Exposure: public addresses per organization, their authorization, scans and open ports. */
export class ExposureService {
  constructor(private readonly deps: { db: Database; events: DomainEventBus; probe: PortProbe; now: () => number }) {}

  /** Agent check-in: remember the public address it came from (at most every 10 minutes per agent). */
  async observe(tx: Queryable, tenantId: string, organizationId: string, agentId: string, rawIp: string | undefined): Promise<void> {
    if (!rawIp) return;
    const ip = normalizeAddress(rawIp);
    if (!isPublicAddress(ip)) return;
    const { rowCount } = await tx.query(
      `UPDATE agents SET public_ip = $2, public_ip_seen_at = now()
        WHERE id = $1 AND (public_ip IS DISTINCT FROM $2 OR public_ip_seen_at IS NULL OR public_ip_seen_at < now() - interval '10 minutes')`,
      [agentId, ip],
    );
    if (!rowCount) return;
    await tx.query(
      `INSERT INTO exposure_targets (tenant_id, organization_id, ip, source, last_seen_at) VALUES ($1, $2, $3, 'agent', now())
       ON CONFLICT (organization_id, ip) DO UPDATE SET last_seen_at = now()`,
      [tenantId, organizationId, ip],
    );
  }

  async authorization(tx: Queryable, organizationId: string): Promise<ExposureAuthorization | null> {
    const { rows } = await tx.query<Row>("SELECT * FROM exposure_settings WHERE organization_id = $1", [organizationId]);
    const r = rows[0];
    if (!r) return null;
    const expiresAt = iso(r.expires_at)!;
    return { reference: String(r.reference), authorizedBy: (r.authorized_by as string | null) ?? null, authorizedAt: iso(r.authorized_at)!, expiresAt, valid: Date.parse(expiresAt) > this.deps.now() };
  }

  async authorize(tx: Queryable, tenantId: string, organizationId: string, input: { reference: string; expiresAt: string }, actor: string): Promise<ExposureAuthorization> {
    await tx.query(
      `INSERT INTO exposure_settings (organization_id, tenant_id, reference, authorized_by, authorized_at, expires_at) VALUES ($1, $2, $3, $4, now(), $5)
       ON CONFLICT (organization_id) DO UPDATE SET reference = EXCLUDED.reference, authorized_by = EXCLUDED.authorized_by, authorized_at = now(), expires_at = EXCLUDED.expires_at`,
      [organizationId, tenantId, input.reference, actor, input.expiresAt],
    );
    return (await this.authorization(tx, organizationId))!;
  }

  async revoke(tx: Queryable, organizationId: string): Promise<boolean> {
    return ((await tx.query("DELETE FROM exposure_settings WHERE organization_id = $1", [organizationId])).rowCount ?? 0) > 0;
  }

  async targets(tx: Queryable, organizationId: string): Promise<ExposureTarget[]> {
    const { rows } = await tx.query<Row>(
      `SELECT t.*,
              coalesce((SELECT array_agg(a.hostname ORDER BY a.hostname) FROM agents a
                         WHERE a.organization_id = t.organization_id AND a.public_ip = t.ip
                           AND a.public_ip_seen_at > now() - make_interval(days => $2)), '{}') AS hostnames,
              (SELECT count(*)::int FROM exposure_ports p WHERE p.organization_id = t.organization_id AND p.ip = t.ip AND p.closed_at IS NULL) AS open_ports
         FROM exposure_targets t WHERE t.organization_id = $1
        ORDER BY CASE t.status WHEN 'discovered' THEN 0 WHEN 'confirmed' THEN 1 ELSE 2 END, t.ip`,
      [organizationId, HOST_WINDOW_DAYS],
    );
    return rows.map((r) => ({
      id: String(r.id),
      ip: String(r.ip),
      source: r.source as ExposureTarget["source"],
      status: r.status as ExposureTargetStatus,
      note: (r.note as string | null) ?? null,
      hostnames: (r.hostnames as string[]) ?? [],
      firstSeenAt: iso(r.first_seen_at)!,
      lastSeenAt: iso(r.last_seen_at),
      lastScannedAt: iso(r.last_scanned_at),
      openPorts: Number(r.open_ports),
    }));
  }

  async getTarget(tx: Queryable, id: string): Promise<{ id: string; organizationId: string; ip: string; source: string }> {
    const { rows } = await tx.query<Row>("SELECT id, organization_id, ip, source FROM exposure_targets WHERE id = $1", [id]);
    if (!rows[0]) throw notFound("Address");
    return { id: String(rows[0].id), organizationId: String(rows[0].organization_id), ip: String(rows[0].ip), source: String(rows[0].source) };
  }

  /** An administrator adds an address the organization owns (an office's static IP): confirmed at once. */
  async addTarget(tx: Queryable, tenantId: string, organizationId: string, rawIp: string, note: string | null, actor: string): Promise<void> {
    const ip = normalizeAddress(rawIp);
    if (!isPublicAddress(ip)) throw new HttpError(400, "not_public_address", `${rawIp} is not a public internet address — private, reserved and documentation ranges cannot be checked`);
    const { rows } = await tx.query<Row>("SELECT count(*)::int AS n FROM exposure_targets WHERE organization_id = $1 AND status <> 'ignored'", [organizationId]);
    if (Number(rows[0]?.n) >= MAX_TARGETS) throw new HttpError(409, "too_many_addresses", `An organization can have at most ${MAX_TARGETS} addresses`);
    await tx.query(
      `INSERT INTO exposure_targets (tenant_id, organization_id, ip, source, status, note, decided_by, decided_at) VALUES ($1, $2, $3, 'manual', 'confirmed', $4, $5, now())
       ON CONFLICT (organization_id, ip) DO UPDATE SET status = 'confirmed', note = coalesce(EXCLUDED.note, exposure_targets.note), decided_by = EXCLUDED.decided_by, decided_at = now()`,
      [tenantId, organizationId, ip, note, actor],
    );
  }

  async decide(tx: Queryable, id: string, status: "confirmed" | "ignored", actor: string): Promise<void> {
    await tx.query("UPDATE exposure_targets SET status = $2, decided_by = $3, decided_at = now() WHERE id = $1", [id, status, actor]);
    if (status === "ignored") {
      // Ignored addresses are no longer the organization's: forget what was found on them.
      await tx.query("DELETE FROM exposure_ports p USING exposure_targets t WHERE t.id = $1 AND p.organization_id = t.organization_id AND p.ip = t.ip", [id]);
    }
  }

  async removeTarget(tx: Queryable, id: string): Promise<void> {
    await tx.query("DELETE FROM exposure_ports p USING exposure_targets t WHERE t.id = $1 AND p.organization_id = t.organization_id AND p.ip = t.ip", [id]);
    await tx.query("DELETE FROM exposure_targets WHERE id = $1", [id]);
  }

  async findings(tx: Queryable, organizationId: string): Promise<ExposureFinding[]> {
    const { rows } = await tx.query<Row>(
      `SELECT p.ip, p.port, p.first_seen_at, p.last_seen_at,
              coalesce((SELECT array_agg(a.hostname ORDER BY a.hostname) FROM agents a
                         WHERE a.organization_id = p.organization_id AND a.public_ip = p.ip
                           AND a.public_ip_seen_at > now() - make_interval(days => $2)), '{}') AS hostnames
         FROM exposure_ports p JOIN exposure_targets t ON t.organization_id = p.organization_id AND t.ip = p.ip AND t.status = 'confirmed'
        WHERE p.organization_id = $1 AND p.closed_at IS NULL`,
      [organizationId, HOST_WINDOW_DAYS],
    );
    return rows
      .map((r) => {
        const def = exposurePort(Number(r.port));
        return {
          ip: String(r.ip),
          port: Number(r.port),
          service: def?.service ?? `TCP ${r.port}`,
          severity: def?.severity ?? "medium",
          risk: def?.risk ?? "",
          fix: def?.fix ?? "",
          hostnames: (r.hostnames as string[]) ?? [],
          firstSeenAt: iso(r.first_seen_at)!,
          lastSeenAt: iso(r.last_seen_at)!,
        };
      })
      .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.ip.localeCompare(b.ip) || a.port - b.port);
  }

  async scans(tx: Queryable, organizationId: string, limit = 10): Promise<ExposureScan[]> {
    const { rows } = await tx.query<Row>("SELECT * FROM exposure_scans WHERE organization_id = $1 ORDER BY started_at DESC LIMIT $2", [organizationId, limit]);
    return rows.map(toScan);
  }

  /**
   * Start a scan of the organization's confirmed addresses. Refused without a valid authorization,
   * without confirmed addresses, or while another scan of the organization is running. Returns the
   * scan at once; `done` settles when it has finished.
   */
  async startScan(tenantId: string, organizationId: string, trigger: "manual" | "schedule", actor: string | null): Promise<{ scan: ExposureScan; done: Promise<void> }> {
    const { scan, ips } = await this.deps.db.withTenant(tenantId, async (tx) => {
      const auth = await this.authorization(tx, organizationId);
      if (!auth?.valid) throw new HttpError(409, "not_authorized", "Record a valid authorization to test this organization's addresses before scanning");
      const ips = (await tx.query<Row>("SELECT ip FROM exposure_targets WHERE organization_id = $1 AND status = 'confirmed' ORDER BY ip LIMIT $2", [organizationId, MAX_TARGETS])).rows.map((r) => String(r.ip));
      if (!ips.length) throw new HttpError(409, "no_addresses", "Confirm at least one public address before scanning");
      await tx.query(
        `UPDATE exposure_scans SET status = 'failed', finished_at = now(), error = 'Scan did not finish'
          WHERE organization_id = $1 AND status = 'running' AND started_at < now() - make_interval(mins => $2)`,
        [organizationId, STALE_SCAN_MINUTES],
      );
      try {
        await tx.query("SAVEPOINT exposure_scan");
        const { rows } = await tx.query<Row>(
          "INSERT INTO exposure_scans (tenant_id, organization_id, trigger, requested_by, addresses) VALUES ($1, $2, $3, $4, $5) RETURNING *",
          [tenantId, organizationId, trigger, actor, ips.length],
        );
        return { scan: toScan(rows[0]!), ips };
      } catch (err) {
        await tx.query("ROLLBACK TO SAVEPOINT exposure_scan");
        if ((err as { code?: string }).code === "23505") throw new HttpError(409, "scan_running", "A scan of this organization is already running");
        throw err;
      }
    });
    const done = this.run(tenantId, organizationId, scan.id, ips).catch(async (err: unknown) => {
      const message = err instanceof Error ? err.message : String(err);
      await this.deps.db
        .withTenant(tenantId, (tx) => tx.query("UPDATE exposure_scans SET status = 'failed', finished_at = now(), error = $2 WHERE id = $1 AND status = 'running'", [scan.id, message.slice(0, 1000)]))
        .catch(() => undefined);
    });
    return { scan, done };
  }

  private async run(tenantId: string, organizationId: string, scanId: string, ips: string[]): Promise<void> {
    const open = new Set<string>();
    const probes = ips.flatMap((ip) => EXPOSURE_PORTS.map((p) => ({ ip, port: p.port })));
    await pool(probes, CONCURRENCY, async ({ ip, port }) => {
      if (await this.deps.probe(ip, port, PROBE_TIMEOUT_MS)) open.add(`${ip}|${port}`);
    });

    const opened = await this.deps.db.withTenant(tenantId, async (tx) => {
      // Addresses ignored or removed while the scan ran are left alone.
      const still = new Set((await tx.query<Row>("SELECT ip FROM exposure_targets WHERE organization_id = $1 AND status = 'confirmed' AND ip = ANY($2)", [organizationId, ips])).rows.map((r) => String(r.ip)));
      const current = new Set(
        (await tx.query<Row>("SELECT ip, port FROM exposure_ports WHERE organization_id = $1 AND closed_at IS NULL AND ip = ANY($2)", [organizationId, [...still]])).rows.map((r) => `${r.ip}|${r.port}`),
      );
      const fresh: Array<{ ip: string; port: number }> = [];
      for (const key of open) {
        const [ip, portText] = key.split("|") as [string, string];
        if (!still.has(ip)) continue;
        const port = Number(portText);
        await tx.query(
          `INSERT INTO exposure_ports (tenant_id, organization_id, ip, port) VALUES ($1, $2, $3, $4)
           ON CONFLICT (organization_id, ip, port) DO UPDATE SET last_seen_at = now(), closed_at = NULL,
             first_seen_at = CASE WHEN exposure_ports.closed_at IS NULL THEN exposure_ports.first_seen_at ELSE now() END`,
          [tenantId, organizationId, ip, port],
        );
        if (!current.has(key)) fresh.push({ ip, port });
      }
      for (const key of current) {
        if (open.has(key)) continue;
        const [ip, port] = key.split("|") as [string, string];
        await tx.query("UPDATE exposure_ports SET closed_at = now() WHERE organization_id = $1 AND ip = $2 AND port = $3", [organizationId, ip, Number(port)]);
      }
      await tx.query("UPDATE exposure_targets SET last_scanned_at = now() WHERE organization_id = $1 AND ip = ANY($2)", [organizationId, [...still]]);
      const openCount = [...open].filter((k) => still.has(k.split("|")[0]!)).length;
      await tx.query("UPDATE exposure_scans SET status = 'finished', finished_at = now(), open_ports = $2 WHERE id = $1", [scanId, openCount]);
      const hosts = new Map<string, string[]>();
      for (const { ip } of fresh) {
        if (hosts.has(ip)) continue;
        const { rows } = await tx.query<Row>(
          "SELECT hostname FROM agents WHERE organization_id = $1 AND public_ip = $2 AND public_ip_seen_at > now() - make_interval(days => $3) ORDER BY hostname",
          [organizationId, ip, HOST_WINDOW_DAYS],
        );
        hosts.set(ip, rows.map((r) => String(r.hostname)));
      }
      return fresh.map((f) => ({ ...f, hostnames: hosts.get(f.ip) ?? [] }));
    });

    for (const f of opened) {
      const def = exposurePort(f.port)!;
      this.deps.events.publish({
        tenantId,
        organizationId,
        event: "exposure.port_open",
        occurredAt: new Date(this.deps.now()).toISOString(),
        severity: def.severity,
        subject: { kind: "address", id: `${f.ip}:${f.port}`, label: `${def.service} on ${f.ip}:${f.port}` },
        dedupKey: `exposure:${organizationId}:${f.ip}:${f.port}`,
        data: { exposure: { ip: f.ip, port: f.port, service: def.service, severity: def.severity, risk: def.risk, fix: def.fix, hostnames: f.hostnames.length ? f.hostnames.join(", ") : "none reporting" } },
      });
    }
  }

  /** Scheduler: rescan authorized organizations not scanned in the last day (two per tick). */
  async scanDue(tenantId: string): Promise<number> {
    const due = await this.deps.db.withTenant(tenantId, async (tx) =>
      (
        await tx.query<Row>(
          `SELECT s.organization_id FROM exposure_settings s
            WHERE s.expires_at > now()
              AND EXISTS (SELECT 1 FROM exposure_targets t WHERE t.organization_id = s.organization_id AND t.status = 'confirmed')
              AND NOT EXISTS (SELECT 1 FROM exposure_scans x WHERE x.organization_id = s.organization_id
                               AND (x.status = 'running' OR x.started_at > now() - make_interval(hours => $1)))
            ORDER BY (SELECT max(started_at) FROM exposure_scans x WHERE x.organization_id = s.organization_id) NULLS FIRST
            LIMIT 2`,
          [EXPOSURE_RESCAN_HOURS],
        )
      ).rows,
    );
    let n = 0;
    for (const r of due) {
      try {
        const { done } = await this.startScan(tenantId, String(r.organization_id), "schedule", null);
        await done;
        n++;
      } catch {
        // Recorded on the scan; the next tick tries again.
      }
    }
    return n;
  }
}
