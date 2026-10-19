import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { writeAudit } from "../audit/audit.js";
import type { Database, Queryable } from "../db/pool.js";
import { HttpError } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";
import type { SecretBox } from "../security/crypto.js";
import type { QuotaService } from "./commercial.js";
import type { InventoryService } from "./inventory.js";

/**
 * SCIAT Agent enrollment (proprietary).
 *
 *  - Account key `sak_<tenant hex>_<secret>`: one per account, shown to admins (sealed at rest,
 *    hashed for checks), regenerable — enrolled agents keep their own tokens.
 *  - Organization key: the organization's slug (an identifier, not a secret). Organizations are
 *    never created by enrollment, so a leaked account key cannot add customers.
 *  - Agent token `sat_<tenant hex>_<agent hex>_<secret>`: issued at enrollment, only its hash is
 *    stored; the heartbeat authenticates with it. The tenant is part of every key, so lookups
 *    run inside that tenant's RLS context.
 */

const ACCOUNT_KEY_RE = /^sak_([0-9a-f]{32})_([A-Za-z0-9_-]{32,64})$/;
const AGENT_TOKEN_RE = /^sat_([0-9a-f]{32})_([0-9a-f]{32})_([A-Za-z0-9_-]{32,64})$/;
const hex = (uuid: string) => uuid.replace(/-/g, "").toLowerCase();
const uuidOf = (h: string) => `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
const secret = () => randomBytes(32).toString("base64url");
const sameHash = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

export const AGENT_POLL_SECONDS = 60;
export const SCIAT_AGENT_VERSION = "1.5.0";

export interface EnrollInput {
  accountKey: string;
  organizationKey: string;
  hostname: string;
  platform: "windows" | "macos" | "linux";
  os?: string | undefined;
  version: string;
  ips?: string[] | undefined;
  machineId?: string | undefined;
}

export interface HeartbeatInput {
  hostname: string;
  os?: string | undefined;
  version: string;
  ips?: string[] | undefined;
  uptimeSeconds?: number | undefined;
  isolation?: { state: "isolated" | "not_isolated" | "unknown"; mode?: string | undefined } | undefined;
  engines?: Record<string, string> | undefined;
  /** Addresses the agent reaches the platform at — kept open when the endpoint is isolated. */
  platformIps?: string[] | undefined;
  /** The endpoint's DNS resolvers (kept reachable in full isolation). */
  dnsServers?: string[] | undefined;
}

/** A command for the agent: run `bloody-isolate <args…>` and report the result. */
export interface AgentCommand {
  id: string;
  kind: "isolate" | "release";
  args: string[];
}

export class AgentEnrollmentError extends HttpError {}

const keyContext = (tenantId: string) => `${tenantId}:agent-enrollment:account-key`;

/** Read the account key inside the tenant's transaction (created on first use). */
export async function readAccountKey(tx: Queryable, box: SecretBox, tenantId: string): Promise<string> {
  const { rows } = await tx.query<Row>("SELECT key_sealed FROM agent_enrollment");
  if (rows[0]) return box.decrypt(String(rows[0].key_sealed), keyContext(tenantId));
  return rotateAccountKey(tx, box, tenantId);
}

/** Issue a new account key; endpoints already enrolled keep working with their own tokens. */
export async function rotateAccountKey(tx: Queryable, box: SecretBox, tenantId: string): Promise<string> {
  const key = `sak_${hex(tenantId)}_${secret()}`;
  await tx.query(
    `INSERT INTO agent_enrollment (tenant_id, key_hash, key_sealed) VALUES ($1, $2, $3)
     ON CONFLICT (tenant_id) DO UPDATE SET key_hash = EXCLUDED.key_hash, key_sealed = EXCLUDED.key_sealed, rotated_at = now()`,
    [tenantId, sha256(key), box.encrypt(key, keyContext(tenantId))],
  );
  return key;
}

export class AgentEnrollmentService {
  constructor(
    private readonly deps: { db: Database; box: SecretBox; inventory: InventoryService; quota?: QuotaService; now: () => number },
  ) {}

  /** The account key (created on first use). */
  accountKey(tx: Queryable, tenantId: string): Promise<string> {
    return readAccountKey(tx, this.deps.box, tenantId);
  }

  rotate(tx: Queryable, tenantId: string): Promise<string> {
    return rotateAccountKey(tx, this.deps.box, tenantId);
  }

  /** Enroll (or re-enroll) an endpoint; returns its own token. */
  async enroll(input: EnrollInput): Promise<{ agentId: string; token: string; organizationId: string; pollSeconds: number }> {
    const m = ACCOUNT_KEY_RE.exec(input.accountKey.trim());
    if (!m) throw new AgentEnrollmentError(401, "invalid_account_key", "Invalid account key");
    const tenantId = uuidOf(m[1]!);
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT key_hash FROM agent_enrollment");
      if (!rows[0] || !sameHash(String(rows[0].key_hash), sha256(input.accountKey.trim()))) throw new AgentEnrollmentError(401, "invalid_account_key", "Invalid account key");
      const org = await tx.query<Row>("SELECT id FROM organizations WHERE lower(slug) = lower($1) AND status <> 'offboarded'", [input.organizationKey.trim()]);
      if (!org.rows[0]) throw new AgentEnrollmentError(404, "unknown_organization", "Unknown organization key — create the organization in the Command Center first");
      const organizationId = String(org.rows[0].id);
      // A new endpoint counts against the plan; re-enrolling the same machine does not.
      const known = await tx.query("SELECT 1 FROM agents WHERE organization_id = $1 AND lower(hostname) = lower($2) AND engine = 'sciat'", [organizationId, input.hostname]);
      const now = new Date(this.deps.now()).toISOString();
      const assets = await this.deps.inventory.resolveOrDiscoverHosts(tx, tenantId, organizationId, [{ hostname: input.hostname, os: input.os, ips: input.ips, lastSeenAt: now }]);
      const assetId = [...assets.values()][0] ?? null;
      // The machine id identifies a computer across re-installs. Two cases where it is already taken:
      // - the same computer (same host name) moved to another customer: move its agent over, with a
      //   fresh baseline (findings recorded under the old customer stay there);
      // - a clone of the same disk image / VM template (another host name): enroll it as its own
      //   computer and do not use the shared id.
      let machineRef = input.machineId ?? null;
      let moved = false;
      if (machineRef) {
        const { rows: same } = await tx.query<Row>("SELECT id, organization_id, hostname FROM agents WHERE external_source = 'sciat' AND external_ref = $1", [machineRef]);
        const holder = same[0];
        if (holder && String(holder.organization_id) !== organizationId) {
          if (String(holder.hostname).toLowerCase() === input.hostname.toLowerCase()) {
            const clash = await tx.query("SELECT 1 FROM agents WHERE organization_id = $1 AND lower(hostname) = lower($2) AND engine = 'sciat'", [organizationId, input.hostname]);
            if ((clash.rowCount ?? 0) === 0) {
              await tx.query("DELETE FROM agent_inventory WHERE agent_id = $1", [holder.id]);
              await tx.query("DELETE FROM agent_footholds WHERE agent_id = $1", [holder.id]);
              await tx.query("UPDATE agents SET organization_id = $2, footholds_baselined_at = NULL, security_pending_since = NULL, patch_state = NULL WHERE id = $1", [holder.id, organizationId]);
              moved = true;
            } else {
              machineRef = null;
            }
          } else {
            machineRef = null;
          }
        } else if (holder && String(holder.hostname).toLowerCase() !== input.hostname.toLowerCase()) {
          machineRef = null;
        }
      }
      if ((known.rowCount ?? 0) === 0 && !moved) await this.deps.quota?.assertCapacity(tx, tenantId, "endpoints", 1);
      const agentSecret = secret();
      const { rows: agent } = await tx.query<Row>(
        `INSERT INTO agents (tenant_id, organization_id, asset_id, hostname, platform, version, engine, status, last_checkin_at, antivirus_status, firewall_enabled,
                             external_source, external_ref, agent_token_hash, enrolled_at, host_info)
         VALUES ($1, $2, $3, $4, $5, $6, 'sciat', 'protected', $7, 'unmanaged', false, 'sciat', $8, $9, $7, $10::jsonb)
         ON CONFLICT (tenant_id, organization_id, lower(hostname), engine) DO UPDATE SET
           asset_id = coalesce(EXCLUDED.asset_id, agents.asset_id), platform = EXCLUDED.platform, version = EXCLUDED.version,
           status = CASE WHEN agents.isolation IS NOT NULL THEN 'isolated' ELSE 'protected' END, last_checkin_at = EXCLUDED.last_checkin_at,
           external_ref = coalesce(EXCLUDED.external_ref, agents.external_ref), agent_token_hash = EXCLUDED.agent_token_hash,
           enrolled_at = EXCLUDED.enrolled_at, host_info = EXCLUDED.host_info
         RETURNING id`,
        [tenantId, organizationId, assetId, input.hostname, input.platform, input.version, now, machineRef, sha256(agentSecret), JSON.stringify({ os: input.os ?? null, ips: input.ips ?? [] })],
      );
      const agentId = String(agent[0]!.id);
      return { agentId, token: `sat_${hex(tenantId)}_${hex(agentId)}_${agentSecret}`, organizationId, pollSeconds: AGENT_POLL_SECONDS };
    });
  }

  /** The agent behind a token, inside its tenant's transaction (401 when it does not match). */
  async withAgent<T>(token: string, fn: (tx: Queryable, agent: { tenantId: string; agentId: string; organizationId: string }) => Promise<T>): Promise<T> {
    const m = AGENT_TOKEN_RE.exec(token.trim());
    if (!m) throw new AgentEnrollmentError(401, "invalid_agent_token", "Invalid agent token");
    const tenantId = uuidOf(m[1]!);
    const agentId = uuidOf(m[2]!);
    return this.deps.db.withTenant(tenantId, async (tx) => {
      const { rows } = await tx.query<Row>("SELECT id, organization_id, agent_token_hash FROM agents WHERE id = $1 AND engine = 'sciat'", [agentId]);
      const row = rows[0];
      if (!row?.agent_token_hash || !sameHash(String(row.agent_token_hash), sha256(m[3]!))) throw new AgentEnrollmentError(401, "invalid_agent_token", "Invalid agent token");
      return fn(tx, { tenantId, agentId, organizationId: String(row.organization_id) });
    });
  }

  /** Authenticated check-in: refresh liveness and host facts, hand over queued commands. */
  async heartbeat(token: string, input: HeartbeatInput): Promise<{ pollSeconds: number; agentId: string; tenantId: string; organizationId: string; commands: AgentCommand[] }> {
    return this.withAgent(token, async (tx, { tenantId, agentId, organizationId }) => {
      const now = new Date(this.deps.now()).toISOString();
      const assets = await this.deps.inventory.resolveOrDiscoverHosts(tx, tenantId, organizationId, [{ hostname: input.hostname, os: input.os, ips: input.ips, lastSeenAt: now }]);
      await this.reconcileIsolation(tx, tenantId, organizationId, agentId, input.isolation);
      await tx.query(
        // A computer renamed to a name another agent of the organization still holds keeps its
        // current name (renaming it would collide and fail every check-in).
        `UPDATE agents SET last_checkin_at = $2, version = $3, asset_id = coalesce($5, asset_id),
                hostname = CASE WHEN EXISTS (SELECT 1 FROM agents o WHERE o.organization_id = agents.organization_id AND o.engine = agents.engine
                                             AND lower(o.hostname) = lower($4) AND o.id <> agents.id) THEN hostname ELSE $4 END,
                status = CASE WHEN isolation IS NOT NULL THEN 'isolated' ELSE 'protected' END,
                -- An agent that could not resolve the platform this time keeps the last known addresses.
                host_info = jsonb_build_object('platformIps', coalesce(host_info->'platformIps', '[]'::jsonb), 'dnsServers', coalesce(host_info->'dnsServers', '[]'::jsonb)) || $6::jsonb
         WHERE id = $1`,
        [
          agentId,
          now,
          input.version,
          input.hostname,
          [...assets.values()][0] ?? null,
          JSON.stringify({
            os: input.os ?? null,
            ips: input.ips ?? [],
            uptimeSeconds: input.uptimeSeconds ?? null,
            isolation: input.isolation ?? null,
            engines: input.engines ?? {},
            ...(input.platformIps?.length ? { platformIps: input.platformIps } : {}),
            ...(input.dnsServers?.length ? { dnsServers: input.dnsServers } : {}),
          }),
        ],
      );
      // Pending commands, plus delivered ones that were never answered (redelivered after 5 minutes;
      // isolate / release are idempotent on the endpoint).
      const { rows } = await tx.query<Row>(
        `UPDATE agent_commands SET status = 'delivered', delivered_at = now(), attempts = attempts + 1
          WHERE id IN (SELECT id FROM agent_commands WHERE agent_id = $1 AND expires_at > now()
                         AND (status = 'pending' OR (status = 'delivered' AND delivered_at < now() - interval '5 minutes'))
                       ORDER BY created_at LIMIT 5)
          RETURNING id, kind, args, created_at`,
        [agentId],
      );
      const commands = rows
        .sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)))
        .map((r) => ({ id: String(r.id), kind: r.kind as AgentCommand["kind"], args: (r.args as string[]).map(String) }));
      return { pollSeconds: AGENT_POLL_SECONDS, agentId, tenantId, organizationId, commands };
    });
  }

  /**
   * The computer's own report wins: isolated there but not here (a lost command result, or
   * isolated on the computer itself) is recorded as isolated; released there while no isolate /
   * release command is outstanding (released on the computer itself) clears it. Audited.
   */
  private async reconcileIsolation(tx: Queryable, tenantId: string, organizationId: string, agentId: string, reported: HeartbeatInput["isolation"]): Promise<void> {
    if (reported?.state !== "isolated" && reported?.state !== "not_isolated") return;
    const mode = reported.mode === "lan" ? "lan" : "full";
    const { rows } = await tx.query<Row>(
      `UPDATE agents SET isolation = CASE WHEN $2 = 'isolated' THEN jsonb_build_object('mode', $3::text, 'since', now(), 'actionId', NULL, 'source', 'endpoint') ELSE NULL END
        WHERE id = $1 AND status <> 'pending'
          AND (($2 = 'isolated' AND isolation IS NULL)
            OR ($2 = 'not_isolated' AND isolation IS NOT NULL
                AND coalesce((isolation->>'since')::timestamptz, now()) < now() - interval '2 minutes'
                AND NOT EXISTS (SELECT 1 FROM agent_commands c WHERE c.agent_id = agents.id AND c.status IN ('pending', 'delivered'))))
        RETURNING asset_id`,
      [agentId, reported.state, mode],
    );
    if (!rows[0]) return;
    await writeAudit(
      tx,
      { tenantId, actorKind: "service", actorId: `agent:${agentId}`, actorLabel: "SCIAT Agent", ip: null, userAgent: null, requestId: null },
      {
        action: reported.state === "isolated" ? "agent.isolation_reported" : "agent.release_reported",
        organizationId,
        targetKind: "asset",
        targetId: (rows[0].asset_id as string | null) ?? null,
        details: { agentId, mode: reported.state === "isolated" ? mode : null },
      },
    );
  }

  /** Result of a command; returns the response action to complete (once). */
  async commandResult(token: string, commandId: string, ok: boolean, output: string): Promise<{ tenantId: string; actionId: string | null; applied: boolean }> {
    return this.withAgent(token, async (tx, { tenantId, agentId }) => {
      const { rows } = await tx.query<Row>(
        `UPDATE agent_commands SET status = $3, output = $4, finished_at = now()
          WHERE id = $1 AND agent_id = $2 AND status IN ('pending', 'delivered') RETURNING response_action_id`,
        [commandId, agentId, ok ? "succeeded" : "failed", output.slice(0, 8000)],
      );
      if (rows[0]) return { tenantId, actionId: (rows[0].response_action_id as string | null) ?? null, applied: true };
      const known = await tx.query("SELECT 1 FROM agent_commands WHERE id = $1 AND agent_id = $2", [commandId, agentId]);
      if ((known.rowCount ?? 0) === 0) throw new AgentEnrollmentError(404, "not_found", "Unknown command");
      return { tenantId, actionId: null, applied: false }; // already answered or expired
    });
  }
}
