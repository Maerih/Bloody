import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { HostInventoryReport } from "@bloody/contracts";
import { recordAudit } from "../audit/audit.js";
import { requireAuth, requirePermission } from "../auth/rbac.js";
import type { AppServices } from "../context.js";
import { notFound, unauthorized } from "../http/errors.js";
import type { Row } from "../repo/mappers.js";
import { SCIAT_AGENT_VERSION } from "../services/agent-enrollment.js";
import { IdParam } from "../http/params.js";
import { parse } from "./util.js";

/** Files the platform serves to endpoints: name → path below infra/agent. Nothing else is reachable. */
const AGENT_FILES: Record<string, { file: string; type: string }> = {
  "sciat-agent.sh": { file: "sciat/sciat-agent.sh", type: "text/x-shellscript" },
  "sciat-agent.ps1": { file: "sciat/sciat-agent.ps1", type: "text/plain" },
  "SciatAgentService.cs": { file: "sciat/SciatAgentService.cs", type: "text/plain" },
  "bloody-isolate": { file: "active-response/bloody-isolate", type: "text/x-shellscript" },
  "bloody-isolate.ps1": { file: "active-response/bloody-isolate.ps1", type: "text/plain" },
};
const INSTALLERS = {
  linux: { file: "sciat/install-unix.sh", name: "install-sciat.sh", type: "text/x-shellscript" },
  macos: { file: "sciat/install-unix.sh", name: "install-sciat.sh", type: "text/x-shellscript" },
  windows: { file: "sciat/install-windows.ps1", name: "install-sciat.ps1", type: "text/plain" },
} as const;

/** infra/agent in a checkout (src or dist), or ./agent next to dist in the container image. */
export function agentFilesDir(override?: string): string {
  if (override) return override;
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [path.resolve(here, "../../agent"), path.resolve(here, "../../../../infra/agent")];
  return candidates.find((d) => existsSync(path.join(d, "sciat"))) ?? candidates[1]!;
}

const HOST_RE = /^[A-Za-z0-9.-]+(:\d{1,5})?$|^\[[0-9A-Fa-f:.]+\](:\d{1,5})?$/;
/** The address endpoints reach this platform at: the one the installer was downloaded from. */
export function platformUrlFor(request: FastifyRequest, trustProxy: boolean, fallback: string): string {
  const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)?.split(",")[0]?.trim();
  const host = (trustProxy ? first(request.headers["x-forwarded-host"]) : undefined) ?? request.headers.host;
  const proto = (trustProxy ? first(request.headers["x-forwarded-proto"]) : undefined) ?? request.protocol;
  if (host && HOST_RE.test(host) && (proto === "http" || proto === "https")) return `${proto}://${host}`;
  return new URL(fallback).origin;
}

function bearer(request: FastifyRequest): string {
  const header = request.headers.authorization;
  const token = typeof header === "string" && header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) throw unauthorized("Agent token required");
  return token;
}

const ipsOnly = z
  .array(z.string().max(64))
  .max(32)
  .transform((v) => v.filter((x) => z.string().ip().safeParse(x).success).slice(0, 16))
  .optional();

const EnrollBody = z
  .object({
    accountKey: z.string().min(10).max(200),
    organizationKey: z.string().min(1).max(100),
    hostname: z.string().min(1).max(253),
    platform: z.enum(["windows", "macos", "linux"]),
    os: z.string().max(200).optional(),
    version: z.string().min(1).max(40),
    ips: z.array(z.string().ip()).max(32).optional(),
    machineId: z.string().max(100).optional(),
  })
  .strict();
const HeartbeatBody = z
  .object({
    hostname: z.string().min(1).max(253),
    os: z.string().max(200).optional(),
    version: z.string().min(1).max(40),
    ips: z.array(z.string().ip()).max(32).optional(),
    uptimeSeconds: z.number().int().min(0).max(1e10).optional(),
    isolation: z.object({ state: z.enum(["isolated", "not_isolated", "unknown"]), mode: z.string().max(20).optional() }).optional(),
    engines: z.record(z.string().max(60), z.string().max(40)).optional(),
    // Best-effort facts from the endpoint: anything that is not an IP address is dropped, not refused.
    platformIps: ipsOnly,
    dnsServers: ipsOnly,
  })
  .strict();
const ResultBody = z.object({ status: z.enum(["succeeded", "failed"]), output: z.string().max(20_000).default("") }).strict();

/**
 * SCIAT Agent: enrollment keys for admins, and the public endpoint-facing API (installers, agent
 * files, enroll, heartbeat). Endpoints authenticate with the account key once, then their own token.
 */
export async function agentRoutes(app: FastifyInstance, s: AppServices): Promise<void> {
  const svc = s.agentEnrollment;
  const filesDir = agentFilesDir(s.config.agent.filesDir);
  const endpointLimit = { max: 60, timeWindow: "1 minute" };

  app.get("/agents/enrollment", async (request) => {
    const auth = requireAuth(request);
    requirePermission(request, "asset:write", null);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const accountKey = await svc.accountKey(tx, auth.tenantId);
      const { rows } = await tx.query<Row>(
        `SELECT o.id, o.name, o.slug, count(a.id) FILTER (WHERE a.engine = 'sciat')::int AS agents
           FROM organizations o LEFT JOIN agents a ON a.organization_id = o.id
          WHERE o.status <> 'offboarded' GROUP BY o.id ORDER BY o.name`,
      );
      const meta = await tx.query<Row>("SELECT rotated_at FROM agent_enrollment");
      return {
        accountKey,
        rotatedAt: meta.rows[0]?.rotated_at ? new Date(String(meta.rows[0].rotated_at)).toISOString() : null,
        agentVersion: SCIAT_AGENT_VERSION,
        platformUrl: platformUrlFor(request, s.config.http.trustProxy, s.config.http.publicUrl),
        organizations: rows.map((r) => ({ id: String(r.id), name: String(r.name), key: String(r.slug), agents: Number(r.agents) })),
      };
    });
  });

  app.post("/agents/enrollment/regenerate", { config: { audit: false } }, async (request) => {
    const auth = requireAuth(request);
    requirePermission(request, "settings:write", null);
    return s.db.withTenant(auth.tenantId, async (tx) => {
      const accountKey = await svc.rotate(tx, auth.tenantId);
      await recordAudit(tx, request, { action: "agent.account_key_rotated", targetKind: "tenant", targetId: auth.tenantId, details: {} });
      return { accountKey };
    });
  });

  // ---- Endpoint-facing (public) -------------------------------------------------------------

  app.get("/agent/install/:os", { config: { public: true, audit: false, rateLimit: endpointLimit } }, async (request, reply) => {
    const { os } = parse(z.object({ os: z.enum(["linux", "macos", "windows"]) }), request.params);
    const inst = INSTALLERS[os];
    const script = (await readFile(path.join(filesDir, inst.file), "utf8")).replaceAll("__PLATFORM_URL__", platformUrlFor(request, s.config.http.trustProxy, s.config.http.publicUrl));
    return reply
      .header("content-type", `${inst.type}; charset=utf-8`)
      .header("content-disposition", `attachment; filename="${inst.name}"`)
      .header("cache-control", "no-store")
      .send(script);
  });

  app.get("/agent/files/:name", { config: { public: true, audit: false, rateLimit: endpointLimit } }, async (request, reply) => {
    const { name } = parse(z.object({ name: z.string().max(60) }), request.params);
    const f = Object.hasOwn(AGENT_FILES, name) ? AGENT_FILES[name] : undefined;
    if (!f) throw notFound("Agent file");
    return reply.header("content-type", `${f.type}; charset=utf-8`).header("cache-control", "no-store").send(await readFile(path.join(filesDir, f.file), "utf8"));
  });

  app.post("/agent/enroll", { config: { public: true, audit: false, rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request) => {
    const body = parse(EnrollBody, request.body);
    const res = await svc.enroll(body);
    request.log.info({ agentId: res.agentId, organizationId: res.organizationId, hostname: body.hostname }, "sciat agent enrolled");
    return res;
  });

  app.post("/agent/heartbeat", { config: { public: true, audit: false, rateLimit: endpointLimit } }, async (request) => {
    const token = bearer(request);
    const body = parse(HeartbeatBody, request.body);
    const res = await svc.heartbeat(token, body);
    return {
      pollSeconds: res.pollSeconds,
      serverTime: new Date(s.now()).toISOString(),
      commands: res.commands,
      // Same commands as plain lines ("<id> <args…>") for agents without a JSON parser.
      commandLines: res.commands.map((c) => [c.id, ...c.args].join(" ")),
    };
  });

  // Host inventory (about every 30 minutes): software, services, users, processes, ports, AV, firewall.
  app.post("/agent/inventory", { bodyLimit: 8 * 1024 * 1024, config: { public: true, audit: false, rateLimit: endpointLimit } }, async (request) => {
    const token = bearer(request);
    const report = parse(HostInventoryReport, request.body);
    const res = await svc.withAgent(token, async (tx, agent) => ({ ...agent, ...(await s.hostInventory.record(tx, agent.agentId, report)) }));
    if (res.after === "unhealthy" && res.before !== "unhealthy") {
      s.domainEvents.publish({
        tenantId: res.tenantId,
        organizationId: res.organizationId,
        event: "antivirus.unhealthy",
        occurredAt: new Date(s.now()).toISOString(),
        severity: "high",
        subject: { kind: "agent", id: res.agentId, label: res.hostname },
        dedupKey: `agent:${res.agentId}:antivirus-unhealthy:${new Date(s.now()).toISOString().slice(0, 10)}`,
        data: { agent: { id: res.agentId, hostname: res.hostname }, antivirus: { issues: res.issues.join("; ") || "no antivirus is active", previous: res.before } },
      });
    }
    return { ok: true, antivirusStatus: res.after, nextInSeconds: 1800 };
  });

  app.post("/agent/commands/:id/result", { config: { public: true, audit: false, rateLimit: endpointLimit } }, async (request) => {
    const token = bearer(request);
    const { id } = parse(IdParam, request.params);
    const body = parse(ResultBody, request.body);
    const res = await svc.commandResult(token, id, body.status === "succeeded", body.output);
    if (res.applied && res.actionId) await s.responses.completeFromAgent(res.tenantId, res.actionId, body.status === "succeeded", body.output);
    return { ok: true };
  });
}
