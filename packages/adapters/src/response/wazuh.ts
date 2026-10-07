import type { ResponseActionKey } from "@bloody/contracts";
import { z } from "zod";
import { arr, field, int, isRecord, rec, str } from "../core/json.js";
import { cachedTokenProvider, EngineClient, type EngineClientOptions } from "../http/client.js";
import { runHealthCheck, type HealthCheckResult } from "../http/health.js";
import { classifyIp } from "../net/ip.js";
import {
  executeResponse,
  paramString,
  paramStringList,
  ResponseGuardError,
  type ExecutionOutcome,
  type PreparedCall,
  type ResponseActionHandler,
  type ResponseDeps,
  type ResponseExecutionRequest,
  type ResponseExecutionResult,
} from "./types.js";

/**
 * Wazuh API client + active-response connector.
 *
 * Auth: `POST /security/user/authenticate` with HTTP Basic → short-lived JWT (cached,
 * refreshed on expiry or 401). Use a dedicated Wazuh API user restricted by Wazuh RBAC to
 * `active-response:command` and read-only agent/manager endpoints.
 *
 * Active response: `PUT /active-response?agents_list=001,002` with
 * `{ command, arguments, alert: { data: {...} } }`. Commands prefixed with "!" run the named
 * script from the agent's active-response/bin directly. Stock scripts give `block_ip`
 * (firewall-drop) and `disable_identity` (disable-account); isolation, process kill and file
 * quarantine require customer-deployed scripts and are enabled only when configured.
 */

const WazuhAuthResponse = z.object({ data: z.object({ token: z.string().min(10) }) }).passthrough();

export interface WazuhApiOptions extends Omit<EngineClientOptions, "engine" | "auth"> {
  username: string;
  password: string;
  /** Wazuh `auth_token_exp_timeout` (default 900 s). */
  tokenTtlSeconds?: number;
}

export function createWazuhApiClient(opts: WazuhApiOptions): EngineClient {
  const { username, password, tokenTtlSeconds, ...rest } = opts;
  const login = new EngineClient({ ...rest, engine: "wazuh", auth: { kind: "basic", username, password } });
  const getToken = cachedTokenProvider(
    async () => {
      const res = await login.post("/security/user/authenticate", { schema: WazuhAuthResponse, retry: true });
      return { token: res.data.data.token, expiresInSeconds: tokenTtlSeconds ?? 900 };
    },
    { ...(rest.clock ? { clock: rest.clock } : {}) },
  );
  return new EngineClient({ ...rest, engine: "wazuh", auth: { kind: "token_provider", getToken } });
}

export function wazuhHealthCheck(client: EngineClient): Promise<HealthCheckResult> {
  return runHealthCheck("wazuh", async () => {
    const info = await client.get<unknown>("/");
    const version = str(field(info.data, "data.api_version"));
    const summary = await client.get<unknown>("/agents/summary/status", { acceptStatus: [403] });
    const conn = rec(field(summary.data, "data.connection")) ?? rec(field(summary.data, "data"));
    const active = int(conn?.["active"]) ?? 0;
    const total = int(conn?.["total"]) ?? 0;
    const disconnected = int(conn?.["disconnected"]) ?? 0;
    return {
      status: total > 0 && disconnected / total > 0.2 ? "degraded" : "healthy",
      ...(version ? { version } : {}),
      details: { agentsActive: active, agentsTotal: total, agentsDisconnected: disconnected, neverConnected: int(conn?.["never_connected"]) ?? 0 },
    };
  });
}

export interface WazuhActiveResponseOptions {
  /** Default "!firewall-drop" (Linux). Use "!netsh.exe" style names for Windows fleets. */
  blockIpCommand?: string;
  /** Default "!disable-account". */
  disableAccountCommand?: string;
  /** Customer-deployed isolation script, e.g. "!bloody-isolate". Enables `isolate_endpoint`. */
  isolateCommand?: string;
  /** Enables `release_endpoint`. */
  releaseCommand?: string;
  /** Enables `kill_process` (script receives the pid as first extra argument). */
  killProcessCommand?: string;
  /** Enables `quarantine_file` (script receives the absolute path as first extra argument). */
  quarantineFileCommand?: string;
  /** Allow `block_ip` on every agent (`parameters.scope = "all"`). Default false. */
  allowAllAgents?: boolean;
}

const AGENT_ID_RE = /^\d{3,6}$/;
const COMMAND_RE = /^!?[A-Za-z0-9._-]{1,64}$/;
const USER_RE = /^[A-Za-z0-9._$-]{1,64}$/;

function agentsFor(req: ResponseExecutionRequest, allowAll: boolean): string[] | "all" {
  const listed = paramStringList(req, "agents");
  const fromTarget = req.target.kind === "asset" ? [paramString(req, "agentId") ?? req.target.id] : [];
  const agents = [...new Set([...listed, ...fromTarget])];
  if (agents.length === 0) {
    if (paramString(req, "scope") === "all") {
      if (!allowAll) throw new ResponseGuardError("invalid_parameters", "fleet-wide active response is disabled for this integration");
      return "all";
    }
    throw new ResponseGuardError("invalid_parameters", "parameters.agents (Wazuh agent ids) is required");
  }
  for (const a of agents) if (!AGENT_ID_RE.test(a)) throw new ResponseGuardError("invalid_target", `invalid Wazuh agent id "${a}"`);
  return agents;
}

export function createWazuhActiveResponse(opts: WazuhActiveResponseOptions = {}): {
  supported: ResponseActionKey[];
  handlers: Partial<Record<ResponseActionKey, ResponseActionHandler>>;
  execute: (req: ResponseExecutionRequest, deps: ResponseDeps) => Promise<ResponseExecutionResult>;
} {
  const commands: Partial<Record<ResponseActionKey, string>> = {
    block_ip: opts.blockIpCommand ?? "!firewall-drop",
    disable_identity: opts.disableAccountCommand ?? "!disable-account",
    ...(opts.isolateCommand ? { isolate_endpoint: opts.isolateCommand } : {}),
    ...(opts.releaseCommand ? { release_endpoint: opts.releaseCommand } : {}),
    ...(opts.killProcessCommand ? { kill_process: opts.killProcessCommand } : {}),
    ...(opts.quarantineFileCommand ? { quarantine_file: opts.quarantineFileCommand } : {}),
  };
  for (const [action, cmd] of Object.entries(commands)) {
    if (!cmd || !COMMAND_RE.test(cmd)) throw new Error(`invalid Wazuh active-response command for ${action}`);
  }
  const supported = Object.keys(commands) as ResponseActionKey[];

  const prepare = (req: ResponseExecutionRequest): PreparedCall => {
    const command = commands[req.action];
    if (!command) throw new ResponseGuardError("unsupported_action", `${req.action} is not configured for Wazuh`);
    const args: string[] = [];
    const data: Record<string, string> = {};
    let agents: string[] | "all";
    switch (req.action) {
      case "block_ip": {
        const ip = req.target.id.trim();
        const cls = classifyIp(ip);
        if (!cls) throw new ResponseGuardError("invalid_target", "block_ip target must be an IP address");
        if (["loopback", "unspecified", "broadcast", "multicast", "metadata"].includes(cls)) throw new ResponseGuardError("invalid_target", `refusing to block ${cls} address ${ip}`);
        data["srcip"] = ip;
        agents = agentsFor(req, opts.allowAllAgents ?? false);
        break;
      }
      case "disable_identity": {
        const user = paramString(req, "username") ?? req.target.label ?? req.target.id;
        if (!USER_RE.test(user)) throw new ResponseGuardError("invalid_target", "invalid local account name");
        if (/^(root|administrator)$/i.test(user)) throw new ResponseGuardError("invalid_target", `refusing to disable built-in account ${user}`);
        data["dstuser"] = user;
        agents = agentsFor(req, false);
        if (agents === "all") throw new ResponseGuardError("invalid_parameters", "disable_identity must target specific agents");
        break;
      }
      case "kill_process": {
        const pid = int(req.parameters["pid"]);
        if (pid === undefined || pid <= 4) throw new ResponseGuardError("invalid_parameters", "parameters.pid must be a user-space process id");
        args.push(String(pid));
        agents = agentsFor(req, false);
        break;
      }
      case "quarantine_file": {
        const path = paramString(req, "path");
        if (!path || !/^(\/|[A-Za-z]:\\)/.test(path) || /[\r\n\0]/.test(path)) throw new ResponseGuardError("invalid_parameters", "parameters.path must be an absolute file path");
        args.push(path);
        agents = agentsFor(req, false);
        break;
      }
      default:
        agents = agentsFor(req, false);
    }
    if (agents === "all" && req.action !== "block_ip") throw new ResponseGuardError("invalid_parameters", `${req.action} must target specific agents`);
    const body = { command, arguments: args, alert: { data: { ...data, bloody_action_id: req.actionId } } };
    return {
      method: "PUT",
      path: "/active-response",
      ...(agents === "all" ? {} : { query: { agents_list: agents.join(",") } }),
      json: body,
    };
  };

  const interpret = (data: unknown): ExecutionOutcome => {
    const d = rec(field(data, "data")) ?? {};
    const affected = arr(d["affected_items"]).map((a) => (isRecord(a) ? str(a["id"]) : str(a))).filter((a): a is string => a !== undefined);
    const failed: Array<{ id: string; reason: string }> = [];
    for (const f of arr(d["failed_items"])) {
      if (!isRecord(f)) continue;
      const reason = str(field(f, "error.message")) ?? `error ${str(field(f, "error.code")) ?? "unknown"}`;
      for (const id of arr(f["id"])) failed.push({ id: str(id) ?? "?", reason });
    }
    const outcome = failed.length === 0 && affected.length > 0 ? "succeeded" : affected.length > 0 ? "partial" : "failed";
    return {
      outcome,
      affected,
      failed,
      engineRef: affected.length ? `wazuh-agents:${affected.join(",")}` : null,
      summary:
        outcome === "succeeded"
          ? `Wazuh active response sent to ${affected.length} agent${affected.length === 1 ? "" : "s"}`
          : outcome === "partial"
            ? `Wazuh active response sent to ${affected.length} agent(s), failed on ${failed.length}`
            : `Wazuh active response failed${failed[0] ? `: ${failed[0].reason}` : ""}`,
      details: { affected: affected.length, failed: failed.length, wazuhMessage: str(field(data, "message")) ?? "" },
    };
  };

  const execute = async (req: ResponseExecutionRequest, deps: ResponseDeps): Promise<ResponseExecutionResult> => {
    const result = await executeResponse({ connector: "wazuh.active_response", engine: "wazuh" }, supported, req, deps, prepare, interpret);
    if (req.action === "isolate_endpoint" && commands.release_endpoint && (result.outcome === "succeeded" || result.outcome === "partial")) {
      result.reversal = { action: "release_endpoint", parameters: { agents: result.affected } };
    }
    return result;
  };

  const handlers: Partial<Record<ResponseActionKey, ResponseActionHandler>> = {};
  for (const a of supported) handlers[a] = execute;
  return { supported, handlers, execute };
}
