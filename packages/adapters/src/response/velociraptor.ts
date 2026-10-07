import type { ResponseActionKey } from "@bloody/contracts";
import { field, str } from "../core/json.js";
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
 * Velociraptor connector — schedules artifact collections on a client through the server's
 * API gateway (grpc-gateway JSON: `POST /api/v1/CollectArtifact`). Deploy the gateway with
 * an API client certificate (mTLS dispatcher) or behind an authenticating proxy; Velociraptor
 * itself (AGPL) runs unmodified.
 *
 * Request shape: `{ client_id, artifacts[], specs[{ artifact, parameters: { env: [{key,value}] } }],
 * urgent, timeout, max_rows, max_upload_bytes }` → `{ flow_id }`. A success means the collection
 * was SCHEDULED; results arrive through the collection adapter (flow results).
 */

export interface VelociraptorResponseOptions {
  collectPath?: string;
  /** Quarantine artifacts per platform (network isolation leaving only the server reachable). */
  isolateArtifacts?: Partial<Record<"windows" | "linux" | "macos", string>>;
  /** Parameter that removes the quarantine policy (Windows.Remediation.Quarantine: RemovePolicy=Y). */
  releaseParameter?: { key: string; value: string };
  /** Customer-approved artifact killing a process (receives `Pid`). Enables `kill_process`. */
  killProcessArtifact?: string;
  /** Customer-approved artifact quarantining a file (receives `TargetPath`). Enables `quarantine_file`. */
  quarantineFileArtifact?: string;
  /** Artifact allow-list for `collect_evidence` (glob suffix "*" allowed). Default: triage + info. */
  evidenceArtifactAllowList?: string[];
  yaraArtifact?: string;
  timeoutSeconds?: number;
  maxUploadBytes?: number;
}

const CLIENT_ID_RE = /^C\.[0-9A-Za-z]{6,32}$/;
const ARTIFACT_RE = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/;

function allowed(artifact: string, list: string[]): boolean {
  return list.some((p) => (p.endsWith("*") ? artifact.startsWith(p.slice(0, -1)) : artifact === p));
}

export function createVelociraptorResponse(opts: VelociraptorResponseOptions = {}): {
  supported: ResponseActionKey[];
  handlers: Partial<Record<ResponseActionKey, ResponseActionHandler>>;
  execute: (req: ResponseExecutionRequest, deps: ResponseDeps) => Promise<ResponseExecutionResult>;
} {
  const isolate = { windows: "Windows.Remediation.Quarantine", linux: "Linux.Remediation.Quarantine", ...opts.isolateArtifacts };
  const release = opts.releaseParameter ?? { key: "RemovePolicy", value: "Y" };
  const evidenceAllow = opts.evidenceArtifactAllowList ?? ["Windows.KapeFiles.Targets", "Windows.Triage.*", "Linux.Collection.*", "Generic.Client.Info", "Windows.Memory.Acquisition", "Generic.Forensic.*"];
  const supported: ResponseActionKey[] = ["isolate_endpoint", "release_endpoint", "collect_evidence", "run_yara_scan"];
  if (opts.killProcessArtifact) supported.push("kill_process");
  if (opts.quarantineFileArtifact) supported.push("quarantine_file");

  const prepare = (req: ResponseExecutionRequest): PreparedCall => {
    if (req.target.kind !== "asset") throw new ResponseGuardError("invalid_target", "Velociraptor actions target an asset");
    const clientId = paramString(req, "clientId") ?? req.target.id;
    if (!CLIENT_ID_RE.test(clientId)) throw new ResponseGuardError("invalid_target", `invalid Velociraptor client id "${clientId}"`);
    const specs: Array<{ artifact: string; env: Array<{ key: string; value: string }> }> = [];
    switch (req.action) {
      case "isolate_endpoint":
      case "release_endpoint": {
        const platform = paramString(req, "platform") as "windows" | "linux" | "macos" | undefined;
        const artifact = platform ? isolate[platform] : undefined;
        if (!artifact) throw new ResponseGuardError("invalid_parameters", "parameters.platform (windows|linux|macos) with a configured quarantine artifact is required");
        specs.push({ artifact, env: req.action === "release_endpoint" ? [release] : [] });
        break;
      }
      case "collect_evidence": {
        const artifacts = paramStringList(req, "artifacts");
        if (artifacts.length === 0) throw new ResponseGuardError("invalid_parameters", "parameters.artifacts is required");
        for (const a of artifacts) {
          if (!ARTIFACT_RE.test(a)) throw new ResponseGuardError("invalid_parameters", `invalid artifact name "${a}"`);
          if (!allowed(a, evidenceAllow)) throw new ResponseGuardError("invalid_parameters", `artifact "${a}" is not on the evidence allow-list`);
          specs.push({ artifact: a, env: [] });
        }
        break;
      }
      case "run_yara_scan": {
        const rule = paramString(req, "yaraRule");
        const glob = paramString(req, "pathGlob");
        if (!rule || rule.length > 256 * 1024) throw new ResponseGuardError("invalid_parameters", "parameters.yaraRule is required (≤ 256 KiB)");
        if (!glob) throw new ResponseGuardError("invalid_parameters", "parameters.pathGlob is required");
        specs.push({ artifact: opts.yaraArtifact ?? "Generic.Detection.Yara.Glob", env: [{ key: "PathGlob", value: glob }, { key: "YaraRule", value: rule }] });
        break;
      }
      case "kill_process": {
        const pid = Number(req.parameters["pid"]);
        if (!Number.isInteger(pid) || pid <= 4) throw new ResponseGuardError("invalid_parameters", "parameters.pid must be a user-space process id");
        specs.push({ artifact: opts.killProcessArtifact!, env: [{ key: "Pid", value: String(pid) }] });
        break;
      }
      case "quarantine_file": {
        const path = paramString(req, "path");
        if (!path || /[\r\n\0]/.test(path)) throw new ResponseGuardError("invalid_parameters", "parameters.path is required");
        specs.push({ artifact: opts.quarantineFileArtifact!, env: [{ key: "TargetPath", value: path }] });
        break;
      }
      default:
        throw new ResponseGuardError("unsupported_action", `${req.action} is not supported by Velociraptor`);
    }
    const body = {
      client_id: clientId,
      artifacts: specs.map((s) => s.artifact),
      specs: specs.map((s) => ({ artifact: s.artifact, parameters: { env: s.env } })),
      urgent: req.action === "isolate_endpoint" || req.action === "release_endpoint" || req.action === "kill_process",
      timeout: opts.timeoutSeconds ?? 600,
      max_upload_bytes: opts.maxUploadBytes ?? 2 * 1024 * 1024 * 1024,
    };
    // YARA rule text can be large; audit keeps its digest (bodySha256) and length only.
    const auditBody =
      req.action === "run_yara_scan"
        ? { ...body, specs: body.specs.map((s) => ({ artifact: s.artifact, parameters: { env: s.parameters.env.map((e) => (e.key === "YaraRule" ? { key: e.key, value: `[${e.value.length} chars]` } : e)) } })) }
        : body;
    return { method: "POST", path: opts.collectPath ?? "/api/v1/CollectArtifact", json: body, auditBody };
  };

  const interpret = (data: unknown): ExecutionOutcome => {
    const flowId = str(field(data, "flow_id"));
    const clientId = str(field(data, "request.client_id"));
    if (!flowId) return { outcome: "failed", affected: [], failed: [{ id: clientId ?? "?", reason: "no flow id returned" }], engineRef: null, summary: "Velociraptor did not schedule the collection" };
    return {
      outcome: "succeeded",
      affected: clientId ? [clientId] : [],
      failed: [],
      engineRef: flowId,
      summary: `Velociraptor collection scheduled (flow ${flowId})`,
      details: { state: "scheduled", flowId },
    };
  };

  const execute = async (req: ResponseExecutionRequest, deps: ResponseDeps): Promise<ResponseExecutionResult> => {
    const result = await executeResponse({ connector: "velociraptor.collect", engine: "velociraptor" }, supported, req, deps, prepare, interpret);
    if (req.action === "isolate_endpoint" && result.outcome === "succeeded") {
      result.reversal = { action: "release_endpoint", parameters: { clientId: paramString(req, "clientId") ?? req.target.id, platform: paramString(req, "platform") ?? "" } };
    }
    return result;
  };

  const handlers: Partial<Record<ResponseActionKey, ResponseActionHandler>> = {};
  for (const a of supported) handlers[a] = execute;
  return { supported, handlers, execute };
}
