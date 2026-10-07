import type { EventCategory } from "@bloody/contracts";
import { defineAdapter, type Adapter, type AdapterExtras, skip, type EventDraft, type MapContext, type MapOutput } from "../core/adapter.js";
import { canonicalJson, sha256Hex } from "../core/hash.js";
import { ObservableSet } from "../core/indicators.js";
import { arr, basename, field, int, isRecord, port, rec, str, uint, type JsonRecord } from "../core/json.js";
import { toIso } from "../core/time.js";
import { inferDirection } from "../net/ip.js";

/**
 * osquery adapter — consumes scheduled-query result logs (filesystem/TLS/Kafka logger
 * plugins): differential events (`columns` + `action`), batched differentials
 * (`diffResults.added/removed`) and snapshots (`snapshot[]`). One canonical event per row.
 *
 * Category is inferred from the query name and columns: process, network, file,
 * authentication, identity, registry, otherwise configuration (inventory/state).
 * Up to 24 result columns are kept as `osquery.col.*` labels for detection rules.
 * Option `maxRowsPerSnapshot` (default 10 000) bounds very large snapshots.
 */
export const OSQUERY_ADAPTER_VERSION = "1.0.0";

const FILE_ACTIONS: Record<string, "create" | "modify" | "delete" | "rename" | "read"> = {
  CREATED: "create",
  UPDATED: "modify",
  ATTRIBUTES_MODIFIED: "modify",
  DELETED: "delete",
  MOVED_FROM: "rename",
  MOVED_TO: "rename",
  ACCESSED: "read",
  OPENED: "read",
};

const IP_PROTO: Record<string, string> = { "6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6" };

export function osqueryCategory(queryName: string, cols: JsonRecord): EventCategory {
  const n = queryName.toLowerCase();
  const has = (k: string): boolean => Object.prototype.hasOwnProperty.call(cols, k);
  if (n.includes("registry")) return "registry";
  if (has("remote_address") || has("remote_port") || /socket|connection|listening_ports|arp_cache|routes/.test(n)) return "network";
  if (n.includes("file_events") || n.includes("yara") || has("target_path")) return "file";
  if (has("cmdline") || /process_events|processes|process_open|bpf_process/.test(n)) return "process";
  if (/logged_in_users|last|logon|user_events|shell_history|authorized_keys_events/.test(n)) return "authentication";
  if (/\busers\b|groups|sudoers|user_groups|admins|authorized_keys/.test(n)) return "identity";
  if (/dns/.test(n)) return "dns";
  return "configuration";
}

function rowDraft(row: JsonRecord, meta: { name: string; host?: string; hostUuid?: string; os?: string; at?: string; action: string; counter?: number; decorations: JsonRecord }): EventDraft {
  const category = osqueryCategory(meta.name, row);
  const c = (k: string): string | undefined => str(row[k]);
  const obs = new ObservableSet();
  const labels: Record<string, string | number | boolean | undefined> = {
    "osquery.query": meta.name,
    "osquery.action": meta.action,
    "osquery.counter": meta.counter,
    "osquery.pack": /^pack[_/]([^_/]+)[_/]/.exec(meta.name)?.[1],
  };
  let n = 0;
  for (const [k, v] of Object.entries(row)) {
    if (n >= 24) break;
    const s = str(v);
    if (s === undefined) continue;
    labels[`osquery.col.${k}`] = s;
    n++;
  }
  const draft: EventDraft = {
    timestamp: meta.at,
    category,
    eventType: `osquery.${meta.name.replace(/[^A-Za-z0-9_.:-]/g, "_")}`,
    action: meta.action,
    asset: { hostname: meta.host, agentId: meta.hostUuid, os: meta.os },
    severity: "info",
    raw: { name: meta.name, hostIdentifier: meta.host, action: meta.action, columns: row, decorations: meta.decorations },
    dedupKey: `${meta.host ?? ""}:${meta.name}:${meta.at ?? ""}:${meta.action}:${sha256Hex(canonicalJson(row)).slice(0, 24)}`,
  };

  const path = c("path");
  const sha256 = c("sha256");
  obs.addHash(sha256).addHash(c("md5")).addHash(c("sha1"));
  switch (category) {
    case "process":
      draft.process = {
        pid: int(row["pid"]),
        name: c("name") ?? basename(path),
        path,
        commandLine: c("cmdline"),
        user: c("username") ?? c("uid"),
        hashSha256: sha256,
        parent: { pid: int(row["parent"]) ?? int(row["ppid"]) },
      };
      break;
    case "network": {
      const remote = c("remote_address");
      const local = c("local_address") ?? c("address");
      const outbound = remote !== undefined && remote !== "0.0.0.0" && remote !== "::";
      draft.network = {
        srcIp: local,
        srcPort: port(row["local_port"] ?? row["port"]),
        dstIp: outbound ? remote : undefined,
        dstPort: outbound ? port(row["remote_port"]) : undefined,
        protocol: IP_PROTO[c("protocol") ?? ""] ?? c("protocol"),
        direction: outbound ? inferDirection(local, remote) : "unknown",
      };
      if (row["pid"] !== undefined || c("name")) draft.process = { pid: int(row["pid"]), name: c("name"), path };
      if (outbound) obs.add("ip", remote);
      break;
    }
    case "file": {
      const target = c("target_path") ?? path;
      draft.file = {
        path: target,
        name: basename(target),
        action: FILE_ACTIONS[(c("action") ?? "").toUpperCase()],
        sha256,
        md5: c("md5"),
        size: uint(row["size"]),
      };
      break;
    }
    case "authentication":
    case "identity": {
      const user = c("username") ?? c("user");
      if (user) draft.user = { name: user };
      const host = c("host");
      if (category === "authentication") {
        draft.identity = { provider: "host", principal: user, sourceIp: host };
        obs.add("ip", host);
      }
      break;
    }
    case "registry":
      labels["registry.key"] = c("key") ?? c("path");
      labels["registry.value"] = c("data");
      break;
    case "dns":
      if (c("name")) draft.network = { dnsQuery: c("name"), protocol: "dns" };
      obs.add("domain", c("name"));
      break;
    default:
      break;
  }
  draft.indicators = obs.toArray();
  draft.labels = labels;
  return draft;
}

function mapOsquery(record: unknown, ctx: MapContext): MapOutput {
  if (!isRecord(record)) return skip("not a JSON object");
  const name = str(record["name"]);
  if (!name) return skip("not an osquery result (no query name)");
  const decorations = rec(record["decorations"]) ?? {};
  const meta = {
    name,
    host: str(decorations["hostname"]) ?? str(record["hostIdentifier"]),
    hostUuid: str(decorations["host_uuid"]) ?? str(decorations["uuid"]),
    os: str(decorations["os_name"]) ?? str(field(decorations, "os_version.name")),
    at: toIso(record["unixTime"]) ?? toIso(record["calendarTime"]),
    counter: int(record["counter"]),
    decorations,
  };
  const maxRows = Math.max(1, int(ctx.options["maxRowsPerSnapshot"]) ?? 10_000);

  if (Array.isArray(record["snapshot"])) {
    const rows = record["snapshot"].filter(isRecord);
    if (rows.length === 0) return skip("empty snapshot");
    return rows.slice(0, maxRows).map((row) => rowDraft(row, { ...meta, action: "snapshot" }));
  }
  const diff = rec(record["diffResults"]);
  if (diff) {
    const out: EventDraft[] = [];
    for (const row of arr(diff["added"])) if (isRecord(row)) out.push(rowDraft(row, { ...meta, action: "added" }));
    for (const row of arr(diff["removed"])) if (isRecord(row)) out.push(rowDraft(row, { ...meta, action: "removed" }));
    return out.length > 0 ? out.slice(0, maxRows) : skip("empty differential");
  }
  const cols = rec(record["columns"]);
  if (cols) return rowDraft(cols, { ...meta, action: str(record["action"]) ?? "added" });
  return skip("osquery record has no columns, diffResults or snapshot");
}

export function createOsqueryAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    ...extras,
    key: "osquery",
    version: OSQUERY_ADAPTER_VERSION,
    name: "osquery results",
    sourceKind: "endpoint",
    vendor: "osquery Foundation",
    consumes: ["differential results (columns/action)", "batched differentials (diffResults)", "snapshot results"],
    map: mapOsquery,
  });
}
