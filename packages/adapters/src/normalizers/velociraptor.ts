import { technique, techniquesInText } from "../core/attack.js";
import { defineAdapter, skip, type Adapter, type AdapterExtras, type EventDraft, type MapContext, type MapOutput } from "../core/adapter.js";
import { canonicalJson, sha256Hex } from "../core/hash.js";
import { ObservableSet } from "../core/indicators.js";
import { arr, basename, field, int, isRecord, port, rec, redactKeys, str, strArr, uint, type JsonRecord } from "../core/json.js";
import { atLeast, isSensitiveKey, severityFromWord } from "../core/severity.js";
import { toIso } from "../core/time.js";
import { inferDirection } from "../net/ip.js";
import { mapWindowsEvent } from "./windows.js";

/**
 * Velociraptor adapter — consumes collection / hunt results (artifact rows).
 *
 * Accepted shapes:
 *  - collection envelope `{ artifact, client_id, hostname?, flow_id?, hunt_id?, rows: [...] }`
 *    (what Bloody's collector produces when it reads a flow via the API gateway);
 *  - hunt / notebook exports: one JSON row per line carrying `ClientId`, `Fqdn`, `FlowId`
 *    and `_Source` (artifact name) — or pass `options.artifact` for single-artifact files.
 *
 * Artifact families: process listings, netstat, YARA hits, Sigma/Hayabusa detections,
 * persistence (autoruns, services, tasks), file finders/MFT/timelines, EVTX rows (mapped
 * through the Windows event model), client info. Unknown artifacts map to `device` events.
 */
export const VELOCIRAPTOR_ADAPTER_VERSION = "1.0.0";

type Family = "process" | "netstat" | "yara" | "sigma" | "persistence" | "file" | "evtx" | "clientinfo" | "generic";

export function artifactFamily(artifact: string): Family {
  const a = artifact.toLowerCase();
  if (/yara/.test(a)) return "yara";
  if (/hayabusa|sigma|chainsaw|detection\.(?!yara)/.test(a)) return "sigma";
  if (/evtx|eventlogs/.test(a)) return "evtx";
  if (/pslist|pstree|processinfo|\.processes|process\.info/.test(a)) return "process";
  if (/netstat|connections/.test(a)) return "netstat";
  if (/autoruns|startupitems|services|scheduledtasks|persistence|cron|systemd/.test(a)) return "persistence";
  if (/filefinder|glob|\.mft|timeline|usn|search\.file|\.files/.test(a)) return "file";
  if (/client\.info|clientinfo|generic\.client\.info/.test(a)) return "clientinfo";
  return "generic";
}

interface Meta {
  artifact: string;
  clientId?: string;
  hostname?: string;
  flowId?: string;
  huntId?: string;
  collectedAt?: string;
}

function rowDraft(row: JsonRecord, meta: Meta): EventDraft {
  const g = (k: string): string | undefined => str(field(row, k));
  const fam = artifactFamily(meta.artifact);
  const obs = new ObservableSet();
  const labels: Record<string, string | number | boolean | undefined> = {
    "velociraptor.artifact": meta.artifact,
    "velociraptor.client_id": meta.clientId,
    "velociraptor.flow_id": meta.flowId,
    "velociraptor.hunt_id": meta.huntId,
  };
  const draft: EventDraft = {
    category: "device",
    eventType: `velociraptor.${meta.artifact}`,
    asset: { hostname: g("Fqdn") ?? g("Hostname") ?? meta.hostname, agentId: meta.clientId },
    severity: "info",
    raw: row,
    dedupKey: `${meta.clientId ?? ""}:${meta.flowId ?? meta.huntId ?? ""}:${meta.artifact}:${sha256Hex(canonicalJson(row)).slice(0, 24)}`,
  };
  const sha256 = g("Hash.SHA256") ?? g("Hashes.SHA256") ?? g("SHA256") ?? g("sha256");
  const md5 = g("Hash.MD5") ?? g("Hashes.MD5") ?? g("MD5");
  obs.addHash(sha256).addHash(md5);

  switch (fam) {
    case "process": {
      const exe = g("Exe") ?? g("Path") ?? g("Image");
      draft.category = "process";
      draft.timestamp = toIso(g("CreateTime") ?? g("StartTime"));
      draft.action = "process-observed";
      draft.process = {
        pid: int(row["Pid"]),
        name: g("Name") ?? basename(exe),
        path: exe,
        commandLine: g("CommandLine"),
        user: g("Username") ?? g("User"),
        hashSha256: sha256,
        parent: { pid: int(row["Ppid"]) },
      };
      if (draft.process.user) draft.user = { name: draft.process.user };
      break;
    }
    case "netstat": {
      const lip = g("Laddr.IP") ?? g("LocalAddress") ?? g("Laddr");
      const rip = g("Raddr.IP") ?? g("RemoteAddress") ?? g("Raddr");
      draft.category = "network";
      draft.timestamp = toIso(g("Timestamp"));
      draft.action = g("Status")?.toLowerCase() ?? "connection";
      draft.network = {
        srcIp: lip,
        srcPort: port(field(row, "Laddr.Port") ?? row["LocalPort"]),
        dstIp: rip && rip !== "0.0.0.0" && rip !== "::" ? rip : undefined,
        dstPort: port(field(row, "Raddr.Port") ?? row["RemotePort"]),
        protocol: g("Type")?.toLowerCase() ?? g("Protocol")?.toLowerCase(),
        direction: inferDirection(lip, rip),
      };
      draft.process = { pid: int(row["Pid"]), name: g("Name") };
      obs.add("ip", rip);
      break;
    }
    case "yara": {
      const rule = g("Rule") ?? g("RuleName");
      const file = g("FileName") ?? g("OSPath") ?? g("FullPath") ?? g("Path");
      draft.category = "detection";
      draft.eventType = "velociraptor.yara_match";
      draft.severity = "high";
      draft.message = `YARA rule ${rule ?? "?"} matched ${file ?? g("ProcessName") ?? "target"}`;
      draft.detection = { ruleId: rule, ruleName: rule, engine: "yara" };
      if (file) draft.file = { path: file, name: basename(file), sha256, md5, size: uint(row["Size"]) };
      if (row["Pid"] !== undefined) draft.process = { pid: int(row["Pid"]), name: g("ProcessName") ?? g("Name") };
      labels["yara.tags"] = strArr(row["Tags"]).join(",") || undefined;
      labels["severity_basis"] = "YARA signature match";
      draft.attack = techniquesInText(strArr(row["Tags"]), g("Meta.mitre") ?? g("Meta.attack"));
      break;
    }
    case "sigma": {
      const title = g("RuleTitle") ?? g("Title") ?? g("rule_title") ?? g("Rule.Title");
      const level = g("Level") ?? g("level") ?? g("Rule.Level");
      draft.category = "detection";
      draft.eventType = "velociraptor.sigma_match";
      draft.timestamp = toIso(g("Timestamp") ?? g("EventTime") ?? g("System.TimeCreated.SystemTime"));
      draft.severity = severityFromWord(level === "crit" ? "critical" : level === "med" ? "medium" : level) ?? "medium";
      draft.message = title;
      draft.detection = { ruleId: g("RuleID") ?? g("Rule.Id") ?? title, ruleName: title, engine: "sigma" };
      draft.asset = { ...draft.asset, hostname: g("Computer") ?? draft.asset?.hostname };
      draft.attack = techniquesInText(strArr(row["MitreTags"] ?? row["Tags"] ?? field(row, "Rule.Tags")), g("MitreTactics"));
      labels["severity_basis"] = `sigma level ${level ?? "unknown"}`;
      labels["windows.event_id"] = g("EventID");
      labels["details"] = g("Details");
      break;
    }
    case "evtx": {
      const system = rec(row["System"]) ?? {};
      const sysNorm = {
        eventID: str(field(system, "EventID.Value")) ?? str(system["EventID"]),
        channel: str(system["Channel"]),
        computer: str(system["Computer"]),
        providerName: str(field(system, "Provider.Name")),
      };
      const mapped = mapWindowsEvent(sysNorm, row["EventData"]);
      draft.timestamp = toIso(field(system, "TimeCreated.SystemTime"));
      draft.asset = { ...draft.asset, hostname: sysNorm.computer ?? draft.asset?.hostname };
      if (mapped) {
        Object.assign(draft, mapped.draft, { severity: atLeast("info", mapped.severityFloor) });
        for (const o of mapped.draft.indicators ?? []) obs.add(o.type, o.value);
        Object.assign(labels, mapped.draft.labels);
      } else {
        draft.category = "audit";
        draft.eventType = `windows.event_${sysNorm.eventID ?? "unknown"}`;
        labels["windows.event_id"] = sysNorm.eventID;
        labels["windows.channel"] = sysNorm.channel;
      }
      break;
    }
    case "persistence": {
      const cmd = g("Command") ?? g("ImagePath") ?? g("Image Path") ?? g("Launch String") ?? g("Path");
      draft.category = "configuration";
      draft.eventType = "velociraptor.persistence_item";
      draft.message = `${g("Name") ?? g("Entry") ?? "persistence entry"}: ${cmd ?? ""}`.trim();
      draft.process = cmd ? { commandLine: cmd, path: g("ImagePath") ?? g("Image Path"), name: basename(g("ImagePath") ?? g("Image Path")) } : undefined;
      labels["persistence.name"] = g("Name") ?? g("Entry");
      labels["persistence.location"] = g("Entry Location") ?? g("Location") ?? g("Category");
      labels["persistence.enabled"] = g("Enabled");
      labels["persistence.signer"] = g("Signer");
      const t = technique(/task/i.test(meta.artifact) ? "T1053.005" : /service/i.test(meta.artifact) ? "T1543.003" : "T1547");
      draft.attack = t ? [t] : [];
      break;
    }
    case "file": {
      const path = g("OSPath") ?? g("FullPath") ?? g("Path") ?? g("FileName");
      draft.category = "file";
      draft.eventType = "velociraptor.file_observed";
      draft.timestamp = toIso(g("Mtime") ?? g("Btime") ?? g("Ctime") ?? g("LastModified0x10") ?? g("Timestamp"));
      draft.file = { path, name: g("Name") ?? basename(path), sha256, md5, size: uint(row["Size"]) };
      labels["file.mode"] = g("Mode");
      break;
    }
    case "clientinfo": {
      draft.category = "device";
      draft.eventType = "velociraptor.client_info";
      draft.asset = {
        hostname: g("Fqdn") ?? g("Hostname") ?? meta.hostname,
        agentId: meta.clientId ?? g("ClientId"),
        os: [g("OS") ?? g("Platform"), g("PlatformVersion") ?? g("Release")].filter(Boolean).join(" ") || undefined,
        mac: strArr(row["MACAddresses"] ?? row["MAC"]),
      };
      labels["client.architecture"] = g("Architecture");
      labels["client.build_time"] = g("build_time") ?? g("BuildTime");
      break;
    }
    case "generic": {
      let n = 0;
      for (const [k, v] of Object.entries(row)) {
        if (n >= 16 || k.startsWith("_")) continue;
        const s = str(v);
        if (s === undefined) continue;
        labels[`row.${k}`] = s;
        n++;
      }
      break;
    }
  }
  draft.timestamp = draft.timestamp ?? meta.collectedAt;
  draft.indicators = obs.toArray();
  draft.labels = labels;
  return draft;
}

function mapVelociraptor(record: unknown, ctx: MapContext): MapOutput {
  if (!isRecord(record)) return skip("not a JSON object");
  // Envelope form
  if (Array.isArray(record["rows"])) {
    const artifact = str(record["artifact"]) ?? str(ctx.options["artifact"]);
    if (!artifact) return skip("collection envelope without artifact name");
    const meta: Meta = {
      artifact,
      clientId: str(record["client_id"]),
      hostname: str(record["hostname"]) ?? str(record["fqdn"]),
      flowId: str(record["flow_id"]),
      huntId: str(record["hunt_id"]),
      collectedAt: toIso(record["collected_at"]) ?? toIso(record["create_time"]),
    };
    const rows = arr(record["rows"]).filter(isRecord);
    return rows.length > 0 ? rows.map((r) => rowDraft(r, meta)) : skip("collection returned no rows");
  }
  // Row form (hunt export)
  const artifact = str(record["_Source"]) ?? str(record["Artifact"]) ?? str(ctx.options["artifact"]);
  if (!artifact) return skip("row without artifact name (_Source); pass options.artifact");
  return rowDraft(record, {
    artifact,
    clientId: str(record["ClientId"]) ?? str(record["client_id"]),
    hostname: str(record["Fqdn"]) ?? str(record["Hostname"]),
    flowId: str(record["FlowId"]),
    huntId: str(record["HuntId"]),
    collectedAt: toIso(record["_ts"]),
  });
}

export function createVelociraptorAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    ...extras,
    key: "velociraptor",
    version: VELOCIRAPTOR_ADAPTER_VERSION,
    name: "Velociraptor collections & hunts",
    sourceKind: "endpoint",
    vendor: "Rapid7 / Velocidex",
    consumes: ["collection envelopes {artifact, client_id, rows}", "hunt / notebook JSONL exports (_Source, ClientId, Fqdn)"],
    map: mapVelociraptor,
    redactRaw: (r) => redactKeys(r, isSensitiveKey),
  });
}
