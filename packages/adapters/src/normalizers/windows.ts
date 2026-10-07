import type { AttackTechnique, EventCategory, Severity } from "@bloody/contracts";
import { technique } from "../core/attack.js";
import type { EventDraft } from "../core/adapter.js";
import { ObservableSet, parseHashList } from "../core/indicators.js";
import { basename, int, isRecord, port, str } from "../core/json.js";
import { inferDirection, isIp } from "../net/ip.js";

/**
 * Windows Security / System / Sysmon event semantics, independent of the transport.
 * Used by the Wazuh adapter (`data.win.system` + `data.win.eventdata`, camelCase) and by any
 * collector delivering raw EVTX JSON (PascalCase) — field lookup is case-insensitive.
 * Mapping derived from Microsoft's public event documentation and Sysmon's event schema.
 */

interface WinEventSpec {
  type: string;
  category: EventCategory;
  action: string;
  outcome?: "success" | "failure";
  attack?: string[];
  severityFloor?: Severity;
}

export const WINDOWS_SECURITY_EVENTS: Record<number, WinEventSpec> = {
  1102: { type: "audit_log_cleared", category: "audit", action: "clear-log", attack: ["T1070.001"], severityFloor: "high" },
  4624: { type: "logon_success", category: "authentication", action: "logon", outcome: "success" },
  4625: { type: "logon_failure", category: "authentication", action: "logon", outcome: "failure", attack: ["T1110"] },
  4634: { type: "logoff", category: "authentication", action: "logoff", outcome: "success" },
  4647: { type: "logoff_user_initiated", category: "authentication", action: "logoff", outcome: "success" },
  4648: { type: "explicit_credential_logon", category: "authentication", action: "logon-explicit-credentials" },
  4662: { type: "directory_object_access", category: "identity", action: "object-access" },
  4663: { type: "object_access", category: "file", action: "object-access" },
  4672: { type: "special_privileges_assigned", category: "authentication", action: "privileged-logon", outcome: "success" },
  4688: { type: "process_creation", category: "process", action: "process-create" },
  4689: { type: "process_exit", category: "process", action: "process-exit" },
  4697: { type: "service_installed", category: "configuration", action: "service-install", attack: ["T1543.003"], severityFloor: "medium" },
  4698: { type: "scheduled_task_created", category: "configuration", action: "scheduled-task-create", attack: ["T1053.005"], severityFloor: "medium" },
  4719: { type: "audit_policy_changed", category: "audit", action: "audit-policy-change", attack: ["T1562.002"], severityFloor: "medium" },
  4720: { type: "user_created", category: "identity", action: "user-create", attack: ["T1136"] },
  4722: { type: "user_enabled", category: "identity", action: "user-enable" },
  4723: { type: "password_change_attempt", category: "identity", action: "password-change" },
  4724: { type: "password_reset_attempt", category: "identity", action: "password-reset", attack: ["T1098"] },
  4725: { type: "user_disabled", category: "identity", action: "user-disable" },
  4726: { type: "user_deleted", category: "identity", action: "user-delete", attack: ["T1531"] },
  4728: { type: "member_added_global_group", category: "identity", action: "group-member-add", attack: ["T1098"] },
  4732: { type: "member_added_local_group", category: "identity", action: "group-member-add", attack: ["T1098"] },
  4740: { type: "account_locked_out", category: "identity", action: "lockout", outcome: "failure" },
  4756: { type: "member_added_universal_group", category: "identity", action: "group-member-add", attack: ["T1098"] },
  4768: { type: "kerberos_tgt_requested", category: "authentication", action: "kerberos-tgt" },
  4769: { type: "kerberos_service_ticket_requested", category: "authentication", action: "kerberos-tgs" },
  4771: { type: "kerberos_preauth_failed", category: "authentication", action: "kerberos-preauth", outcome: "failure" },
  4776: { type: "credential_validation", category: "authentication", action: "ntlm-validate" },
  5140: { type: "network_share_accessed", category: "file", action: "share-access" },
  7045: { type: "service_installed", category: "configuration", action: "service-install", attack: ["T1543.003"], severityFloor: "medium" },
};

export const SYSMON_EVENTS: Record<number, WinEventSpec> = {
  1: { type: "process_create", category: "process", action: "process-create" },
  2: { type: "file_creation_time_changed", category: "file", action: "timestomp", attack: ["T1070.006"] },
  3: { type: "network_connection", category: "network", action: "connect" },
  5: { type: "process_terminated", category: "process", action: "process-exit" },
  6: { type: "driver_loaded", category: "configuration", action: "driver-load" },
  7: { type: "image_loaded", category: "process", action: "image-load" },
  8: { type: "create_remote_thread", category: "process", action: "remote-thread", attack: ["T1055"], severityFloor: "medium" },
  10: { type: "process_access", category: "process", action: "process-access" },
  11: { type: "file_create", category: "file", action: "create" },
  12: { type: "registry_object", category: "registry", action: "registry-create-delete" },
  13: { type: "registry_value_set", category: "registry", action: "registry-set" },
  14: { type: "registry_rename", category: "registry", action: "registry-rename" },
  15: { type: "file_stream_created", category: "file", action: "ads-create" },
  17: { type: "pipe_created", category: "process", action: "pipe-create" },
  18: { type: "pipe_connected", category: "process", action: "pipe-connect" },
  22: { type: "dns_query", category: "dns", action: "dns-query" },
  23: { type: "file_delete", category: "file", action: "delete" },
  25: { type: "process_tampering", category: "process", action: "process-tamper", attack: ["T1055"], severityFloor: "high" },
  26: { type: "file_delete_detected", category: "file", action: "delete" },
};

/** Case-insensitive view of an eventdata object. */
function ci(obj: unknown): (key: string) => string | undefined {
  const map = new Map<string, unknown>();
  if (isRecord(obj)) for (const [k, v] of Object.entries(obj)) map.set(k.toLowerCase(), v);
  return (key) => str(map.get(key.toLowerCase()));
}

/** "CORP\\alice" → { domain: "CORP", name: "alice" }. */
export function splitDomainUser(value: string | undefined, domain?: string): { name?: string; domain?: string } {
  if (!value) return domain ? { domain } : {};
  const bs = value.indexOf("\\");
  if (bs > 0) return { domain: value.slice(0, bs), name: value.slice(bs + 1) };
  const at = value.indexOf("@");
  if (at > 0 && !domain) return { name: value.slice(0, at), domain: value.slice(at + 1) };
  return domain ? { name: value, domain } : { name: value };
}

const SENSITIVE_PROCESS_TARGETS = /\\(lsass|csrss|winlogon|services)\.exe$/i;

export interface WindowsMapping {
  draft: Omit<EventDraft, "timestamp" | "severity">;
  severityFloor?: Severity;
  isSysmon: boolean;
  eventId: number;
}

function techniques(ids: string[] | undefined): AttackTechnique[] {
  return (ids ?? []).map((id) => technique(id)).filter((t): t is AttackTechnique => t !== undefined);
}

function cleanIp(ip: string | undefined): string | undefined {
  if (!ip) return undefined;
  const v = ip.replace(/^::ffff:/i, "");
  return isIp(v) && v !== "127.0.0.1" && v !== "::1" ? v : undefined;
}

/**
 * Map a Windows event (system + eventdata) to canonical fields. Returns undefined when the
 * event id is not one we model; the caller then keeps its generic mapping.
 */
export function mapWindowsEvent(system: unknown, eventdata: unknown): WindowsMapping | undefined {
  const sys = ci(system);
  const ed = ci(eventdata);
  const eventId = int(sys("eventID") ?? sys("EventID"));
  if (eventId === undefined) return undefined;
  const channel = sys("channel") ?? "";
  const provider = sys("providerName") ?? "";
  const isSysmon = /sysmon/i.test(channel) || /sysmon/i.test(provider);
  const spec = isSysmon ? SYSMON_EVENTS[eventId] : WINDOWS_SECURITY_EVENTS[eventId];
  if (!spec) return undefined;

  const obs = new ObservableSet();
  const attack = techniques(spec.attack);
  let severityFloor = spec.severityFloor;
  const labels: Record<string, string | number | boolean | undefined> = {
    "windows.event_id": eventId,
    "windows.channel": channel || undefined,
    "windows.provider": provider || undefined,
  };
  const draft: Omit<EventDraft, "timestamp" | "severity"> = {
    category: spec.category,
    eventType: isSysmon ? `sysmon.${spec.type}` : `windows.${spec.type}`,
    action: spec.action,
    ...(spec.outcome ? { outcome: spec.outcome } : {}),
  };

  const hashes = parseHashList(ed("hashes") ?? ed("hash"));
  obs.addHash(hashes.sha256).addHash(hashes.md5).addHash(hashes.sha1);

  if (isSysmon) {
    const user = splitDomainUser(ed("user"));
    if (user.name) draft.user = user;
    const image = ed("image") ?? ed("sourceImage");
    switch (eventId) {
      case 1:
      case 5:
        draft.process = {
          pid: int(ed("processId")),
          name: basename(image),
          path: image,
          commandLine: ed("commandLine"),
          user: ed("user"),
          hashSha256: hashes.sha256,
          parent: { pid: int(ed("parentProcessId")), name: basename(ed("parentImage")), path: ed("parentImage"), commandLine: ed("parentCommandLine") },
        };
        labels["process.integrity_level"] = ed("integrityLevel");
        labels["process.original_file_name"] = ed("originalFileName");
        break;
      case 3: {
        const srcIp = ed("sourceIp");
        const dstIp = ed("destinationIp");
        const initiated = ed("initiated");
        draft.process = { pid: int(ed("processId")), name: basename(image), path: image, user: ed("user") };
        draft.network = {
          protocol: ed("protocol")?.toLowerCase(),
          srcIp,
          srcPort: port(ed("sourcePort")),
          dstIp,
          dstPort: port(ed("destinationPort")),
          direction: inferDirection(srcIp, dstIp),
        };
        labels["network.initiated"] = initiated;
        obs.add("ip", dstIp).add("ip", srcIp).addHost(ed("destinationHostname"));
        break;
      }
      case 7:
        draft.process = { pid: int(ed("processId")), name: basename(image), path: image, user: ed("user") };
        draft.file = { path: ed("imageLoaded"), name: basename(ed("imageLoaded")), action: "read", sha256: hashes.sha256, md5: hashes.md5 };
        labels["image.signed"] = ed("signed");
        labels["image.signature"] = ed("signature");
        break;
      case 8:
      case 10: {
        const target = ed("targetImage");
        draft.process = {
          pid: int(ed("sourceProcessId") ?? ed("processId")),
          name: basename(image),
          path: image,
          user: ed("sourceUser") ?? ed("user"),
        };
        labels["target.image"] = target;
        labels["target.pid"] = ed("targetProcessId");
        labels["granted_access"] = ed("grantedAccess");
        if (target && /\\lsass\.exe$/i.test(target)) {
          attack.push(...techniques(["T1003.001"]));
          severityFloor = "high";
        } else if (target && SENSITIVE_PROCESS_TARGETS.test(target)) {
          severityFloor = severityFloor ?? "medium";
        }
        break;
      }
      case 2:
      case 11:
      case 15:
      case 23:
      case 26: {
        const path = ed("targetFilename");
        draft.process = { pid: int(ed("processId")), name: basename(image), path: image, user: ed("user") };
        draft.file = {
          path,
          name: basename(path),
          action: eventId === 23 || eventId === 26 ? "delete" : eventId === 2 ? "modify" : "create",
          sha256: hashes.sha256,
          md5: hashes.md5,
        };
        break;
      }
      case 12:
      case 13:
      case 14:
        draft.process = { pid: int(ed("processId")), name: basename(image), path: image, user: ed("user") };
        labels["registry.key"] = ed("targetObject");
        labels["registry.value"] = ed("details");
        labels["registry.event_type"] = ed("eventType");
        if (/\\CurrentVersion\\Run(Once)?\\/i.test(ed("targetObject") ?? "")) {
          attack.push(...techniques(["T1547.001"]));
          severityFloor = severityFloor ?? "medium";
        }
        break;
      case 22: {
        const query = ed("queryName");
        draft.process = { pid: int(ed("processId")), name: basename(image), path: image, user: ed("user") };
        draft.network = { protocol: "dns", dnsQuery: query };
        obs.add("domain", query);
        for (const part of (ed("queryResults") ?? "").split(";")) obs.add("ip", part.replace(/^::ffff:/i, "").trim());
        labels["dns.status"] = ed("queryStatus");
        break;
      }
      default:
        draft.process = { pid: int(ed("processId")), name: basename(image), path: image, user: ed("user") };
    }
  } else {
    const target = splitDomainUser(ed("targetUserName"), ed("targetDomainName"));
    const subject = splitDomainUser(ed("subjectUserName"), ed("subjectDomainName"));
    const srcIp = cleanIp(ed("ipAddress"));
    switch (spec.category) {
      case "authentication": {
        const who = target.name ? target : subject;
        if (who.name) draft.user = { ...who, sid: ed("targetUserSid") ?? ed("subjectUserSid") };
        draft.identity = {
          provider: eventId >= 4768 && eventId <= 4776 ? "active_directory" : "windows",
          principal: who.name ? (who.domain ? `${who.domain}\\${who.name}` : who.name) : undefined,
          sourceIp: srcIp,
          outcome: spec.outcome ?? (ed("status") && ed("status") !== "0x0" ? "failure" : "success"),
          privileged: eventId === 4672 ? true : undefined,
        };
        if (spec.outcome === undefined) draft.outcome = draft.identity.outcome;
        if (srcIp) draft.network = { srcIp, srcPort: port(ed("ipPort")) };
        obs.add("ip", srcIp);
        labels["logon.type"] = ed("logonType");
        labels["logon.workstation"] = ed("workstationName");
        labels["logon.status"] = ed("status");
        labels["logon.sub_status"] = ed("subStatus");
        labels["kerberos.ticket_encryption"] = ed("ticketEncryptionType");
        labels["kerberos.service"] = ed("serviceName");
        if (eventId === 4769 && ed("ticketEncryptionType") === "0x17" && !(ed("serviceName") ?? "").endsWith("$")) {
          attack.push(...techniques(["T1558.003"]));
          severityFloor = severityFloor ?? "medium";
        }
        break;
      }
      case "process": {
        const path = ed("newProcessName") ?? ed("processName");
        draft.process = {
          pid: int(ed("newProcessId") ?? ed("processId")),
          name: basename(path),
          path,
          commandLine: ed("commandLine"),
          user: subject.name ? (subject.domain ? `${subject.domain}\\${subject.name}` : subject.name) : undefined,
          parent: { pid: int(ed("processId")), name: basename(ed("parentProcessName")), path: ed("parentProcessName") },
        };
        if (subject.name) draft.user = subject;
        break;
      }
      case "identity": {
        const who = target.name ? target : splitDomainUser(ed("memberName"));
        if (who.name) draft.user = { ...who, sid: ed("targetSid") ?? ed("memberSid") };
        draft.identity = {
          provider: "windows",
          principal: who.name ? (who.domain ? `${who.domain}\\${who.name}` : who.name) : undefined,
          outcome: spec.outcome ?? "success",
        };
        labels["actor"] = subject.name ? (subject.domain ? `${subject.domain}\\${subject.name}` : subject.name) : undefined;
        labels["group"] = ed("targetUserName") && (eventId === 4728 || eventId === 4732 || eventId === 4756) ? ed("targetUserName") : undefined;
        if (eventId === 4728 || eventId === 4732 || eventId === 4756) {
          const group = ed("targetUserName") ?? "";
          draft.user = splitDomainUser(ed("memberName"));
          if (/admin|domain admins|enterprise admins|schema admins/i.test(group)) severityFloor = "high";
        }
        break;
      }
      case "configuration": {
        labels["service.name"] = ed("serviceName");
        labels["service.image_path"] = ed("imagePath") ?? ed("serviceFileName");
        labels["task.name"] = ed("taskName");
        if (subject.name) draft.user = subject;
        break;
      }
      case "file": {
        const path = ed("objectName") ?? ed("relativeTargetName");
        draft.file = { path, name: basename(path), action: "read" };
        if (subject.name) draft.user = subject;
        labels["share.name"] = ed("shareName");
        if (srcIp) draft.network = { srcIp };
        break;
      }
      default:
        if (subject.name) draft.user = subject;
    }
  }

  draft.indicators = obs.toArray();
  draft.attack = attack;
  draft.labels = labels;
  return { draft, isSysmon, eventId, ...(severityFloor ? { severityFloor } : {}) };
}

