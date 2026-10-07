import type { Severity } from "@bloody/contracts";
import { normalizeTactic, techniquesInText } from "../core/attack.js";
import { defineAdapter, type Adapter, type AdapterExtras, skip, type EventDraft, type MapOutput } from "../core/adapter.js";
import { ObservableSet } from "../core/indicators.js";
import { basename, field, int, isRecord, port, rec, redactKeys, str, strArr } from "../core/json.js";
import { DEFAULT_SENSITIVE_KEYS } from "../core/severity.js";
import { toIso } from "../core/time.js";
import { inferDirection } from "../net/ip.js";

/**
 * Falco adapter — consumes Falco JSON alerts (`json_output: true`, stdout/file/http output)
 * and Falcosidekick webhook payloads (same shape). Syscall and k8s_audit sources supported.
 *
 *   priority Emergency/Alert/Critical → critical · Error → high · Warning → medium ·
 *   Notice → low · Informational/Debug → info.  tags "T1059" / "mitre_*" → attack[].
 */
export const FALCO_ADAPTER_VERSION = "1.0.0";

export function falcoPriorityToSeverity(priority: string | undefined): Severity {
  switch (priority?.trim().toLowerCase()) {
    case "emergency":
    case "alert":
    case "critical":
      return "critical";
    case "error":
      return "high";
    case "warning":
      return "medium";
    case "notice":
      return "low";
    default:
      return "info";
  }
}

function mapFalco(record: unknown): MapOutput {
  if (!isRecord(record)) return skip("not a JSON object");
  const rule = str(record["rule"]);
  const priority = str(record["priority"]);
  if (!rule || !priority) return skip("not a Falco alert (rule/priority missing)");
  const of = rec(record["output_fields"]) ?? {};
  const o = (k: string): string | undefined => str(field(of, k));
  const source = str(record["source"]) ?? "syscall";
  const tags = strArr(record["tags"]);
  const tactic = tags.map((t) => normalizeTactic(t)).find((t) => t !== undefined);
  const attack = techniquesInText(tags).map((t) => (tactic && !t.tactic ? { ...t, tactic } : t));
  const hostname = str(record["hostname"]) ?? o("evt.hostname");
  const obs = new ObservableSet();
  const labels: Record<string, string | number | boolean | undefined> = {
    severity_basis: `falco priority ${priority}`,
    "falco.source": source,
    "falco.tags": tags.join(",") || undefined,
    "container.id": o("container.id"),
    "container.name": o("container.name"),
    "container.image": o("container.image.repository") ? `${o("container.image.repository")}${o("container.image.tag") ? `:${o("container.image.tag")}` : ""}` : undefined,
    "k8s.namespace": o("k8s.ns.name"),
    "k8s.pod": o("k8s.pod.name"),
  };

  const draft: EventDraft = {
    timestamp: toIso(record["time"]) ?? toIso(o("evt.time")),
    category: "detection",
    eventType: `falco.${source}`,
    message: str(record["output"]) ?? rule,
    severity: falcoPriorityToSeverity(priority),
    detection: { ruleId: rule, ruleName: rule, engine: "falco" },
    attack,
    asset: { hostname },
    dedupKey: str(record["uuid"]) ?? `${str(record["time"]) ?? ""}:${rule}:${hostname ?? ""}:${o("proc.pid") ?? ""}`,
    raw: record,
  };

  if (source === "k8s_audit") {
    const user = o("ka.user.name");
    const ns = o("ka.target.namespace");
    const name = o("ka.target.name");
    const srcIps = strArr(field(of, "ka.sourceips"));
    draft.category = "cloud";
    draft.action = o("ka.verb");
    draft.user = user ? { name: user } : undefined;
    draft.identity = { provider: "kubernetes", principal: user, sourceIp: srcIps[0] };
    draft.cloudResource = {
      provider: "kubernetes",
      resourceType: o("ka.target.resource"),
      resourceId: ns && name ? `${ns}/${name}` : name ?? ns,
      action: o("ka.verb"),
    };
    const code = int(o("ka.response.code"));
    draft.outcome = code === undefined ? "unknown" : code < 400 ? "success" : "failure";
    labels["k8s.audit_uri"] = o("ka.uri");
    labels["k8s.response_code"] = code;
    for (const ip of srcIps) obs.add("ip", ip);
  } else {
    const exe = o("proc.exepath") ?? o("proc.exe");
    draft.process = {
      pid: int(o("proc.pid")),
      name: o("proc.name") ?? basename(exe),
      path: exe,
      commandLine: o("proc.cmdline"),
      user: o("user.name"),
      parent: { pid: int(o("proc.ppid")), name: o("proc.pname"), path: o("proc.pexepath"), commandLine: o("proc.pcmdline") },
    };
    const userName = o("user.name");
    if (userName) draft.user = { name: userName };
    const fdName = o("fd.name") ?? o("fs.path.name");
    const fdType = o("fd.type") ?? (o("fd.typechar") === "f" ? "file" : undefined);
    if (fdName && (fdType === "file" || fdType === "directory" || (!fdType && fdName.startsWith("/")))) {
      draft.file = { path: fdName, name: basename(fdName) };
    }
    const sip = o("fd.sip") ?? o("fd.rip");
    const cip = o("fd.cip") ?? o("fd.lip");
    if (sip || cip) {
      // fd.cip/cport = client side, fd.sip/sport = server side of the socket
      draft.network = {
        srcIp: cip,
        srcPort: port(o("fd.cport") ?? o("fd.lport")),
        dstIp: sip,
        dstPort: port(o("fd.sport") ?? o("fd.rport")),
        protocol: o("fd.l4proto"),
        direction: inferDirection(cip, sip),
      };
      obs.add("ip", sip).add("ip", cip);
    }
    if (o("k8s.ns.name") || o("k8s.pod.name")) {
      draft.cloudResource = {
        provider: "kubernetes",
        resourceType: "pod",
        resourceId: [o("k8s.ns.name"), o("k8s.pod.name")].filter(Boolean).join("/"),
      };
    }
  }
  draft.indicators = obs.toArray();
  draft.labels = labels;
  return draft;
}

export function createFalcoAdapter(extras: AdapterExtras = {}): Adapter {
  return defineAdapter({
    ...extras,
    key: "falco",
    version: FALCO_ADAPTER_VERSION,
    name: "Falco runtime alerts",
    sourceKind: "endpoint",
    vendor: "The Falco Authors",
    consumes: ["Falco JSON alerts (syscall, k8s_audit)", "Falcosidekick webhook payloads"],
    map: mapFalco,
    redactRaw: (r) => redactKeys(r, DEFAULT_SENSITIVE_KEYS),
  });
}
