import type { CanonicalEvent, Severity } from "@bloody/contracts";
import { SEVERITY_RANK } from "@bloody/contracts";

/**
 * Reconstruct process trees from canonical process events (EDR / osquery / Sysmon via Wazuh).
 * Processes are keyed per host by PID; when a parent never appears as its own event it is
 * synthesized from the child's `process.parent` fields so the lineage is still visible.
 */

export interface ProcessNode {
  key: string;
  host: string;
  pid: number | null;
  name: string;
  path: string | null;
  commandLine: string | null;
  user: string | null;
  sha256: string | null;
  /** First time this process was observed. */
  firstSeen: string | null;
  /** Highest event severity observed for this process. */
  severity: Severity;
  /** Event ids attributed to this process (newest last). */
  eventIds: string[];
  /** True when built only from a child's parent reference. */
  synthetic: boolean;
  children: ProcessNode[];
}

export interface HostProcessTree {
  host: string;
  roots: ProcessNode[];
  processCount: number;
}

function hostOf(e: CanonicalEvent): string {
  return e.asset?.hostname ?? e.asset?.id ?? e.asset?.agentId ?? "unknown host";
}

function baseName(path: string | undefined | null): string | null {
  if (!path) return null;
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || null;
}

function processKey(host: string, pid: number | null | undefined, name: string | null): string {
  return pid !== null && pid !== undefined ? `${host}|pid:${pid}` : `${host}|name:${(name ?? "?").toLowerCase()}`;
}

function maxSev(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

export function buildProcessTrees(events: CanonicalEvent[]): HostProcessTree[] {
  const nodes = new Map<string, ProcessNode>();
  const parentOf = new Map<string, string>();
  const sorted = [...events].filter((e) => e.process && (e.process.pid !== undefined || e.process.name || e.process.path)).sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  for (const e of sorted) {
    const p = e.process!;
    const host = hostOf(e);
    const name = p.name ?? baseName(p.path) ?? (p.pid !== undefined ? `pid ${p.pid}` : "process");
    const key = processKey(host, p.pid, name);
    let node = nodes.get(key);
    if (!node) {
      node = {
        key,
        host,
        pid: p.pid ?? null,
        name,
        path: p.path ?? null,
        commandLine: p.commandLine ?? null,
        user: p.user ?? e.user?.name ?? null,
        sha256: p.hashSha256 ?? null,
        firstSeen: e.timestamp,
        severity: e.severity ?? "info",
        eventIds: [],
        synthetic: false,
        children: [],
      };
      nodes.set(key, node);
    } else if (node.synthetic) {
      // A real event for a previously synthesized parent: fill in what we now know.
      Object.assign(node, {
        synthetic: false,
        name,
        path: p.path ?? node.path,
        commandLine: p.commandLine ?? node.commandLine,
        user: p.user ?? e.user?.name ?? node.user,
        sha256: p.hashSha256 ?? node.sha256,
        firstSeen: node.firstSeen && node.firstSeen < e.timestamp ? node.firstSeen : e.timestamp,
      });
    } else {
      node.commandLine ??= p.commandLine ?? null;
      node.path ??= p.path ?? null;
      node.sha256 ??= p.hashSha256 ?? null;
      node.user ??= p.user ?? null;
    }
    node.severity = maxSev(node.severity, e.severity ?? "info");
    node.eventIds.push(e.id);

    const parent = p.parent;
    if (parent && (parent.pid !== undefined || parent.name || parent.path)) {
      const parentName = parent.name ?? baseName(parent.path) ?? (parent.pid !== undefined ? `pid ${parent.pid}` : "parent");
      const parentKey = processKey(host, parent.pid, parentName);
      if (parentKey !== key) {
        if (!nodes.has(parentKey)) {
          nodes.set(parentKey, {
            key: parentKey,
            host,
            pid: parent.pid ?? null,
            name: parentName,
            path: parent.path ?? null,
            commandLine: parent.commandLine ?? null,
            user: null,
            sha256: null,
            firstSeen: null,
            severity: "info",
            eventIds: [],
            synthetic: true,
            children: [],
          });
        }
        if (!parentOf.has(key)) parentOf.set(key, parentKey);
      }
    }
  }

  // Link children; guard against cycles introduced by PID reuse.
  const isAncestor = (candidate: string, of: string): boolean => {
    let cur: string | undefined = candidate;
    const seen = new Set<string>();
    while (cur && !seen.has(cur)) {
      if (cur === of) return true;
      seen.add(cur);
      cur = parentOf.get(cur);
    }
    return false;
  };
  const roots: ProcessNode[] = [];
  for (const node of nodes.values()) {
    const parentKey = parentOf.get(node.key);
    const parent = parentKey ? nodes.get(parentKey) : undefined;
    // Linking would create a cycle when this node is already an ancestor of its parent.
    if (parent && !isAncestor(parent.key, node.key)) parent.children.push(node);
    else roots.push(node);
  }
  const byTime = (a: ProcessNode, b: ProcessNode) => (a.firstSeen ?? "").localeCompare(b.firstSeen ?? "") || a.name.localeCompare(b.name);
  const sortRec = (list: ProcessNode[]) => {
    list.sort(byTime);
    for (const n of list) sortRec(n.children);
  };

  const hosts = new Map<string, ProcessNode[]>();
  for (const r of roots) {
    const list = hosts.get(r.host) ?? [];
    list.push(r);
    hosts.set(r.host, list);
  }
  const out: HostProcessTree[] = [];
  for (const [host, list] of hosts) {
    sortRec(list);
    out.push({ host, roots: list, processCount: countNodes(list) });
  }
  return out.sort((a, b) => b.processCount - a.processCount || a.host.localeCompare(b.host));
}

function countNodes(list: ProcessNode[]): number {
  return list.reduce((n, p) => n + 1 + countNodes(p.children), 0);
}

/** Depth-first flattening for rendering with indentation. */
export function flattenTree(roots: ProcessNode[], depth = 0, out: { node: ProcessNode; depth: number }[] = []): { node: ProcessNode; depth: number }[] {
  for (const n of roots) {
    out.push({ node: n, depth });
    flattenTree(n.children, depth + 1, out);
  }
  return out;
}
