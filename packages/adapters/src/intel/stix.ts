import type { AttackTechnique, IndicatorType, Severity } from "@bloody/contracts";
import { technique } from "../core/attack.js";
import type { Observable } from "../core/indicators.js";
import { normalizeObservable } from "../core/indicators.js";
import { arr, int, isRecord, rec, str, strArr, type JsonRecord } from "../core/json.js";
import { toIso } from "../core/time.js";
import { buildIndicatorRecord, parseTlp, severityFromConfidence, strictestTlp, type IntelParseResult, type Tlp } from "./types.js";

/**
 * STIX 2.1 support (written against the OASIS STIX 2.1 specification):
 *  - `parseStixPattern` extracts atomic observables from STIX patterning expressions;
 *  - `parseStixBundle` turns indicator SDOs of a bundle into Bloody indicator records,
 *    resolving `indicates` relationships (malware, threat actor, intrusion set, campaign,
 *    attack pattern, vulnerability) and TLP markings.
 */

/** Fixed TLP 1.0 marking-definition ids from the STIX 2.1 specification. */
export const STIX_TLP_MARKINGS: Record<string, Tlp> = {
  "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "clear",
  "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
  "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
  "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
};

export interface StixPatternResult {
  observables: Observable[];
  /** True when the expression combines observations with AND / FOLLOWEDBY / qualifiers. */
  conjunctive: boolean;
  unsupported: string[];
}

const COMPARISON_RE = /([a-z0-9-]+):((?:[A-Za-z0-9_-]+|'[^']*')(?:\.(?:[A-Za-z0-9_-]+|'[^']*'))*)\s*(=|!=|LIKE|MATCHES|IN|>=|<=|>|<|ISSUBSET|ISSUPERSET)\s*('(?:[^'\\]|\\.)*'|\([^)]*\)|-?[\d.]+|true|false)/g;

function pathToType(object: string, path: string): IndicatorType | undefined {
  const p = path.replace(/'/g, "").toLowerCase();
  if (object === "ipv4-addr" || object === "ipv6-addr") return p === "value" ? "ip" : undefined;
  if (object === "domain-name") return p === "value" ? "domain" : undefined;
  if (object === "url") return p === "value" ? "url" : undefined;
  if (object === "email-addr") return p === "value" ? "email" : undefined;
  if (object === "file" || object === "artifact") {
    if (p === "hashes.md5") return "md5";
    if (p === "hashes.sha-1" || p === "hashes.sha1") return "sha1";
    if (p === "hashes.sha-256" || p === "hashes.sha256") return "sha256";
  }
  if (object === "network-traffic" && p.endsWith("ja3")) return "ja3";
  return undefined;
}

function outsideQuotes(pattern: string): string {
  return pattern.replace(/'(?:[^'\\]|\\.)*'/g, "''");
}

export function parseStixPattern(pattern: string): StixPatternResult {
  const structure = outsideQuotes(pattern);
  const conjunctive = /\bAND\b|\bFOLLOWEDBY\b|\bWITHIN\b|\bREPEATS\b|\bSTART\b/.test(structure);
  const observables: Observable[] = [];
  const unsupported: string[] = [];
  const seen = new Set<string>();
  for (const m of pattern.matchAll(COMPARISON_RE)) {
    const object = m[1] ?? "";
    const path = m[2] ?? "";
    const op = m[3] ?? "";
    const rawValue = m[4] ?? "";
    const type = pathToType(object, path);
    if (!type || op !== "=" || !rawValue.startsWith("'")) {
      unsupported.push(`${object}:${path} ${op}`);
      continue;
    }
    // In conjunctive expressions only strong, self-sufficient observables (hashes) are kept:
    // an IP that is only malicious "AND port 4444" must not become a standalone IOC.
    if (conjunctive && !["md5", "sha1", "sha256"].includes(type)) {
      unsupported.push(`${object}:${path} (part of a conjunctive expression)`);
      continue;
    }
    let value = rawValue.slice(1, -1).replace(/\\(.)/g, "$1");
    if (type === "ip" && value.includes("/")) {
      const [addr, prefix] = value.split("/");
      if ((prefix === "32" || prefix === "128") && addr) value = addr;
      else {
        unsupported.push(`${object}:${path} CIDR ${value}`);
        continue;
      }
    }
    const norm = normalizeObservable(type, value);
    if (!norm) {
      unsupported.push(`${object}:${path} invalid value`);
      continue;
    }
    const key = `${type}:${norm}`;
    if (!seen.has(key)) {
      seen.add(key);
      observables.push({ type, value: norm });
    }
  }
  return { observables, conjunctive, unsupported };
}

export interface StixBundleOptions {
  now: string;
  /** Source label stored on records (e.g. "stix:feed-name", "opencti"). */
  source?: string;
  defaultConfidence?: number;
  includeRevoked?: boolean;
}

function attackFromAttackPattern(obj: JsonRecord): AttackTechnique | undefined {
  for (const ref of arr(obj["external_references"])) {
    if (!isRecord(ref)) continue;
    const src = str(ref["source_name"]);
    const id = str(ref["external_id"]);
    if (id && (src === "mitre-attack" || /^T\d{4}/.test(id))) return technique(id, str(obj["name"]));
  }
  const id = str(obj["x_mitre_id"]);
  return id ? technique(id, str(obj["name"])) : undefined;
}

function tlpOf(refs: string[], objects: Map<string, JsonRecord>): Tlp | null {
  const found: Array<Tlp | null> = [];
  for (const ref of refs) {
    const fixed = STIX_TLP_MARKINGS[ref];
    if (fixed) {
      found.push(fixed);
      continue;
    }
    const md = objects.get(ref);
    if (!md) continue;
    found.push(parseTlp(str(rec(md["definition"])?.["tlp"]) ?? str(md["name"]) ?? str(md["definition"])));
  }
  return strictestTlp(found);
}

/** Convert one STIX indicator SDO (+ bundle context) to records. */
export function stixIndicatorToRecords(ind: JsonRecord, objects: Map<string, JsonRecord>, relations: Map<string, JsonRecord[]>, opts: StixBundleOptions): IntelParseResult {
  const out: IntelParseResult = { records: [], skipped: [] };
  const id = str(ind["id"]) ?? "indicator--unknown";
  const revoked = ind["revoked"] === true;
  if (revoked && !opts.includeRevoked) {
    out.skipped.push({ ref: id, reason: "revoked" });
    return out;
  }
  const types = strArr(ind["indicator_types"]).map((t) => t.toLowerCase());
  if (types.includes("benign")) {
    out.skipped.push({ ref: id, reason: "benign indicator (allow-list entry, never a block/match indicator)" });
    return out;
  }
  const patternType = str(ind["pattern_type"]) ?? "stix";
  if (patternType !== "stix") {
    out.skipped.push({ ref: id, reason: `pattern type "${patternType}" is a detection rule, not an atomic indicator` });
    return out;
  }
  const pattern = str(ind["pattern"]);
  if (!pattern) {
    out.skipped.push({ ref: id, reason: "indicator without pattern" });
    return out;
  }
  const parsed = parseStixPattern(pattern);
  if (parsed.observables.length === 0) {
    out.skipped.push({ ref: id, reason: `no atomic observable in pattern${parsed.unsupported.length ? ` (${parsed.unsupported.slice(0, 3).join(", ")})` : ""}` });
    return out;
  }

  let threatActor: string | null = null;
  let malware: string | null = null;
  let campaign: string | null = null;
  const attack: AttackTechnique[] = [];
  const tags = [...strArr(ind["labels"])];
  for (const rel of relations.get(id) ?? []) {
    const target = objects.get(str(rel["target_ref"]) ?? "");
    if (!target) continue;
    const tType = str(target["type"]);
    const name = str(target["name"]);
    if ((tType === "threat-actor" || tType === "intrusion-set") && name) threatActor ??= name;
    else if ((tType === "malware" || tType === "tool") && name) malware ??= name;
    else if (tType === "campaign" && name) campaign ??= name;
    else if (tType === "attack-pattern") {
      const t = attackFromAttackPattern(target);
      if (t) attack.push(t);
    } else if (tType === "vulnerability" && name) tags.push(`vulnerability:${name}`);
  }
  for (const phase of arr(ind["kill_chain_phases"])) {
    if (isRecord(phase) && str(phase["kill_chain_name"]) === "mitre-attack" && str(phase["phase_name"])) tags.push(`tactic:${str(phase["phase_name"])}`);
  }

  const scoring: string[] = [];
  const declared = int(ind["confidence"]) ?? int(ind["x_opencti_score"]);
  let confidence = declared ?? opts.defaultConfidence ?? 50;
  scoring.push(declared !== undefined ? `confidence ${declared} declared by the producer` : `no producer confidence; default ${confidence}`);
  if (parsed.conjunctive && confidence > 80) {
    confidence = 80;
    scoring.push("confidence capped at 80: pattern is conjunctive, only self-sufficient hash observables were extracted");
  }
  let severity: Severity = severityFromConfidence(confidence);
  scoring.push(`severity ${severity} from confidence ${confidence}`);
  if (types.includes("anomalous-activity") || types.includes("unknown")) {
    severity = severity === "high" ? "medium" : severity === "medium" ? "low" : severity;
    scoring.push(`severity lowered to ${severity}: indicator type is anomalous/unknown activity`);
  }
  const tlp = tlpOf(strArr(ind["object_marking_refs"]), objects);
  const references = arr(ind["external_references"])
    .map((r) => (isRecord(r) ? str(r["url"]) : undefined))
    .filter((u): u is string => u !== undefined)
    .slice(0, 10);
  const firstSeen = toIso(ind["valid_from"]) ?? toIso(ind["created"]) ?? opts.now;
  const lastSeen = toIso(ind["modified"]) ?? toIso(ind["created"]) ?? opts.now;
  const validUntil = toIso(ind["valid_until"]);
  parsed.observables.forEach((obs, i) => {
    const r = buildIndicatorRecord({
      type: obs.type,
      value: obs.value,
      externalRef: parsed.observables.length > 1 ? `stix:${id}#${i}` : `stix:${id}`,
      source: opts.source ?? "stix",
      confidence,
      severity,
      firstSeenAt: firstSeen,
      lastSeenAt: lastSeen,
      ...(validUntil ? { expiresAt: validUntil } : {}),
      threatActor,
      malware,
      campaign,
      tags,
      description: str(ind["description"]) ?? str(ind["name"]) ?? null,
      references,
      attack,
      tlp,
      revoked,
      scoring,
    });
    if (typeof r === "string") out.skipped.push({ ref: `${id}#${i}`, reason: r });
    else out.records.push(r);
  });
  return out;
}

/** Parse a STIX 2.x bundle (object or JSON string). */
export function parseStixBundle(input: unknown, opts: StixBundleOptions): IntelParseResult {
  let bundle: unknown = input;
  if (typeof input === "string") {
    try {
      bundle = JSON.parse(input);
    } catch {
      return { records: [], skipped: [{ ref: "bundle", reason: "invalid JSON" }] };
    }
  }
  const objectsList = Array.isArray(bundle) ? bundle : arr(rec(bundle)?.["objects"]);
  if (!Array.isArray(bundle) && str(rec(bundle)?.["type"]) !== "bundle" && objectsList.length === 0) {
    return { records: [], skipped: [{ ref: "bundle", reason: "not a STIX bundle" }] };
  }
  const objects = new Map<string, JsonRecord>();
  const relations = new Map<string, JsonRecord[]>();
  for (const o of objectsList) {
    if (!isRecord(o)) continue;
    const id = str(o["id"]);
    if (id) objects.set(id, o);
    if (str(o["type"]) === "relationship" && str(o["relationship_type"]) === "indicates") {
      const src = str(o["source_ref"]);
      if (src) relations.set(src, [...(relations.get(src) ?? []), o]);
    }
  }
  const out: IntelParseResult = { records: [], skipped: [] };
  for (const o of objects.values()) {
    if (str(o["type"]) !== "indicator") continue;
    const r = stixIndicatorToRecords(o, objects, relations, opts);
    out.records.push(...r.records);
    out.skipped.push(...r.skipped);
  }
  return out;
}

