import type { AttackTechnique, CanonicalEvent, EventCategory, Severity } from "@bloody/contracts";
import { parseAllDocuments } from "yaml";
import { compileDetection, type CompiledDetection, type CompileOptions } from "./compiler.js";
import type { DetectionRuleInput } from "../types.js";

/** Parsed (not yet compiled) Sigma rule. */
export interface SigmaRuleAst {
  title: string;
  id?: string;
  status?: string;
  description?: string;
  author?: string;
  references: string[];
  level?: Severity;
  tags: string[];
  attack: AttackTechnique[];
  falsePositives: string[];
  logsource: { category?: string; product?: string; service?: string };
  detection: Record<string, unknown>;
  condition: string | string[];
  timeframe?: string;
}

export interface CompiledSigmaRule {
  ast: SigmaRuleAst;
  detection: CompiledDetection;
  /** Logsource pre-filter (category / product) applied before the detection. */
  logsource: (event: CanonicalEvent) => boolean;
  evaluate(event: CanonicalEvent): { matched: boolean; matchedSelections: string[] };
}

export interface SigmaParseResult<T> {
  value: T | null;
  errors: string[];
  warnings: string[];
}

const LEVELS: Record<string, Severity> = { informational: "info", info: "info", low: "low", medium: "medium", high: "high", critical: "critical" };

/**
 * Logsource category → BCE categories (and file actions). Bloody mapping of the public
 * Sigma taxonomy onto the canonical event model.
 */
const LOGSOURCE_CATEGORIES: Record<string, { categories: EventCategory[]; fileActions?: string[] }> = {
  process_creation: { categories: ["process"] },
  process_access: { categories: ["process"] },
  process_termination: { categories: ["process"] },
  image_load: { categories: ["process", "file"] },
  ps_script: { categories: ["process"] },
  ps_module: { categories: ["process"] },
  ps_classic_start: { categories: ["process"] },
  create_remote_thread: { categories: ["process"] },
  file_event: { categories: ["file"] },
  file_change: { categories: ["file"], fileActions: ["modify"] },
  file_rename: { categories: ["file"], fileActions: ["rename"] },
  file_delete: { categories: ["file"], fileActions: ["delete"] },
  file_access: { categories: ["file"], fileActions: ["read"] },
  file_executable_detected: { categories: ["file"] },
  network_connection: { categories: ["network"] },
  firewall: { categories: ["network"] },
  dns_query: { categories: ["dns", "network"] },
  dns: { categories: ["dns", "network"] },
  proxy: { categories: ["http", "network"] },
  webserver: { categories: ["http"] },
  registry_add: { categories: ["registry"] },
  registry_set: { categories: ["registry"] },
  registry_delete: { categories: ["registry"] },
  registry_event: { categories: ["registry"] },
  registry_rename: { categories: ["registry"] },
  authentication: { categories: ["authentication"] },
  logon: { categories: ["authentication"] },
  ids: { categories: ["detection"] },
  antivirus: { categories: ["detection"] },
};

const PRODUCTS: Record<string, RegExp> = {
  windows: /windows/i,
  linux: /linux|ubuntu|debian|centos|rhel|red hat|fedora|suse|alpine|amazon linux/i,
  macos: /mac ?os|darwin|os ?x/i,
};

/** Parse a single Sigma rule document. Rule collections (multi-document YAML) are rejected. */
export function parseSigma(source: string): SigmaParseResult<SigmaRuleAst> {
  const errors: string[] = [];
  const warnings: string[] = [];
  let doc: unknown;
  try {
    const docs = parseAllDocuments(source, { prettyErrors: false, uniqueKeys: true });
    if (!Array.isArray(docs)) return { value: null, errors: ["sigma: empty document"], warnings };
    const real = docs.filter((d) => d.contents !== null);
    if (real.length !== 1) return { value: null, errors: [`sigma: expected exactly one YAML document, found ${real.length} (rule collections are not supported)`], warnings };
    const d = real[0]!;
    if (d.errors.length > 0) return { value: null, errors: d.errors.map((e) => `sigma: YAML ${e.message}`), warnings };
    doc = d.toJS({ maxAliasCount: 50 });
  } catch (err) {
    return { value: null, errors: [`sigma: YAML ${(err as Error).message}`], warnings };
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return { value: null, errors: ["sigma: rule must be a YAML mapping"], warnings };
  const r = doc as Record<string, unknown>;

  const title = typeof r.title === "string" ? r.title.trim() : "";
  if (!title) errors.push("sigma.title: required");
  const detection = r.detection;
  if (!detection || typeof detection !== "object" || Array.isArray(detection)) errors.push("sigma.detection: required mapping");
  const det = (detection ?? {}) as Record<string, unknown>;
  const condition = det.condition;
  const condOk = typeof condition === "string" || (Array.isArray(condition) && condition.length > 0 && condition.every((c) => typeof c === "string"));
  if (!condOk) errors.push("sigma.detection.condition: required string or list of strings");
  const logsource = r.logsource;
  if (logsource !== undefined && (typeof logsource !== "object" || logsource === null || Array.isArray(logsource))) errors.push("sigma.logsource: must be a mapping");
  const ls = (logsource ?? {}) as Record<string, unknown>;
  if (logsource === undefined) warnings.push("sigma.logsource: missing — rule is evaluated against every event");

  let level: Severity | undefined;
  if (r.level !== undefined) {
    level = typeof r.level === "string" ? LEVELS[r.level.toLowerCase()] : undefined;
    if (!level) errors.push(`sigma.level: unknown level ${JSON.stringify(r.level)}`);
  }
  const tags = stringList(r.tags, "sigma.tags", errors);
  const attack = attackFromTags(tags);
  if (det.timeframe !== undefined) warnings.push("sigma.detection.timeframe: ignored (use a threshold or sequence rule for time windows)");
  if (errors.length > 0) return { value: null, errors, warnings };

  const { condition: _c, timeframe, ...selections } = det;
  const ast: SigmaRuleAst = {
    title,
    ...(typeof r.id === "string" ? { id: r.id } : {}),
    ...(typeof r.status === "string" ? { status: r.status } : {}),
    ...(typeof r.description === "string" ? { description: r.description } : {}),
    ...(typeof r.author === "string" ? { author: r.author } : {}),
    references: stringList(r.references, "sigma.references", warnings),
    ...(level ? { level } : {}),
    tags,
    attack,
    falsePositives: stringList(r.falsepositives, "sigma.falsepositives", warnings),
    logsource: {
      ...(typeof ls.category === "string" ? { category: ls.category } : {}),
      ...(typeof ls.product === "string" ? { product: ls.product } : {}),
      ...(typeof ls.service === "string" ? { service: ls.service } : {}),
    },
    detection: selections,
    condition: condition as string | string[],
    ...(typeof timeframe === "string" ? { timeframe } : {}),
  };
  return { value: ast, errors, warnings };
}

/** Parse + compile a Sigma rule into an event predicate. */
export function compileSigma(source: string, options: CompileOptions = {}): SigmaParseResult<CompiledSigmaRule> {
  const parsed = parseSigma(source);
  if (!parsed.value) return { value: null, errors: parsed.errors, warnings: parsed.warnings };
  const ast = parsed.value;
  const { compiled, errors, warnings } = compileDetection(ast.detection, ast.condition, options);
  const allWarnings = [...parsed.warnings, ...warnings];
  const ls = compileLogsource(ast.logsource, allWarnings);
  if (!compiled) return { value: null, errors, warnings: allWarnings };
  return {
    value: {
      ast,
      detection: compiled,
      logsource: ls,
      evaluate: (event) => (ls(event) ? compiled.evaluate(event) : { matched: false, matchedSelections: [] }),
    },
    errors: [],
    warnings: allWarnings,
  };
}

function compileLogsource(ls: SigmaRuleAst["logsource"], warnings: string[]): (e: CanonicalEvent) => boolean {
  const checks: Array<(e: CanonicalEvent) => boolean> = [];
  if (ls.category) {
    const m = LOGSOURCE_CATEGORIES[ls.category.toLowerCase()];
    if (!m) warnings.push(`sigma.logsource.category: "${ls.category}" is not mapped — category is not enforced`);
    else {
      const cats = new Set<string>(m.categories);
      checks.push((e) => cats.has(e.category));
      if (m.fileActions) {
        const acts = new Set(m.fileActions);
        checks.push((e) => e.category !== "file" || e.file?.action === undefined || acts.has(e.file.action));
      }
      if (ls.category.toLowerCase().startsWith("dns")) checks.push((e) => e.category === "dns" || !!e.network?.dnsQuery);
    }
  }
  if (ls.product) {
    const re = PRODUCTS[ls.product.toLowerCase()];
    // Product is enforced only when the event declares an OS: telemetry without OS info is not dropped.
    if (re) checks.push((e) => !e.asset?.os || re.test(e.asset.os));
  }
  return (e) => checks.every((c) => c(e));
}

/** attack.t1059.001 → T1059.001; tactic tags (attack.execution) annotate the techniques. */
export function attackFromTags(tags: readonly string[]): AttackTechnique[] {
  const techniques: AttackTechnique[] = [];
  const tactics: string[] = [];
  for (const t of tags) {
    const m = /^attack\.(t\d{4}(?:\.\d{3})?)$/i.exec(t.trim());
    if (m) {
      const id = m[1]!.toUpperCase();
      if (!techniques.some((x) => x.id === id)) techniques.push({ id });
      continue;
    }
    const tac = /^attack\.([a-z_-]+)$/i.exec(t.trim());
    if (tac && !/^g\d+|^s\d+/i.test(tac[1]!)) tactics.push(tac[1]!.toLowerCase().replace(/_/g, "-"));
  }
  if (tactics.length === 1) for (const t of techniques) t.tactic = tactics[0]!;
  return techniques;
}

/** Wrap a Sigma YAML rule as a Bloody detection rule definition (for import / authoring). */
export function sigmaToRule(source: string, overrides: Partial<Omit<Extract<DetectionRuleInput, { kind: "sigma" }>, "kind" | "sigma">> & { id?: string } = {}): SigmaParseResult<Extract<DetectionRuleInput, { kind: "sigma" }>> {
  const parsed = parseSigma(source);
  if (!parsed.value) return { value: null, errors: parsed.errors, warnings: parsed.warnings };
  const ast = parsed.value;
  const id = overrides.id ?? (ast.id ? `sigma-${ast.id.toLowerCase()}` : undefined);
  if (!id) return { value: null, errors: ["sigma.id: missing — pass an explicit rule id"], warnings: parsed.warnings };
  return {
    value: {
      kind: "sigma",
      id,
      name: overrides.name ?? ast.title,
      description: overrides.description ?? ast.description ?? "",
      version: overrides.version ?? 1,
      enabled: overrides.enabled ?? ast.status !== "deprecated",
      severity: overrides.severity ?? ast.level ?? "medium",
      attack: overrides.attack ?? ast.attack,
      tags: overrides.tags ?? ast.tags,
      ...(ast.author ? { author: ast.author } : {}),
      references: overrides.references ?? ast.references,
      falsePositives: overrides.falsePositives ?? ast.falsePositives,
      sigma: source,
      ...(overrides.fieldMapping ? { fieldMapping: overrides.fieldMapping } : {}),
      ...(overrides.tests ? { tests: overrides.tests } : {}),
      ...(overrides.confidence !== undefined ? { confidence: overrides.confidence } : {}),
    },
    errors: [],
    warnings: parsed.warnings,
  };
}

function stringList(v: unknown, where: string, sink: string[]): string[] {
  if (v === undefined || v === null) return [];
  if (typeof v === "string") return [v];
  if (Array.isArray(v) && v.every((x) => typeof x === "string")) return v as string[];
  sink.push(`${where}: must be a list of strings`);
  return [];
}
