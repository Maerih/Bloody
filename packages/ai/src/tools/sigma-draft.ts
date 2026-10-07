import { z } from "zod";

/**
 * Sigma rule drafting for the AI SOC. The model supplies structured fields; Bloody renders the
 * YAML itself (so the model cannot inject arbitrary YAML), checks the structure locally and the
 * API validates it with the proprietary Detection Engine compiler. Drafts are never deployed.
 */

export const SIGMA_MODIFIERS = new Set([
  "contains",
  "startswith",
  "endswith",
  "all",
  "re",
  "base64",
  "base64offset",
  "cidr",
  "windash",
  "wide",
  "utf16",
  "utf16le",
  "utf16be",
  "gt",
  "gte",
  "lt",
  "lte",
  "exists",
  "cased",
  "expand",
  "fieldref",
  "i",
  "m",
  "s",
]);

export const SIGMA_LEVELS = ["informational", "low", "medium", "high", "critical"] as const;

const FIELD_KEY_RE = /^[A-Za-z0-9_.-]{1,128}(\|[a-z0-9]{1,20}){0,4}$/;
const DETECTION_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const LOGSOURCE_RE = /^[a-z0-9_-]{1,64}$/;

const SigmaScalar = z.union([z.string().max(1000), z.number().finite(), z.boolean(), z.null()]);
const SigmaFieldMap = z.record(z.string().regex(FIELD_KEY_RE, "field name with optional |modifiers"), z.union([SigmaScalar, z.array(SigmaScalar).min(1).max(100)]));
const SigmaSelection = z.union([SigmaFieldMap, z.array(z.string().min(1).max(1000)).min(1).max(100)]);

export const DraftSigmaArgs = z
  .object({
    title: z.string().min(3).max(200),
    description: z.string().min(3).max(2000),
    logsource: z
      .object({
        product: z.string().regex(LOGSOURCE_RE).optional(),
        category: z.string().regex(LOGSOURCE_RE).optional(),
        service: z.string().regex(LOGSOURCE_RE).optional(),
      })
      .strict()
      .refine((l) => Boolean(l.product || l.category || l.service), "logsource needs product, category or service"),
    detection: z
      .record(z.string().regex(DETECTION_NAME_RE), SigmaSelection)
      .refine((d) => Object.keys(d).length >= 1 && Object.keys(d).length <= 20, "1-20 named selections")
      .refine((d) => !("condition" in d), "put the condition in the 'condition' field"),
    condition: z.string().min(1).max(500),
    level: z.enum(SIGMA_LEVELS),
    falsepositives: z.array(z.string().min(1).max(300)).max(10).default([]),
    attack: z.array(z.string().regex(/^T\d{4}(\.\d{3})?$/)).max(10).default([]),
    tactics: z.array(z.string().regex(/^[a-z_-]{3,40}$/)).max(5).default([]),
  })
  .strict();
export type DraftSigmaArgs = z.output<typeof DraftSigmaArgs>;

function yamlString(s: string): string {
  return `'${s.replace(/[\r\n\t]+/g, " ").replace(/'/g, "''")}'`;
}

function yamlScalar(v: string | number | boolean | null): string {
  if (v === null) return "null";
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return yamlString(v);
}

export function renderSigmaYaml(args: DraftSigmaArgs, meta: { id: string; date: string }): string {
  const lines: string[] = [];
  lines.push(`title: ${yamlString(args.title)}`);
  lines.push(`id: ${meta.id}`);
  lines.push("status: experimental");
  lines.push(`description: ${yamlString(args.description)}`);
  lines.push(`author: ${yamlString("Bloody AI SOC (draft - requires analyst review)")}`);
  lines.push(`date: ${meta.date}`);
  const tags = [...args.tactics.map((t) => `attack.${t.replace(/-/g, "_")}`), ...args.attack.map((t) => `attack.${t.toLowerCase()}`)];
  if (tags.length) {
    lines.push("tags:");
    for (const t of tags) lines.push(`  - ${t}`);
  }
  lines.push("logsource:");
  for (const key of ["category", "product", "service"] as const) {
    const v = args.logsource[key];
    if (v) lines.push(`  ${key}: ${v}`);
  }
  lines.push("detection:");
  for (const [name, selection] of Object.entries(args.detection)) {
    lines.push(`  ${name}:`);
    if (Array.isArray(selection)) {
      for (const kw of selection) lines.push(`    - ${yamlString(kw)}`);
      continue;
    }
    for (const [field, value] of Object.entries(selection)) {
      if (Array.isArray(value)) {
        lines.push(`    ${field}:`);
        for (const v of value) lines.push(`      - ${yamlScalar(v)}`);
      } else {
        lines.push(`    ${field}: ${yamlScalar(value)}`);
      }
    }
  }
  lines.push(`  condition: ${args.condition.replace(/[\r\n]+/g, " ").trim()}`);
  if (args.falsepositives.length) {
    lines.push("falsepositives:");
    for (const fp of args.falsepositives) lines.push(`  - ${yamlString(fp)}`);
  }
  lines.push(`level: ${args.level}`);
  return lines.join("\n") + "\n";
}

const CONDITION_KEYWORDS = new Set(["and", "or", "not", "of", "all", "them", "1", "any"]);

function globToRegExp(glob: string): RegExp {
  return new RegExp(`^${glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`);
}

/** Structural checks the Detection Engine would also reject — fast feedback for the model. */
export function checkSigmaStructure(args: DraftSigmaArgs): { errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  const names = Object.keys(args.detection);
  if (/[^A-Za-z0-9_*()\s|]/.test(args.condition)) errors.push("condition contains unsupported characters");
  if (/\|/.test(args.condition)) warnings.push("aggregation expressions ('|') in conditions are deprecated in Sigma; prefer correlation rules");
  const tokens = args.condition.split(/[\s()|]+/).filter(Boolean);
  const referenced = new Set<string>();
  for (const token of tokens) {
    if (CONDITION_KEYWORDS.has(token.toLowerCase())) continue;
    if (/^\d+$/.test(token)) continue;
    if (token.includes("*")) {
      const re = globToRegExp(token);
      const hits = names.filter((n) => re.test(n));
      if (hits.length === 0) errors.push(`condition pattern '${token}' matches no selection`);
      hits.forEach((h) => referenced.add(h));
      continue;
    }
    if (!names.includes(token)) errors.push(`condition references undefined selection '${token}'`);
    else referenced.add(token);
  }
  if (/\bthem\b/.test(args.condition)) names.forEach((n) => referenced.add(n));
  for (const n of names) if (!referenced.has(n)) warnings.push(`selection '${n}' is not used by the condition`);
  for (const [name, selection] of Object.entries(args.detection)) {
    if (Array.isArray(selection)) continue;
    for (const field of Object.keys(selection)) {
      const [, ...mods] = field.split("|");
      for (const m of mods) if (!SIGMA_MODIFIERS.has(m)) errors.push(`selection '${name}': unknown modifier '${m}' on '${field}'`);
      if (mods.includes("re") && mods.some((m) => ["contains", "startswith", "endswith"].includes(m))) {
        warnings.push(`selection '${name}': 're' combined with contains/startswith/endswith on '${field}'`);
      }
    }
  }
  if (referenced.size === 0) errors.push("condition does not reference any selection");
  if (args.level === "critical" && args.falsepositives.length === 0) warnings.push("critical rules should document expected false positives");
  return { errors, warnings };
}
