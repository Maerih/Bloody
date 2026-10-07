import { getEventField, type CanonicalEvent } from "@bloody/contracts";
import { cidrContains, parseCidr } from "../../util/ip.js";
import { KEYWORD_FIELDS, resolveField } from "../field-mapping.js";
import { ConditionError, evaluateCondition, parseCondition, referencedSelections, type ConditionNode } from "./condition.js";

/**
 * Compiler for Sigma *detection* sections (Bloody implementation of the public Sigma
 * specification subset):
 *
 *  - a selection that is a map  → AND of its field conditions
 *  - a selection that is a list of maps → OR of those maps
 *  - a selection that is a list of scalars → keyword search (OR) over KEYWORD_FIELDS
 *  - a field whose value is a list → OR over the values (AND with the `all` modifier)
 *  - `Field: null` → field absent / empty
 *  - plain values: case-insensitive equality with `*` / `?` wildcards (`\*` escapes)
 *  - modifiers: contains, startswith, endswith, re (+ i, m, s flags), cidr, gt, gte, lt, lte,
 *    exists, all, cased
 */
export type EventPredicate = (event: CanonicalEvent) => boolean;

export interface CompiledSelection {
  name: string;
  test: EventPredicate;
  /** BCE paths this selection reads (for explanations / validation). */
  fields: string[];
  description: string;
}

export interface CompiledDetection {
  selections: Map<string, CompiledSelection>;
  conditions: ConditionNode[];
  evaluate(event: CanonicalEvent): { matched: boolean; matchedSelections: string[] };
}

export interface CompileOptions {
  fieldMapping?: Readonly<Record<string, string>>;
  /** Treat unmapped field names as errors (default true). */
  strictFields?: boolean;
}

export interface CompileResult {
  compiled: CompiledDetection | null;
  errors: string[];
  warnings: string[];
}

const TYPE_MODIFIERS = new Set(["contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte", "exists"]);
const FLAG_MODIFIERS = new Set(["all", "cased"]);
const RE_FLAGS = new Set(["i", "m", "s"]);
const UNSUPPORTED = new Set(["base64", "base64offset", "utf16le", "utf16be", "utf16", "wide", "windash", "expand", "fieldref"]);
const MAX_REGEX_LENGTH = 1000;
const MAX_TEXT_LENGTH = 65_536;

export function compileDetection(detection: Record<string, unknown>, condition: string | readonly string[], options: CompileOptions = {}): CompileResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const selections = new Map<string, CompiledSelection>();
  const entries = Object.entries(detection).filter(([k]) => k !== "condition" && k !== "timeframe");
  if (entries.length === 0) errors.push("detection: no selections defined");
  for (const [name, def] of entries) {
    if (!/^[A-Za-z0-9_.\-]+$/.test(name)) {
      errors.push(`detection.${name}: invalid selection name`);
      continue;
    }
    const sel = compileSelection(name, def, options, errors, warnings);
    if (sel) selections.set(name, sel);
  }
  const condList = typeof condition === "string" ? [condition] : [...condition];
  const conditions: ConditionNode[] = [];
  for (const c of condList) {
    try {
      conditions.push(parseCondition(c, [...selections.keys()]));
    } catch (err) {
      errors.push(`condition: ${err instanceof ConditionError ? err.message : String(err)}`);
    }
  }
  if (errors.length > 0) return { compiled: null, errors, warnings };
  const used = new Set<string>();
  for (const c of conditions) referencedSelections(c, used);
  for (const name of selections.keys()) if (!used.has(name)) warnings.push(`detection.${name}: selection is never used by the condition`);

  const compiled: CompiledDetection = {
    selections,
    conditions,
    evaluate(event) {
      const memo = new Map<string, boolean>();
      const sel = (name: string) => {
        let v = memo.get(name);
        if (v === undefined) {
          v = selections.get(name)!.test(event);
          memo.set(name, v);
        }
        return v;
      };
      const matched = conditions.some((c) => evaluateCondition(c, sel));
      return { matched, matchedSelections: matched ? [...memo.entries()].filter(([, v]) => v).map(([k]) => k) : [] };
    },
  };
  return { compiled, errors, warnings };
}

function compileSelection(name: string, def: unknown, options: CompileOptions, errors: string[], warnings: string[]): CompiledSelection | null {
  const where = `detection.${name}`;
  if (isPlainObject(def)) return compileMap(name, def, options, errors, warnings, where);
  if (Array.isArray(def)) {
    if (def.length === 0) {
      errors.push(`${where}: empty list`);
      return null;
    }
    if (def.every(isPlainObject)) {
      const maps = def.map((m, i) => compileMap(name, m as Record<string, unknown>, options, errors, warnings, `${where}[${i}]`));
      if (maps.some((m) => m === null)) return null;
      const ok = maps as CompiledSelection[];
      return { name, test: (e) => ok.some((m) => m.test(e)), fields: [...new Set(ok.flatMap((m) => m.fields))], description: ok.map((m) => `(${m.description})`).join(" OR ") };
    }
    if (def.every(isScalar)) return compileKeywords(name, def as Array<string | number | boolean>, errors, where);
    errors.push(`${where}: a list must contain only maps or only keyword values`);
    return null;
  }
  if (isScalar(def)) return compileKeywords(name, [def], errors, where);
  errors.push(`${where}: unsupported selection type`);
  return null;
}

function compileKeywords(name: string, values: Array<string | number | boolean>, errors: string[], where: string): CompiledSelection | null {
  const matchers: Array<(s: string) => boolean> = [];
  for (const v of values) {
    const m = buildStringMatcher(String(v), "contains", false);
    if (typeof m === "string") {
      errors.push(`${where}: ${m}`);
      return null;
    }
    matchers.push(m);
  }
  return {
    name,
    fields: [...KEYWORD_FIELDS],
    description: `keywords ${values.map((v) => JSON.stringify(v)).join(" | ")}`,
    test: (e) => {
      for (const f of KEYWORD_FIELDS) {
        const fv = getEventField(e, f);
        if (typeof fv !== "string" || fv.length === 0) continue;
        if (matchers.some((m) => m(fv))) return true;
      }
      return false;
    },
  };
}

function compileMap(name: string, map: Record<string, unknown>, options: CompileOptions, errors: string[], warnings: string[], where: string): CompiledSelection | null {
  const preds: EventPredicate[] = [];
  const fields: string[] = [];
  const parts: string[] = [];
  const entries = Object.entries(map);
  if (entries.length === 0) {
    errors.push(`${where}: empty map`);
    return null;
  }
  let ok = true;
  for (const [rawKey, rawValue] of entries) {
    const r = compileFieldCondition(rawKey, rawValue, options, errors, warnings, `${where}.${rawKey}`);
    if (!r) {
      ok = false;
      continue;
    }
    preds.push(r.test);
    fields.push(r.path);
    parts.push(r.description);
  }
  if (!ok) return null;
  return { name, test: (e) => preds.every((p) => p(e)), fields, description: parts.join(" AND ") };
}

interface FieldCondition {
  test: EventPredicate;
  path: string;
  description: string;
}

function compileFieldCondition(rawKey: string, rawValue: unknown, options: CompileOptions, errors: string[], warnings: string[], where: string): FieldCondition | null {
  const [fieldName = "", ...mods] = rawKey.split("|");
  const modifiers = mods.map((m) => m.trim().toLowerCase()).filter(Boolean);
  if (!fieldName) {
    errors.push(`${where}: field name is required (use a keyword list for full-text matches)`);
    return null;
  }
  const res = resolveField(fieldName, options.fieldMapping);
  if (res.path === null) {
    if (options.strictFields ?? true) {
      errors.push(`${where}: field "${fieldName}" has no mapping to the Bloody Canonical Event (add a fieldMapping entry or use a BCE path)`);
      return null;
    }
    warnings.push(`${where}: field "${fieldName}" is unmapped and will never match`);
    return { test: () => false, path: fieldName, description: `${fieldName} (unmapped)` };
  }
  const path = res.path;

  let type: string | null = null;
  const flags = new Set<string>();
  const reFlags = new Set<string>();
  for (const m of modifiers) {
    if (UNSUPPORTED.has(m)) {
      errors.push(`${where}: modifier "${m}" is not supported`);
      return null;
    }
    if (TYPE_MODIFIERS.has(m)) {
      if (type) {
        errors.push(`${where}: modifiers "${type}" and "${m}" cannot be combined`);
        return null;
      }
      type = m;
    } else if (FLAG_MODIFIERS.has(m)) flags.add(m);
    else if (RE_FLAGS.has(m) && type === "re") reFlags.add(m);
    else {
      errors.push(`${where}: unknown modifier "${m}"`);
      return null;
    }
  }
  const values = Array.isArray(rawValue) ? rawValue : [rawValue];
  if (values.length === 0) {
    errors.push(`${where}: empty value list`);
    return null;
  }
  if (flags.has("all") && values.length < 2) warnings.push(`${where}: "all" modifier with a single value has no effect`);

  if (type === "exists") {
    if (values.length !== 1 || typeof values[0] !== "boolean") {
      errors.push(`${where}: "exists" requires a single boolean value`);
      return null;
    }
    const want = values[0];
    return { path, description: `${path} ${want ? "exists" : "is absent"}`, test: (e) => isPresent(getEventField(e, path)) === want };
  }

  const matchers: Array<(fv: unknown) => boolean> = [];
  for (const v of values) {
    const m = compileValue(v, type, flags.has("cased"), reFlags, where, errors);
    if (!m) return null;
    matchers.push(m);
  }
  const combine = flags.has("all") ? "all" : "any";
  const description = `${path}${type ? ` ${type}` : ""}${combine === "all" ? " all of" : ""} ${values.map((v) => JSON.stringify(v)).join(combine === "all" ? " & " : " | ")}`;
  return {
    path,
    description,
    test: (e) => {
      const fv = getEventField(e, path);
      return combine === "all" ? matchers.every((m) => m(fv)) : matchers.some((m) => m(fv));
    },
  };
}

function compileValue(value: unknown, type: string | null, cased: boolean, reFlags: Set<string>, where: string, errors: string[]): ((fv: unknown) => boolean) | null {
  if (value === null) {
    if (type) {
      errors.push(`${where}: null cannot be combined with "${type}"`);
      return null;
    }
    return (fv) => !isPresent(fv);
  }
  if (!isScalar(value)) {
    errors.push(`${where}: values must be scalars`);
    return null;
  }
  switch (type) {
    case "gt":
    case "gte":
    case "lt":
    case "lte": {
      const n = typeof value === "number" ? value : Number(value);
      if (!Number.isFinite(n)) {
        errors.push(`${where}: "${type}" requires a numeric value`);
        return null;
      }
      const cmp = type === "gt" ? (x: number) => x > n : type === "gte" ? (x: number) => x >= n : type === "lt" ? (x: number) => x < n : (x: number) => x <= n;
      return anyElement((fv) => {
        const x = typeof fv === "number" ? fv : typeof fv === "string" && fv.trim() !== "" ? Number(fv) : NaN;
        return Number.isFinite(x) && cmp(x);
      });
    }
    case "cidr": {
      const c = typeof value === "string" ? parseCidr(value) : null;
      if (!c) {
        errors.push(`${where}: invalid CIDR ${JSON.stringify(value)}`);
        return null;
      }
      return anyElement((fv) => typeof fv === "string" && cidrContains(c, fv));
    }
    case "re": {
      const pattern = String(value);
      if (pattern.length > MAX_REGEX_LENGTH) {
        errors.push(`${where}: regular expression longer than ${MAX_REGEX_LENGTH} characters`);
        return null;
      }
      let re: RegExp;
      try {
        re = new RegExp(pattern, [...reFlags].join(""));
      } catch (err) {
        errors.push(`${where}: invalid regular expression (${(err as Error).message})`);
        return null;
      }
      return anyElement((fv) => {
        const s = scalarText(fv);
        return s !== null && re.test(s.length > MAX_TEXT_LENGTH ? s.slice(0, MAX_TEXT_LENGTH) : s);
      });
    }
    case "contains":
    case "startswith":
    case "endswith":
    case null: {
      if (type === null && typeof value === "number") {
        return anyElement((fv) => (typeof fv === "number" ? fv === value : typeof fv === "string" && fv.trim() !== "" && Number(fv) === value));
      }
      if (type === null && typeof value === "boolean") {
        return anyElement((fv) => fv === value || (typeof fv === "string" && fv.toLowerCase() === String(value)));
      }
      const m = buildStringMatcher(String(value), type ?? "equals", cased);
      if (typeof m === "string") {
        errors.push(`${where}: ${m}`);
        return null;
      }
      return anyElement((fv) => {
        const s = scalarText(fv);
        return s !== null && m(s.length > MAX_TEXT_LENGTH ? s.slice(0, MAX_TEXT_LENGTH) : s);
      });
    }
    default:
      errors.push(`${where}: unsupported modifier "${type}"`);
      return null;
  }
}

/**
 * Sigma string matcher with wildcards: `*` = any run, `?` = one character, `\*` `\?` `\\`
 * are escapes; any other backslash is literal (Windows paths stay readable).
 */
export function buildStringMatcher(pattern: string, mode: "equals" | "contains" | "startswith" | "endswith", cased: boolean): ((s: string) => boolean) | string {
  let hasWildcard = false;
  let literal = "";
  let regex = "";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;
    if (ch === "\\" && (pattern[i + 1] === "*" || pattern[i + 1] === "?" || pattern[i + 1] === "\\")) {
      const next = pattern[++i]!;
      literal += next;
      regex += escapeRegex(next);
      continue;
    }
    if (ch === "*" || ch === "?") {
      hasWildcard = true;
      regex += ch === "*" ? "[\\s\\S]*" : "[\\s\\S]";
      continue;
    }
    literal += ch;
    regex += escapeRegex(ch);
  }
  if (!hasWildcard) {
    const needle = cased ? literal : literal.toLowerCase();
    const norm = (s: string) => (cased ? s : s.toLowerCase());
    switch (mode) {
      case "equals":
        return (s) => norm(s) === needle;
      case "contains":
        return (s) => norm(s).includes(needle);
      case "startswith":
        return (s) => norm(s).startsWith(needle);
      case "endswith":
        return (s) => norm(s).endsWith(needle);
    }
  }
  const source = mode === "equals" ? `^${regex}$` : mode === "startswith" ? `^${regex}` : mode === "endswith" ? `${regex}$` : regex;
  try {
    const re = new RegExp(source, cased ? "" : "i");
    return (s) => re.test(s);
  } catch (err) {
    return `invalid wildcard pattern (${(err as Error).message})`;
  }
}

function escapeRegex(ch: string): string {
  return /[.*+?^${}()|[\]\\/-]/.test(ch) ? `\\${ch}` : ch;
}

function anyElement(m: (fv: unknown) => boolean): (fv: unknown) => boolean {
  return (fv) => (Array.isArray(fv) ? fv.some((x) => m(x)) : m(fv));
}

function scalarText(v: unknown): string | null {
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return null;
}

function isPresent(v: unknown): boolean {
  if (v === undefined || v === null) return false;
  if (typeof v === "string") return v.length > 0;
  if (Array.isArray(v)) return v.length > 0;
  return true;
}

function isScalar(v: unknown): v is string | number | boolean {
  return typeof v === "string" || typeof v === "number" || typeof v === "boolean";
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}
