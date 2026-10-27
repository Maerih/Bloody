import type { z } from "zod";

/**
 * Bloody's own zod → JSON Schema (draft 2020-12 subset) converter for tool parameter
 * declarations. Covers the zod constructs used by tool schemas; unknown constructs degrade to
 * an unconstrained schema `{}` (validation still happens with zod at invocation time).
 */
export type JsonSchema = { [key: string]: unknown };

export interface ZodToJsonSchemaOptions {
  /** Recursion guard for z.lazy. Default 12. */
  maxDepth?: number;
}

type AnySchema = z.ZodType;
type AnyDef = { type: string; checks?: AnySchema[] } & Record<string, unknown>;
type CheckDef = { check?: string } & Record<string, unknown>;

function defOf(schema: AnySchema): AnyDef {
  return schema._zod.def as unknown as AnyDef;
}

/** A schema's checks; top-level formats (z.email(), z.int()) carry their own check on the def. */
function checksOf(def: AnyDef): CheckDef[] {
  const own = typeof def.check === "string" ? [def as CheckDef] : [];
  return [...own, ...(def.checks ?? []).map((c) => c._zod.def as unknown as CheckDef)];
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
}

const STRING_FORMATS: Record<string, string> = {
  email: "email",
  url: "uri",
  uuid: "uuid",
  guid: "uuid",
  datetime: "date-time",
  date: "date",
  time: "time",
  ipv4: "ipv4",
  ipv6: "ipv6",
};

function stringSchema(def: AnyDef): JsonSchema {
  const out: JsonSchema = { type: "string" };
  const patterns: string[] = [];
  for (const check of checksOf(def)) {
    switch (check.check) {
      case "min_length":
        out.minLength = check.minimum;
        break;
      case "max_length":
        out.maxLength = check.maximum;
        break;
      case "length_equals":
        out.minLength = check.length;
        out.maxLength = check.length;
        break;
      case "string_format": {
        const format = String(check.format);
        if (format === "regex" && check.pattern instanceof RegExp) patterns.push(check.pattern.source);
        else if (format === "starts_with") patterns.push(`^${escapeRegex(String(check.prefix))}`);
        else if (format === "ends_with") patterns.push(`${escapeRegex(String(check.suffix))}$`);
        else if (STRING_FORMATS[format]) out.format = STRING_FORMATS[format];
        break;
      }
      default:
        break;
    }
  }
  if (patterns.length === 1) out.pattern = patterns[0];
  else if (patterns.length > 1) out.allOf = patterns.map((p) => ({ pattern: p }));
  return out;
}

function numberSchema(def: AnyDef): JsonSchema {
  const out: JsonSchema = { type: "number" };
  for (const check of checksOf(def)) {
    switch (check.check) {
      case "number_format":
        if (String(check.format).includes("int")) out.type = "integer";
        break;
      case "greater_than":
        if (check.inclusive === false) out.exclusiveMinimum = check.value;
        else out.minimum = check.value;
        break;
      case "less_than":
        if (check.inclusive === false) out.exclusiveMaximum = check.value;
        else out.maximum = check.value;
        break;
      case "multiple_of":
        out.multipleOf = check.value;
        break;
      default:
        break;
    }
  }
  return out;
}

function literalType(value: unknown): string | undefined {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return "string";
    case "number":
      return Number.isInteger(value) ? "integer" : "number";
    case "boolean":
      return "boolean";
    default:
      return undefined;
  }
}

function valuesSchema(values: unknown[]): JsonSchema {
  const types = [...new Set(values.map(literalType))];
  if (values.length === 1) return types[0] ? { type: types[0], const: values[0] } : { const: values[0] };
  return types.length === 1 && types[0] ? { type: types[0], enum: values } : { enum: values };
}

class Converter {
  constructor(private readonly maxDepth: number) {}

  convert(schema: AnySchema, depth: number): JsonSchema {
    if (depth > this.maxDepth) return {};
    const def = defOf(schema);
    const out = this.convertDef(def, depth);
    const description = schema.description;
    if (description && out.description === undefined) out.description = description;
    return out;
  }

  private convertDef(def: AnyDef, depth: number): JsonSchema {
    const next = (s: unknown): JsonSchema => this.convert(s as AnySchema, depth + 1);
    switch (def.type) {
      case "string":
        return stringSchema(def);
      case "number":
        return numberSchema(def);
      case "bigint":
        return { type: "integer" };
      case "boolean":
        return { type: "boolean" };
      case "date":
        return { type: "string", format: "date-time" };
      case "null":
        return { type: "null" };
      case "literal":
        return valuesSchema(def.values as unknown[]);
      case "enum": {
        const entries = def.entries as Record<string, string | number>;
        // Drop the reverse mapping TypeScript emits for numeric enums.
        const values = Object.keys(entries)
          .filter((k) => typeof entries[entries[k] as string] !== "number")
          .map((k) => entries[k]!);
        const types = [...new Set(values.map((v) => (typeof v === "number" ? "number" : "string")))];
        return { type: types.length === 1 ? types[0] : types, enum: values };
      }
      case "array": {
        const out: JsonSchema = { type: "array", items: next(def.element) };
        for (const check of checksOf(def)) {
          if (check.check === "min_length") out.minItems = check.minimum;
          else if (check.check === "max_length") out.maxItems = check.maximum;
          else if (check.check === "length_equals") {
            out.minItems = check.length;
            out.maxItems = check.length;
          }
        }
        return out;
      }
      case "set":
        return { type: "array", uniqueItems: true, items: next(def.valueType) };
      case "tuple": {
        const items = (def.items as AnySchema[]).map((i) => next(i));
        const out: JsonSchema = { type: "array", prefixItems: items, minItems: items.length };
        if (def.rest) out.items = next(def.rest);
        else out.maxItems = items.length;
        return out;
      }
      case "object": {
        const shape = def.shape as Record<string, AnySchema>;
        const properties: Record<string, JsonSchema> = {};
        const required: string[] = [];
        for (const [key, value] of Object.entries(shape)) {
          properties[key] = next(value);
          if (!value._zod.optin) required.push(key);
        }
        const out: JsonSchema = { type: "object", properties };
        if (required.length > 0) out.required = required;
        const catchall = def.catchall as AnySchema | undefined;
        const catchallType = catchall ? defOf(catchall).type : "never";
        if (catchallType === "never") out.additionalProperties = false;
        else if (catchallType === "unknown" || catchallType === "any") out.additionalProperties = true;
        else out.additionalProperties = next(catchall);
        return out;
      }
      case "record":
        return { type: "object", additionalProperties: next(def.valueType) };
      case "map":
        return { type: "object" };
      case "union": {
        const options = def.options as AnySchema[];
        const defs = options.map((o) => defOf(o));
        if (defs.every((d) => d.type === "literal")) return valuesSchema(defs.flatMap((d) => d.values as unknown[]));
        return { anyOf: options.map((o) => next(o)) };
      }
      case "intersection":
        return { allOf: [next(def.left), next(def.right)] };
      case "optional":
      case "nonoptional":
      case "catch":
      case "readonly":
        return next(def.innerType);
      case "nullable": {
        const inner = next(def.innerType);
        if (typeof inner.type === "string" && inner.enum === undefined && inner.const === undefined) return { ...inner, type: [inner.type, "null"] };
        return { anyOf: [inner, { type: "null" }] };
      }
      case "default":
      case "prefault": {
        const inner = next(def.innerType);
        let value: unknown;
        try {
          value = def.defaultValue;
        } catch {
          value = undefined;
        }
        return value === undefined ? inner : { ...inner, default: value };
      }
      case "pipe":
        return next(def.in);
      case "lazy":
        return next((def.getter as () => AnySchema)());
      case "never":
        return { not: {} };
      default:
        return {};
    }
  }
}

export function zodToJsonSchema(schema: z.ZodType, options: ZodToJsonSchemaOptions = {}): JsonSchema {
  return new Converter(options.maxDepth ?? 12).convert(schema, 0);
}
