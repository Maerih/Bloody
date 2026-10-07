import { ZodFirstPartyTypeKind, type ZodTypeAny } from "zod";

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

type AnyDef = { typeName?: ZodFirstPartyTypeKind } & Record<string, unknown>;

function defOf(schema: ZodTypeAny): AnyDef {
  return schema._def as AnyDef;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
}

function stringSchema(def: AnyDef): JsonSchema {
  const out: JsonSchema = { type: "string" };
  const patterns: string[] = [];
  for (const check of (def.checks as Array<Record<string, unknown>> | undefined) ?? []) {
    switch (check.kind) {
      case "min":
        out.minLength = check.value;
        break;
      case "max":
        out.maxLength = check.value;
        break;
      case "length":
        out.minLength = check.value;
        out.maxLength = check.value;
        break;
      case "email":
        out.format = "email";
        break;
      case "url":
        out.format = "uri";
        break;
      case "uuid":
        out.format = "uuid";
        break;
      case "datetime":
        out.format = "date-time";
        break;
      case "date":
        out.format = "date";
        break;
      case "time":
        out.format = "time";
        break;
      case "ip":
        out.format = check.version === "v6" ? "ipv6" : "ipv4";
        break;
      case "regex":
        if (check.regex instanceof RegExp) patterns.push(check.regex.source);
        break;
      case "startsWith":
        patterns.push(`^${escapeRegex(String(check.value))}`);
        break;
      case "endsWith":
        patterns.push(`${escapeRegex(String(check.value))}$`);
        break;
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
  for (const check of (def.checks as Array<Record<string, unknown>> | undefined) ?? []) {
    switch (check.kind) {
      case "int":
        out.type = "integer";
        break;
      case "min":
        if (check.inclusive === false) out.exclusiveMinimum = check.value;
        else out.minimum = check.value;
        break;
      case "max":
        if (check.inclusive === false) out.exclusiveMaximum = check.value;
        else out.maximum = check.value;
        break;
      case "multipleOf":
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

class Converter {
  constructor(private readonly maxDepth: number) {}

  convert(schema: ZodTypeAny, depth: number): JsonSchema {
    if (depth > this.maxDepth) return {};
    const def = defOf(schema);
    const out = this.convertDef(schema, def, depth);
    const description = schema.description;
    if (description && out.description === undefined) out.description = description;
    return out;
  }

  private convertDef(schema: ZodTypeAny, def: AnyDef, depth: number): JsonSchema {
    const next = (s: unknown): JsonSchema => this.convert(s as ZodTypeAny, depth + 1);
    switch (def.typeName) {
      case ZodFirstPartyTypeKind.ZodString:
        return stringSchema(def);
      case ZodFirstPartyTypeKind.ZodNumber:
        return numberSchema(def);
      case ZodFirstPartyTypeKind.ZodBigInt:
        return { type: "integer" };
      case ZodFirstPartyTypeKind.ZodBoolean:
        return { type: "boolean" };
      case ZodFirstPartyTypeKind.ZodDate:
        return { type: "string", format: "date-time" };
      case ZodFirstPartyTypeKind.ZodNull:
        return { type: "null" };
      case ZodFirstPartyTypeKind.ZodLiteral: {
        const value = def.value;
        const type = literalType(value);
        return type ? { type, const: value } : { const: value };
      }
      case ZodFirstPartyTypeKind.ZodEnum:
        return { type: "string", enum: [...(def.values as string[])] };
      case ZodFirstPartyTypeKind.ZodNativeEnum: {
        const obj = def.values as Record<string, string | number>;
        // Drop the reverse mapping TypeScript emits for numeric enums.
        const values = Object.keys(obj)
          .filter((k) => typeof obj[obj[k] as string] !== "number")
          .map((k) => obj[k]!);
        const types = [...new Set(values.map((v) => (typeof v === "number" ? "number" : "string")))];
        return { type: types.length === 1 ? types[0] : types, enum: values };
      }
      case ZodFirstPartyTypeKind.ZodArray: {
        const out: JsonSchema = { type: "array", items: next(def.type) };
        const min = def.minLength as { value: number } | null;
        const max = def.maxLength as { value: number } | null;
        const exact = def.exactLength as { value: number } | null;
        if (min) out.minItems = min.value;
        if (max) out.maxItems = max.value;
        if (exact) {
          out.minItems = exact.value;
          out.maxItems = exact.value;
        }
        return out;
      }
      case ZodFirstPartyTypeKind.ZodSet:
        return { type: "array", uniqueItems: true, items: next(def.valueType) };
      case ZodFirstPartyTypeKind.ZodTuple: {
        const items = (def.items as ZodTypeAny[]).map((i) => next(i));
        const out: JsonSchema = { type: "array", prefixItems: items, minItems: items.length };
        if (def.rest) out.items = next(def.rest);
        else out.maxItems = items.length;
        return out;
      }
      case ZodFirstPartyTypeKind.ZodObject: {
        const shape = (def.shape as () => Record<string, ZodTypeAny>)();
        const properties: Record<string, JsonSchema> = {};
        const required: string[] = [];
        for (const [key, value] of Object.entries(shape)) {
          properties[key] = next(value);
          if (!value.isOptional()) required.push(key);
        }
        const out: JsonSchema = { type: "object", properties };
        if (required.length > 0) out.required = required;
        const catchall = def.catchall as ZodTypeAny | undefined;
        const catchallIsNever = !catchall || defOf(catchall).typeName === ZodFirstPartyTypeKind.ZodNever;
        if (!catchallIsNever) out.additionalProperties = next(catchall);
        else out.additionalProperties = def.unknownKeys === "passthrough";
        return out;
      }
      case ZodFirstPartyTypeKind.ZodRecord:
        return { type: "object", additionalProperties: next(def.valueType) };
      case ZodFirstPartyTypeKind.ZodMap:
        return { type: "object" };
      case ZodFirstPartyTypeKind.ZodUnion:
      case ZodFirstPartyTypeKind.ZodDiscriminatedUnion: {
        const raw = def.options as ZodTypeAny[] | Map<unknown, ZodTypeAny>;
        const options = Array.isArray(raw) ? raw : [...raw.values()];
        const literals = options.map((o) => defOf(o)).filter((d) => d.typeName === ZodFirstPartyTypeKind.ZodLiteral);
        if (literals.length === options.length) {
          const values = literals.map((d) => d.value);
          const types = [...new Set(values.map(literalType))];
          return types.length === 1 && types[0] ? { type: types[0], enum: values } : { enum: values };
        }
        return { anyOf: options.map((o) => next(o)) };
      }
      case ZodFirstPartyTypeKind.ZodIntersection:
        return { allOf: [next(def.left), next(def.right)] };
      case ZodFirstPartyTypeKind.ZodOptional:
        return next(def.innerType);
      case ZodFirstPartyTypeKind.ZodNullable: {
        const inner = next(def.innerType);
        if (typeof inner.type === "string" && inner.enum === undefined && inner.const === undefined) return { ...inner, type: [inner.type, "null"] };
        return { anyOf: [inner, { type: "null" }] };
      }
      case ZodFirstPartyTypeKind.ZodDefault: {
        const inner = next(def.innerType);
        let value: unknown;
        try {
          value = (def.defaultValue as () => unknown)();
        } catch {
          value = undefined;
        }
        return value === undefined ? inner : { ...inner, default: value };
      }
      case ZodFirstPartyTypeKind.ZodCatch:
      case ZodFirstPartyTypeKind.ZodReadonly:
        return next(def.innerType);
      case ZodFirstPartyTypeKind.ZodEffects:
        return next(def.schema);
      case ZodFirstPartyTypeKind.ZodBranded:
        return next(def.type);
      case ZodFirstPartyTypeKind.ZodPipeline:
        return next(def.in);
      case ZodFirstPartyTypeKind.ZodLazy:
        return next((def.getter as () => ZodTypeAny)());
      case ZodFirstPartyTypeKind.ZodNever:
        return { not: {} };
      case ZodFirstPartyTypeKind.ZodAny:
      case ZodFirstPartyTypeKind.ZodUnknown:
      default:
        void schema;
        return {};
    }
  }
}

export function zodToJsonSchema(schema: ZodTypeAny, options: ZodToJsonSchemaOptions = {}): JsonSchema {
  return new Converter(options.maxDepth ?? 12).convert(schema, 0);
}
