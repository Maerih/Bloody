import { z } from "zod";
import { describe, expect, it } from "vitest";
import { zodToJsonSchema } from "./json-schema.js";

describe("zodToJsonSchema", () => {
  it("converts objects with required/optional/default fields and constraints", () => {
    const schema = z
      .object({
        id: z.string().uuid().describe("Entity id"),
        name: z.string().min(3).max(20).regex(/^[a-z]+$/),
        email: z.string().email().optional(),
        count: z.number().int().min(1).max(10).default(5),
        ratio: z.number().gt(0).lte(1),
        tags: z.array(z.string()).min(1).max(4),
        mode: z.enum(["a", "b"]),
        flag: z.boolean().nullable(),
        note: z.string().nullable(),
        kind: z.union([z.literal("x"), z.literal("y")]),
        meta: z.record(z.number()),
        nested: z.object({ at: z.string().datetime({ offset: true }) }).passthrough(),
      })
      .strict();
    expect(zodToJsonSchema(schema)).toEqual({
      type: "object",
      additionalProperties: false,
      required: ["id", "name", "ratio", "tags", "mode", "flag", "note", "kind", "meta", "nested"],
      properties: {
        id: { type: "string", format: "uuid", description: "Entity id" },
        name: { type: "string", minLength: 3, maxLength: 20, pattern: "^[a-z]+$" },
        email: { type: "string", format: "email" },
        count: { type: "integer", minimum: 1, maximum: 10, default: 5 },
        ratio: { type: "number", exclusiveMinimum: 0, maximum: 1 },
        tags: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 4 },
        mode: { type: "string", enum: ["a", "b"] },
        flag: { type: ["boolean", "null"] },
        note: { type: ["string", "null"] },
        kind: { type: "string", enum: ["x", "y"] },
        meta: { type: "object", additionalProperties: { type: "number" } },
        nested: { type: "object", properties: { at: { type: "string", format: "date-time" } }, required: ["at"], additionalProperties: true },
      },
    });
  });

  it("handles effects, unions, tuples, intersections, native enums and lazy recursion", () => {
    enum Color {
      Red = "red",
      Blue = "blue",
    }
    enum Level {
      Low,
      High,
    }
    type Tree = { name: string; children?: Tree[] };
    const tree: z.ZodType<Tree> = z.lazy(() => z.object({ name: z.string(), children: z.array(tree).optional() }));
    const s = z.object({
      refined: z.object({ a: z.string() }).refine((v) => v.a.length > 0),
      union: z.union([z.string(), z.number()]),
      tuple: z.tuple([z.string(), z.number()]),
      both: z.intersection(z.object({ a: z.string() }), z.object({ b: z.number() })),
      color: z.nativeEnum(Color),
      level: z.nativeEnum(Level),
      tree,
      anything: z.unknown(),
    });
    const out = zodToJsonSchema(s) as { properties: Record<string, unknown> };
    expect(out.properties.refined).toEqual({ type: "object", properties: { a: { type: "string" } }, required: ["a"], additionalProperties: false });
    expect(out.properties.union).toEqual({ anyOf: [{ type: "string" }, { type: "number" }] });
    expect(out.properties.tuple).toEqual({ type: "array", prefixItems: [{ type: "string" }, { type: "number" }], minItems: 2, maxItems: 2 });
    expect(out.properties.both).toMatchObject({ allOf: [{ type: "object" }, { type: "object" }] });
    expect(out.properties.color).toEqual({ type: "string", enum: ["red", "blue"] });
    expect(out.properties.level).toEqual({ type: "number", enum: [0, 1] });
    expect(out.properties.tree).toMatchObject({ type: "object", properties: { name: { type: "string" }, children: { type: "array" } } });
    expect(out.properties.anything).toEqual({});
  });
});
