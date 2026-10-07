import { z } from "zod";
import { badRequest } from "./errors.js";

/** Comma-separated (or repeated) query values → validated array. `?severity=critical,high`. */
export function csvOf<T extends z.ZodTypeAny>(item: T) {
  return z
    .union([z.string(), z.array(z.string())])
    .transform((v) => (Array.isArray(v) ? v : [v]).flatMap((s) => s.split(",")).map((s) => s.trim()).filter((s) => s.length > 0))
    .pipe(z.array(item).max(50));
}

export const Limit = (max = 200, dflt = 50) => z.coerce.number().int().min(1).max(max).default(dflt);
export const OptionalUuid = z.string().uuid().optional();
export const IdParam = z.object({ id: z.string().uuid() });

/** Opaque keyset cursor: base64url(JSON [sortValue, id]). */
export function encodeCursor(values: Array<string | number | null>): string {
  return Buffer.from(JSON.stringify(values), "utf8").toString("base64url");
}

export function decodeCursor(cursor: string | undefined, arity = 2): Array<string | number | null> | null {
  if (!cursor) return null;
  try {
    const parsed: unknown = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
    if (!Array.isArray(parsed) || parsed.length !== arity || !parsed.every((v) => v === null || typeof v === "string" || typeof v === "number")) throw new Error("shape");
    return parsed as Array<string | number | null>;
  } catch {
    throw badRequest("Invalid pagination cursor");
  }
}

/** Escape a user-supplied term for ILIKE '%term%'. */
export function likePattern(term: string, mode: "contains" | "prefix" = "contains"): string {
  const escaped = term.replace(/[\\%_]/g, (c) => `\\${c}`);
  return mode === "prefix" ? `${escaped}%` : `%${escaped}%`;
}

/**
 * Minimal parameterized SQL builder: collects values and hands back `$n` placeholders so
 * dynamic WHERE clauses never interpolate user input.
 */
export class SqlParams {
  readonly values: unknown[] = [];
  add(value: unknown): string {
    this.values.push(value);
    return `$${this.values.length}`;
  }
}

export function page<T>(rows: T[], limit: number, cursorOf: (last: T) => Array<string | number | null>): { items: T[]; nextCursor: string | null } {
  const hasMore = rows.length > limit;
  const items = hasMore ? rows.slice(0, limit) : rows;
  return { items, nextCursor: hasMore && items.length > 0 ? encodeCursor(cursorOf(items[items.length - 1]!)) : null };
}
