import type { FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { CSRF_COOKIE, SESSION_COOKIE } from "../auth/types.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { notFound } from "../http/errors.js";
import { encodeCursor } from "../http/params.js";
import type { Row } from "../repo/mappers.js";

export function parse<T extends z.ZodTypeAny>(schema: T, value: unknown): z.output<T> {
  return schema.parse(value ?? {}) as z.output<T>;
}

export function setSessionCookies(services: AppServices, reply: FastifyReply, session: { sessionId: string; cookieValue: string; expiresAt: string }): string {
  const secure = services.config.http.cookieSecure;
  const expires = new Date(session.expiresAt);
  void reply.setCookie(SESSION_COOKIE, session.cookieValue, { httpOnly: true, secure, sameSite: "lax", path: "/", expires });
  const csrf = services.auth.csrfTokenFor(session.sessionId);
  void reply.setCookie(CSRF_COOKIE, csrf, { httpOnly: false, secure, sameSite: "lax", path: "/", expires });
  return csrf;
}

export function clearSessionCookies(services: AppServices, reply: FastifyReply): void {
  const secure = services.config.http.cookieSecure;
  void reply.clearCookie(SESSION_COOKIE, { path: "/", secure, sameSite: "lax", httpOnly: true });
  void reply.clearCookie(CSRF_COOKIE, { path: "/", secure, sameSite: "lax" });
}

/** Load one row by id inside the tenant transaction (RLS-scoped) or 404. */
export async function loadOne(tx: Queryable, table: string, id: string, what: string): Promise<Row> {
  if (!/^[a-z_]+$/.test(table)) throw new Error("invalid table");
  const { rows } = await tx.query<Row>(`SELECT * FROM ${table} WHERE id = $1`, [id]);
  if (!rows[0]) throw notFound(what);
  return rows[0];
}

export function clientInfo(request: FastifyRequest) {
  return { ip: request.ip ?? null, userAgent: (request.headers["user-agent"] as string | undefined) ?? null, requestId: request.id };
}

/** SQL fragment restricting `organization_id` to the resolved scope (null = whole tenant). */
export function orgClause(column: string, orgs: string[] | null, params: unknown[]): string {
  if (orgs === null) return "TRUE";
  params.push(orgs);
  return `${column} = ANY($${params.length}::uuid[])`;
}

/** Query-string boolean: "true"/"1"/"yes" → true, "false"/"0"/"no" → false. */
export const QueryBool = z.preprocess((v) => {
  if (typeof v === "boolean") return v;
  if (typeof v !== "string") return v;
  const s = v.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(s)) return true;
  if (["0", "false", "no", "off"].includes(s)) return false;
  return v;
}, z.boolean());

export interface KeysetSort {
  /** SQL expression ordered on (must be deterministic per row). */
  expr: string;
  dir: "asc" | "desc";
  /** Cast for the cursor value placeholder (e.g. "numeric", "timestamptz", "text"). */
  cast: string;
}

/**
 * Keyset pagination: `(expr, id) < (cursorValue, cursorId)` (or `>` for ascending order).
 * Appends the predicate's parameters and returns the SQL fragment ("TRUE" without a cursor).
 */
export function keysetClause(sort: KeysetSort, idColumn: string, cursor: Array<string | number | null> | null, params: unknown[]): string {
  if (!cursor) return "TRUE";
  params.push(cursor[0]);
  const v = `$${params.length}::${sort.cast}`;
  params.push(cursor[1]);
  const id = `$${params.length}::uuid`;
  return `(${sort.expr}, ${idColumn}) ${sort.dir === "desc" ? "<" : ">"} (${v}, ${id})`;
}

export function orderBy(sort: KeysetSort, idColumn: string): string {
  return `${sort.expr} ${sort.dir.toUpperCase()}, ${idColumn} ${sort.dir.toUpperCase()}`;
}

/**
 * Page raw rows selected with `<sort expr> AS sort_key`, then map them. The cursor carries the
 * database-computed sort key, so ordering and cursor comparison always use SQL semantics.
 */
export function pageRows<T>(rows: Row[], limit: number, map: (r: Row) => T): { items: T[]; nextCursor: string | null } {
  const hasMore = rows.length > limit;
  const slice = hasMore ? rows.slice(0, limit) : rows;
  const last = slice[slice.length - 1];
  const sortKey = (v: unknown): string | number | null => (v === null || v === undefined ? null : typeof v === "number" ? v : String(v));
  return { items: slice.map(map), nextCursor: hasMore && last ? encodeCursor([sortKey(last.sort_key), String(last.id)]) : null };
}
