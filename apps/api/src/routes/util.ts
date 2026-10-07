import type { FastifyReply, FastifyRequest } from "fastify";
import type { z } from "zod";
import { CSRF_COOKIE, SESSION_COOKIE } from "../auth/types.js";
import type { AppServices } from "../context.js";
import type { Queryable } from "../db/pool.js";
import { notFound } from "../http/errors.js";
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
