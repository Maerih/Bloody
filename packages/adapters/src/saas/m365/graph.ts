/**
 * Minimal Microsoft Graph client for read-only posture collection (proprietary).
 * Client-credentials token from the customer's own Entra app registration; only the fixed
 * Microsoft endpoints are ever contacted (no user-supplied URLs), and paging links are followed
 * only when they stay on graph.microsoft.com.
 */

export const GRAPH_BASE = "https://graph.microsoft.com/v1.0";
const LOGIN_BASE = "https://login.microsoftonline.com";

export class GraphError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
  /** 401 / 403: the app registration lacks a permission (or admin consent). */
  get isPermission(): boolean {
    return this.status === 401 || this.status === 403;
  }
}

export interface GraphClientOptions {
  directoryTenantId: string;
  clientId: string;
  clientSecret: string;
  fetch?: typeof fetch;
  now?: () => number;
  timeoutMs?: number;
}

export interface GraphClient {
  get<T = unknown>(path: string): Promise<T>;
  /** All pages of a collection (stops at `max` items). */
  list<T = unknown>(path: string, max?: number): Promise<T[]>;
}

const TENANT_RE = /^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[a-z0-9-]+(\.[a-z0-9-]+)+)$/i;

export function createGraphClient(opts: GraphClientOptions): GraphClient {
  if (!TENANT_RE.test(opts.directoryTenantId)) throw new GraphError(400, "invalid_tenant", "Invalid directory (tenant) ID");
  const doFetch = opts.fetch ?? fetch;
  const now = opts.now ?? Date.now;
  const timeoutMs = opts.timeoutMs ?? 20_000;
  let token: { value: string; expiresAt: number } | null = null;

  const timed = async (url: string, init: RequestInit): Promise<Response> => {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      return await doFetch(url, { ...init, signal: ctl.signal, redirect: "error" });
    } finally {
      clearTimeout(t);
    }
  };

  const accessToken = async (): Promise<string> => {
    if (token && token.expiresAt - 60_000 > now()) return token.value;
    const body = new URLSearchParams({ client_id: opts.clientId, client_secret: opts.clientSecret, grant_type: "client_credentials", scope: "https://graph.microsoft.com/.default" });
    const res = await timed(`${LOGIN_BASE}/${encodeURIComponent(opts.directoryTenantId)}/oauth2/v2.0/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    const json = (await res.json().catch(() => ({}))) as { access_token?: string; expires_in?: number; error?: string; error_description?: string };
    if (!res.ok || !json.access_token) {
      const desc = (json.error_description ?? "").split("\r\n")[0] ?? "";
      throw new GraphError(res.status === 400 ? 401 : res.status, json.error ?? "token_failed", `Sign-in to Microsoft 365 failed: ${json.error ?? res.status}${desc ? ` — ${desc}` : ""}`);
    }
    token = { value: json.access_token, expiresAt: now() + (json.expires_in ?? 3600) * 1000 };
    return token.value;
  };

  const request = async <T>(url: string): Promise<T> => {
    const res = await timed(url, { headers: { authorization: `Bearer ${await accessToken()}`, accept: "application/json", ConsistencyLevel: "eventual" } });
    if (!res.ok) {
      const json = (await res.json().catch(() => ({}))) as { error?: { code?: string; message?: string } };
      throw new GraphError(res.status, json.error?.code ?? `http_${res.status}`, json.error?.message ?? `Microsoft Graph returned ${res.status}`);
    }
    return (await res.json()) as T;
  };

  return {
    get: <T>(path: string) => request<T>(`${GRAPH_BASE}${path}`),
    async list<T>(path: string, max = 5000): Promise<T[]> {
      const out: T[] = [];
      let url: string | undefined = `${GRAPH_BASE}${path}`;
      while (url && out.length < max) {
        const page: { value?: T[]; "@odata.nextLink"?: string } = await request(url);
        out.push(...(page.value ?? []));
        const next = page["@odata.nextLink"];
        url = next && next.startsWith("https://graph.microsoft.com/") ? next : undefined;
      }
      return out.slice(0, max);
    },
  };
}
