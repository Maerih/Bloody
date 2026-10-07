import type { ZodType, ZodTypeDef } from "zod";
import { cachedTokenProvider, EngineClient, EngineError, type EngineClientOptions, type QueryValue } from "../http/client.js";
import { runHealthCheck, type HealthCheckResult } from "../http/health.js";
import {
  CoPilotAgentsResponse,
  CoPilotAlertsResponse,
  CoPilotCasesResponse,
  CoPilotCustomerCodesResponse,
  CoPilotCustomersResponse,
  CoPilotTokenResponse,
  CoPilotUsersResponse,
  COPILOT_CUSTOMER_USER_ROLE_ID,
  type CoPilotAgent,
  type CoPilotAlert,
  type CoPilotCase,
  type CoPilotCustomer,
  type CoPilotUser,
} from "./schemas.js";

/**
 * SOCFortress CoPilot REST client (network API only — CoPilot is AGPL-3.0 and is never
 * linked or copied).
 *
 * Two deployment modes:
 *  - `portal: "main"` — MSSP/business side. A CoPilot admin/analyst service account; the
 *    sync sees every customer it may access, their agents, alerts, cases and portal users.
 *  - `portal: "customer"` — customer side. A CoPilot `customer_user` account authenticates
 *    against `/api/auth/token/customer-portal`; CoPilot itself scopes every response to that
 *    customer's codes, and the sync maps them onto the customer's own Bloody organization.
 *
 * Auth is the OAuth2 password flow (`application/x-www-form-urlencoded`) → bearer JWT,
 * cached and refreshed on expiry / 401. Accounts with interactive 2FA cannot be used.
 */

export type CoPilotPortal = "main" | "customer";

export interface CoPilotClientOptions extends Omit<EngineClientOptions, "engine" | "auth"> {
  username: string;
  password: string;
  portal?: CoPilotPortal;
  /** Refresh tokens after this many seconds (CoPilot default lifetime is 24 h). Default 3600. */
  tokenTtlSeconds?: number;
  /** API prefix, default "/api". */
  apiPrefix?: string;
}

export interface CoPilotSnapshot {
  fetchedAt: string;
  baseUrl: string;
  portal: CoPilotPortal;
  /** Customer codes the service account can see ("*" = deployment-wide). */
  scope: string[] | "*";
  customers: CoPilotCustomer[];
  agents: CoPilotAgent[];
  alerts: CoPilotAlert[];
  cases: CoPilotCase[];
  /** Portal users with their customer access (main portal only). */
  users: Array<CoPilotUser & { customerCodes: string[] }>;
  warnings: string[];
}

export interface SnapshotOptions {
  /** Restrict the sync to these customer codes (customer-side or staged onboarding). */
  customerCodes?: string[];
  includeUsers?: boolean;
  pageSize?: number;
  maxAlertPages?: number;
  maxCasePages?: number;
  now?: () => Date;
}

export class CoPilotClient {
  readonly http: EngineClient;
  readonly portal: CoPilotPortal;
  private readonly prefix: string;

  constructor(opts: CoPilotClientOptions) {
    const { username, password, portal = "main", tokenTtlSeconds, apiPrefix, ...rest } = opts;
    this.portal = portal;
    this.prefix = (apiPrefix ?? "/api").replace(/\/$/, "");
    const login = new EngineClient({ ...rest, engine: "copilot" });
    const tokenPath = `${this.prefix}/auth/token${portal === "customer" ? "/customer-portal" : ""}`;
    const getToken = cachedTokenProvider(
      async () => {
        const res = await login.post(tokenPath, {
          form: { grant_type: "password", username, password },
          schema: CoPilotTokenResponse,
          retry: true,
          skipAuth: true,
        });
        if (res.data.requires_2fa) {
          throw new EngineError("unauthorized", "CoPilot account requires interactive 2FA; use a dedicated service account", { engine: "copilot", status: res.status, url: res.url, retryable: false });
        }
        return { token: res.data.access_token, expiresInSeconds: tokenTtlSeconds ?? 3600 };
      },
      { ...(rest.clock ? { clock: rest.clock } : {}) },
    );
    this.http = new EngineClient({ ...rest, engine: "copilot", auth: { kind: "token_provider", getToken } });
  }

  private async get<T>(path: string, schema: ZodType<T, ZodTypeDef, unknown>, query?: Record<string, QueryValue>): Promise<T> {
    const res = await this.http.get<T>(`${this.prefix}${path}`, { schema, ...(query ? { query } : {}) });
    const success = (res.data as { success?: unknown }).success;
    if (success === false) {
      throw new EngineError("invalid_response", `CoPilot reported failure for ${path}: ${String((res.data as { message?: unknown }).message ?? "")}`.slice(0, 300), {
        engine: "copilot",
        status: res.status,
        url: res.url,
        retryable: false,
      });
    }
    return res.data;
  }

  async listCustomers(): Promise<CoPilotCustomer[]> {
    return (await this.get("/customers", CoPilotCustomersResponse)).customers;
  }

  async listCustomerAgents(customerCode: string): Promise<CoPilotAgent[]> {
    return (await this.get(`/customers/${encodeURIComponent(customerCode)}/agents`, CoPilotAgentsResponse)).agents ?? [];
  }

  async listAgents(customerCodes?: string[]): Promise<CoPilotAgent[]> {
    return (await this.get("/agents", CoPilotAgentsResponse, customerCodes?.length ? { customer_codes: customerCodes } : undefined)).agents ?? [];
  }

  async listAlerts(params: { page?: number; pageSize?: number; order?: "asc" | "desc"; customerCodes?: string[] } = {}): Promise<{ alerts: CoPilotAlert[]; total: number | null }> {
    const data = await this.get("/incidents/db_operations/alerts", CoPilotAlertsResponse, {
      page: params.page ?? 1,
      page_size: params.pageSize ?? 100,
      order: params.order ?? "desc",
      ...(params.customerCodes?.length ? { customer_codes: params.customerCodes } : {}),
    });
    return { alerts: data.alerts, total: data.total ?? null };
  }

  async getAlert(alertId: string | number): Promise<CoPilotAlert | undefined> {
    return (await this.get(`/incidents/db_operations/alert/${encodeURIComponent(String(alertId))}`, CoPilotAlertsResponse)).alerts[0];
  }

  async listCases(params: { page?: number; pageSize?: number; order?: "asc" | "desc"; customerCodes?: string[] } = {}): Promise<{ cases: CoPilotCase[]; total: number | null }> {
    const data = await this.get("/incidents/db_operations/cases", CoPilotCasesResponse, {
      page: params.page ?? 1,
      page_size: params.pageSize ?? 100,
      order: params.order ?? "desc",
      ...(params.customerCodes?.length ? { customer_codes: params.customerCodes } : {}),
    });
    return { cases: data.cases, total: data.total ?? null };
  }

  async listUsers(): Promise<CoPilotUser[]> {
    return (await this.get("/auth/users", CoPilotUsersResponse)).users;
  }

  async getUserCustomerCodes(userId: string): Promise<string[]> {
    return (await this.get(`/auth/users/${encodeURIComponent(userId)}/customers`, CoPilotCustomerCodesResponse)).customer_codes;
  }

  async myCustomerCodes(): Promise<string[]> {
    return (await this.get("/auth/me/customers", CoPilotCustomerCodesResponse)).customer_codes;
  }

  private async paginate<T>(fetchPage: (page: number) => Promise<{ items: T[]; total: number | null }>, pageSize: number, maxPages: number, warnings: string[], what: string): Promise<T[]> {
    const out: T[] = [];
    for (let page = 1; page <= maxPages; page++) {
      const { items, total } = await fetchPage(page);
      out.push(...items);
      if (items.length < pageSize || (total !== null && out.length >= total)) return out;
      if (page === maxPages) warnings.push(`${what}: stopped after ${maxPages} pages (${out.length} items); increase the page budget for a complete sync`);
    }
    return out;
  }

  /** Fetch everything the sync needs. All calls are reads. */
  async snapshot(opts: SnapshotOptions = {}): Promise<CoPilotSnapshot> {
    const now = opts.now ?? (() => new Date());
    const warnings: string[] = [];
    const pageSize = Math.min(Math.max(opts.pageSize ?? 200, 1), 1000);
    const scopeCodes = await this.myCustomerCodes().catch((err: unknown) => {
      warnings.push(`could not read customer scope: ${(err as Error).message}`);
      return null;
    });
    const scope: string[] | "*" = scopeCodes === null || scopeCodes.includes("*") ? "*" : scopeCodes;
    const restrict = opts.customerCodes?.length ? opts.customerCodes : undefined;

    let customers: CoPilotCustomer[];
    if (this.portal === "main") {
      customers = await this.listCustomers();
    } else {
      // The customer portal cannot list customers; its scope is the token's customer codes.
      customers = (scope === "*" ? [] : scope).map((code) => ({ customer_code: code, customer_name: code }) as CoPilotCustomer);
    }
    if (restrict) customers = customers.filter((c) => restrict.includes(c.customer_code));
    const codes = customers.map((c) => c.customer_code);
    const filterCodes = restrict ?? (this.portal === "customer" && scope !== "*" ? scope : undefined);

    const agents = await this.listAgents(filterCodes);
    const alerts = await this.paginate(
      async (page) => {
        const r = await this.listAlerts({ page, pageSize, order: "desc", ...(filterCodes ? { customerCodes: filterCodes } : {}) });
        return { items: r.alerts, total: r.total };
      },
      pageSize,
      opts.maxAlertPages ?? 50,
      warnings,
      "alerts",
    );
    const cases = await this.paginate(
      async (page) => {
        const r = await this.listCases({ page, pageSize, order: "desc", ...(filterCodes ? { customerCodes: filterCodes } : {}) });
        return { items: r.cases, total: r.total };
      },
      pageSize,
      opts.maxCasePages ?? 50,
      warnings,
      "cases",
    );

    const users: Array<CoPilotUser & { customerCodes: string[] }> = [];
    if (this.portal === "main" && opts.includeUsers !== false) {
      try {
        for (const u of await this.listUsers()) {
          const isCustomerUser = u.role_id === COPILOT_CUSTOMER_USER_ROLE_ID || (u.role_name ?? "").toLowerCase() === "customer_user";
          // Only portal (customer) users are mapped; staff accounts never get automatic bindings.
          const customerCodes = isCustomerUser ? await this.getUserCustomerCodes(u.id) : [];
          users.push({ ...u, customerCodes });
        }
      } catch (err) {
        warnings.push(`portal users not synced: ${(err as Error).message}`);
      }
    }

    return {
      fetchedAt: now().toISOString(),
      baseUrl: this.http.describe().baseUrl,
      portal: this.portal,
      scope,
      customers,
      agents: restrict ? agents.filter((a) => a.customer_code && codes.includes(a.customer_code)) : agents,
      alerts: restrict ? alerts.filter((a) => codes.includes(a.customer_code)) : alerts,
      cases: restrict ? cases.filter((c) => c.customer_code && codes.includes(c.customer_code)) : cases,
      users,
      warnings,
    };
  }

  healthCheck(): Promise<HealthCheckResult> {
    return runHealthCheck("copilot", async () => {
      const codes = await this.myCustomerCodes();
      const details: Record<string, string | number | boolean> = { portal: this.portal, customerScope: codes.includes("*") ? "deployment" : codes.length };
      if (this.portal === "main") details["customers"] = (await this.listCustomers()).length;
      return { status: "healthy", details };
    });
  }
}
