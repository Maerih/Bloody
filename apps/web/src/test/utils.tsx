/** TEST-ONLY helpers: fetch mocking and provider-wrapped rendering. */
import { QueryClient } from "@tanstack/react-query";
import { render, type RenderResult } from "@testing-library/react";
import type { ReactElement, ReactNode } from "react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { vi } from "vitest";
import { AppProviders, AppRoutes, ROUTER_FUTURE } from "../App";
import type { MeResponse } from "../api/types";
import { SessionProvider } from "../app/session";
import { UiProvider } from "../app/ui";
import { makeMe } from "./fixtures";

export type MockHandler = unknown | ((ctx: { url: URL; init: RequestInit; body: unknown }) => unknown);

export interface MockRoute {
  status?: number;
  body: MockHandler;
  headers?: Record<string, string>;
}

export interface FetchCall {
  method: string;
  path: string;
  url: URL;
  init: RequestInit;
  body: unknown;
}

/**
 * Stub global fetch. Keys are "METHOD /path" or "/path" (GET) relative to /api/v1.
 * Unmatched requests return a 404 ApiError envelope.
 */
export function mockApi(routes: Record<string, MockHandler | MockRoute>) {
  const calls: FetchCall[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, "http://localhost");
    const method = (init.method ?? "GET").toUpperCase();
    const path = url.pathname.replace(/^\/api\/v1/, "");
    let body: unknown = undefined;
    if (typeof init.body === "string") {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = init.body;
      }
    }
    calls.push({ method, path, url, init, body });
    const entry = routes[`${method} ${path}`] ?? (method === "GET" ? routes[path] : undefined);
    if (entry === undefined) {
      return new Response(JSON.stringify({ error: { code: "not_found", message: `No mock for ${method} ${path}` } }), {
        status: 404,
        headers: { "content-type": "application/json" },
      });
    }
    const route: MockRoute =
      typeof entry === "object" && entry !== null && "body" in (entry as Record<string, unknown>) && ("status" in (entry as Record<string, unknown>) || "headers" in (entry as Record<string, unknown>))
        ? (entry as MockRoute)
        : { body: entry };
    const payload = typeof route.body === "function" ? (route.body as (ctx: { url: URL; init: RequestInit; body: unknown }) => unknown)({ url, init, body }) : route.body;
    const status = route.status ?? 200;
    return new Response(status === 204 ? null : JSON.stringify(payload), {
      status,
      headers: { "content-type": "application/json", ...route.headers },
    });
  });
  vi.stubGlobal("fetch", fetchMock);
  return { fetchMock, calls };
}

export function testQueryClient(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: Infinity }, mutations: { retry: false } } });
}

let currentLocation = { pathname: "/", search: "" };
function LocationSpy() {
  const loc = useLocation();
  currentLocation = { pathname: loc.pathname, search: loc.search };
  return null;
}
export function getLocation() {
  return currentLocation;
}

/** Render the whole app (session gate, shell, routes) at `route`. Requires /auth/me mocked. */
export function renderApp(route = "/"): RenderResult {
  return render(
    <MemoryRouter initialEntries={[route]} future={ROUTER_FUTURE}>
      <AppProviders queryClient={testQueryClient()}>
        <AppRoutes />
        <LocationSpy />
      </AppProviders>
    </MemoryRouter>,
  );
}

/** Render a component inside providers + an authenticated session (no shell). */
export function renderWithSession(ui: ReactElement, { me = makeMe(), route = "/", path = "*" }: { me?: MeResponse; route?: string; path?: string } = {}): RenderResult {
  const Wrapper = ({ children }: { children: ReactNode }) => (
    <MemoryRouter initialEntries={[route]} future={ROUTER_FUTURE}>
      <AppProviders queryClient={testQueryClient()}>
        <Routes>
          <Route
            path={path}
            element={
              <SessionProvider me={me}>
                <UiProvider>
                  {children}
                  <LocationSpy />
                </UiProvider>
              </SessionProvider>
            }
          />
        </Routes>
      </AppProviders>
    </MemoryRouter>
  );
  return render(ui, { wrapper: Wrapper });
}
