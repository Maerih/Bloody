import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { makeMe, makeSummary, ORG_A, TENANT_ID } from "../../test/fixtures";
import { mockApi, renderApp } from "../../test/utils";

const EMPTY = { items: [], nextCursor: null };

function incident(id: string, severity: string, assets: string[], identities: string[]) {
  return {
    id,
    tenantId: TENANT_ID,
    organizationId: ORG_A,
    number: 1,
    title: `Incident ${id}`,
    summary: null,
    severity,
    status: "investigating",
    riskScore: 80,
    assigneeId: null,
    attack: [],
    alertCount: 1,
    assetIds: assets,
    identityIds: identities,
    detectedAt: "2026-10-07T10:00:00.000Z",
    acknowledgedAt: null,
    containedAt: null,
    closedAt: null,
    createdAt: "2026-10-07T10:00:00.000Z",
    updatedAt: "2026-10-07T10:00:00.000Z",
  };
}

function api(overrides: Record<string, unknown> = {}) {
  return mockApi({
    "/auth/me": makeMe(),
    "/command-center/summary": makeSummary(),
    "/incidents": {
      items: [incident("a", "critical", ["x"], []), incident("b", "high", ["x"], ["y"]), incident("c", "high", [], ["y"]), incident("d", "medium", ["x"], [])],
      nextCursor: null,
    },
    "/escalations": EMPTY,
    "/response/actions": EMPTY,
    "/reports/schedules": [],
    ...overrides,
  });
}

describe("CommandCenterPage", () => {
  it("renders the summary: severity bars, SOC pipeline, escalations, donuts and triage", async () => {
    const { calls } = api();
    renderApp("/");
    expect(await screen.findByRole("heading", { name: "Command Center", level: 1 })).toBeInTheDocument();

    const active = (await screen.findByText("Active Incidents")).closest("section")!;
    expect(within(active).getByText("(4)")).toBeInTheDocument();
    expect(within(active).getByTestId("severity-count-critical")).toHaveTextContent("1");
    expect(within(active).getByTestId("severity-count-high")).toHaveTextContent("2");
    expect(within(active).getByTestId("severity-count-low_medium")).toHaveTextContent("1");
    // Per-severity endpoint/identity sub-counts derived from the (complete) active incident list.
    await waitFor(() => expect(within(active).getByRole("link", { name: "2 High incidents, 1 endpoint, 2 identity" })).toBeInTheDocument());

    expect(screen.getByText("58.7K")).toBeInTheDocument();
    expect(screen.getByText("last 90 days")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /All Escalations Resolved/ })).toHaveAttribute("href", "/escalations");
    expect(screen.getByRole("link", { name: /All Firewalls Active/ })).toBeInTheDocument();
    expect(screen.getByText("Agents").closest("section")).toHaveTextContent("(1)");
    expect(screen.getByText("Managed Antivirus").closest("section")!.querySelector("svg[role=img]")).toHaveAttribute("aria-label", expect.stringContaining("Protected: 1 (100%)"));
    expect(screen.getByText("1h 24m")).toBeInTheDocument();
    expect(screen.getByText("Enforce MFA on privileged identities")).toBeInTheDocument();

    expect(screen.getByText("Triage Feed")).toBeInTheDocument();
    expect(screen.getByText("All caught up, no active incidents!")).toBeInTheDocument();
    expect(screen.queryByText("Explore Your Bloody Trial")).not.toBeInTheDocument();

    const summaryCall = calls.find((c) => c.path === "/command-center/summary")!;
    expect(summaryCall.url.searchParams.get("windowDays")).toBe("90");
    expect(summaryCall.url.searchParams.has("organizationId")).toBe(false);
  });

  it("scopes the summary to the organization in ?org=", async () => {
    const { calls } = api();
    renderApp(`/?org=${ORG_A}`);
    await screen.findByText("Active Incidents");
    expect(calls.find((c) => c.path === "/command-center/summary")!.url.searchParams.get("organizationId")).toBe(ORG_A);
  });

  it("shows the trial banner only on the trial plan", async () => {
    api({ "/auth/me": makeMe({ plan: "trial", entitlements: [{ module: "edr", state: "trial", trialEndsAt: "2099-01-01T00:00:00.000Z" }] }) });
    renderApp("/");
    expect(await screen.findByText("Explore Your Bloody Trial")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Launch Demo Sandbox/ })).toHaveAttribute("href", "/sandbox");
    expect(screen.getByText("Endpoint Detection & Response", { selector: "span" })).toBeInTheDocument();
  });

  it("uses the executive preset: risk widgets first and no triage feed", async () => {
    api({ "/auth/me": makeMe({ bindings: [{ role: "executive", organizationId: null }] }) });
    renderApp("/");
    await screen.findByText("Exposure Score");
    const widgets = screen.getByTestId("command-center-widgets").querySelectorAll("[data-widget]");
    expect([...widgets].slice(0, 3).map((w) => w.getAttribute("data-widget"))).toEqual(["exposure", "mttr", "identityRisk"]);
    expect(screen.queryByText("Triage Feed")).not.toBeInTheDocument();
  });

  it("renders triage items in the feed", async () => {
    api({
      "/command-center/summary": makeSummary({
        triage: [
          { id: "i1", kind: "incident", title: "Credential dumping on DC01", severity: "critical", organizationId: ORG_A, organizationName: "Acme Corp", at: new Date().toISOString(), status: "new" },
          { id: "e1", kind: "escalation", title: "Approve isolation", severity: "high", organizationId: ORG_A, organizationName: "Acme Corp", at: new Date().toISOString(), status: "open" },
        ],
      }),
    });
    renderApp("/");
    const link = await screen.findByRole("link", { name: /Credential dumping on DC01/ });
    expect(link).toHaveAttribute("href", "/incidents/i1");
    expect(screen.queryByText("Approve isolation")).not.toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Escalations/ })).toHaveTextContent("1");
  });

  it("shows the API error instead of numbers when the summary fails", async () => {
    api({ "/command-center/summary": { status: 500, body: { error: { code: "internal", message: "Summary unavailable", requestId: "req-42" } } } });
    renderApp("/");
    expect(await screen.findByText("Summary unavailable")).toBeInTheDocument();
    expect(screen.getByText("Request ID: req-42")).toBeInTheDocument();
    expect(screen.queryByText("58.7K")).not.toBeInTheDocument();
  });

  it("redirects to /login when the session is missing", async () => {
    api({ "/auth/me": { status: 401, body: { error: { code: "unauthorized", message: "No session" } } } });
    renderApp("/incidents");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });
});
