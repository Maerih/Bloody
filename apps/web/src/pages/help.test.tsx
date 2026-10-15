import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { buildAppRoutes, ModulePlaceholderPage } from "../app/routes";
import { makeMe, makeSummary, ORG_A } from "../test/fixtures";
import { mockApi, renderApp } from "../test/utils";
import { credentialTheftScenario } from "./SimulateIncidentPage";

describe("help & onboarding pages", () => {
  it("no hamburger-menu page is a placeholder any more", () => {
    const placeholders = buildAppRoutes()
      .filter((r) => (r.element as { type?: unknown }).type === ModulePlaceholderPage)
      .map((r) => r.path);
    for (const p of ["/simulate", "/agents/download", "/sandbox", "/support", "/feedback"]) expect(placeholders).not.toContain(p);
  });

  it("builds a labelled, schema-shaped simulation chain", () => {
    const events = credentialTheftScenario("ws-x");
    expect(events).toHaveLength(3);
    expect(events.every((e) => e.labels.simulated === "true" && e.asset.hostname === "ws-x")).toBe(true);
    expect(events.map((e) => e.timestamp)).toEqual([...events.map((e) => e.timestamp)].sort());
  });

  it("sends the simulation to the ingest API", async () => {
    const api = mockApi({ "/auth/me": makeMe(), "/command-center/summary": makeSummary(), "POST /ingest/events": { accepted: 3 } });
    renderApp(`/simulate?org=${ORG_A}`);
    const run = await screen.findByRole("button", { name: /run simulation/i });
    await waitFor(() => expect(run).not.toBeDisabled());
    fireEvent.click(run);
    await screen.findByText(/3 events ingested/i);
    const call = api.calls.find((c) => c.method === "POST" && c.path === "/ingest/events");
    expect((call?.body as { events: unknown[] }).events).toHaveLength(3);
  });

});
