import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { makeMe, makeSummary } from "../test/fixtures";
import { getLocation, mockApi, renderApp } from "../test/utils";

const EMPTY = { items: [], nextCursor: null };

function api() {
  return mockApi({
    "/auth/me": makeMe(),
    "/command-center/summary": makeSummary({ activeIncidents: { critical: 0, high: 0, medium: 0, low: 0, total: 0, byAssetType: { endpoint: 0, identity: 0 } } }),
    "/escalations": EMPTY,
    "/response/actions": EMPTY,
    "/incidents": EMPTY,
    "/reports/schedules": [],
    "/search": { items: [{ kind: "incident", id: "inc-9", title: "Ransomware on FILESRV01", severity: "critical" }] },
  });
}

describe("CommandPalette & shortcuts", () => {
  it("opens with Ctrl+K, filters pages and navigates on Enter", async () => {
    api();
    renderApp("/");
    await screen.findByRole("heading", { name: "Command Center", level: 1 });
    expect(screen.queryByRole("dialog", { name: "Command palette" })).not.toBeInTheDocument();

    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    const input = await screen.findByRole("combobox", { name: /Search pages/ });
    expect(screen.getByRole("dialog", { name: "Command palette" })).toBeInTheDocument();
    expect(input).toHaveFocus();

    fireEvent.change(input, { target: { value: "escal" } });
    const option = within(screen.getByRole("listbox", { name: "Results" })).getAllByRole("option")[0]!;
    expect(option).toHaveTextContent("Escalations");
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(getLocation().pathname).toBe("/escalations"));
    expect(screen.queryByRole("dialog", { name: "Command palette" })).not.toBeInTheDocument();
  });

  it("searches tenant data via /api/v1/search and closes on Escape", async () => {
    const { calls } = api();
    renderApp("/");
    await screen.findByRole("heading", { name: "Command Center", level: 1 });
    fireEvent.keyDown(document.body, { key: "k", ctrlKey: true });
    const input = await screen.findByRole("combobox", { name: /Search pages/ });
    fireEvent.change(input, { target: { value: "ransom" } });
    expect(await screen.findByRole("option", { name: /Ransomware on FILESRV01/ })).toBeInTheDocument();
    expect(calls.some((c) => c.path === "/search" && c.url.searchParams.get("q") === "ransom")).toBe(true);
    fireEvent.keyDown(input, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Command palette" })).not.toBeInTheDocument();
  });

  it("supports g-sequences and ? for help", async () => {
    api();
    renderApp("/");
    await screen.findByRole("heading", { name: "Command Center", level: 1 });
    fireEvent.keyDown(document.body, { key: "g" });
    fireEvent.keyDown(document.body, { key: "i" });
    await waitFor(() => expect(getLocation().pathname).toBe("/incidents"));
    fireEvent.keyDown(document.body, { key: "g" });
    fireEvent.keyDown(document.body, { key: "h" });
    await waitFor(() => expect(getLocation().pathname).toBe("/"));
    fireEvent.keyDown(document.body, { key: "?", shiftKey: true });
    expect(await screen.findByRole("dialog", { name: "Keyboard shortcuts" })).toBeInTheDocument();
  });
});
