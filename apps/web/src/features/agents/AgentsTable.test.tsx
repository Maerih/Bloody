import type { Agent } from "@bloody/contracts";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ORG_A, TENANT_ID } from "../../test/fixtures";
import { mockApi, renderWithSession } from "../../test/utils";
import { AgentsTable } from "./AgentsTable";

const ASSET_ID = "00000000-0000-4000-8000-0000000000d1";
const NOW = new Date().toISOString();

function agent(overrides: Partial<Agent> = {}): Agent {
  return {
    id: "00000000-0000-4000-8000-0000000000e1",
    tenantId: TENANT_ID,
    organizationId: ORG_A,
    createdAt: NOW,
    updatedAt: NOW,
    assetId: ASSET_ID,
    hostname: "ws-sales-03",
    platform: "linux",
    version: "4.9.0",
    engine: "wazuh",
    status: "protected",
    lastCheckinAt: NOW,
    antivirusStatus: "protected",
    firewallEnabled: true,
    isolation: null,
    ...overrides,
  };
}

const pending = (body: unknown) => ({ ...(body as object), id: "00000000-0000-4000-8000-0000000000f1", status: "pending_approval" });

describe("Agent isolation", () => {
  it("requests LAN isolation (internet kept) with the chosen mode", async () => {
    const { calls } = mockApi({ "/agents": { items: [agent()], nextCursor: null }, "POST /response/actions": ({ body }: { body: unknown }) => pending(body) });
    renderWithSession(<AgentsTable />);
    fireEvent.click(await screen.findByRole("button", { name: "Isolate" }));
    const dialog = await screen.findByRole("dialog");
    const modes = within(dialog).getByRole("group", { name: "Isolation mode" });
    expect(within(modes).getByLabelText(/Full isolation/)).toBeChecked();
    fireEvent.click(within(modes).getByLabelText(/LAN isolation — keep internet/));
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: "Lateral movement from this host" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Request approval" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/response/actions")).toBe(true));
    const sent = calls.find((c) => c.method === "POST" && c.path === "/response/actions")!.body as Record<string, unknown>;
    expect(sent).toMatchObject({ action: "isolate_endpoint", target: { kind: "asset", id: ASSET_ID }, parameters: { mode: "lan" } });
    expect(await within(dialog).findByText(/waiting in the approval queue/)).toBeInTheDocument();
  });

  it("shows the isolation mode and offers release from the platform", async () => {
    const { calls } = mockApi({
      "/agents": { items: [agent({ status: "isolated", isolation: { mode: "lan", since: NOW, actionId: null } })], nextCursor: null },
      "POST /response/actions": ({ body }: { body: unknown }) => pending(body),
    });
    renderWithSession(<AgentsTable />);
    expect(await screen.findByText("Isolated · LAN only")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Release" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).queryByRole("group", { name: "Isolation mode" })).toBeNull();
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: "Host cleaned and verified" } });
    fireEvent.click(within(dialog).getByRole("button", { name: /Submit action|Request approval/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/response/actions")).toBe(true));
    expect(calls.find((c) => c.method === "POST")!.body).toMatchObject({ action: "release_endpoint", parameters: {} });
  });
});
