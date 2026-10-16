import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ORG_A } from "../../test/fixtures";
import { mockApi, renderWithSession } from "../../test/utils";
import { RmmGuardView } from "./RmmGuardView";

const NOW = new Date().toISOString();
const overview = (approved: string[] = []) => ({
  organizationId: ORG_A,
  catalog: [
    { key: "anydesk", name: "AnyDesk", vendor: "AnyDesk Software" },
    { key: "screenconnect", name: "ScreenConnect (ConnectWise Control)", vendor: "ConnectWise" },
  ],
  approved,
  findings: [
    { tool: { key: "anydesk", name: "AnyDesk", vendor: "AnyDesk Software" }, approved: approved.includes("anydesk"), endpoints: [{ agentId: "a1", hostname: "kb-ws-07", evidence: [{ kind: "software", value: "AnyDesk 8.0.14" }], seenAt: NOW }] },
    { tool: { key: "screenconnect", name: "ScreenConnect (ConnectWise Control)", vendor: "ConnectWise" }, approved: approved.includes("screenconnect"), endpoints: [{ agentId: "a2", hostname: "kb-srv-01", evidence: [{ kind: "process", value: "ScreenConnect.ClientService.exe" }], seenAt: NOW }] },
  ],
  endpointsWithInventory: 4,
  appControl: "audit",
});

describe("RMM Guard", () => {
  it("lists unapproved tools with the computers they were found on, and approves one", async () => {
    const { calls } = mockApi({ "/rmm-guard/overview": overview(["screenconnect"]), [`PUT /rmm-guard/settings/${ORG_A}`]: { approved: ["screenconnect", "anydesk"] } });
    renderWithSession(<RmmGuardView />);
    expect(await screen.findByText("kb-ws-07")).toBeInTheDocument();
    expect(screen.getByText(/installed: AnyDesk 8.0.14/)).toBeInTheDocument();
    expect(screen.getByText(/App Control is in audit mode/)).toBeInTheDocument();
    expect(screen.getByText("Unapproved")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Approve AnyDesk" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ approved: ["screenconnect", "anydesk"] }));
  });

  it("blocks a tool through App Control after confirming", async () => {
    const { calls } = mockApi({ "/rmm-guard/overview": overview(), "POST /rmm-guard/block": { created: 2, skipped: 0, appControl: "audit" } });
    renderWithSession(<RmmGuardView />);
    fireEvent.click(await screen.findByRole("button", { name: "Block AnyDesk" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/Found on 1 computer: kb-ws-07/)).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    fireEvent.click(within(dialog).getByRole("button", { name: "Add block rules" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ organizationId: ORG_A, tools: ["anydesk"] }));
    expect(await within(dialog).findByRole("status")).toHaveTextContent("2 block rules added. App Control is in audit mode");
  });
});
