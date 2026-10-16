import { fireEvent, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { mockApi, renderWithSession } from "../../test/utils";
import { HostInventorySection } from "./HostInventory";

const ASSET = "00000000-0000-4000-8000-0000000000d1";
const inventory = {
  agentId: "00000000-0000-4000-8000-0000000000e1",
  hostname: "kb-ws-07",
  platform: "windows",
  collectedAt: new Date().toISOString(),
  software: [{ name: "AnyDesk", version: "8.0.14", publisher: "AnyDesk Software GmbH", installedAt: null }],
  services: [{ name: "WinDefend", displayName: "Microsoft Defender Antivirus Service", state: "stopped", startMode: "disabled", account: "LocalSystem" }],
  users: [{ name: "amina", fullName: "Amina Mushi", admin: true, enabled: true, loggedIn: true, lastLogon: null }],
  processes: [{ pid: 4120, name: "chrome.exe", path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", user: null }],
  ports: [{ protocol: "tcp", address: "0.0.0.0", port: 3389, process: "svchost" }],
  antivirus: [{ name: "Microsoft Defender Antivirus", enabled: true, upToDate: true, realTimeProtection: false, tamperProtection: false, signatureAgeDays: 0 }],
  firewall: { enabled: false, detail: "all profiles off" },
  antivirusStatus: "unhealthy",
  antivirusIssues: ["Microsoft Defender Antivirus: real-time protection is off", "Microsoft Defender Antivirus: tamper protection is off"],
};

describe("Host inventory section", () => {
  it("shows software, services, users, ports and tampered antivirus", async () => {
    mockApi({ [`/assets/${ASSET}/inventory`]: { inventory } });
    renderWithSession(<HostInventorySection assetId={ASSET} />);
    expect(await screen.findByText("AnyDesk")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: /Services/ }));
    expect(screen.getByText("Microsoft Defender Antivirus Service")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: /Users/ }));
    expect(screen.getByText("Administrator")).toBeInTheDocument();
    expect(screen.getAllByText("Signed in")).toHaveLength(2); // column header + badge
    fireEvent.click(screen.getByRole("tab", { name: /Open ports/ }));
    expect(screen.getByText("3389")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: /Antivirus & firewall/ }));
    expect(screen.getByRole("list", { name: "Antivirus issues" })).toHaveTextContent("tamper protection is off");
    expect(screen.getByText("all profiles off")).toBeInTheDocument();
  });

  it("explains how to get an inventory when no agent reported", async () => {
    mockApi({ [`/assets/${ASSET}/inventory`]: { inventory: null } });
    renderWithSession(<HostInventorySection assetId={ASSET} />);
    expect(await screen.findByText("No host inventory yet")).toBeInTheDocument();
  });
});
