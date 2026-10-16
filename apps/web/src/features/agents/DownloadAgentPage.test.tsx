import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { makeMe, makeSummary } from "../../test/fixtures";
import { mockApi, renderApp } from "../../test/utils";
import { deploymentScript, oneLiner } from "./DownloadAgentPage";

const KEY = "sak_e52275396bdb4f119aa48bfdba3cb08a_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_xyz";
const enrollment = {
  accountKey: KEY,
  rotatedAt: null,
  agentVersion: "1.0.0",
  platformUrl: "http://localhost",
  organizations: [
    { id: "o1", name: "Kilimanjaro Bank", key: "kilimanjaro-bank", agents: 3 },
    { id: "o2", name: "Nile Health Clinics", key: "nile-health", agents: 1 },
  ],
};

describe("Download agent page", () => {
  it("builds install commands for each OS with the account and organization keys", () => {
    const k = { url: "https://soc.example", accountKey: KEY, orgKey: "nile-health" };
    expect(oneLiner("linux", k)).toBe(`curl -fsSL https://soc.example/api/v1/agent/install/linux -o install-sciat.sh && sudo bash install-sciat.sh --account-key '${KEY}' --org-key 'nile-health'`);
    expect(oneLiner("windows", k)).toContain(`install-sciat.ps1 -AccountKey '${KEY}' -OrgKey 'nile-health'`);
    expect(deploymentScript("windows", k)).toContain("if (Get-Service -Name SCIATAgent -ErrorAction SilentlyContinue) { exit 0 }");
    expect(deploymentScript("macos", k)).toContain("launchctl print system/africa.sciat.agent");
    expect(deploymentScript("linux", k)).toContain("systemctl is-active --quiet sciat-agent");
  });

  it("shows keys, switches organization and OS, and offers RMM / MDM / GPO guides", async () => {
    mockApi({ "/auth/me": makeMe(), "/command-center/summary": makeSummary(), "/agents/enrollment": enrollment });
    renderApp("/agents/download");
    expect(await screen.findByText("Install the SCIAT Agent")).toBeInTheDocument();
    // Account key is masked until shown.
    expect((await screen.findByTestId("account-key")).textContent).not.toContain(KEY);
    fireEvent.click(screen.getByRole("button", { name: "Show account key" }));
    expect(screen.getByTestId("account-key").textContent).toBe(KEY);

    const command = () => screen.getByLabelText("Install command").textContent ?? "";
    expect(command()).toContain("-OrgKey 'kilimanjaro-bank'");
    fireEvent.change(screen.getByRole("combobox", { name: "Organization" }), { target: { value: "nile-health" } });
    expect(screen.getByTestId("org-key").textContent).toBe("nile-health");
    expect(command()).toContain("-OrgKey 'nile-health'");
    fireEvent.click(screen.getByRole("tab", { name: /Linux/ }));
    expect(command()).toContain("/api/v1/agent/install/linux");
    expect(screen.getByText(/sciat-agent systemd service/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: /RMM \/ MDM \/ GPO/ }));
    expect(screen.getByText(/Platform scripts → Add → Windows 10 and later/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Jamf Pro" }));
    expect(screen.getByLabelText("Deployment script").textContent).toContain("africa.sciat.agent");
    expect(screen.getByText(/About the SCIAT Agent/)).toBeInTheDocument();
  });

  it("regenerates the account key after confirmation", async () => {
    const { calls } = mockApi({
      "/auth/me": makeMe(),
      "/command-center/summary": makeSummary(),
      "/agents/enrollment": enrollment,
      "POST /agents/enrollment/regenerate": { accountKey: KEY.replace("xyz", "new") },
    });
    renderApp("/agents/download");
    fireEvent.click(await screen.findByRole("button", { name: "Regenerate" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/Installed agents keep working/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Regenerate key" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/agents/enrollment/regenerate")).toBe(true));
  });
});

describe("Automatic agent updates", () => {
  it("shows versions in use and turns automatic updates off", async () => {
    const { calls } = mockApi({
      "/auth/me": makeMe(),
      "/command-center/summary": makeSummary(),
      "/agents/enrollment": enrollment,
      "/agents/auto-update": {
        enabled: true,
        latestVersion: "1.3.0",
        versions: [
          { version: "1.3.0", agents: 3, current: true },
          { version: "1.2.0", agents: 1, current: false },
        ],
      },
      "PUT /agents/auto-update": { enabled: false },
    });
    renderApp("/agents/download");
    const versions = await screen.findByRole("list", { name: "Agent versions" });
    expect(within(versions).getByText("1.2.0")).toBeInTheDocument();
    expect(within(versions).getByText("3 computers")).toBeInTheDocument();
    expect(screen.getByText("1 computer runs an older version and will update at the next check-in.")).toBeInTheDocument();
    const box = screen.getByRole("checkbox", { name: /Keep agents up to date/ });
    expect(box).toBeChecked();
    fireEvent.click(box);
    await waitFor(() => expect(calls.find((c) => c.method === "PUT" && c.path === "/agents/auto-update")?.body).toEqual({ enabled: false }));
  });
});
