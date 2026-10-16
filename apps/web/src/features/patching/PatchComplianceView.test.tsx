import { fireEvent, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ORG_A } from "../../test/fixtures";
import { mockApi, renderWithSession } from "../../test/utils";
import { PatchComplianceView } from "./PatchComplianceView";

const NOW = new Date().toISOString();
const endpoint = (over: object) => ({
  agentId: "a1",
  hostname: "kb-ws-10",
  os: "Microsoft Windows 10 Pro 10.0.19045",
  osSupport: { product: "Windows 10", endsOn: "2025-10-14", status: "ended", note: "Only computers enrolled in Extended Security Updates (ESU) still get fixes" },
  source: "windows_update",
  pendingCount: 2,
  securityCount: 1,
  criticalCount: 1,
  rebootRequired: true,
  lastInstalledAt: NOW,
  lastCheckedAt: NOW,
  securityPendingSince: NOW,
  reportedAt: NOW,
  grade: { state: "breached", reasons: ["Windows 10 no longer gets security updates (since 2025-10-14)", "1 security update waiting, 1 critical", "Restart needed to finish installing updates"] },
  pending: [
    { title: "2026-10 Cumulative Update for Windows 10 (KB5066791)", id: "KB5066791", version: null, security: true, severity: "critical" },
    { title: "Microsoft .NET Framework 4.8.1 Update", id: "KB5049624", version: null, security: false, severity: "unspecified" },
  ],
  ...over,
});
const overview = {
  organizationId: ORG_A,
  endpoints: [
    endpoint({}),
    endpoint({ agentId: "a2", hostname: "kb-lnx-01", os: "Ubuntu 24.04.1 LTS", osSupport: { product: "Ubuntu 24.04", endsOn: "2029-05-31", status: "supported", note: null }, source: "apt", pendingCount: 0, securityCount: 0, criticalCount: 0, rebootRequired: false, securityPendingSince: null, grade: { state: "current", reasons: [] }, pending: [] }),
  ],
  missing: [{ title: "2026-10 Cumulative Update for Windows 10 (KB5066791)", id: "KB5066791", security: true, severity: "critical", endpoints: 1 }],
  summary: { endpoints: 2, reporting: 2, current: 1, behind: 0, breached: 1, unknown: 0, compliance: 50, unsupportedOs: 1, securityUpdates: 1, rebootPending: 1 },
};

describe("Patch Compliance", () => {
  it("shows compliance, unsupported operating systems and missing updates", async () => {
    mockApi({ "/patching/overview": overview });
    renderWithSession(<PatchComplianceView />);
    expect(await screen.findByText("kb-ws-10")).toBeInTheDocument();
    expect(screen.getByText("50%")).toBeInTheDocument();
    expect(screen.getByText("Unsupported since 2025-10-14")).toBeInTheDocument();
    expect(screen.getByText("Out of compliance", { selector: "span" })).toBeInTheDocument();
    expect(screen.getByText("Up to date")).toBeInTheDocument();
    expect(screen.getByText("(1 critical)")).toBeInTheDocument();
    const missing = screen.getByRole("table", { name: "Missing updates" });
    expect(within(missing).getByText("KB5066791")).toBeInTheDocument();
    expect(within(missing).getByText("Security · critical")).toBeInTheDocument();
  });

  it("opens a computer with its reasons and pending updates", async () => {
    mockApi({ "/patching/overview": overview });
    renderWithSession(<PatchComplianceView />);
    fireEvent.click(await screen.findByText("kb-ws-10"));
    const drawer = await screen.findByRole("dialog");
    expect(within(drawer).getByText("Restart needed to finish installing updates")).toBeInTheDocument();
    expect(within(drawer).getByText(/Extended Security Updates/)).toBeInTheDocument();
    expect(within(within(drawer).getByRole("list", { name: "Security updates" })).getByText("critical")).toBeInTheDocument();
    expect(within(drawer).getByRole("list", { name: "Other updates" })).toHaveTextContent(".NET Framework");
  });
});
