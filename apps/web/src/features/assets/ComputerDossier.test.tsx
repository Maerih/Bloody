import type { EndpointDossier } from "@bloody/contracts";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ORG_A } from "../../test/fixtures";
import { mockApi, renderWithSession } from "../../test/utils";
import { ComputerActivity, ComputerPosture, ComputerReportButton } from "./ComputerDossier";

const ASSET = "00000000-0000-4000-8000-0000000000d1";
const day = (d: number, h = 10) => new Date(Date.UTC(2026, 9, d, h)).toISOString();
const dossier: EndpointDossier = {
  assetId: ASSET,
  organizationId: ORG_A,
  hostname: "kb-fin-07",
  generatedAt: day(21),
  agents: [{ id: "ag", engine: "sciat", version: "1.5.0", platform: "windows", status: "isolated", isolation: { mode: "full", since: day(20), source: "platform" }, enrolledAt: day(1), lastCheckinAt: day(21) }],
  patching: {
    agentId: "ag",
    hostname: "kb-fin-07",
    os: "Microsoft Windows 10 Pro",
    osSupport: { status: "ended", product: "Windows 10", endsOn: "2025-10-14", note: null },
    source: "windows_update",
    pendingCount: 1,
    securityCount: 1,
    criticalCount: 1,
    rebootRequired: true,
    lastInstalledAt: day(1),
    lastCheckedAt: day(21),
    securityPendingSince: day(1),
    reportedAt: day(21),
    grade: { state: "breached", reasons: ["1 security update waiting for 40 days."] },
    pending: [{ title: "2026-10 Cumulative Update", id: "KB5066835", security: true, severity: "critical", version: null }],
  },
  hardening: { score: 55, collectedAt: day(21), checks: [{ key: "fw", title: "Host firewall is on", severity: "high", status: "fail", detail: null, accepted: false, fix: "Turn it on" }] },
  footholds: [{ name: "WinUpdateSvc", kind: "scheduled_task", location: "\\Update", command: "powershell -enc SQBFAFgA", level: "high", score: 85, reasons: ["Encoded PowerShell"], verdict: null, isNew: true, firstSeen: day(19) }],
  remoteAccess: [{ name: "AnyDesk", vendor: "AnyDesk", approved: false, evidence: ["Installed: AnyDesk 8.0"] }],
  activity: [
    { at: day(20, 11), kind: "isolation", title: "Isolated from the network", detail: null, actor: "SCIAT Agent", outcome: "success", severity: null },
    { at: day(20, 10), kind: "isolation", title: "Isolation (full) requested", detail: "Beaconing", actor: "Amina Mushi", outcome: "pending", severity: null },
    { at: day(19), kind: "alert", title: "Encoded PowerShell launched", detail: null, actor: null, outcome: null, severity: "high" },
    { at: day(19, 9), kind: "persistence", title: "New autostart entry: WinUpdateSvc", detail: "powershell -enc SQBFAFgA", actor: "SCIAT Agent", outcome: null, severity: "high" },
  ],
  activityTruncated: false,
  activitySince: day(1),
};

describe("computer page sections", () => {
  it("shows patching, hardening, persistence and remote access", async () => {
    mockApi({ [`/assets/${ASSET}/dossier`]: dossier });
    renderWithSession(<ComputerPosture assetId={ASSET} />);
    expect(await screen.findByText("Out of compliance")).toBeInTheDocument();
    expect(screen.getByText("Unsupported since 2025-10-14")).toBeInTheDocument();
    expect(screen.getByText("Restart needed")).toBeInTheDocument();
    expect(screen.getByText("2026-10 Cumulative Update")).toBeInTheDocument();
    expect(screen.getByText("Host firewall is on")).toBeInTheDocument();
    expect(screen.getByText("WinUpdateSvc")).toBeInTheDocument();
    expect(screen.getByText("Not approved")).toBeInTheDocument();
  });

  it("lists the activity by day, newest first, and filters by type", async () => {
    const { calls } = mockApi({ [`/assets/${ASSET}/dossier`]: dossier });
    renderWithSession(<ComputerActivity assetId={ASSET} />);
    const list = await screen.findByRole("list", { name: "Activity" });
    const titles = [...list.querySelectorAll("span.font-medium")].map((e) => e.textContent).filter((t) => t !== "Done" && t !== "Requested");
    expect(titles).toEqual(["Isolated from the network", "Isolation (full) requested", "Encoded PowerShell launched", "New autostart entry: WinUpdateSvc"]);
    expect(within(list).getByText(/Amina Mushi/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Alert \(1\)/ }));
    expect(within(screen.getByRole("list", { name: "Activity" })).queryByText("Isolated from the network")).toBeNull();
    fireEvent.change(screen.getByLabelText("Activity period"), { target: { value: "365" } });
    await waitFor(() => expect(calls.some((c) => c.url.searchParams.get("days") === "365")).toBe(true));
  });

  it("downloads the report about this computer", async () => {
    const { calls } = mockApi({ "POST /reports/generate": { status: 200, body: { ok: true }, headers: { "content-disposition": 'attachment; filename="org-kb-fin-07-computer-report-2026-10-21.pdf"' } } });
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: vi.fn(() => "blob:r"), revokeObjectURL: vi.fn() }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    renderWithSession(<ComputerReportButton assetId={ASSET} organizationId={ORG_A} />);
    fireEvent.click(screen.getByRole("button", { name: "Download report" }));
    fireEvent.change(screen.getByLabelText("Activity period"), { target: { value: "90" } });
    fireEvent.click(screen.getByRole("button", { name: "Download" }));
    await waitFor(() => expect(click).toHaveBeenCalled());
    expect(calls.find((c) => c.path === "/reports/generate")!.body).toEqual({ type: "endpoint_posture", format: "pdf", organizationId: ORG_A, periodDays: 90, options: { assetId: ASSET } });
    click.mockRestore();
  });
});
