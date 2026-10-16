import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ORG_A } from "../../test/fixtures";
import { mockApi, renderWithSession } from "../../test/utils";
import { ExternalExposureView } from "./ExternalExposureView";

const NOW = new Date().toISOString();
const LATER = new Date(Date.now() + 200 * 86_400_000).toISOString();
const T1 = "00000000-0000-4000-8000-0000000000e1";
const T2 = "00000000-0000-4000-8000-0000000000e2";

const overview = (authorized: boolean) => ({
  organizationId: ORG_A,
  authorization: authorized ? { reference: "MSA-2026-014 §4", authorizedBy: null, authorizedAt: NOW, expiresAt: LATER, valid: true } : null,
  targets: [
    { id: T1, ip: "41.90.64.10", source: "agent", status: "discovered", note: null, hostnames: ["kb-ws-01"], firstSeenAt: NOW, lastSeenAt: NOW, lastScannedAt: null, openPorts: 0 },
    { id: T2, ip: "102.68.1.7", source: "manual", status: "confirmed", note: "Nairobi office", hostnames: [], firstSeenAt: NOW, lastSeenAt: null, lastScannedAt: NOW, openPorts: 1 },
  ],
  findings: authorized
    ? [{ ip: "102.68.1.7", port: 3389, service: "Remote Desktop (RDP)", severity: "critical", risk: "The most common way ransomware crews break in.", fix: "Close the port on the firewall.", hostnames: [], firstSeenAt: NOW, lastSeenAt: NOW }]
    : [],
  scans: authorized ? [{ id: "s1", status: "finished", trigger: "manual", startedAt: NOW, finishedAt: NOW, addresses: 1, openPorts: 1, error: null }] : [],
  portsChecked: [{ port: 3389, service: "Remote Desktop (RDP)", severity: "critical" }],
});

describe("External Exposure", () => {
  it("needs an authorization (with attestation) before scanning", async () => {
    const { calls } = mockApi({ "/exposure/overview": overview(false), [`PUT /exposure/authorization/${ORG_A}`]: { reference: "MSA-2026-014 §4", authorizedBy: null, authorizedAt: NOW, expiresAt: LATER, valid: true } });
    renderWithSession(<ExternalExposureView />);
    expect(await screen.findByText("Not authorized")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Scan now" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Authorize testing" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Authorization reference"), { target: { value: "MSA-2026-014 §4" } });
    const save = within(dialog).getByRole("button", { name: "Save authorization" });
    expect(save).toBeDisabled();
    fireEvent.click(within(dialog).getByRole("checkbox"));
    fireEvent.click(save);
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toMatchObject({ reference: "MSA-2026-014 §4", attest: true, expiresAt: expect.any(String) }));
  });

  it("shows exposed services, and confirms or scans addresses", async () => {
    const { calls } = mockApi({
      "/exposure/overview": overview(true),
      [`PATCH /exposure/targets/${T1}`]: { ok: true },
      "POST /exposure/scans": { id: "s2", status: "running", trigger: "manual", startedAt: NOW, finishedAt: null, addresses: 2, openPorts: 0, error: null },
    });
    renderWithSession(<ExternalExposureView />);
    expect(await screen.findByText("102.68.1.7:3389")).toBeInTheDocument();
    expect(screen.getByText(/ransomware crews/)).toBeInTheDocument();
    expect(screen.getByText(/1 address was seen from SCIAT Agents/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Confirm 41.90.64.10" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ status: "confirmed" }));
    fireEvent.click(screen.getByRole("button", { name: "Scan now" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ organizationId: ORG_A }));
  });
});
