import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ORG_A } from "../../test/fixtures";
import { mockApi, renderWithSession } from "../../test/utils";
import { FootholdsView } from "./FootholdsView";

const NOW = new Date().toISOString();
const evil = {
  fingerprint: "0123456789abcdef",
  kind: "scheduled_task",
  location: "\\Microsoft\\Windows\\UpdateCheck",
  name: "UpdateCheck",
  command: "powershell.exe -nop -w hidden -enc SQBFAFgA",
  signer: null,
  signed: null,
  assessment: { score: 65, level: "high", reasons: [{ points: 45, text: "Encoded or obfuscated PowerShell" }, { points: 20, text: "PowerShell with a hidden window" }] },
  verdict: null,
  isNew: true,
  firstSeen: NOW,
  endpointCount: 2,
  endpoints: [
    { agentId: "a1", hostname: "kb-ws-01", user: "SYSTEM", firstSeen: NOW, lastSeen: NOW, baseline: false },
    { agentId: "a2", hostname: "kb-ws-02", user: "SYSTEM", firstSeen: NOW, lastSeen: NOW, baseline: true },
  ],
};
const teams = {
  ...evil,
  fingerprint: "fedcba9876543210",
  kind: "run_key",
  name: "Teams",
  command: "C:\\Users\\amina\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart Teams.exe",
  signed: true,
  signer: "Microsoft Corporation",
  assessment: { score: 0, level: "low", reasons: [] },
  verdict: { verdict: "expected", note: null, by: "admin@kb.example", at: NOW },
  isNew: false,
  endpointCount: 1,
  endpoints: [{ agentId: "a1", hostname: "kb-ws-01", user: "amina", firstSeen: NOW, lastSeen: NOW, baseline: true }],
};
const overview = { organizationId: ORG_A, footholds: [evil, teams], truncated: false, summary: { entries: 2, suspicious: 1, malicious: 0, newLast7Days: 1, endpointsReporting: 2 } };

describe("Persistent Footholds", () => {
  it("lists autostart entries with their rating and opens the details", async () => {
    mockApi({ "/footholds/overview": overview });
    renderWithSession(<FootholdsView />);
    expect(await screen.findByText("UpdateCheck")).toBeInTheDocument();
    expect(screen.getByText("Highly suspicious")).toBeInTheDocument();
    expect(screen.getByText("Expected")).toBeInTheDocument();
    expect(screen.getByText("2 computers")).toBeInTheDocument();
    expect(screen.getByText("Suspicious, not reviewed").closest("div")!.parentElement).toHaveTextContent("1");
    fireEvent.click(screen.getByText("UpdateCheck"));
    const drawer = await screen.findByRole("dialog");
    expect(within(drawer).getByText("powershell.exe -nop -w hidden -enc SQBFAFgA")).toBeInTheDocument();
    expect(within(drawer).getByText("PowerShell with a hidden window")).toBeInTheDocument();
    const computers = within(drawer).getByRole("list", { name: "Computers with this entry" });
    expect(within(computers).getByText("kb-ws-01")).toBeInTheDocument();
    expect(within(computers).getAllByText("New")).toHaveLength(1);
    expect(within(drawer).getByText(/If nobody can explain this entry/)).toBeInTheDocument();
  });

  it("marks an entry malicious with a note", async () => {
    const { calls } = mockApi({ "/footholds/overview": overview, "PUT /footholds/verdicts": { changed: 1 } });
    renderWithSession(<FootholdsView />);
    fireEvent.click(await screen.findByText("UpdateCheck"));
    const drawer = await screen.findByRole("dialog");
    fireEvent.change(within(drawer).getByLabelText(/Note/), { target: { value: "IR-2026-41" } });
    fireEvent.click(within(drawer).getByRole("button", { name: "Mark malicious" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ organizationId: ORG_A, fingerprints: ["0123456789abcdef"], verdict: "malicious", note: "IR-2026-41" }));
  });
});
