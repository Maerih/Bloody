import { hardeningCatalog } from "@bloody/contracts";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ORG_A } from "../../test/fixtures";
import { mockApi, renderWithSession } from "../../test/utils";
import { AttackReductionView } from "./AttackReductionView";

const NOW = new Date().toISOString();
const overview = (exception: boolean) => ({
  organizationId: ORG_A,
  catalog: hardeningCatalog(),
  score: 58,
  checks: [
    { key: "win_smb1", failing: 1, passing: 1, unknown: 0, exception: exception ? { reason: "Legacy scanner needs SMBv1 until March", createdBy: null, createdAt: NOW } : null },
    { key: "win_llmnr", failing: 2, passing: 0, unknown: 0, exception: null },
    { key: "win_bitlocker", failing: 0, passing: 2, unknown: 0, exception: null },
  ],
  endpoints: [
    {
      agentId: "a1",
      hostname: "kb-ws-07",
      platform: "windows",
      collectedAt: NOW,
      score: 40,
      results: [
        { key: "win_smb1", status: "fail", detail: "SMBv1 is enabled" },
        { key: "win_llmnr", status: "fail", detail: "LLMNR is on (Windows default)" },
        { key: "win_bitlocker", status: "pass", detail: null },
      ],
    },
    {
      agentId: "a2",
      hostname: "kb-ws-08",
      platform: "windows",
      collectedAt: NOW,
      score: 75,
      results: [
        { key: "win_smb1", status: "pass", detail: null },
        { key: "win_llmnr", status: "fail", detail: "LLMNR is on (Windows default)" },
        { key: "win_bitlocker", status: "pass", detail: null },
      ],
    },
  ],
});

describe("Attack Reduction", () => {
  it("shows the score, the gaps and a check's fix, and accepts a risk with a reason", async () => {
    const { calls } = mockApi({ "/attack-reduction/overview": overview(false), [`PUT /attack-reduction/exceptions/${ORG_A}/win_smb1`]: { key: "win_smb1", reason: "x" } });
    renderWithSession(<AttackReductionView />);
    expect(await screen.findByText("58%")).toBeInTheDocument();
    expect(screen.getByText("LLMNR is turned off")).toBeInTheDocument();
    expect(screen.getByText("2 of 2")).toBeInTheDocument();
    fireEvent.click(screen.getByText("SMBv1 is disabled"));
    const drawer = await screen.findByRole("dialog");
    expect(within(drawer).getByText(/WannaCry/)).toBeInTheDocument();
    expect(within(drawer).getByText(/Set-SmbServerConfiguration -EnableSMB1Protocol \$false/)).toBeInTheDocument();
    expect(within(drawer).getByText("kb-ws-07")).toBeInTheDocument();
    const accept = within(drawer).getByRole("button", { name: "Accept risk" });
    expect(accept).toBeDisabled();
    fireEvent.change(within(drawer).getByLabelText("Reason"), { target: { value: "Legacy scanner needs SMBv1 until March" } });
    fireEvent.click(accept);
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ reason: "Legacy scanner needs SMBv1 until March" }));
  });

  it("lists computers and opens one computer's results; accepted risks are marked", async () => {
    mockApi({ "/attack-reduction/overview": overview(true) });
    renderWithSession(<AttackReductionView />);
    expect(await screen.findAllByText("Accepted risk")).not.toHaveLength(0);
    fireEvent.click(screen.getByText("kb-ws-07"));
    const drawer = await screen.findByRole("dialog");
    expect(within(drawer).getByText("SMBv1 is enabled")).toBeInTheDocument();
    expect(within(drawer).getAllByText("Fail")).toHaveLength(2);
  });
});
