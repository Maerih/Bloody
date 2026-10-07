import { act, fireEvent, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeMe } from "../test/fixtures";
import { renderWithSession } from "../test/utils";
import { LeftRail } from "./LeftRail";

describe("LeftRail", () => {
  beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }));
  afterEach(() => vi.useRealTimers());

  it("lists every module with tiny labels and lock badges for non-entitled modules", () => {
    renderWithSession(<LeftRail />);
    const nav = screen.getByRole("navigation", { name: "Security modules" });
    for (const short of ["Home", "EDR", "ITDR", "NDR", "SIEM", "XDR", "ASM", "ESPM", "ISPM", "CSPM", "CIEM", "SSPM", "VM", "K8S", "CTI", "DFIR", "SOAR", "MAIL", "DECOY", "AI", "Trials", "Hub"]) {
      expect(within(nav).getByText(short)).toBeInTheDocument();
    }
    // Fixture entitlements: itdr trial_ended, ndr locked; edr active.
    expect(screen.getByTestId("rail-lock-itdr")).toBeInTheDocument();
    expect(screen.getByTestId("rail-lock-ndr")).toBeInTheDocument();
    expect(screen.queryByTestId("rail-lock-edr")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Command Center" })).toHaveAttribute("aria-current", "page");
  });

  it("opens the module flyout on hover with its sub-pages", async () => {
    renderWithSession(<LeftRail />);
    fireEvent.mouseEnter(screen.getByRole("link", { name: "Endpoint Detection & Response" }));
    await act(async () => {
      vi.advanceTimersByTime(100);
    });
    const flyout = screen.getByRole("menu", { name: "Endpoint Detection & Response" });
    for (const label of ["EDR Dashboard", "Persistent Footholds", "Process Insights", "Managed Antivirus", "Ransomware Canaries", "External Recon"]) {
      expect(within(flyout).getByRole("menuitem", { name: label })).toBeInTheDocument();
    }
  });

  it("shows an upsell instead of links for locked modules", async () => {
    renderWithSession(<LeftRail />);
    fireEvent.focus(screen.getByRole("link", { name: /Network Detection & Response \(not in your plan\)/ }));
    const flyout = screen.getByRole("menu", { name: "Network Detection & Response" });
    expect(within(flyout).getByText("Not included in your current plan.")).toBeInTheDocument();
    expect(within(flyout).getByRole("menuitem", { name: "Manage modules" })).toHaveAttribute("href", "/trials?module=ndr");
  });

  it("hides the MSSP entry for non-MSSP accounts", async () => {
    const me = makeMe();
    renderWithSession(<LeftRail />, { me: { ...me, account: { ...me.account, kind: "enterprise" } } });
    fireEvent.focus(screen.getByRole("link", { name: "Command Center" }));
    const flyout = screen.getByRole("menu", { name: "Command Center" });
    expect(within(flyout).queryByRole("menuitem", { name: "MSSP Command Center" })).not.toBeInTheDocument();
  });
});
