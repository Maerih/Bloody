import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeMe, makeSummary } from "../../test/fixtures";
import { getLocation, mockApi, renderApp, renderWithSession } from "../../test/utils";
import { DemoSandboxPage } from "./DemoSandboxPage";
import { SandboxBanner } from "./SandboxBanner";
import { TourProvider } from "./Tour";
import { TOUR_STEPS } from "./tourSteps";

const assign = vi.fn();
beforeEach(() => {
  assign.mockReset();
  Object.defineProperty(window, "location", { configurable: true, value: { ...window.location, assign } });
  window.localStorage.removeItem("sciat.tour");
});
afterEach(() => window.localStorage.removeItem("sciat.tour"));

const sandboxMe = () => ({ ...makeMe(), session: { id: "s1", method: "sandbox" as const, mfaVerified: true } });

describe("Demo sandbox", () => {
  it("shows the exploring banner only in the sandbox, and returns to the user's account", async () => {
    const { calls } = mockApi({ "POST /sandbox/exit": { restored: true } });
    const { unmount } = renderWithSession(
      <TourProvider steps={[]}>
        <SandboxBanner />
      </TourProvider>,
    );
    expect(screen.queryByRole("region", { name: "Demo sandbox" })).toBeNull();
    unmount();
    renderWithSession(
      <TourProvider steps={[]}>
        <SandboxBanner />
      </TourProvider>,
      { me: sandboxMe() },
    );
    const banner = screen.getByRole("region", { name: "Demo sandbox" });
    expect(banner).toHaveTextContent("Currently exploring the SCIAT Demo Sandbox");
    fireEvent.click(within(banner).getByRole("button", { name: /Return to My Account/ }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/"));
    expect(calls.some((c) => c.method === "POST" && c.path === "/sandbox/exit")).toBe(true);
  });

  it("enters the sandbox and queues the guided tour", async () => {
    const { calls } = mockApi({ "/sandbox": { available: true, accountName: "SCIAT AFRICA", inSandbox: false }, "POST /sandbox/enter": { ok: true } });
    renderWithSession(
      <TourProvider steps={[]}>
        <DemoSandboxPage />
      </TourProvider>,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Enter the Demo Sandbox" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/"));
    expect(calls.some((c) => c.method === "POST" && c.path === "/sandbox/enter")).toBe(true);
    expect(window.localStorage.getItem("sciat.tour")).toBe("0");
  });

  it("walks through the tour page by page; Back, Next and Skip work", async () => {
    mockApi({ "/auth/me": makeMe(), "/command-center/summary": makeSummary() });
    window.localStorage.setItem("sciat.tour", "0");
    renderApp("/");
    const dialog = await screen.findByRole("dialog", { name: "Product tour" });
    expect(within(dialog).getByText(`Step 1 of ${TOUR_STEPS.length}`)).toBeInTheDocument();
    expect(within(dialog).getByText(TOUR_STEPS[0]!.title)).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: "Back" })).toBeNull();
    fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    expect(await screen.findByText(TOUR_STEPS[1]!.title)).toBeInTheDocument();
    expect(window.localStorage.getItem("sciat.tour")).toBe("1");
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(await screen.findByText(TOUR_STEPS[0]!.title)).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole("button", { name: "Skip tour" })[0]!);
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Product tour" })).toBeNull());
    expect(window.localStorage.getItem("sciat.tour")).toBeNull();
  });

  it("moves to the next feature's page", async () => {
    mockApi({ "/auth/me": makeMe(), "/command-center/summary": makeSummary(), "/incidents": { items: [], nextCursor: null } });
    window.localStorage.setItem("sciat.tour", "2");
    renderApp("/");
    const dialog = await screen.findByRole("dialog", { name: "Product tour" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    const next = await screen.findByRole("dialog", { name: "Product tour" });
    await waitFor(() => expect(within(next).getByText(`Step 4 of ${TOUR_STEPS.length}`)).toBeInTheDocument());
    expect(TOUR_STEPS[3]!.path).toBe("/incidents");
    await waitFor(() => expect(getLocation().pathname).toBe("/incidents"));
  });
});

describe("tour placement", () => {
  it("goes below, above, beside a tall rail, or centred", async () => {
    const { placement } = await import("./Tour");
    expect(placement({ top: 100, left: 80, width: 600, height: 80 }, 360, 200, 12, 1400, 900)).toMatchObject({ top: 192, left: 80 });
    expect(placement({ top: 700, left: 80, width: 600, height: 120 }, 360, 200, 12, 1400, 900)).toMatchObject({ top: 488 });
    expect(placement({ top: 44, left: 0, width: 60, height: 856 }, 360, 200, 12, 1400, 900)).toMatchObject({ left: 72, top: 44 });
    expect(placement(null, 360, 200, 12, 1400, 900)).toMatchObject({ left: "50%" });
  });
});
