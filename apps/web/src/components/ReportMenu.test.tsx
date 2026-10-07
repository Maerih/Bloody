import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { makeMe, ORG_A } from "../test/fixtures";
import { mockApi, renderWithSession } from "../test/utils";
import { ReportMenu } from "./ReportMenu";
import { buildCron, isValidCron } from "./ScheduleReportDialog";

describe("ReportMenu", () => {
  it("generates and downloads a report for the selected scope", async () => {
    const { calls } = mockApi({
      "POST /reports/generate": { status: 200, body: { ok: true }, headers: { "content-disposition": 'attachment; filename="exec.pdf"' } },
    });
    const createObjectURL = vi.fn(() => "blob:report");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);

    renderWithSession(<ReportMenu reports={["executive", "soc_operations"]} defaultReport="executive" periodDays={30} />, { route: `/?org=${ORG_A}` });
    fireEvent.click(screen.getByRole("button", { name: "Report" }));
    fireEvent.change(screen.getByLabelText("Format"), { target: { value: "csv" } });
    fireEvent.click(screen.getByRole("button", { name: /Generate & download/ }));

    await waitFor(() => expect(click).toHaveBeenCalled());
    const call = calls.find((c) => c.path === "/reports/generate")!;
    expect(call.method).toBe("POST");
    expect(call.body).toEqual({ type: "executive", format: "csv", organizationId: ORG_A, periodDays: 30 });
    expect(createObjectURL).toHaveBeenCalled();
    click.mockRestore();
  });

  it("schedules email delivery to a notification channel", async () => {
    const { calls } = mockApi({
      "/notifications/channels": [
        { id: "ch-1", tenantId: "t", organizationId: null, name: "SOC leadership", kind: "email", config: { to: ["a@x.test", "b@x.test"] }, enabled: true },
      ],
      "POST /reports/schedules": { id: "s1" },
    });
    renderWithSession(<ReportMenu reports={["executive"]} defaultReport="executive" />);
    fireEvent.click(screen.getByRole("button", { name: "Report" }));
    fireEvent.click(screen.getByRole("button", { name: /Schedule email delivery/ }));
    const dialog = await screen.findByRole("dialog", { name: "Schedule report delivery" });
    expect(await within(dialog).findByText("2 recipients")).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("checkbox", { name: /SOC leadership/ }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Create schedule" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/reports/schedules")).toBe(true));
    const body = calls.find((c) => c.path === "/reports/schedules" && c.method === "POST")!.body as Record<string, unknown>;
    expect(body).toMatchObject({ type: "executive", cron: "0 7 * * 1", format: "pdf", channelIds: ["ch-1"], organizationId: null, enabled: true });
  });

  it("requires a delivery channel before scheduling", async () => {
    const { calls } = mockApi({ "/notifications/channels": [{ id: "ch-1", tenantId: "t", organizationId: null, name: "SOC", kind: "slack", config: {}, enabled: true }] });
    renderWithSession(<ReportMenu reports={["soc_operations"]} />);
    fireEvent.click(screen.getByRole("button", { name: "Report" }));
    fireEvent.click(screen.getByRole("button", { name: /Schedule email delivery/ }));
    const dialog = await screen.findByRole("dialog", { name: "Schedule report delivery" });
    await within(dialog).findByRole("checkbox", { name: /SOC/ });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create schedule" }));
    expect(await within(dialog).findByText("Choose at least one delivery channel")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("is hidden without report:read", () => {
    mockApi({});
    const { container } = renderWithSession(<ReportMenu reports={["executive"]} />, {
      me: makeMe({ bindings: [{ role: "api_service", organizationId: null }] }),
    });
    expect(container).toBeEmptyDOMElement();
  });
});

describe("cron helpers", () => {
  it("builds schedule expressions", () => {
    expect(buildCron("daily", "07:30", 1, 1, "")).toBe("30 7 * * *");
    expect(buildCron("weekdays", "08:00", 1, 1, "")).toBe("0 8 * * 1-5");
    expect(buildCron("weekly", "06:00", 5, 1, "")).toBe("0 6 * * 5");
    expect(buildCron("monthly", "06:00", 1, 15, "")).toBe("0 6 15 * *");
    expect(isValidCron("0 7 * * 1")).toBe(true);
    expect(isValidCron("0 7 * *")).toBe(false);
    expect(isValidCron("rm -rf / * * *")).toBe(false);
  });
});
