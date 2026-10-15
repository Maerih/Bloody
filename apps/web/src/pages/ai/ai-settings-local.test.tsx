import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { makeMe, makeSummary } from "../../test/fixtures";
import { mockApi, renderApp } from "../../test/utils";

describe("AI settings — local models toggle", () => {
  it("shows the current setting and lets an admin enable private endpoints", async () => {
    const mock = mockApi({
      "/auth/me": makeMe(),
      "/command-center/summary": makeSummary(),
      "/ai/providers": { items: [], nextCursor: null },
      "/ai/settings": { allowPrivateEndpoints: false, effectiveAllowPrivateEndpoints: false, enforcedByDeployment: false },
      "PATCH /ai/settings": { allowPrivateEndpoints: true, effectiveAllowPrivateEndpoints: true, enforcedByDeployment: false },
    });
    renderApp("/settings/ai");
    const box = await screen.findByRole("checkbox", { name: /private and loopback addresses/i });
    expect(box).not.toBeChecked();
    fireEvent.click(box);
    await waitFor(() => expect(box).toBeChecked());
    const call = mock.calls.find((c) => c.method === "PATCH" && c.path === "/ai/settings");
    expect(call?.body).toEqual({ allowPrivateEndpoints: true });
  });
});
