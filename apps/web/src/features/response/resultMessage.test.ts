import { describe, expect, it } from "vitest";
import { resultMessage } from "./RequestActionDialog";

describe("request result message", () => {
  it("tells the analyst where the action went", () => {
    expect(resultMessage({ status: "running", executor: "sciat:agent" })).toMatch(/^Sent to the SCIAT Agent/);
    expect(resultMessage({ status: "running", executor: "sciat:agent", emergency: true })).toMatch(/second responder must review/);
    expect(resultMessage({ status: "succeeded", emergency: true })).toBe("Done — executed as an emergency. A second responder must review it.");
    expect(resultMessage({ status: "pending_approval" })).toBe("Submitted — waiting in the approval queue.");
    expect(resultMessage({ status: "failed", error: { message: "No enabled integration" } })).toBe("Failed — No enabled integration");
  });
});
