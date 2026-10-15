import { afterEach, describe, expect, it, vi } from "vitest";
import { copyText } from "./clipboard";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("copyText", () => {
  it("falls back to execCommand on plain HTTP (no navigator.clipboard)", async () => {
    vi.stubGlobal("navigator", { ...navigator, clipboard: undefined });
    let copied = "";
    document.execCommand = vi.fn(() => {
      copied = (document.activeElement as HTMLTextAreaElement).value;
      return true;
    }) as typeof document.execCommand;
    expect(await copyText("curl -fsSL https://192.168.1.3:5173/agent | sudo bash")).toBe(true);
    expect(copied).toBe("curl -fsSL https://192.168.1.3:5173/agent | sudo bash");
    expect(document.querySelectorAll("textarea")).toHaveLength(0);
  });

  it("uses the async clipboard API in a secure context, and falls back when it is refused", async () => {
    vi.stubGlobal("isSecureContext", true);
    const writeText = vi.fn().mockRejectedValue(new Error("denied"));
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
    document.execCommand = vi.fn(() => false) as typeof document.execCommand;
    expect(await copyText("x")).toBe(false);
    expect(writeText).toHaveBeenCalledWith("x");
    writeText.mockResolvedValue(undefined);
    expect(await copyText("y")).toBe(true);
  });
});
