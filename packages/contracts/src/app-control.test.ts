import { describe, expect, it } from "vitest";
import { AppControlRuleInput, blocksProtected, decideProgram, wildcardMatch } from "./app-control.js";

const rule = (id: string, action: "allow" | "block", kind: "name" | "path" | "sha256" | "publisher", value: string, platform: "any" | "windows" | "linux" = "any") => ({ id, action, kind, value, platform });

describe("app control", () => {
  it("matches wildcards case-insensitively and literally otherwise", () => {
    expect(wildcardMatch("C:\\Users\\*\\AppData\\*\\AnyDesk.exe", "c:\\users\\amina\\appdata\\local\\anydesk.exe")).toBe(true);
    expect(wildcardMatch("any?desk.exe", "anyXdesk.exe")).toBe(false); // only * is special
    expect(wildcardMatch("team*.exe", "TeamViewer.exe")).toBe(true);
  });

  it("allow beats block; audit reports, enforce blocks; platforms and protected programs respected", () => {
    const rules = [rule("b1", "block", "name", "anydesk.exe"), rule("a1", "allow", "path", "C:\\Program Files\\Helpdesk\\anydesk.exe"), rule("b2", "block", "name", "nc", "linux")];
    const p = { name: "AnyDesk.exe", path: "C:\\Users\\x\\Downloads\\AnyDesk.exe" };
    expect(decideProgram({ mode: "enforce", rules }, "windows", p)).toEqual({ verdict: "blocked", ruleId: "b1" });
    expect(decideProgram({ mode: "audit", rules }, "windows", p)).toEqual({ verdict: "audited", ruleId: "b1" });
    expect(decideProgram({ mode: "off", rules }, "windows", p).verdict).toBe("none");
    expect(decideProgram({ mode: "enforce", rules }, "windows", { name: "anydesk.exe", path: "C:\\Program Files\\Helpdesk\\anydesk.exe" })).toEqual({ verdict: "allowed", ruleId: "a1" });
    expect(decideProgram({ mode: "enforce", rules }, "windows", { name: "nc", path: "/usr/bin/nc" }).verdict).toBe("none");
    expect(decideProgram({ mode: "enforce", rules }, "linux", { name: "nc", path: "/usr/bin/nc" }).verdict).toBe("blocked");
    expect(decideProgram({ mode: "enforce", rules: [rule("h", "block", "sha256", "AB".repeat(32))] }, "linux", { name: "x", sha256: "ab".repeat(32) }).verdict).toBe("blocked");
    expect(decideProgram({ mode: "enforce", rules: [rule("w", "block", "name", "*")] }, "linux", { name: "sshd", path: "/usr/sbin/sshd" }).verdict).toBe("none");
  });

  it("refuses rules that would stop core processes or are malformed", () => {
    expect(blocksProtected("name", "lsass.exe")).toBe(true);
    expect(blocksProtected("name", "*")).toBe(true);
    expect(blocksProtected("path", "C:\\Windows\\System32\\svchost.exe")).toBe(true);
    expect(blocksProtected("name", "anydesk.exe")).toBe(false);
    const ok = (v: object) => AppControlRuleInput.safeParse({ organizationId: null, action: "block", kind: "name", value: "anydesk.exe", ...v }).success;
    expect(ok({})).toBe(true);
    expect(ok({ value: "LSASS.EXE" })).toBe(false);
    expect(ok({ action: "allow", value: "lsass.exe" })).toBe(true);
    expect(ok({ kind: "sha256", value: "1234" })).toBe(false);
    expect(ok({ value: "C:\\x\\anydesk.exe" })).toBe(false);
    expect(ok({ value: 'bad"quote' })).toBe(false);
  });
});
