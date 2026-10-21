import { Apple, ArrowUpCircle, BookOpen, Download, Eye, EyeOff, KeyRound, LifeBuoy, Monitor, Plug, RefreshCw, ShieldCheck, Terminal } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useAgentAutoUpdate, useAgentEnrollment, useNativeAgentRelease, useRegenerateAccountKey, useSetAgentAutoUpdate, type NativeAgentRelease } from "../../api/hooks";
import type { AgentEnrollment } from "../../api/types";
import { useSession } from "../../app/session";
import { Button, ButtonLink, Card, CopyButton, Dialog, EmptyState, ErrorState, Input, PageHeader, Select, Skeleton, TabPanel, Tabs } from "../../components";
import { useDocumentTitle } from "../../hooks/useDocumentTitle";

export type AgentOs = "windows" | "macos" | "linux";
type Method = "manual" | "deploy";
type ToolKey = "intune" | "gpo" | "sccm" | "rmm" | "jamf" | "ansible";

const OS_TABS: Array<{ id: AgentOs; label: string }> = [
  { id: "windows", label: "Windows" },
  { id: "macos", label: "macOS" },
  { id: "linux", label: "Linux" },
];

interface Keys {
  url: string;
  accountKey: string;
  orgKey: string;
}

/** Single-quote for PowerShell / POSIX shells (keys are [A-Za-z0-9_-], this is belt and braces). */
const psq = (v: string) => `'${v.replace(/'/g, "''")}'`;
const shq = (v: string) => `'${v.replace(/'/g, `'"'"'`)}'`;

export function oneLiner(os: AgentOs, k: Keys): string {
  if (os === "windows") {
    return `Invoke-WebRequest -UseBasicParsing ${k.url}/api/v1/agent/install/windows -OutFile install-sciat.ps1; powershell -ExecutionPolicy Bypass -File .\\install-sciat.ps1 -AccountKey ${psq(k.accountKey)} -OrgKey ${psq(k.orgKey)}`;
  }
  return `curl -fsSL ${k.url}/api/v1/agent/install/${os} -o install-sciat.sh && sudo bash install-sciat.sh --account-key ${shq(k.accountKey)} --org-key ${shq(k.orgKey)}`;
}

/** Idempotent deployment script (skips machines that already run the agent) for RMM / MDM / GPO. */
export function deploymentScript(os: AgentOs, k: Keys): string {
  if (os === "windows") {
    return [
      "# SCIAT Agent deployment (run as SYSTEM / Administrator)",
      "$ErrorActionPreference = 'Stop'",
      "if (Get-Service -Name SCIATAgent -ErrorAction SilentlyContinue) { exit 0 }",
      "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12",
      "$installer = Join-Path $env:TEMP 'install-sciat.ps1'",
      `Invoke-WebRequest -UseBasicParsing -Uri '${k.url}/api/v1/agent/install/windows' -OutFile $installer`,
      `& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer -AccountKey ${psq(k.accountKey)} -OrgKey ${psq(k.orgKey)}`,
      "exit $LASTEXITCODE",
    ].join("\n");
  }
  const running = os === "macos" ? "launchctl print system/africa.sciat.agent >/dev/null 2>&1" : "systemctl is-active --quiet sciat-agent";
  return [
    "#!/bin/bash",
    "# SCIAT Agent deployment (run as root)",
    "set -e",
    `if ${running}; then exit 0; fi`,
    `curl -fsSL '${k.url}/api/v1/agent/install/${os}' -o /tmp/install-sciat.sh`,
    `bash /tmp/install-sciat.sh --account-key ${shq(k.accountKey)} --org-key ${shq(k.orgKey)}`,
  ].join("\n");
}

const scriptName = (os: AgentOs) => (os === "windows" ? "deploy-sciat-agent.ps1" : "deploy-sciat-agent.sh");

function downloadText(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function Snippet({ code, label }: { code: string; label: string }) {
  return (
    <div className="relative">
      <pre aria-label={label} className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded border border-line bg-canvas p-3 pr-20 font-mono text-xs leading-relaxed">
        {code}
      </pre>
      <div className="absolute right-2 top-2">
        <CopyButton value={code} />
      </div>
    </div>
  );
}

function Step({ n, title, children }: { n: number; title: ReactNode; children: ReactNode }) {
  return (
    <li className="flex gap-3">
      <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-brand text-xs font-semibold text-white">{n}</span>
      <div className="min-w-0 flex-1 space-y-2">
        <div className="font-medium">{title}</div>
        {children}
      </div>
    </li>
  );
}

const TOOLS: Array<{ key: ToolKey; label: string; os: AgentOs; steps: string[] }> = [
  {
    key: "intune",
    label: "Microsoft Intune",
    os: "windows",
    steps: [
      "Intune admin center → Devices → Scripts and remediations → Platform scripts → Add → Windows 10 and later.",
      "Upload the deployment script below.",
      "Run this script using the logged-on credentials: No. Enforce signature check: No. Run in 64-bit PowerShell: Yes.",
      "Assign it to the device group of this customer.",
    ],
  },
  {
    key: "gpo",
    label: "Group Policy (GPO)",
    os: "windows",
    steps: [
      "Copy the deployment script to a share every computer can read, e.g. \\\\domain\\NETLOGON\\deploy-sciat-agent.ps1.",
      "Group Policy Management → create a GPO linked to the computers' OU.",
      "Computer Configuration → Policies → Windows Settings → Scripts → Startup → PowerShell Scripts → add the script.",
      "Computers install the agent at the next restart (the script does nothing where the agent already runs).",
    ],
  },
  {
    key: "sccm",
    label: "Configuration Manager (SCCM)",
    os: "windows",
    steps: [
      "Software Library → Applications → Create Application → Manually specify; content: a folder with the deployment script.",
      "Installation program: powershell.exe -NoProfile -ExecutionPolicy Bypass -File deploy-sciat-agent.ps1",
      "Detection method: registry key HKLM\\SYSTEM\\CurrentControlSet\\Services\\SCIATAgent exists. Install for system.",
      "Deploy the application to the customer's device collection as Required.",
    ],
  },
  {
    key: "rmm",
    label: "Any RMM (NinjaOne, Datto, ConnectWise, Atera…)",
    os: "windows",
    steps: [
      "Add the deployment script to the RMM's script library (PowerShell for Windows, Bash for macOS / Linux).",
      "Run it as SYSTEM (Windows) or root (macOS / Linux) on the customer's devices — once, or as a recurring job.",
      "The script exits immediately on devices that already run the SCIAT Agent.",
    ],
  },
  {
    key: "jamf",
    label: "Jamf Pro",
    os: "macos",
    steps: [
      "Settings → Computer management → Scripts → New: paste the deployment script.",
      "Computers → Policies → New: add the script, trigger Recurring Check-in, frequency Once per computer.",
      "Scope the policy to the customer's computers.",
    ],
  },
  {
    key: "ansible",
    label: "Ansible",
    os: "linux",
    steps: ["Save the deployment script next to your playbook as deploy-sciat-agent.sh.", "Run the task below against the customer's Linux hosts with become: true."],
  },
];

function KeysPanel({ data, orgKey, setOrgKey }: { data: AgentEnrollment; orgKey: string; setOrgKey: (k: string) => void }) {
  const session = useSession();
  const [show, setShow] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [filter, setFilter] = useState("");
  const regenerate = useRegenerateAccountKey();
  const canRotate = session.can("settings:write", null);
  const orgs = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return q ? data.organizations.filter((o) => o.name.toLowerCase().includes(q) || o.key.includes(q)) : data.organizations;
  }, [data.organizations, filter]);
  const masked = `${data.accountKey.slice(0, 12)}${"•".repeat(16)}`;
  return (
    <Card title={<span className="inline-flex items-center gap-2"><KeyRound className="h-4 w-4" aria-hidden /> Get your keys</span>}>
      <div className="space-y-5 text-sm">
        <div className="space-y-2">
          <div className="font-medium">Account key</div>
          <p className="text-muted">Identifies your SCIAT account. Keep it private — anyone with it can add computers to your customers.</p>
          <div className="flex items-center gap-2">
            <code data-testid="account-key" className="min-w-0 flex-1 truncate rounded border border-line bg-canvas px-2 py-1.5 font-mono text-xs">
              {show ? data.accountKey : masked}
            </code>
            <Button size="sm" variant="ghost" onClick={() => setShow((v) => !v)} aria-label={show ? "Hide account key" : "Show account key"} icon={show ? EyeOff : Eye} />
            <CopyButton value={data.accountKey} />
          </div>
          {canRotate ? (
            <Button size="sm" variant="secondary" icon={RefreshCw} onClick={() => setConfirm(true)}>
              Regenerate
            </Button>
          ) : null}
        </div>
        <div className="space-y-2">
          <div className="font-medium">Organization key</div>
          <p className="text-muted">Chooses the customer the computer belongs to.</p>
          {data.organizations.length > 6 ? <Input aria-label="Search organizations" placeholder="Search organizations" value={filter} onChange={(e) => setFilter(e.target.value)} /> : null}
          <Select aria-label="Organization" value={orgKey} onChange={(e) => setOrgKey(e.target.value)}>
            {orgs.map((o) => (
              <option key={o.id} value={o.key}>
                {o.name} ({o.agents} {o.agents === 1 ? "agent" : "agents"})
              </option>
            ))}
          </Select>
          <div className="flex items-center gap-2">
            <code data-testid="org-key" className="min-w-0 flex-1 truncate rounded border border-line bg-canvas px-2 py-1.5 font-mono text-xs">
              {orgKey}
            </code>
            <CopyButton value={orgKey} />
          </div>
        </div>
      </div>
      <Dialog
        open={confirm}
        onClose={() => setConfirm(false)}
        title="Regenerate the account key?"
        description="Installed agents keep working. Deployment scripts and RMM / MDM jobs that use the old key stop enrolling new computers until you update them."
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirm(false)}>
              Cancel
            </Button>
            <Button variant="danger" loading={regenerate.isPending} onClick={() => regenerate.mutate(undefined, { onSuccess: () => setConfirm(false) })}>
              Regenerate key
            </Button>
          </>
        }
      >
        {regenerate.error ? <p className="text-sm text-danger">{regenerate.error.message}</p> : null}
      </Dialog>
    </Card>
  );
}

function ManualInstall({ os, keys }: { os: AgentOs; keys: Keys }) {
  const installer = `${keys.url}/api/v1/agent/install/${os}`;
  return (
    <ol className="space-y-5 text-sm">
      <Step n={1} title="Download the installer">
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="primary" icon={Download} onClick={() => downloadText(scriptName(os), deploymentScript(os, keys))}>
            Download script with your keys
          </Button>
          <a className="inline-flex items-center gap-1 rounded border border-line px-3 py-1.5 text-sm hover:bg-canvas" href={installer} download>
            Installer only ({os === "windows" ? "install-sciat.ps1" : "install-sciat.sh"})
          </a>
        </div>
      </Step>
      <Step n={2} title={os === "windows" ? "Run it in PowerShell as Administrator" : "Run it as root"}>
        <p className="text-muted">Or paste this one command on the computer — it downloads the installer and enrolls it with your keys:</p>
        <Snippet label="Install command" code={oneLiner(os, keys)} />
      </Step>
      <Step n={3} title="Confirm it checks in">
        <p className="text-muted">
          The computer appears under{" "}
          <Link to="/agents" className="font-medium text-brand hover:underline">
            Agents
          </Link>{" "}
          within a minute, running as the{" "}
          <span className="font-medium">{os === "windows" ? "“SCIAT Agent” Windows service" : os === "macos" ? "africa.sciat.agent launch daemon" : "sciat-agent systemd service"}</span>.
        </p>
      </Step>
    </ol>
  );
}

function DeploymentTools({ keys }: { keys: Keys }) {
  const [tool, setTool] = useState<ToolKey>("intune");
  const [rmmOs, setRmmOs] = useState<AgentOs>("windows");
  const def = TOOLS.find((t) => t.key === tool)!;
  const os = tool === "rmm" ? rmmOs : def.os;
  const script = deploymentScript(os, keys);
  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap gap-2" role="group" aria-label="Deployment tool">
        {TOOLS.map((t) => (
          <Button key={t.key} size="sm" variant={t.key === tool ? "primary" : "secondary"} aria-pressed={t.key === tool} onClick={() => setTool(t.key)}>
            {t.label}
          </Button>
        ))}
      </div>
      {tool === "rmm" ? <Tabs ariaLabel="Operating system" idPrefix="rmm-os" variant="boxed" tabs={OS_TABS} value={rmmOs} onChange={setRmmOs} /> : null}
      <ol className="list-decimal space-y-1 pl-5 text-muted">
        {def.steps.map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ol>
      <div className="flex items-center justify-between gap-2">
        <div className="font-medium">Deployment script ({os === "windows" ? "PowerShell" : "Bash"})</div>
        <Button size="sm" variant="secondary" icon={Download} onClick={() => downloadText(scriptName(os), script)}>
          Download {scriptName(os)}
        </Button>
      </div>
      <Snippet label="Deployment script" code={script} />
      {tool === "ansible" ? (
        <Snippet
          label="Ansible task"
          code={["- name: Install the SCIAT Agent", "  ansible.builtin.script: deploy-sciat-agent.sh", "  args:", "    creates: /etc/sciat-agent/agent.conf", "  become: true"].join("\n")}
        />
      ) : null}
    </div>
  );
}

/** Install command for the native binary (it enrolls and installs itself as a service). */
export function nativeInstallCommand(file: NativeAgentRelease["files"][number], k: Keys): string {
  const src = `${k.url}/api/v1/agent/download/${file.name}`;
  if (file.os === "windows") {
    return `Invoke-WebRequest -UseBasicParsing ${src} -OutFile sciat-agent.exe; .\\sciat-agent.exe install --url ${k.url} --account-key ${psq(k.accountKey)} --org-key ${psq(k.orgKey)}`;
  }
  return `curl -fsSLo sciat-agent ${src} && chmod +x sciat-agent && sudo ./sciat-agent install --url ${k.url} --account-key ${shq(k.accountKey)} --org-key ${shq(k.orgKey)}`;
}

const OS_LABEL = { windows: "Windows", linux: "Linux" } as const;
const ARCH_LABEL = { amd64: "Intel / AMD (x64)", arm64: "ARM64" } as const;

function NativeAgentCard({ keys }: { keys: Keys }) {
  const native = useNativeAgentRelease();
  const release = native.data?.release ?? null;
  const [pick, setPick] = useState<string | null>(null);
  if (native.isLoading) return <Skeleton className="h-40 w-full" />;
  if (!release) {
    return (
      <Card title={<span className="inline-flex items-center gap-2"><Download className="h-4 w-4" aria-hidden /> Native agent — preview</span>}>
        <div className="space-y-2 text-sm" data-testid="native-agent-missing">
          <p>This server has no native agent binaries (Windows and Linux) to offer yet.</p>
          <ul className="list-disc space-y-1 pl-5 text-xs text-muted">
            <li>The SCIAT API container image includes them — deploy or update the API image and they appear here.</li>
            <li>Running from source: build them with <code className="font-mono">scripts/build-agent.sh</code> (needs Go), then reload this page.</li>
            <li>Or point <code className="font-mono">BLOODY_AGENT_BINARIES_DIR</code> at a folder holding the binaries and their <code className="font-mono">SHA256SUMS</code>.</li>
          </ul>
        </div>
      </Card>
    );
  }
  const file = release.files.find((f) => f.name === pick) ?? release.files.find((f) => f.os === "windows" && f.arch === "amd64") ?? release.files[0]!;
  const mb = (n: number) => `${(n / 1_048_576).toFixed(1)} MB`;
  return (
    <Card title={<span className="inline-flex items-center gap-2"><Download className="h-4 w-4" aria-hidden /> Native agent {release.version} — preview</span>}>
      <div className="space-y-3 text-sm">
        <p className="rounded border border-sev-medium/40 bg-sev-medium/5 p-2 text-xs">
          For lab and test computers only: the binaries are not code-signed yet (Windows SmartScreen and antivirus may warn) and App Control blocking is not in the native agent yet. Customer computers keep
          the installer above.
        </p>
        <ul aria-label="Native agent downloads" className="divide-y divide-line rounded border border-line">
          {release.files.map((f) => (
            <li key={f.name} className="flex flex-wrap items-center gap-2 px-2.5 py-1.5">
              <label className="flex min-w-0 flex-1 items-center gap-2">
                <input type="radio" name="native-file" checked={f.name === file.name} onChange={() => setPick(f.name)} />
                <span className="font-medium">{OS_LABEL[f.os]}</span>
                <span className="text-xs text-fg-muted">{ARCH_LABEL[f.arch]} · {mb(f.size)}</span>
              </label>
              <a className="text-xs font-medium text-brand hover:underline" href={`/api/v1/agent/download/${encodeURIComponent(f.name)}`} download={f.name}>
                Download
              </a>
            </li>
          ))}
        </ul>
        <div>
          <div className="mb-1 text-xs font-medium text-fg-muted">SHA-256 of {file.name}</div>
          <div className="flex items-center gap-2">
            <code className="min-w-0 flex-1 truncate rounded border border-line bg-canvas px-2 py-1 font-mono text-2xs" title={file.sha256}>
              {file.sha256}
            </code>
            <CopyButton value={file.sha256} label="Copy checksum" />
          </div>
        </div>
        <div>
          <div className="mb-1 text-xs font-medium text-fg-muted">Install on {OS_LABEL[file.os]} ({file.os === "windows" ? "PowerShell as Administrator" : "as root"})</div>
          <Snippet label={`Install the native agent on ${OS_LABEL[file.os]}`} code={nativeInstallCommand(file, keys)} />
        </div>
        <p className="text-xs text-fg-muted">
          Enrolls the computer (or keeps the enrollment of an existing agent), installs itself as the SCIAT Agent service and checks in. Remove with <code>sciat-agent uninstall</code>.
        </p>
      </div>
    </Card>
  );
}

function AboutAgent({ version }: { version: string }) {
  const rows: Array<[string, ReactNode]> = [
    ["Version", version],
    ["Windows", <>Service “SCIAT Agent” (SCIATAgent) in C:\Program Files\SCIAT\Agent</>],
    ["macOS", <>Launch daemon africa.sciat.agent in /opt/sciat-agent</>],
    ["Linux", <>systemd service sciat-agent in /opt/sciat-agent</>],
    ["Check-in", "Every 60 seconds over HTTPS to this platform; backs off while offline"],
    ["Reports", "Host name, OS, IP addresses, uptime, isolation state and the security engines running beside it"],
    ["Updates", "Updates itself from this platform when automatic updates are on; every file is checked against its SHA-256 first"],
    ["Response", "Isolates the computer (LAN only or full) and releases it on command from the platform — Windows, macOS and Linux; this platform always stays reachable"],
  ];
  return (
    <Card title={<span className="inline-flex items-center gap-2"><ShieldCheck className="h-4 w-4" aria-hidden /> About the SCIAT Agent</span>}>
      <div className="space-y-3 text-sm">
        <p className="text-muted">
          A lightweight agent by SCIAT AFRICA that keeps each computer connected to your Command Center. Every computer gets its own credential; the account key is only used once, to enroll.
        </p>
        <dl className="grid grid-cols-[6rem_1fr] gap-x-3 gap-y-1.5">
          {rows.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-muted">{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
        <div className="space-y-1">
          <div className="font-medium">Uninstall</div>
          <Snippet label="Uninstall commands" code={"# Windows (Administrator)\npowershell -ExecutionPolicy Bypass -File .\\install-sciat.ps1 -Uninstall\n# macOS / Linux\nsudo bash install-sciat.sh --uninstall"} />
        </div>
      </div>
    </Card>
  );
}

/** Account-wide switch for automatic agent updates, with how many computers run each version. */
function AutoUpdateCard() {
  const session = useSession();
  const q = useAgentAutoUpdate();
  const set = useSetAgentAutoUpdate();
  const canChange = session.can("settings:write", null);
  if (!q.data) return null;
  const { enabled, latestVersion, versions } = q.data;
  const behind = versions.filter((v) => !v.current).reduce((n, v) => n + v.agents, 0);
  return (
    <Card title={<span className="inline-flex items-center gap-2"><ArrowUpCircle className="h-4 w-4" aria-hidden /> Automatic updates</span>}>
      <div className="space-y-3 text-sm">
        <label className="flex items-start gap-2">
          <input type="checkbox" className="mt-0.5" checked={enabled} disabled={set.isPending || !canChange} onChange={(e) => set.mutate(e.target.checked)} />
          <span>
            <span className="font-medium">Keep agents up to date</span>
            <span className="block text-muted">
              Agents older than {latestVersion} download the new version at their next check-in, verify every file's SHA-256 against the platform and restart themselves.
            </span>
          </span>
        </label>
        {!canChange ? <p className="text-fg-muted">An account administrator (settings:write) can change this.</p> : null}
        {set.error ? <p className="text-sev-critical">{set.error.message}</p> : null}
        {versions.length > 0 ? (
          <ul aria-label="Agent versions" className="space-y-1">
            {versions.map((v) => (
              <li key={v.version} className="flex justify-between">
                <span className="font-mono text-xs">
                  {v.version}
                  {v.current ? <span className="ml-2 font-sans text-healthy">latest</span> : null}
                </span>
                <span className="text-muted">
                  {v.agents} {v.agents === 1 ? "computer" : "computers"}
                </span>
              </li>
            ))}
          </ul>
        ) : null}
        {behind > 0 ? (
          <p className="text-muted">
            {behind} {behind === 1 ? "computer runs" : "computers run"} an older version{enabled ? " and will update at the next check-in." : ". Turn on automatic updates or reinstall to update."}
          </p>
        ) : null}
      </div>
    </Card>
  );
}

function Resources({ ingest }: { ingest: string }) {
  return (
    <Card title={<span className="inline-flex items-center gap-2"><BookOpen className="h-4 w-4" aria-hidden /> Helpful resources</span>}>
      <div className="space-y-3 text-sm">
        <div className="flex flex-wrap gap-2">
          <ButtonLink to="/agents" size="sm" variant="secondary" icon={Monitor}>
            Enrolled agents
          </ButtonLink>
          <ButtonLink to="/integrations" size="sm" variant="secondary" icon={Plug}>
            Engine integrations (Wazuh, Velociraptor…)
          </ButtonLink>
          <ButtonLink to="/settings/api-credentials" size="sm" variant="secondary" icon={KeyRound}>
            Ingest API keys
          </ButtonLink>
          <ButtonLink to="/support" size="sm" variant="secondary" icon={LifeBuoy}>
            Support &amp; FAQ
          </ButtonLink>
        </div>
        <details className="rounded border border-line p-3">
          <summary className="cursor-pointer font-medium">Send other engines' output straight to the platform</summary>
          <p className="my-2 text-muted">Raw output from Wazuh, Zeek, Suricata, Falco, osquery, OpenCanary, Trivy or Nuclei is normalized by its adapter. Use an organization ingest API key.</p>
          <Snippet label="Ingest example" code={`curl -X POST ${ingest}/suricata \\\n  -H "Authorization: Bearer <bk_… API key>" \\\n  -H "Content-Type: application/x-ndjson" \\\n  --data-binary @/var/log/suricata/eve.json`} />
        </details>
      </div>
    </Card>
  );
}

/** Install the SCIAT Agent: manual install or RMM / MDM / GPO deployment, with the account's keys. */
export function DownloadAgentPage() {
  useDocumentTitle("Download agent");
  const session = useSession();
  const allowed = session.can("asset:write", null);
  const enrollment = useAgentEnrollment({ enabled: allowed });
  const [method, setMethod] = useState<Method>("manual");
  const [os, setOs] = useState<AgentOs>("windows");
  const [picked, setPicked] = useState<string | null>(null);
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  const data = enrollment.data;
  const orgKey = picked ?? data?.organizations[0]?.key ?? "";
  const keys: Keys | null = data ? { url: origin, accountKey: data.accountKey, orgKey } : null;

  let body: ReactNode;
  if (!allowed) {
    body = <EmptyState icon={KeyRound} title="You can't deploy agents" description="Installing agents needs the asset:write permission for the whole account. Ask an administrator." />;
  } else if (enrollment.isLoading) {
    body = <Skeleton className="h-64 w-full" />;
  } else if (enrollment.error || !data || !keys) {
    body = <ErrorState title="Could not load your agent keys" error={enrollment.error} onRetry={() => void enrollment.refetch()} />;
  } else if (data.organizations.length === 0) {
    body = <EmptyState icon={Monitor} title="Create an organization first" description="Agents are enrolled into a customer organization." action={<ButtonLink to="/organizations" variant="primary" size="sm">Organizations</ButtonLink>} />;
  } else {
    body = (
      <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="space-y-4">
          <Card title="Installation method">
            <Tabs
              ariaLabel="Installation method"
              idPrefix="method"
              tabs={[
                { id: "manual", label: "Manual installation", icon: Terminal },
                { id: "deploy", label: "RMM / MDM / GPO", icon: Plug },
              ]}
              value={method}
              onChange={setMethod}
            />
            <div className="pt-4">
              {method === "manual" ? (
                <TabPanel id="manual" idPrefix="method" className="space-y-4">
                  <Tabs ariaLabel="Operating system" idPrefix="os" variant="boxed" tabs={OS_TABS.map((t) => ({ ...t, icon: t.id === "macos" ? Apple : Monitor }))} value={os} onChange={setOs} />
                  <ManualInstall os={os} keys={keys} />
                </TabPanel>
              ) : (
                <TabPanel id="deploy" idPrefix="method">
                  <DeploymentTools keys={keys} />
                </TabPanel>
              )}
            </div>
          </Card>
          <Resources ingest={`${origin}/api/v1/ingest`} />
        </div>
        <div className="space-y-4">
          <KeysPanel data={data} orgKey={orgKey} setOrgKey={setPicked} />
          <AboutAgent version={data.agentVersion} />
          <NativeAgentCard keys={keys} />
          <AutoUpdateCard />
        </div>
      </div>
    );
  }
  return (
    <div className="space-y-4">
      <PageHeader title="Install the SCIAT Agent" subtitle="Protect a customer's computers: pick how to install, then use your account and organization keys." />
      {body}
    </div>
  );
}
