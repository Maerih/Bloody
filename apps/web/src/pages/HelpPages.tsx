import { BookOpen, Download, FlaskConical, LifeBuoy, MessageSquare } from "lucide-react";
import { useState, type ReactNode } from "react";
import { ButtonLink, Card, CopyButton, Field, PageHeader, Textarea } from "../components";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

function Snippet({ code }: { code: string }) {
  return (
    <div className="relative">
      <pre className="overflow-x-auto rounded border border-line bg-canvas p-3 font-mono text-xs leading-relaxed">{code}</pre>
      <div className="absolute right-2 top-2">
        <CopyButton value={code} />
      </div>
    </div>
  );
}

function Section({ title, children }: { title: ReactNode; children: ReactNode }) {
  return (
    <Card title={title}>
      <div className="space-y-3 text-sm">{children}</div>
    </Card>
  );
}

/** Agent / collector deployment: every engine ships to Bloody's ingest API with an organization API key. */
export function DownloadAgentPage() {
  useDocumentTitle("Download agent");
  const origin = typeof window !== "undefined" ? window.location.origin : "https://bloody.example";
  const ingest = `${origin}/api/v1/ingest`;
  return (
    <div className="space-y-4">
      <PageHeader title="Deploy agents & collectors" subtitle="Bloody collects through open-source engines. Each one sends to your tenant's ingest API with an organization API key." actions={<ButtonLink to="/settings/api-credentials" variant="primary" size="sm">Create an ingest API key</ButtonLink>} />
      <div className="grid gap-4 xl:grid-cols-2">
        <Section title={<span className="inline-flex items-center gap-2"><Download className="h-4 w-4" aria-hidden /> Endpoints — Wazuh agent</span>}>
          <p className="text-muted">Install the Wazuh agent pointing at your Wazuh manager; the manager's alerts are forwarded to Bloody by Vector.</p>
          <Snippet code={`# Linux (Debian/Ubuntu)\ncurl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.2-1_amd64.deb\nsudo WAZUH_MANAGER='<wazuh-manager-ip>' dpkg -i ./wazuh-agent.deb\nsudo systemctl enable --now wazuh-agent`} />
          <Snippet code={`# Windows (PowerShell, as Administrator)\nInvoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi -OutFile wazuh-agent.msi\nmsiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER='<wazuh-manager-ip>'\nNET START WazuhSvc`} />
        </Section>
        <Section title="Send any engine's output straight to Bloody">
          <p className="text-muted">Raw engine output (Wazuh, Zeek, Suricata, Falco, osquery, OpenCanary, Trivy, Nuclei…) is normalized server-side by its adapter.</p>
          <Snippet code={`curl -X POST ${ingest}/suricata \\\n  -H "Authorization: Bearer <bk_… API key>" \\\n  -H "Content-Type: application/x-ndjson" \\\n  --data-binary @/var/log/suricata/eve.json`} />
          <p className="text-muted">Production collectors (Vector / OpenTelemetry Collector) are preconfigured in <span className="font-mono">infra/engines/</span>.</p>
        </Section>
      </div>
    </div>
  );
}

export function DemoSandboxPage() {
  useDocumentTitle("Demo sandbox");
  return (
    <div className="space-y-4">
      <PageHeader title="Demo sandbox" subtitle="Explore a fully configured MSSP tenant without installing anything." />
      <Section title={<span className="inline-flex items-center gap-2"><FlaskConical className="h-4 w-4" aria-hidden /> What's in the demo tenant</span>}>
        <ul className="list-disc space-y-1 pl-5 text-muted">
          <li>An MSSP account with three customer organizations, analysts and customer-side users.</li>
          <li>Assets, agents, identities, vulnerabilities (incl. known-exploited) and threat-intel indicators.</li>
          <li>~1,000 events processed by the real detection, correlation, graph and risk engines — producing the incidents, escalations and attack paths you see.</li>
        </ul>
        <div className="flex flex-wrap gap-2">
          <ButtonLink to="/" size="sm">Command Center</ButtonLink>
          <ButtonLink to="/mssp" size="sm">MSSP view</ButtonLink>
          <ButtonLink to="/attack-paths" size="sm">Attack paths</ButtonLink>
          <ButtonLink to="/simulate" variant="primary" size="sm">Simulate an incident</ButtonLink>
        </div>
      </Section>
    </div>
  );
}

export function SupportPage() {
  useDocumentTitle("Support & FAQ");
  const faqs: [string, string][] = [
    ["Which engines power a module?", "Customers see modules (EDR, NDR, SIEM…). The engine behind each is listed in Integrations → Hub, with its licence."],
    ["How do I connect a local AI model?", "Settings → AI Models & Policies → Add provider → Ollama (http://<host>:11434) or any OpenAI-compatible endpoint."],
    ["Why is an action waiting for approval?", "High-risk response actions (isolate, block, disable identity) always need a second person with response:approve."],
    ["How are customers kept apart?", "Every record is scoped to a tenant and organization and enforced again by database row-level security."],
  ];
  return (
    <div className="space-y-4">
      <PageHeader title="Support & FAQ" />
      <Section title={<span className="inline-flex items-center gap-2"><LifeBuoy className="h-4 w-4" aria-hidden /> Frequently asked</span>}>
        <dl className="space-y-3">
          {faqs.map(([q, a]) => (
            <div key={q}>
              <dt className="font-medium">{q}</dt>
              <dd className="text-muted">{a}</dd>
            </div>
          ))}
        </dl>
      </Section>
      <Section title={<span className="inline-flex items-center gap-2"><BookOpen className="h-4 w-4" aria-hidden /> Documentation</span>}>
        <p className="text-muted">Architecture, operations, MSSP workflows and licence inventory ship with the platform under <span className="font-mono">docs/</span>.</p>
      </Section>
    </div>
  );
}

export function FeedbackPage() {
  useDocumentTitle("Feedback");
  const [text, setText] = useState("");
  const mailto = `mailto:feedback@bloody.local?subject=${encodeURIComponent("Bloody feedback")}&body=${encodeURIComponent(text)}`;
  return (
    <div className="space-y-4">
      <PageHeader title="Feedback" subtitle="Tell the product team what to improve." />
      <Section title={<span className="inline-flex items-center gap-2"><MessageSquare className="h-4 w-4" aria-hidden /> Your feedback</span>}>
        <Field label="Message">{(f) => <Textarea {...f} rows={6} value={text} onChange={(e) => setText(e.target.value)} maxLength={5000} />}</Field>
        <a className={`inline-flex rounded bg-brand px-3 py-1.5 text-sm font-medium text-white ${text.trim() ? "" : "pointer-events-none opacity-50"}`} href={mailto}>
          Send by e-mail
        </a>
      </Section>
    </div>
  );
}
