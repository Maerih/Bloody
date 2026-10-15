import { BookOpen, FlaskConical, LifeBuoy, MessageSquare } from "lucide-react";
import { useState, type ReactNode } from "react";
import { ButtonLink, Card, Field, PageHeader, Textarea } from "../components";
import { useDocumentTitle } from "../hooks/useDocumentTitle";

function Section({ title, children }: { title: ReactNode; children: ReactNode }) {
  return (
    <Card title={title}>
      <div className="space-y-3 text-sm">{children}</div>
    </Card>
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
