/** The guided product tour: one feature at a time, page by page. */
export interface TourStep {
  path: string;
  /** data-tour target on the page; the step is centred when the element is not on screen. */
  target: string;
  title: string;
  body: string;
}

export const TOUR_STEPS: TourStep[] = [
  { path: "/", target: "page-header", title: "Welcome to the SCIAT Command Center", body: "This is the live picture across every customer you protect: active incidents, escalations waiting on customers, exposure and agent health — all in one place." },
  { path: "/", target: "module-rail", title: "Every security module, one click away", body: "EDR, ITDR, NDR, SIEM, XDR, attack-surface and posture management, threat intel, DFIR and SOAR each have their own workspace here. Hover an icon to see what's inside." },
  { path: "/", target: "search", title: "Search anything", body: "Find any host, user, IP, incident or page instantly. Press Ctrl + K anywhere to open the command palette." },
  { path: "/incidents", target: "page-header", title: "Incidents", body: "Alerts from every engine are correlated into incidents with a risk score that explains itself. Open one to investigate, assign it, or respond." },
  { path: "/escalations", target: "page-header", title: "Customer escalations", body: "When the customer needs to act — reset a password, approve a change — SCIAT tracks it here with a due time, and reminds everyone when it is overdue." },
  { path: "/agents", target: "page-header", title: "Agents & one-click isolation", body: "Every endpoint running the SCIAT Agent. Isolate a compromised computer from the network (LAN-only or full), then release it — with approvals, or immediately in an emergency." },
  { path: "/agents/download", target: "page-header", title: "Deploy the SCIAT Agent", body: "Install on Windows, macOS or Linux by hand, or roll it out with Intune, Group Policy, SCCM, Jamf, Ansible or any RMM. Your account and organization keys are on the right." },
  { path: "/assets", target: "page-header", title: "Assets & host inventory", body: "Every device, its risk and vulnerabilities. Open one to see its installed software, services, users, running processes, open ports, antivirus and firewall." },
  { path: "/edr/antivirus", target: "page-header", title: "Managed antivirus", body: "Which antivirus each endpoint runs, and whether it is on, up to date and tamper-protected. You are alerted the moment protection is switched off." },
  { path: "/espm/app-control", target: "page-header", title: "App Control", body: "Decide which programs may run. Start in Audit mode to see what would be stopped, then Enforce — the SCIAT Agent stops blocked programs on every computer." },
  { path: "/itdr/m365", target: "page-header", title: "Microsoft 365 hardening", body: "Connect a customer's Microsoft 365 tenant (read-only) and get a hardening score against CISA and CIS, with step-by-step fixes for every gap." },
  { path: "/graph", target: "page-header", title: "Security graph", body: "See how users, devices, processes and threats connect. Expand any node to follow an attacker's path." },
  { path: "/attack-paths", target: "page-header", title: "Attack paths", body: "The routes an attacker could take to your crown jewels — and the one fix that breaks the most of them." },
  { path: "/soar/approvals", target: "page-header", title: "Automation & approvals", body: "Playbooks respond automatically; risky actions wait here for a second person to approve. Every decision is recorded in the audit log." },
  { path: "/reports", target: "page-header", title: "Reports", body: "Executive, SOC and customer reports — on demand or on a schedule, delivered by email." },
  { path: "/", target: "help", title: "That's the tour", body: "You can restart it any time from Help → Demo Sandbox. Explore freely — nothing here can be changed." },
];
