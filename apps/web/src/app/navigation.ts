import {
  Activity,
  AppWindow,
  Archive,
  BadgeCheck,
  Binoculars,
  Blocks,
  Bot,
  BrainCircuit,
  Bug,
  Building2,
  Cable,
  CalendarClock,
  ChartLine,
  ChartPie,
  CircleAlert,
  ClipboardCheck,
  ClipboardList,
  Clock,
  Cloud,
  CloudCog,
  Code,
  Container,
  CreditCard,
  Crosshair,
  Crown,
  Database,
  Download,
  Earth,
  FileSearch,
  FileText,
  Fingerprint,
  FlaskConical,
  FolderLock,
  Gauge,
  Ghost,
  Globe,
  GlobeLock,
  Handshake,
  HardDrive,
  History,
  House,
  IdCard,
  Inbox,
  KeyRound,
  Layers,
  LayoutDashboard,
  LifeBuoy,
  ListChecks,
  LogOut,
  Mail,
  MailWarning,
  MessageSquare,
  MessagesSquare,
  Microscope,
  Monitor,
  MonitorSmartphone,
  Network,
  Package,
  Plug,
  Puzzle,
  Radar,
  Radio,
  Route,
  Rss,
  Satellite,
  ScanSearch,
  ScrollText,
  Search,
  Send,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldHalf,
  Sigma,
  Siren,
  Skull,
  SlidersHorizontal,
  Sparkles,
  SquareTerminal,
  Target,
  Terminal,
  Timer,
  UserCog,
  UserRound,
  UserX,
  Users,
  UsersRound,
  Waypoints,
  Webhook,
  Workflow,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import type { ModuleKey, Permission } from "@bloody/contracts";

/**
 * Single source of truth for navigation: top bar, left rail + flyouts, hamburger menu,
 * command palette "Pages" results and the placeholder route table all derive from here.
 * Part B adds real pages by registering routes; it should not need to touch this file except
 * to add/rename sub-pages.
 */

export interface NavItem {
  label: string;
  path: string;
  icon: LucideIcon;
  description?: string;
  permission?: Permission;
  /** Open in a new tab (external URL). */
  external?: boolean;
  keywords?: string[];
}

export interface RailModule {
  id: string;
  /** Tiny uppercase rail label. */
  short: string;
  /** Flyout heading / page title. */
  name: string;
  path: string;
  icon: LucideIcon;
  /** Licensable module (null = always available: Home, Trials, Hub). */
  module: ModuleKey | null;
  description: string;
  items: NavItem[];
}

export const TOP_NAV: NavItem[] = [
  { label: "Organizations", path: "/organizations", icon: Building2, permission: "org:read", description: "Customer organizations and business units" },
  { label: "Assets", path: "/assets", icon: Server, permission: "asset:read", description: "Endpoints, servers, cloud and external assets" },
  { label: "Incidents", path: "/incidents", icon: Siren, permission: "incident:read", description: "Correlated incidents across every module" },
  { label: "Investigations", path: "/investigations", icon: Search, permission: "investigation:read", description: "Investigation workspaces: timeline, evidence, graph" },
  { label: "Escalations", path: "/escalations", icon: CircleAlert, permission: "escalation:read", description: "Items requiring customer or analyst action" },
  { label: "Reports", path: "/reports", icon: FileText, permission: "report:read", description: "Executive, SOC, MSSP and customer reports, schedules and email delivery" },
  { label: "Users", path: "/users", icon: Users, permission: "user:read", description: "Users, teams and role bindings" },
  { label: "Integrations", path: "/integrations", icon: Plug, permission: "integration:read", description: "Connected engines, identity providers and data sources" },
  { label: "AI SOC", path: "/ai", icon: Sparkles, permission: "ai:use", description: "AI analyst: investigate, hunt, explain and recommend" },
];

export const RAIL_MODULES: RailModule[] = [
  {
    id: "home",
    short: "Home",
    name: "Command Center",
    path: "/",
    icon: House,
    module: null,
    description: "Unified operational view across every module and organization.",
    items: [
      { label: "Command Center", path: "/", icon: LayoutDashboard, description: "Role-aware unified dashboard" },
      { label: "MSSP Command Center", path: "/mssp", icon: Building2, description: "Portfolio view across customer organizations", keywords: ["portfolio", "customers"] },
      { label: "Incidents", path: "/incidents", icon: Siren, permission: "incident:read" },
      { label: "Escalations", path: "/escalations", icon: CircleAlert, permission: "escalation:read" },
    ],
  },
  {
    id: "edr",
    short: "EDR",
    name: "Endpoint Detection & Response",
    path: "/edr",
    icon: ChartLine,
    module: "edr",
    description: "Endpoint telemetry, behavioural detection, live response and containment.",
    items: [
      { label: "EDR Dashboard", path: "/edr", icon: ChartLine, description: "Endpoint detections, coverage and health" },
      { label: "Persistent Footholds", path: "/edr/persistence", icon: Fingerprint, description: "Autoruns, services, scheduled tasks and persistence mechanisms" },
      { label: "Process Insights", path: "/edr/processes", icon: MonitorSmartphone, description: "Process trees, command lines and hashes" },
      { label: "Managed Antivirus", path: "/edr/antivirus", icon: ShieldCheck, description: "Antivirus protection state and detections per endpoint" },
      { label: "Ransomware Canaries", path: "/edr/ransomware-canaries", icon: Skull, description: "Canary files that trip on encryption behaviour" },
      { label: "External Recon", path: "/edr/external-recon", icon: Globe, description: "Exposed RDP/SMB and services on endpoint public IPs" },
      { label: "Live Response", path: "/edr/live-response", icon: SquareTerminal, permission: "response:execute", description: "Remote shell, collection and remediation" },
      { label: "Endpoint Policies", path: "/edr/policies", icon: SlidersHorizontal, description: "Detection, isolation and agent update policies" },
    ],
  },
  {
    id: "itdr",
    short: "ITDR",
    name: "Identity Threat Detection & Response",
    path: "/itdr",
    icon: Fingerprint,
    module: "itdr",
    description: "Detect account takeover, token theft, MFA abuse and identity attack paths.",
    items: [
      { label: "ITDR Dashboard", path: "/itdr", icon: ChartLine },
      { label: "Identity Detections", path: "/itdr/detections", icon: ShieldAlert, description: "Impossible travel, password spraying, privilege escalation" },
      { label: "Risky Sign-ins", path: "/itdr/sign-ins", icon: Earth, description: "Suspicious authentications by geo, device and outcome" },
      { label: "Token & Session Abuse", path: "/itdr/sessions", icon: KeyRound, description: "Token theft, session hijack and MFA manipulation" },
      { label: "OAuth Applications", path: "/itdr/oauth-apps", icon: AppWindow, description: "Consented apps and OAuth abuse" },
      { label: "Identity Sources", path: "/itdr/sources", icon: Cable, description: "AD, Entra ID, Okta, Google Workspace, VPN" },
    ],
  },
  {
    id: "ndr",
    short: "NDR",
    name: "Network Detection & Response",
    path: "/ndr",
    icon: Network,
    module: "ndr",
    description: "Flow, DNS, TLS and HTTP analytics with beaconing and exfiltration detection.",
    items: [
      { label: "NDR Dashboard", path: "/ndr", icon: ChartLine },
      { label: "Network Flows", path: "/ndr/flows", icon: Waypoints, description: "North-south and east-west traffic" },
      { label: "DNS Analytics", path: "/ndr/dns", icon: Globe, description: "Rare domains, DGA and tunnelling" },
      { label: "TLS & HTTP", path: "/ndr/tls-http", icon: GlobeLock, description: "JA3, certificates, user agents" },
      { label: "Beaconing & C2", path: "/ndr/beaconing", icon: Radio, description: "Periodic callbacks and command-and-control" },
      { label: "Exfiltration", path: "/ndr/exfiltration", icon: Send, description: "Unusual outbound volume and destinations" },
      { label: "Packet Capture", path: "/ndr/pcap", icon: HardDrive, description: "Session PCAP retrieval for evidence" },
      { label: "Sensors", path: "/ndr/sensors", icon: Satellite, description: "Network sensor health and coverage" },
    ],
  },
  {
    id: "siem",
    short: "SIEM",
    name: "Security Information & Event Management",
    path: "/siem",
    icon: Database,
    module: "siem",
    description: "Ingestion, normalization, search, correlation and detection-as-code.",
    items: [
      { label: "SIEM Dashboard", path: "/siem", icon: ChartLine },
      { label: "Event Search", path: "/siem/search", icon: Search, permission: "event:read", description: "Query normalized events across all sources" },
      { label: "Alerts", path: "/siem/alerts", icon: ShieldAlert, permission: "alert:read" },
      { label: "Detection Rules", path: "/siem/detections", icon: Sigma, permission: "detection:read", description: "Sigma, threshold and sequence rules with versioning" },
      { label: "Saved Searches", path: "/siem/saved", icon: ListChecks },
      { label: "Log Sources", path: "/siem/sources", icon: Rss, description: "Source health, volume and parsing" },
      { label: "Retention & Archive", path: "/siem/retention", icon: Archive, description: "Data lifecycle and archive tiers" },
    ],
  },
  {
    id: "xdr",
    short: "XDR",
    name: "Extended Detection & Response",
    path: "/xdr",
    icon: Layers,
    module: "xdr",
    description: "Cross-domain correlation over the Security Graph.",
    items: [
      { label: "XDR Overview", path: "/xdr", icon: ChartLine },
      { label: "Correlations", path: "/xdr/correlations", icon: Workflow, description: "Alerts correlated into incidents across domains" },
      { label: "Security Graph", path: "/xdr/graph", icon: Waypoints, permission: "graph:read", description: "Pivot users, identities, endpoints, processes, IPs" },
      { label: "Threat Hunting", path: "/xdr/hunting", icon: Binoculars, description: "Hypothesis-driven hunts across telemetry" },
    ],
  },
  {
    id: "asm",
    short: "ASM",
    name: "Attack Surface Management",
    path: "/asm",
    icon: Radar,
    module: "asm",
    description: "Continuous discovery of domains, certificates, services and shadow IT.",
    items: [
      { label: "ASM Dashboard", path: "/asm", icon: ChartLine },
      { label: "Discovered Assets", path: "/asm/inventory", icon: Globe, description: "Domains, subdomains, IPs, ASNs" },
      { label: "Exposed Services", path: "/asm/services", icon: Server, description: "Open ports, technologies, web apps and APIs" },
      { label: "Certificates", path: "/asm/certificates", icon: BadgeCheck, description: "Certificate transparency and expiry" },
      { label: "Findings", path: "/asm/findings", icon: Bug, description: "Exposure findings from authorized scans" },
      { label: "Scan Scopes", path: "/asm/scopes", icon: Crosshair, description: "Authorized targets, rate limits and audit" },
    ],
  },
  {
    id: "espm",
    short: "ESPM",
    name: "Exposure & Security Posture Management",
    path: "/espm",
    icon: Gauge,
    module: "espm",
    description: "Unified exposure prioritized by exploitable paths and business impact.",
    items: [
      { label: "Exposure Dashboard", path: "/espm", icon: Gauge },
      { label: "Attack Paths", path: "/espm/attack-paths", icon: Route, permission: "risk:read", description: "Paths from entry points to crown jewels" },
      { label: "Crown Jewels", path: "/espm/crown-jewels", icon: Crown, description: "Business-critical assets and their exposure" },
      { label: "Exposure Findings", path: "/espm/findings", icon: ScanSearch },
      { label: "Remediation Plan", path: "/espm/remediation", icon: ClipboardCheck, description: "Fixes ranked by paths broken" },
    ],
  },
  {
    id: "ispm",
    short: "ISPM",
    name: "Identity Security Posture Management",
    path: "/ispm",
    icon: IdCard,
    module: "ispm",
    description: "Privilege analysis, MFA coverage, dormant and risky service accounts.",
    items: [
      { label: "ISPM Dashboard", path: "/ispm", icon: ChartLine },
      { label: "Identity Inventory", path: "/ispm/identities", icon: UsersRound, permission: "identity:read" },
      { label: "Privileged Access", path: "/ispm/privileged", icon: Crown },
      { label: "MFA Coverage", path: "/ispm/mfa", icon: ShieldCheck },
      { label: "Dormant Accounts", path: "/ispm/dormant", icon: UserX },
      { label: "Service Accounts", path: "/ispm/service-accounts", icon: UserCog },
      { label: "Recommendations", path: "/ispm/recommendations", icon: ListChecks },
    ],
  },
  {
    id: "cspm",
    short: "CSPM",
    name: "Cloud Security Posture Management",
    path: "/cspm",
    icon: Cloud,
    module: "cspm",
    description: "AWS, Azure and GCP misconfigurations, public exposure and benchmarks.",
    items: [
      { label: "CSPM Dashboard", path: "/cspm", icon: ChartLine },
      { label: "Cloud Accounts", path: "/cspm/accounts", icon: Cloud },
      { label: "Misconfigurations", path: "/cspm/findings", icon: Wrench },
      { label: "Public Exposure", path: "/cspm/exposure", icon: Globe, description: "Public storage, open security groups" },
      { label: "Compliance Benchmarks", path: "/cspm/compliance", icon: ClipboardList },
      { label: "Workload Inventory", path: "/cspm/workloads", icon: Server },
    ],
  },
  {
    id: "ciem",
    short: "CIEM",
    name: "Cloud Infrastructure Entitlement Management",
    path: "/ciem",
    icon: CloudCog,
    module: "ciem",
    description: "Cloud IAM analysis, excessive permissions and cross-account trust.",
    items: [
      { label: "CIEM Dashboard", path: "/ciem", icon: ChartLine },
      { label: "Cloud Identities", path: "/ciem/identities", icon: UsersRound },
      { label: "Excessive Permissions", path: "/ciem/permissions", icon: KeyRound },
      { label: "Cross-account Trust", path: "/ciem/trust", icon: Handshake },
      { label: "Access Reviews", path: "/ciem/reviews", icon: ClipboardCheck },
    ],
  },
  {
    id: "sspm",
    short: "SSPM",
    name: "SaaS Security Posture Management",
    path: "/sspm",
    icon: AppWindow,
    module: "sspm",
    description: "SaaS configuration, third-party apps and data sharing.",
    items: [
      { label: "SSPM Dashboard", path: "/sspm", icon: ChartLine },
      { label: "SaaS Applications", path: "/sspm/apps", icon: AppWindow },
      { label: "Misconfigurations", path: "/sspm/findings", icon: Wrench },
      { label: "Third-party Apps", path: "/sspm/oauth", icon: Puzzle },
      { label: "Data Sharing", path: "/sspm/sharing", icon: Globe },
    ],
  },
  {
    id: "vm",
    short: "VM",
    name: "Vulnerability Management",
    path: "/vm",
    icon: Bug,
    module: "vuln",
    description: "Risk-based prioritization with CVSS, EPSS, KEV and asset criticality.",
    items: [
      { label: "Vulnerability Dashboard", path: "/vm", icon: ChartLine },
      { label: "Vulnerabilities", path: "/vm/vulnerabilities", icon: Bug, permission: "vuln:read" },
      { label: "Known Exploited (KEV)", path: "/vm/kev", icon: Siren, description: "CISA KEV matches in your environment" },
      { label: "Software Inventory", path: "/vm/software", icon: Package },
      { label: "Remediation & SLA", path: "/vm/remediation", icon: Timer },
      { label: "Exceptions", path: "/vm/exceptions", icon: ClipboardList },
      { label: "Scanners", path: "/vm/scanners", icon: ScanSearch },
    ],
  },
  {
    id: "k8s",
    short: "K8S",
    name: "Container & Kubernetes Security",
    path: "/k8s",
    icon: Container,
    module: "container",
    description: "Image vulnerabilities, cluster posture and runtime detection.",
    items: [
      { label: "Container Dashboard", path: "/k8s", icon: ChartLine },
      { label: "Clusters", path: "/k8s/clusters", icon: Container },
      { label: "Images & Registries", path: "/k8s/images", icon: Package },
      { label: "Runtime Detections", path: "/k8s/runtime", icon: Activity },
      { label: "Kubernetes Posture", path: "/k8s/posture", icon: ClipboardCheck },
    ],
  },
  {
    id: "cti",
    short: "CTI",
    name: "Threat Intelligence",
    path: "/cti",
    icon: Target,
    module: "cti",
    description: "IOCs, actors and campaigns matched against your environment.",
    items: [
      { label: "CTI Dashboard", path: "/cti", icon: ChartLine },
      { label: "Indicators", path: "/cti/indicators", icon: Target, permission: "intel:read" },
      { label: "Environment Matches", path: "/cti/matches", icon: Crosshair, description: "IOCs seen in telemetry, identities and cloud" },
      { label: "Threat Actors", path: "/cti/actors", icon: Skull },
      { label: "Campaigns & Malware", path: "/cti/campaigns", icon: Bug },
      { label: "Feeds", path: "/cti/feeds", icon: Rss, description: "STIX/TAXII, MISP, OpenCTI and open feeds" },
    ],
  },
  {
    id: "dfir",
    short: "DFIR",
    name: "Digital Forensics & Incident Response",
    path: "/dfir",
    icon: Microscope,
    module: "dfir",
    description: "Cases, evidence with chain of custody, timelines and collections.",
    items: [
      { label: "Cases", path: "/dfir", icon: FolderLock },
      { label: "Evidence Locker", path: "/dfir/evidence", icon: Archive },
      { label: "Timelines", path: "/dfir/timelines", icon: History },
      { label: "Collections", path: "/dfir/collections", icon: Download, description: "Endpoint artifact and memory collection" },
      { label: "YARA Scans", path: "/dfir/yara", icon: FileSearch },
      { label: "Forensic Reports", path: "/dfir/reports", icon: FileText },
    ],
  },
  {
    id: "soar",
    short: "SOAR",
    name: "Security Orchestration, Automation & Response",
    path: "/soar",
    icon: Workflow,
    module: "soar",
    description: "Playbooks, approvals, automation rules and notification delivery.",
    items: [
      { label: "SOAR Dashboard", path: "/soar", icon: ChartLine },
      { label: "Playbooks", path: "/soar/playbooks", icon: Workflow, permission: "playbook:read" },
      { label: "Approvals", path: "/soar/approvals", icon: ClipboardCheck, description: "High-risk actions awaiting human approval" },
      { label: "Response Actions", path: "/soar/actions", icon: Terminal, description: "Execution log of response actions" },
      { label: "Automation Rules", path: "/soar/automations", icon: CalendarClock, description: "When <event> and <conditions>, notify <channels>", keywords: ["email", "alerting", "rules"] },
      { label: "Notification Channels", path: "/soar/channels", icon: Webhook, description: "Email, Slack, Teams, webhook and syslog delivery", keywords: ["email", "smtp", "slack", "teams"] },
    ],
  },
  {
    id: "mail",
    short: "MAIL",
    name: "Email Security",
    path: "/mail",
    icon: Mail,
    module: "email",
    description: "Phishing, impersonation and malicious attachments.",
    items: [
      { label: "Email Dashboard", path: "/mail", icon: ChartLine },
      { label: "Quarantine", path: "/mail/quarantine", icon: Inbox },
      { label: "Reported Phishing", path: "/mail/reported", icon: MailWarning },
      { label: "Impersonation", path: "/mail/impersonation", icon: UserRound },
      { label: "Mail Flow", path: "/mail/flow", icon: Send },
    ],
  },
  {
    id: "decoy",
    short: "DECOY",
    name: "Deception",
    path: "/decoy",
    icon: Ghost,
    module: "deception",
    description: "Decoys, canaries and honeytokens with zero-false-positive alerts.",
    items: [
      { label: "Deception Dashboard", path: "/decoy", icon: ChartLine },
      { label: "Decoys", path: "/decoy/decoys", icon: Ghost },
      { label: "Honeytokens", path: "/decoy/tokens", icon: KeyRound },
      { label: "Decoy Alerts", path: "/decoy/alerts", icon: Siren },
    ],
  },
  {
    id: "ai",
    short: "AI",
    name: "AI SOC Analyst",
    path: "/ai",
    icon: Bot,
    module: "ai_soc",
    description: "Investigate, hunt, explain and recommend — within permitted tool tiers.",
    items: [
      { label: "AI Analyst", path: "/ai", icon: Bot, permission: "ai:use" },
      { label: "Conversations", path: "/ai/conversations", icon: MessagesSquare },
      { label: "AI Actions & Approvals", path: "/ai/actions", icon: ClipboardCheck },
      { label: "Models & Providers", path: "/ai/providers", icon: BrainCircuit, permission: "ai:configure", description: "Local and cloud model configuration" },
      { label: "AI Policies", path: "/ai/policies", icon: Shield, permission: "ai:configure", description: "Tool tiers, redaction, retention" },
    ],
  },
  {
    id: "trials",
    short: "Trials",
    name: "Trials & Modules",
    path: "/trials",
    icon: Clock,
    module: null,
    description: "Start trials and manage module subscriptions.",
    items: [
      { label: "Trial Manager", path: "/trials", icon: Clock },
      { label: "Billing & Invoices", path: "/billing", icon: CreditCard, permission: "billing:read" },
    ],
  },
  {
    id: "hub",
    short: "Hub",
    name: "Hub & Marketplace",
    path: "/hub",
    icon: Handshake,
    module: null,
    description: "Integrations, detection content and playbook library.",
    items: [
      { label: "Hub", path: "/hub", icon: Blocks },
      { label: "Engine Catalog", path: "/hub/engines", icon: Puzzle, description: "Open-source engines Bloody can drive" },
      { label: "Detection Content", path: "/hub/content", icon: Sigma },
      { label: "Playbook Library", path: "/hub/playbooks", icon: Workflow },
    ],
  },
];

export interface MenuItem extends NavItem {
  action?: "logout";
}
export interface MenuSection {
  title?: string;
  items: MenuItem[];
}

/** Hamburger menu, mirroring the reference layout (support, account, profile). */
export const HAMBURGER_SECTIONS: MenuSection[] = [
  {
    items: [
      { label: "Support & FAQ", path: "/support", icon: LifeBuoy, external: true },
      { label: "Download Agent", path: "/agents/download", icon: Download, permission: "asset:write" },
      { label: "Demo Sandbox", path: "/sandbox", icon: FlaskConical },
      { label: "Simulate an Incident", path: "/simulate", icon: Siren, permission: "incident:write" },
    ],
  },
  {
    title: "Account",
    items: [
      { label: "Dashboard", path: "/", icon: LayoutDashboard },
      { label: "Organizations", path: "/organizations", icon: Building2, permission: "org:read" },
      { label: "Agents", path: "/agents", icon: Monitor, permission: "asset:read" },
      { label: "Escalations", path: "/escalations", icon: CircleAlert, permission: "escalation:read" },
      { label: "Incidents", path: "/incidents", icon: Siren, permission: "incident:read" },
      { label: "Investigations", path: "/investigations", icon: Search, permission: "investigation:read" },
      { label: "Reports", path: "/reports", icon: FileText, permission: "report:read" },
      { label: "Hub", path: "/hub", icon: Handshake, external: true },
      { label: "Users", path: "/users", icon: Users, permission: "user:read" },
      { label: "Integrations", path: "/integrations", icon: Code, permission: "integration:read" },
      { label: "API Credentials", path: "/settings/api-credentials", icon: KeyRound, permission: "apikey:write" },
      { label: "Settings", path: "/settings", icon: Settings },
      { label: "Billing & Invoices", path: "/billing", icon: CreditCard, permission: "billing:read" },
      { label: "Data Archive", path: "/settings/data-archive", icon: Archive },
      { label: "Audit Log", path: "/audit", icon: ScrollText, permission: "audit:read" },
    ],
  },
  {
    title: "Profile",
    items: [
      { label: "Preferences", path: "/preferences", icon: UserRound },
      { label: "Trial Manager", path: "/trials", icon: Clock },
      { label: "Feedback", path: "/feedback", icon: MessageSquare, external: true },
      { label: "Logout", path: "/login", icon: LogOut, action: "logout" },
    ],
  },
];

/** Additional routable pages that are not in the rail/top nav but must never 404. */
export const AUX_PAGES: NavItem[] = [
  { label: "Settings", path: "/settings", icon: Settings, description: "Account settings, SSO, retention and data policies" },
  { label: "Notification Settings", path: "/settings/notifications", icon: Webhook, description: "Email and chat delivery for alerts, escalations and reports", keywords: ["email", "smtp"] },
  { label: "API Credentials", path: "/settings/api-credentials", icon: KeyRound, description: "Service accounts and API keys" },
  { label: "Data Archive", path: "/settings/data-archive", icon: Archive, description: "Archived events and exports" },
  { label: "Audit Log", path: "/audit", icon: ScrollText, description: "Every mutating action with actor, target and request id" },
  { label: "Billing & Invoices", path: "/billing", icon: CreditCard, description: "Plan, usage metering and invoices" },
  { label: "Agents", path: "/agents", icon: Monitor, description: "Agent fleet health, versions and isolation state" },
  { label: "Download Agent", path: "/agents/download", icon: Download, description: "Signed agent installers and deployment keys" },
  { label: "Demo Sandbox", path: "/sandbox", icon: FlaskConical, description: "Explore a fully configured demo account" },
  { label: "Simulate an Incident", path: "/simulate", icon: Siren, description: "Run a safe, labelled attack simulation to validate detection and response" },
  { label: "Support & FAQ", path: "/support", icon: LifeBuoy, description: "Support portal and frequently asked questions" },
  { label: "Feedback", path: "/feedback", icon: MessageSquare, description: "Tell us what to improve" },
  { label: "Preferences", path: "/preferences", icon: UserRound, description: "Theme, dashboard view and shortcuts" },
];

export interface NavMatch {
  module: RailModule | null;
  item: NavItem | null;
}

function normalize(path: string): string {
  if (path.length > 1 && path.endsWith("/")) return path.slice(0, -1);
  return path;
}

/** Find the rail module + item for a pathname (longest prefix match). */
export function findNavMatch(pathname: string): NavMatch {
  const path = normalize(pathname);
  let best: NavMatch = { module: null, item: null };
  let bestLen = -1;
  const consider = (module: RailModule | null, item: NavItem) => {
    const p = item.path;
    if ((path === p || (p !== "/" && path.startsWith(`${p}/`))) && p.length > bestLen) {
      best = { module, item };
      bestLen = p.length;
    }
  };
  for (const m of RAIL_MODULES) for (const item of m.items) consider(m, item);
  for (const item of [...TOP_NAV, ...AUX_PAGES]) consider(null, item);
  if (!best.module) {
    const module = RAIL_MODULES.find((m) => m.path !== "/" && (path === m.path || path.startsWith(`${m.path}/`)));
    if (module) best = { module, item: best.item };
  }
  return best;
}

/** Rail module that should be highlighted for a pathname. */
export function activeRailModule(pathname: string): RailModule | null {
  const path = normalize(pathname);
  if (path === "/" || path === "/mssp") return RAIL_MODULES[0] ?? null;
  return RAIL_MODULES.find((m) => m.path !== "/" && (path === m.path || path.startsWith(`${m.path}/`))) ?? null;
}

/** Every internal path reachable from navigation (used to generate placeholder routes). */
export function allNavPaths(): string[] {
  const paths = new Set<string>();
  for (const m of RAIL_MODULES) {
    paths.add(m.path);
    for (const i of m.items) paths.add(i.path);
  }
  for (const i of TOP_NAV) paths.add(i.path);
  for (const i of AUX_PAGES) paths.add(i.path);
  for (const s of HAMBURGER_SECTIONS) for (const i of s.items) if (!i.action) paths.add(i.path);
  return [...paths].filter((p) => p.startsWith("/"));
}
