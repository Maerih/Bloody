import type { NodeKind } from "@bloody/contracts";
import {
  AppWindow,
  Award,
  Box,
  Building2,
  Bug,
  Cloud,
  Cpu,
  Database,
  Earth,
  File,
  Fingerprint,
  Flag,
  Globe,
  Hash,
  IdCard,
  KeyRound,
  Link2,
  Monitor,
  Network,
  Puzzle,
  Search,
  Server,
  ShieldCheck,
  Siren,
  Skull,
  Swords,
  Target,
  Ticket,
  User,
  UserCog,
  Users,
  Waypoints,
  type LucideIcon,
} from "lucide-react";

export interface NodeKindMeta {
  label: string;
  icon: LucideIcon;
  /** Fill colour for the node badge (mid-tone, readable on light and dark canvases). */
  color: string;
}

const C = {
  identity: "#8b5cf6",
  user: "#6366f1",
  endpoint: "#0ea5e9",
  server: "#0284c7",
  cloud: "#38bdf8",
  process: "#64748b",
  file: "#f59e0b",
  hash: "#d97706",
  network: "#14b8a6",
  threat: "#dc2626",
  vuln: "#f97316",
  case: "#e11d48",
  control: "#16a34a",
  neutral: "#94a3b8",
};

export const NODE_KIND_META: Record<NodeKind, NodeKindMeta> = {
  organization: { label: "Organization", icon: Building2, color: C.neutral },
  user: { label: "User", icon: User, color: C.user },
  identity: { label: "Identity", icon: Fingerprint, color: C.identity },
  group: { label: "Group", icon: Users, color: C.identity },
  service_account: { label: "Service account", icon: UserCog, color: C.identity },
  endpoint: { label: "Endpoint", icon: Monitor, color: C.endpoint },
  server: { label: "Server", icon: Server, color: C.server },
  cloud_asset: { label: "Cloud asset", icon: Cloud, color: C.cloud },
  application: { label: "Application", icon: AppWindow, color: C.server },
  container: { label: "Container", icon: Box, color: C.cloud },
  k8s_resource: { label: "Kubernetes", icon: Box, color: C.cloud },
  process: { label: "Process", icon: Cpu, color: C.process },
  file: { label: "File", icon: File, color: C.file },
  hash: { label: "Hash", icon: Hash, color: C.hash },
  ip: { label: "IP", icon: Network, color: C.network },
  domain: { label: "Domain", icon: Globe, color: C.network },
  url: { label: "URL", icon: Link2, color: C.network },
  certificate: { label: "Certificate", icon: Award, color: C.network },
  vulnerability: { label: "Vulnerability", icon: Bug, color: C.vuln },
  credential: { label: "Credential", icon: KeyRound, color: C.identity },
  session: { label: "Session", icon: Ticket, color: C.identity },
  oauth_app: { label: "OAuth app", icon: Puzzle, color: C.identity },
  saas_app: { label: "SaaS app", icon: AppWindow, color: C.cloud },
  threat_actor: { label: "Threat actor", icon: Skull, color: C.threat },
  malware: { label: "Malware", icon: Bug, color: C.threat },
  campaign: { label: "Campaign", icon: Flag, color: C.threat },
  indicator: { label: "Indicator", icon: Target, color: C.threat },
  incident: { label: "Incident", icon: Siren, color: C.case },
  investigation: { label: "Investigation", icon: Search, color: C.case },
  technique: { label: "ATT&CK technique", icon: Swords, color: C.threat },
  control: { label: "Control", icon: ShieldCheck, color: C.control },
  policy: { label: "Policy", icon: IdCard, color: C.control },
  internet: { label: "Internet", icon: Earth, color: C.neutral },
  data_store: { label: "Data store", icon: Database, color: C.server },
};

const FALLBACK: NodeKindMeta = { label: "Entity", icon: Waypoints, color: C.neutral };

export function nodeKindMeta(kind: string): NodeKindMeta {
  return (NODE_KIND_META as Record<string, NodeKindMeta>)[kind] ?? FALLBACK;
}

/** Kinds the explorer's legend/filters feature first (the analyst pivot chain). */
export const PIVOT_KINDS: NodeKind[] = ["user", "identity", "endpoint", "server", "process", "file", "hash", "domain", "ip", "threat_actor", "vulnerability", "incident"];

export const ASSET_NODE_KINDS: NodeKind[] = ["endpoint", "server", "cloud_asset", "application", "container", "k8s_resource", "data_store", "saas_app"];
export const IDENTITY_NODE_KINDS: NodeKind[] = ["user", "identity", "service_account", "group"];
export const INDICATOR_NODE_KINDS: NodeKind[] = ["ip", "domain", "url", "hash", "indicator"];
