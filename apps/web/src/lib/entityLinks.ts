/**
 * Canonical in-app links for entity kinds, used by search results, triage feed, notifications
 * and pivots (Alert → Incident → Investigation → Graph → Risk → Response). Part B pages that
 * add detail views for a kind should register them here so every pivot stays consistent.
 */
const ENTITY_ROUTES: Record<string, (id: string) => string> = {
  incident: (id) => `/incidents/${encodeURIComponent(id)}`,
  investigation: (id) => `/investigations/${encodeURIComponent(id)}`,
  escalation: (id) => `/escalations?id=${encodeURIComponent(id)}`,
  alert: (id) => `/siem/alerts?id=${encodeURIComponent(id)}`,
  asset: (id) => `/assets/${encodeURIComponent(id)}`,
  endpoint: (id) => `/assets/${encodeURIComponent(id)}`,
  server: (id) => `/assets/${encodeURIComponent(id)}`,
  agent: (id) => `/agents?id=${encodeURIComponent(id)}`,
  identity: (id) => `/ispm/identities?id=${encodeURIComponent(id)}`,
  user: (id) => `/users?id=${encodeURIComponent(id)}`,
  organization: (id) => `/organizations?id=${encodeURIComponent(id)}`,
  indicator: (id) => `/cti/indicators?id=${encodeURIComponent(id)}`,
  ip: (id) => `/cti/indicators?q=${encodeURIComponent(id)}`,
  domain: (id) => `/cti/indicators?q=${encodeURIComponent(id)}`,
  url: (id) => `/cti/indicators?q=${encodeURIComponent(id)}`,
  hash: (id) => `/cti/indicators?q=${encodeURIComponent(id)}`,
  threat_actor: (id) => `/cti/actors?id=${encodeURIComponent(id)}`,
  campaign: (id) => `/cti/campaigns?id=${encodeURIComponent(id)}`,
  malware: (id) => `/cti/campaigns?q=${encodeURIComponent(id)}`,
  vulnerability: (id) => `/vm/vulnerabilities?id=${encodeURIComponent(id)}`,
  cve: (id) => `/vm/vulnerabilities?q=${encodeURIComponent(id)}`,
  cloud_asset: (id) => `/cspm/workloads?id=${encodeURIComponent(id)}`,
  application: (id) => `/asm/inventory?id=${encodeURIComponent(id)}`,
  attack_path: (id) => `/espm/attack-paths?id=${encodeURIComponent(id)}`,
  playbook: (id) => `/soar/playbooks?id=${encodeURIComponent(id)}`,
  response_action: (id) => `/soar/actions?id=${encodeURIComponent(id)}`,
  report: (id) => `/reports?id=${encodeURIComponent(id)}`,
};

export function hrefForEntity(kind: string, id: string): string {
  const route = ENTITY_ROUTES[kind];
  return route ? route(id) : `/search?q=${encodeURIComponent(id)}`;
}

export function registerEntityRoute(kind: string, build: (id: string) => string): void {
  ENTITY_ROUTES[kind] = build;
}

/** Only allow same-origin, path-absolute redirects (prevents open redirects via ?next=). */
export function safeInternalPath(value: string | null | undefined, fallback = "/"): string {
  if (!value) return fallback;
  if (!value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return fallback;
  if (/^\/(api|login)(\/|$|\?)/.test(value)) return fallback;
  return value;
}
