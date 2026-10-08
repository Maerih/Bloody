import { ENGINES, MODULES, type EngineDefinition, type ModuleKey } from "@bloody/contracts";
import type { IntegrationView } from "../api/types";

/** Product catalogue helpers over the contracts ENGINES list (static product metadata). */

export type EngineLayer = EngineDefinition["layer"];

export const LAYER_LABELS: Record<EngineLayer, string> = {
  endpoint: "Endpoint",
  runtime: "Runtime & containers",
  network: "Network",
  search: "Search & analytics",
  streaming: "Streaming",
  collection: "Collection",
  detection: "Detection content",
  intel: "Threat intelligence",
  case: "Case management & SOC hubs",
  soar: "Automation",
  vulnerability: "Vulnerability scanning",
  asm: "Attack surface",
  cloud: "Cloud & container posture",
  identity: "Identity",
  deception: "Deception",
  forensics: "Forensics",
  storage: "Storage",
  ai: "AI runtimes",
};

export const LAYER_ORDER: EngineLayer[] = [
  "case",
  "endpoint",
  "runtime",
  "network",
  "identity",
  "collection",
  "streaming",
  "search",
  "detection",
  "intel",
  "vulnerability",
  "asm",
  "cloud",
  "deception",
  "forensics",
  "soar",
  "ai",
  "storage",
];

export const MODE_LABELS: Record<EngineDefinition["mode"], string> = {
  network_api: "Network API",
  event_stream: "Event stream",
  file_drop: "File drop",
  agent: "Agent",
  library_permissive: "Permissive library",
};

export function engineByKey(key: string): EngineDefinition | undefined {
  return ENGINES.find((e) => e.key === key);
}

export function moduleName(key: ModuleKey): string {
  return MODULES.find((m) => m.key === key)?.short ?? key;
}

/** Engines that power a module, core engines first. */
export function enginesForModule(module: ModuleKey): EngineDefinition[] {
  return ENGINES.filter((e) => e.powers.includes(module)).sort((a, b) => Number(b.core) - Number(a.core) || a.name.localeCompare(b.name));
}

/** Integrations (configured connections) for a set of engine keys. */
export function integrationsFor(integrations: IntegrationView[] | undefined, engineKeys: string[]): IntegrationView[] {
  return (integrations ?? []).filter((i) => engineKeys.includes(i.engine));
}

/** Configure link into the Integrations Hub with the engine's dialog opened. */
export function connectHref(engineKey: string): string {
  return `/integrations?engine=${encodeURIComponent(engineKey)}`;
}
