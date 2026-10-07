import type { AdapterRegistry } from "@bloody/adapters";
import type { AttackPathEngine, RiskEngine } from "@bloody/engines";
import type { ExternalAuthProvider } from "./auth/oidc.js";
import type { AuthService } from "./auth/service.js";
import type { AppConfig } from "./config.js";
import type { Database } from "./db/pool.js";
import type { Metrics } from "./metrics.js";
import type { AnalyticsPipeline } from "./pipeline/analytics.js";
import type { EventBus } from "./pipeline/event-bus.js";
import type { IngestService } from "./pipeline/ingest.js";
import type { SecretBox } from "./security/crypto.js";
import type { AttackPathService } from "./services/attack-paths.js";
import type { InventoryService } from "./services/inventory.js";

/** Composition root output shared by every route module. */
export interface AppServices {
  config: AppConfig;
  db: Database;
  bus: EventBus;
  metrics: Metrics;
  auth: AuthService;
  secrets: SecretBox;
  risk: RiskEngine;
  attackPathEngine: AttackPathEngine;
  attackPaths: AttackPathService;
  inventory: InventoryService;
  ingest: IngestService;
  pipeline: AnalyticsPipeline;
  adapters: AdapterRegistry;
  oidc: ExternalAuthProvider | null;
  now: () => number;
}
