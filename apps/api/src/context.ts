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
import type { SecretStore } from "./services/secret-store.js";
import type { EntitlementService, QuotaService } from "./services/commercial.js";
import type { DetectionService } from "./services/detections.js";
import type { DomainEventBus } from "./services/domain-events.js";
import type { EnrichmentService } from "./services/enrichment.js";
import type { EventSearchService } from "./services/event-search.js";
import type { GraphQueries } from "./services/graph-queries.js";
import type { IntelService } from "./services/intel.js";
import type { NotificationService } from "./services/notifications.js";

/** Composition root output shared by every route module. */
export interface AppServices {
  config: AppConfig;
  db: Database;
  bus: EventBus;
  metrics: Metrics;
  auth: AuthService;
  secrets: SecretBox;
  /** Tenant credential store (credentialRef → plaintext), for AI providers, integrations, channels. */
  secretStore: SecretStore;
  risk: RiskEngine;
  attackPathEngine: AttackPathEngine;
  attackPaths: AttackPathService;
  inventory: InventoryService;
  ingest: IngestService;
  pipeline: AnalyticsPipeline;
  adapters: AdapterRegistry;
  oidc: ExternalAuthProvider | null;
  now: () => number;

  // ─── Part B: SOC operations ────────────────────────────────────────────────
  /** In-process domain events (automation rules, playbook triggers, in-app notifications). */
  domainEvents: DomainEventBus;
  entitlements: EntitlementService;
  quota: QuotaService;
  graph: GraphQueries;
  detections: DetectionService;
  eventSearch: EventSearchService;
  intel: IntelService;
  enrichment: EnrichmentService;
  notifications: NotificationService;
}
