import type { FastifyInstance } from "fastify";
import type { AppServices } from "../context.js";
import { alertRoutes } from "./alerts.js";
import { apiKeyRoutes } from "./api-keys.js";
import { auditRoutes } from "./audit.js";
import { authRoutes } from "./auth.js";
import { commandCenterRoutes } from "./command-center.js";
import { escalationRoutes } from "./escalations.js";
import { healthRoutes } from "./health.js";
import { incidentRoutes } from "./incidents.js";
import { ingestRoutes } from "./ingest.js";
import { inventoryRoutes } from "./inventory.js";
import { investigationRoutes } from "./investigations.js";
import { msspRoutes } from "./mssp.js";
import { organizationRoutes } from "./organizations.js";
import { searchRoutes } from "./search.js";
import { teamRoutes } from "./teams.js";
import { userRoutes } from "./users.js";

/** Every /api/v1 route module (part A: foundation). */
export async function registerRoutes(app: FastifyInstance, services: AppServices): Promise<void> {
  await healthRoutes(app, services);
  await authRoutes(app, services);
  await organizationRoutes(app, services);
  await userRoutes(app, services);
  await teamRoutes(app, services);
  await apiKeyRoutes(app, services);
  await inventoryRoutes(app, services);
  await incidentRoutes(app, services);
  await alertRoutes(app, services);
  await investigationRoutes(app, services);
  await escalationRoutes(app, services);
  await commandCenterRoutes(app, services);
  await msspRoutes(app, services);
  await searchRoutes(app, services);
  await auditRoutes(app, services);
  await ingestRoutes(app, services);
}
