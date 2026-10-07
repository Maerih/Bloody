-- Inventory: assets, agents, identities, vulnerabilities, threat-intelligence indicators.

CREATE TABLE assets (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  organization_id  uuid NOT NULL,
  kind             text NOT NULL CHECK (kind IN ('endpoint', 'server', 'domain_controller', 'database', 'cloud_instance', 'cloud_storage',
                                                 'container', 'kubernetes_cluster', 'network_device', 'application', 'saas_app',
                                                 'external_host', 'data_store')),
  name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 300),
  hostname         text,
  ip_addresses     text[] NOT NULL DEFAULT '{}',
  os               text,
  criticality      text NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low', 'medium', 'high', 'crown_jewel')),
  internet_facing  boolean NOT NULL DEFAULT false,
  tags             text[] NOT NULL DEFAULT '{}',
  owner            text,
  source           text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'discovered', 'integration', 'agent')),
  last_seen_at     timestamptz,
  risk_score       numeric(5, 2) CHECK (risk_score BETWEEN 0 AND 100),
  -- Explainable RiskAssessment (factors[]) behind risk_score.
  risk             jsonb,
  risk_updated_at  timestamptz,
  external_source  text,
  external_ref     text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX assets_hostname ON assets (tenant_id, organization_id, lower(hostname)) WHERE hostname IS NOT NULL;
CREATE UNIQUE INDEX assets_external_ref ON assets (tenant_id, external_source, external_ref) WHERE external_ref IS NOT NULL;
CREATE INDEX assets_org ON assets (tenant_id, organization_id, created_at DESC);
CREATE INDEX assets_ips ON assets USING gin (ip_addresses);
CREATE INDEX assets_name_search ON assets (tenant_id, lower(name) text_pattern_ops);
CREATE TRIGGER assets_updated_at BEFORE UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE agents (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL,
  organization_id   uuid NOT NULL,
  asset_id          uuid,
  hostname          text NOT NULL,
  platform          text NOT NULL CHECK (platform IN ('windows', 'macos', 'linux')),
  version           text NOT NULL,
  engine            text NOT NULL,
  status            text NOT NULL DEFAULT 'pending' CHECK (status IN ('protected', 'unresponsive', 'outdated', 'isolated', 'pending')),
  last_checkin_at   timestamptz,
  antivirus_status  text NOT NULL DEFAULT 'unmanaged' CHECK (antivirus_status IN ('protected', 'unhealthy', 'unmanaged', 'incompatible')),
  firewall_enabled  boolean NOT NULL DEFAULT false,
  external_source   text,
  external_ref      text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE SET NULL (asset_id)
);
CREATE UNIQUE INDEX agents_hostname_engine ON agents (tenant_id, organization_id, lower(hostname), engine);
CREATE UNIQUE INDEX agents_external_ref ON agents (tenant_id, external_source, external_ref) WHERE external_ref IS NOT NULL;
CREATE INDEX agents_org_status ON agents (tenant_id, organization_id, status);
CREATE TRIGGER agents_updated_at BEFORE UPDATE ON agents FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE identities (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL,
  organization_id   uuid NOT NULL,
  kind              text NOT NULL DEFAULT 'user' CHECK (kind IN ('user', 'service_account', 'service_principal', 'machine', 'api_key', 'group')),
  provider          text NOT NULL CHECK (length(provider) BETWEEN 1 AND 100),
  principal         text NOT NULL CHECK (length(principal) BETWEEN 1 AND 500),
  display_name      text,
  privileged        boolean NOT NULL DEFAULT false,
  mfa_enabled       boolean NOT NULL DEFAULT false,
  enabled           boolean NOT NULL DEFAULT true,
  last_activity_at  timestamptz,
  risk_score        numeric(5, 2) CHECK (risk_score BETWEEN 0 AND 100),
  risk              jsonb,
  risk_updated_at   timestamptz,
  external_source   text,
  external_ref      text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX identities_principal ON identities (tenant_id, organization_id, lower(provider), lower(principal));
CREATE INDEX identities_principal_search ON identities (tenant_id, lower(principal) text_pattern_ops);
CREATE TRIGGER identities_updated_at BEFORE UPDATE ON identities FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE vulnerabilities (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  organization_id  uuid NOT NULL,
  asset_id         uuid NOT NULL,
  cve              text CHECK (cve IS NULL OR cve ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  title            text NOT NULL CHECK (length(title) BETWEEN 1 AND 500),
  cvss             numeric(3, 1) CHECK (cvss BETWEEN 0 AND 10),
  epss             numeric(6, 5) CHECK (epss BETWEEN 0 AND 1),
  known_exploited  boolean NOT NULL DEFAULT false,
  severity         text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  status           text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_remediation', 'accepted', 'mitigated', 'resolved')),
  patch_available  boolean NOT NULL DEFAULT false,
  sla_due_at       timestamptz,
  priority         text CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
  risk_score       numeric(5, 2) CHECK (risk_score BETWEEN 0 AND 100),
  risk             jsonb,
  source           text NOT NULL DEFAULT 'manual',
  first_seen_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at     timestamptz NOT NULL DEFAULT now(),
  resolved_at      timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX vulnerabilities_finding ON vulnerabilities (tenant_id, asset_id, coalesce(cve, title));
CREATE INDEX vulnerabilities_open ON vulnerabilities (tenant_id, organization_id, severity) WHERE status IN ('open', 'in_remediation');
CREATE INDEX vulnerabilities_cve ON vulnerabilities (tenant_id, cve);
CREATE TRIGGER vulnerabilities_updated_at BEFORE UPDATE ON vulnerabilities FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE indicators (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  -- NULL = shared across every organization of the tenant (MSSP-wide feed).
  organization_id  uuid,
  type             text NOT NULL CHECK (type IN ('ip', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email', 'cve', 'ja3', 'user_agent')),
  value            text NOT NULL CHECK (length(value) BETWEEN 1 AND 2048),
  confidence       integer NOT NULL CHECK (confidence BETWEEN 0 AND 100),
  severity         text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  source           text NOT NULL CHECK (length(source) BETWEEN 1 AND 200),
  threat_actor     text,
  malware          text,
  campaign         text,
  tags             text[] NOT NULL DEFAULT '{}',
  first_seen_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at     timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz,
  external_ref     text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX indicators_natural ON indicators (tenant_id, org_key(organization_id), type, value, source);
CREATE INDEX indicators_value ON indicators (tenant_id, type, value);
CREATE INDEX indicators_actor ON indicators (tenant_id, lower(threat_actor)) WHERE threat_actor IS NOT NULL;
CREATE TRIGGER indicators_updated_at BEFORE UPDATE ON indicators FOR EACH ROW EXECUTE FUNCTION set_updated_at();
