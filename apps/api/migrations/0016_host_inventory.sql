-- Host inventory reported by the SCIAT Agent: one snapshot per agent (software, services, local
-- users, processes, listening ports, antivirus products, firewall), replaced on every report.
CREATE TABLE agent_inventory (
  agent_id         uuid PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  asset_id         uuid REFERENCES assets(id) ON DELETE SET NULL,
  collected_at     timestamptz NOT NULL DEFAULT now(),
  software         jsonb NOT NULL DEFAULT '[]'::jsonb,
  services         jsonb NOT NULL DEFAULT '[]'::jsonb,
  users            jsonb NOT NULL DEFAULT '[]'::jsonb,
  processes        jsonb NOT NULL DEFAULT '[]'::jsonb,
  ports            jsonb NOT NULL DEFAULT '[]'::jsonb,
  antivirus        jsonb NOT NULL DEFAULT '[]'::jsonb,
  firewall         jsonb
);
CREATE INDEX agent_inventory_asset ON agent_inventory (tenant_id, asset_id);

ALTER TABLE agent_inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_inventory FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_inventory
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
