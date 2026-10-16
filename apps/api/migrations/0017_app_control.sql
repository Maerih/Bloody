-- App Control (ESPM): per-organization mode, allow / block rules (organization_id NULL = every
-- organization of the account), programs seen by SCIAT Agents, and blocked / audited runs.
CREATE TABLE app_control_settings (
  organization_id  uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  mode             text NOT NULL DEFAULT 'off' CHECK (mode IN ('off', 'audit', 'enforce')),
  updated_by       text,
  updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app_control_rules (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid REFERENCES organizations(id) ON DELETE CASCADE,
  action           text NOT NULL CHECK (action IN ('allow', 'block')),
  kind             text NOT NULL CHECK (kind IN ('name', 'path', 'sha256', 'publisher')),
  value            text NOT NULL CHECK (length(value) BETWEEN 1 AND 500 AND value !~ '["\r\n\t]'),
  platform         text NOT NULL DEFAULT 'any' CHECK (platform IN ('any', 'windows', 'linux', 'macos')),
  note             text,
  created_by       text,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX app_control_rules_unique ON app_control_rules
  (tenant_id, coalesce(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), action, kind, lower(value), platform);

CREATE TABLE app_inventory (
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  agent_id         uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  name             text NOT NULL,
  path             text NOT NULL,
  sha256           text,
  publisher        text,
  first_seen_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (agent_id, path)
);
CREATE INDEX app_inventory_org ON app_inventory (tenant_id, organization_id, lower(name));

CREATE TABLE app_control_events (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  agent_id         uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  hostname         text NOT NULL,
  name             text NOT NULL,
  path             text,
  sha256           text,
  publisher        text,
  rule_id          uuid REFERENCES app_control_rules(id) ON DELETE SET NULL,
  verdict          text NOT NULL CHECK (verdict IN ('blocked', 'audited')),
  occurred_at      timestamptz NOT NULL,
  received_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX app_control_events_org ON app_control_events (tenant_id, organization_id, occurred_at DESC);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['app_control_settings', 'app_control_rules', 'app_inventory', 'app_control_events'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)$p$, t);
  END LOOP;
END $$;
