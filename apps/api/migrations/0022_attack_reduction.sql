-- Attack Reduction: hardening facts reported with the host inventory, and the gaps each
-- organization has accepted (with a written reason).
ALTER TABLE agent_inventory ADD COLUMN hardening jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE TABLE attack_reduction_exceptions (
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  check_key        text NOT NULL,
  reason           text NOT NULL,
  created_by       text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, check_key)
);
ALTER TABLE attack_reduction_exceptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE attack_reduction_exceptions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON attack_reduction_exceptions
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
