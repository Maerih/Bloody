-- RMM Guard: the remote-access / RMM tools each organization approves (the rest are reported).
CREATE TABLE rmm_guard_settings (
  organization_id  uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  approved         text[] NOT NULL DEFAULT '{}',
  updated_by       text,
  updated_at       timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE rmm_guard_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE rmm_guard_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON rmm_guard_settings
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
