-- Endpoint posture recorded once a day per organization, so reports can show trends and
-- describe a past period as it was (agents only report their current state).
CREATE TABLE endpoint_posture_snapshots (
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  day              date NOT NULL,
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  fact             jsonb NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, day)
);
ALTER TABLE endpoint_posture_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoint_posture_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON endpoint_posture_snapshots
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
