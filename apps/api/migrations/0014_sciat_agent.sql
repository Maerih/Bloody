-- SCIAT Agent enrollment: one account key per tenant (sealed for display, hashed for checks) and
-- a per-agent token (hash only) used by the agent's heartbeat.
CREATE TABLE agent_enrollment (
  tenant_id    uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  key_hash     text NOT NULL,
  key_sealed   text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  rotated_at   timestamptz,
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER agent_enrollment_updated_at BEFORE UPDATE ON agent_enrollment FOR EACH ROW EXECUTE FUNCTION set_updated_at();

ALTER TABLE agents ADD COLUMN IF NOT EXISTS agent_token_hash text;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS enrolled_at timestamptz;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS host_info jsonb;

ALTER TABLE agent_enrollment ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_enrollment FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON agent_enrollment;
CREATE POLICY tenant_isolation ON agent_enrollment
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
