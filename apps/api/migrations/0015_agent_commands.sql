-- Commands the platform queues for SCIAT Agents (isolate / release). The agent collects them on
-- its next check-in, runs them and reports the result; the linked response action completes then.
CREATE TABLE agent_commands (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  agent_id            uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  response_action_id  uuid REFERENCES response_actions(id) ON DELETE SET NULL,
  kind                text NOT NULL CHECK (kind IN ('isolate', 'release')),
  args                text[] NOT NULL,
  status              text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'succeeded', 'failed', 'expired')),
  attempts            integer NOT NULL DEFAULT 0,
  output              text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  delivered_at        timestamptz,
  finished_at         timestamptz,
  expires_at          timestamptz NOT NULL
);
CREATE INDEX agent_commands_open ON agent_commands (tenant_id, agent_id, created_at) WHERE status IN ('pending', 'delivered');

ALTER TABLE agent_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_commands
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
