-- Persistent Footholds: autostart entries reported by the SCIAT Agent (one row per entry per
-- computer, kept after it disappears so history is visible) and analysts' verdicts per
-- organization (the same entry on every computer is reviewed once).
CREATE TABLE agent_footholds (
  agent_id         uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  fingerprint      text NOT NULL,
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  kind             text NOT NULL,
  location         text NOT NULL,
  name             text NOT NULL,
  command          text,
  user_name        text,
  signed           boolean,
  signer           text,
  score            int NOT NULL DEFAULT 0,
  level            text NOT NULL DEFAULT 'low',
  reasons          jsonb NOT NULL DEFAULT '[]'::jsonb,
  -- Present in the computer's first report (its baseline) rather than added later.
  baseline         boolean NOT NULL DEFAULT false,
  present          boolean NOT NULL DEFAULT true,
  first_seen       timestamptz NOT NULL DEFAULT now(),
  last_seen        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (agent_id, fingerprint)
);
CREATE INDEX agent_footholds_org_idx ON agent_footholds (organization_id, fingerprint) WHERE present;
ALTER TABLE agent_footholds ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_footholds FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_footholds
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- When the agent first reported its autostart entries (everything in that report is baseline).
ALTER TABLE agents ADD COLUMN footholds_baselined_at timestamptz;

CREATE TABLE foothold_verdicts (
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  fingerprint      text NOT NULL,
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  verdict          text NOT NULL CHECK (verdict IN ('expected', 'malicious')),
  note             text,
  decided_by       text,
  decided_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, fingerprint)
);
ALTER TABLE foothold_verdicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE foothold_verdicts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON foothold_verdicts
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
