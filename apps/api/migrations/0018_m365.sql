-- Microsoft 365 hardening: one read-only Graph connection per organization (client secret in the
-- sealed secret store) and the history of posture assessments.
CREATE TABLE m365_connections (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id            uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id      uuid NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  directory_tenant_id  text NOT NULL,
  client_id            text NOT NULL,
  credential_ref       text NOT NULL,
  display_name         text,
  status               text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'connected', 'error')),
  last_error           text,
  last_assessed_at     timestamptz,
  last_score           integer,
  created_by           text,
  created_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE m365_assessments (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  connection_id    uuid NOT NULL REFERENCES m365_connections(id) ON DELETE CASCADE,
  tenant_name      text,
  started_at       timestamptz NOT NULL,
  finished_at      timestamptz NOT NULL,
  score            integer NOT NULL CHECK (score BETWEEN 0 AND 100),
  counts           jsonb NOT NULL,
  results          jsonb NOT NULL
);
CREATE INDEX m365_assessments_org ON m365_assessments (tenant_id, organization_id, finished_at DESC);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['m365_connections', 'm365_assessments'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)$p$, t);
  END LOOP;
END $$;
