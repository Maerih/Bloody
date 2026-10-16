-- External Exposure: public addresses of each organization (learned from SCIAT Agent check-ins or
-- added by an administrator), the authorization to test them, scans and the risky ports found open.
ALTER TABLE agents ADD COLUMN public_ip text, ADD COLUMN public_ip_seen_at timestamptz;

CREATE TABLE exposure_settings (
  organization_id  uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  reference        text NOT NULL,
  authorized_by    text,
  authorized_at    timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL
);

CREATE TABLE exposure_targets (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  ip               text NOT NULL,
  source           text NOT NULL CHECK (source IN ('agent', 'manual')),
  status           text NOT NULL DEFAULT 'discovered' CHECK (status IN ('discovered', 'confirmed', 'ignored')),
  note             text,
  decided_by       text,
  decided_at       timestamptz,
  first_seen_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at     timestamptz,
  last_scanned_at  timestamptz,
  UNIQUE (organization_id, ip)
);

CREATE TABLE exposure_scans (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  status           text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'finished', 'failed')),
  trigger          text NOT NULL CHECK (trigger IN ('manual', 'schedule')),
  requested_by     text,
  started_at       timestamptz NOT NULL DEFAULT now(),
  finished_at      timestamptz,
  addresses        integer NOT NULL DEFAULT 0,
  open_ports       integer NOT NULL DEFAULT 0,
  error            text
);
-- One scan at a time per organization.
CREATE UNIQUE INDEX exposure_scans_running ON exposure_scans (organization_id) WHERE status = 'running';
CREATE INDEX exposure_scans_org ON exposure_scans (tenant_id, organization_id, started_at DESC);

CREATE TABLE exposure_ports (
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  ip               text NOT NULL,
  port             integer NOT NULL,
  first_seen_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at     timestamptz NOT NULL DEFAULT now(),
  closed_at        timestamptz,
  PRIMARY KEY (organization_id, ip, port)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['exposure_settings', 'exposure_targets', 'exposure_scans', 'exposure_ports'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)$p$, t);
  END LOOP;
END $$;
