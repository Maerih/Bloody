-- Mobile device management (Android Enterprise through Google's Android Management API).
--   android_settings          one Google Cloud service account per account (key in the sealed secret store)
--   android_enterprises       one Android Enterprise per organization + SCIAT's baseline policy
--   mobile_enrollment_tokens  QR codes / tokens handed to phones
--   mobile_devices            the phones, synced from Google; each is also an asset (kind mobile_device)

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_kind_check;
ALTER TABLE assets ADD CONSTRAINT assets_kind_check CHECK (kind IN ('endpoint', 'server', 'domain_controller', 'database', 'cloud_instance', 'cloud_storage',
  'container', 'kubernetes_cluster', 'network_device', 'application', 'saas_app', 'external_host', 'data_store', 'mobile_device'));

CREATE TABLE android_settings (
  tenant_id       uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  project_id      text NOT NULL,
  client_email    text NOT NULL,
  credential_ref  text NOT NULL,
  status          text NOT NULL DEFAULT 'ok' CHECK (status IN ('ok', 'error')),
  last_error      text,
  updated_by      text,
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE android_enterprises (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id    uuid NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  status             text NOT NULL CHECK (status IN ('pending_signup', 'active', 'error')),
  enterprise_name    text UNIQUE,
  display_name       text,
  signup_url_name    text,
  -- SHA-256 of the one-time state in the sign-up callback URL.
  signup_state_hash  text,
  signup_expires_at  timestamptz,
  policy             jsonb NOT NULL,
  policy_synced_at   timestamptz,
  last_sync_at       timestamptz,
  last_error         text,
  created_by         text,
  created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE mobile_enrollment_tokens (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  enterprise_id    uuid NOT NULL REFERENCES android_enterprises(id) ON DELETE CASCADE,
  token_name       text NOT NULL,
  value            text NOT NULL,
  qr_code          text NOT NULL,
  ownership        text NOT NULL CHECK (ownership IN ('company', 'personal')),
  assignee         text,
  expires_at       timestamptz NOT NULL,
  -- Revoked codes are kept: phones enrolled with them still map to their assignee.
  revoked_at       timestamptz,
  created_by       text,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mobile_enrollment_tokens_org ON mobile_enrollment_tokens (tenant_id, organization_id, expires_at DESC);

CREATE TABLE mobile_devices (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  asset_id              uuid REFERENCES assets(id) ON DELETE SET NULL,
  platform              text NOT NULL CHECK (platform IN ('android', 'ios')),
  external_id           text NOT NULL,
  name                  text NOT NULL,
  manufacturer          text,
  model                 text,
  serial_number         text,
  os_version            text,
  security_patch_level  text,
  ownership             text CHECK (ownership IN ('company', 'personal')),
  management_mode       text,
  assignee              text,
  user_name             text,
  state                 text NOT NULL,
  compliance            text NOT NULL CHECK (compliance IN ('compliant', 'non_compliant', 'at_risk', 'stale', 'pending')),
  findings              jsonb NOT NULL DEFAULT '[]',
  enrolled_at           timestamptz,
  last_status_at        timestamptz,
  last_sync_at          timestamptz NOT NULL DEFAULT now(),
  removed_at            timestamptz,
  UNIQUE (tenant_id, external_id)
);
CREATE INDEX mobile_devices_org ON mobile_devices (tenant_id, organization_id) WHERE removed_at IS NULL;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['android_settings', 'android_enterprises', 'mobile_enrollment_tokens', 'mobile_devices'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)$p$, t);
  END LOOP;
END $$;
