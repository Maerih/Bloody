-- Apple (iOS / iPadOS) device management. SCIAT is itself the MDM server: devices install an
-- enrollment profile and talk to the server directly; Apple Push wakes them. Each phone is also a
-- mobile_devices row (platform 'ios') and a mobile_device asset, like Android.
--   apple_mdm_settings  one APNs MDM push certificate per account (sealed in the secret store)
--   apple_mdm_policies  the SCIAT baseline per organization (pushed as a configuration profile)
--   apple_enrollments   the enrollment profiles (.mobileconfig links) handed to devices
--   apple_devices       per-device MDM protocol state (UDID, push token, push magic)
--   apple_commands      the per-device command queue (DeviceInformation, DeviceLock, EraseDevice…)

CREATE TABLE apple_mdm_settings (
  tenant_id       uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  topic           text NOT NULL,
  subject         text,
  credential_ref  text NOT NULL,
  expires_at      timestamptz,
  status          text NOT NULL DEFAULT 'ok' CHECK (status IN ('ok', 'expired', 'error')),
  last_error      text,
  updated_by      text,
  updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE apple_mdm_policies (
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  settings         jsonb NOT NULL,
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, organization_id)
);

CREATE TABLE apple_enrollments (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  -- Per-enrollment secret embedded in the profile's check-in / server URLs.
  token            text NOT NULL UNIQUE,
  ownership        text NOT NULL CHECK (ownership IN ('company', 'personal')),
  assignee         text,
  expires_at       timestamptz NOT NULL,
  revoked_at       timestamptz,
  created_by       text,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX apple_enrollments_org ON apple_enrollments (tenant_id, organization_id, created_at DESC);

CREATE TABLE apple_devices (
  udid             text NOT NULL,
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  enrollment_id    uuid REFERENCES apple_enrollments(id) ON DELETE SET NULL,
  mobile_device_id uuid REFERENCES mobile_devices(id) ON DELETE SET NULL,
  topic            text,
  push_token       text,
  push_magic       text,
  unlock_token     bytea,
  last_seen_at     timestamptz,
  enrolled_at      timestamptz,
  unenrolled_at    timestamptz,
  PRIMARY KEY (tenant_id, udid)
);
CREATE INDEX apple_devices_org ON apple_devices (tenant_id, organization_id) WHERE unenrolled_at IS NULL;

CREATE TABLE apple_commands (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  udid             text NOT NULL,
  command_uuid     text NOT NULL,
  request_type     text NOT NULL,
  payload          text NOT NULL,
  status           text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'sent', 'acknowledged', 'error', 'not_now')),
  result           jsonb,
  error            text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  sent_at          timestamptz,
  completed_at     timestamptz,
  UNIQUE (tenant_id, command_uuid)
);
CREATE INDEX apple_commands_queue ON apple_commands (tenant_id, udid, created_at) WHERE status IN ('queued', 'sent', 'not_now');

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['apple_mdm_settings', 'apple_mdm_policies', 'apple_enrollments', 'apple_devices', 'apple_commands'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)$p$, t);
  END LOOP;
END $$;
