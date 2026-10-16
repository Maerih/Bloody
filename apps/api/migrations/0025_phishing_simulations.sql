-- Security Awareness: phishing simulation campaigns (with the authorization they were launched
-- under) and one row per targeted learner (hash of its personal tracking link, send and click).
CREATE TABLE sat_phish_campaigns (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id               uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id         uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name                    text NOT NULL,
  template                text NOT NULL,
  auto_assign             boolean NOT NULL DEFAULT true,
  reference               text NOT NULL,
  launched_by             text,
  launched_at             timestamptz NOT NULL DEFAULT now(),
  -- Training assignment for people who click (created on the first click).
  follow_up_assignment_id uuid REFERENCES sat_assignments(id) ON DELETE SET NULL
);
CREATE INDEX sat_phish_campaigns_org ON sat_phish_campaigns (tenant_id, organization_id, launched_at DESC);

CREATE TABLE sat_phish_targets (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  campaign_id      uuid NOT NULL REFERENCES sat_phish_campaigns(id) ON DELETE CASCADE,
  learner_id       uuid NOT NULL REFERENCES sat_learners(id) ON DELETE CASCADE,
  token_hash       text NOT NULL,
  sent_at          timestamptz,
  send_error       text,
  clicked_at       timestamptz,
  click_count      integer NOT NULL DEFAULT 0,
  UNIQUE (campaign_id, learner_id)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['sat_phish_campaigns', 'sat_phish_targets'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)$p$, t);
  END LOOP;
END $$;
