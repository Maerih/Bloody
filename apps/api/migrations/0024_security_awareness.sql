-- Security Awareness Training: each organization's learners, lesson assignments, the personal
-- (token) enrolment of each learner in an assignment, and quiz results per lesson.
CREATE TABLE sat_learners (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name             text NOT NULL,
  email            text NOT NULL,
  source           text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'directory')),
  identity_id      uuid REFERENCES identities(id) ON DELETE SET NULL,
  active           boolean NOT NULL DEFAULT true,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, email)
);

CREATE TABLE sat_assignments (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  title            text NOT NULL,
  lessons          text[] NOT NULL,
  due_at           timestamptz,
  created_by       text,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sat_assignments_org ON sat_assignments (tenant_id, organization_id, created_at DESC);

CREATE TABLE sat_enrolments (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  assignment_id    uuid NOT NULL REFERENCES sat_assignments(id) ON DELETE CASCADE,
  learner_id       uuid NOT NULL REFERENCES sat_learners(id) ON DELETE CASCADE,
  -- SHA-256 of the secret part of the learner's personal link (the link itself is never stored).
  token_hash       text NOT NULL,
  invited_at       timestamptz,
  invite_error     text,
  started_at       timestamptz,
  completed_at     timestamptz,
  UNIQUE (assignment_id, learner_id)
);

CREATE TABLE sat_progress (
  enrolment_id     uuid NOT NULL REFERENCES sat_enrolments(id) ON DELETE CASCADE,
  tenant_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  lesson_key       text NOT NULL,
  best_score       integer NOT NULL,
  passed           boolean NOT NULL,
  attempts         integer NOT NULL DEFAULT 1,
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (enrolment_id, lesson_key)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['sat_learners', 'sat_assignments', 'sat_enrolments', 'sat_progress'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)$p$, t);
  END LOOP;
END $$;
