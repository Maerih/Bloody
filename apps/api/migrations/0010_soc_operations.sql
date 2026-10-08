-- SOC operations (API part B): detection tuning, approvals, SOAR execution state, AI action
-- links, in-app notifications and delivery dead letters, integration sync state and external
-- references, vulnerability enrichment, report files, scheduler state and the tenant directory.
-- New tenant tables enable + force row level security at the end of this file (0009 only
-- covered the tables that existed then); the migration runner re-verifies every tenant table.

-- ─── Detection tuning ─────────────────────────────────────────────────────────

CREATE TABLE detection_suppressions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  -- NULL = every organization of the tenant.
  organization_id  uuid,
  -- '*' = every rule.
  rule_id          text NOT NULL CHECK (rule_id = '*' OR rule_id ~* '^[a-z0-9][a-z0-9._:-]{2,127}$'),
  entity_kind      text,
  entity_key       text CHECK (entity_key IS NULL OR length(entity_key) BETWEEN 1 AND 2048),
  reason           text NOT NULL CHECK (length(reason) BETWEEN 3 AND 2000),
  source           text NOT NULL DEFAULT 'analyst' CHECK (source IN ('analyst', 'feedback')),
  alert_id         uuid,
  created_by       text NOT NULL,
  expires_at       timestamptz,
  revoked_at       timestamptz,
  revoked_by       text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  CHECK ((entity_kind IS NULL) = (entity_key IS NULL)),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX detection_suppressions_active ON detection_suppressions (tenant_id, rule_id) WHERE revoked_at IS NULL;
CREATE TRIGGER detection_suppressions_updated_at BEFORE UPDATE ON detection_suppressions FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Analyst verdicts per rule (precision tracking; repeated false positives auto-suppress).
CREATE TABLE detection_feedback (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  organization_id  uuid NOT NULL,
  rule_id          text NOT NULL,
  alert_id         uuid,
  verdict          text NOT NULL CHECK (verdict IN ('true_positive', 'false_positive', 'benign_positive')),
  analyst          text NOT NULL,
  entity_kind      text,
  entity_key       text,
  comment          text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, alert_id) REFERENCES alerts (tenant_id, id) ON DELETE SET NULL (alert_id)
);
CREATE INDEX detection_feedback_rule ON detection_feedback (tenant_id, rule_id, created_at DESC);
CREATE INDEX detection_feedback_entity ON detection_feedback (tenant_id, organization_id, rule_id, entity_kind, entity_key) WHERE verdict <> 'true_positive';
CREATE TRIGGER detection_feedback_updated_at BEFORE UPDATE ON detection_feedback FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ─── Approvals (ApprovalGate store, optimistic concurrency on version) ───────

CREATE TABLE approval_requests (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL,
  organization_id  uuid NOT NULL,
  kind             text NOT NULL CHECK (kind IN ('playbook_step', 'response_action', 'ai_action')),
  action           text NOT NULL,
  risk             text NOT NULL CHECK (risk IN ('low', 'medium', 'high')),
  status           text NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')),
  requested_by     text NOT NULL,
  -- Full @bloody/automation ApprovalRequest (subject, votes, gate reasons…).
  record           jsonb NOT NULL,
  version          integer NOT NULL CHECK (version >= 1),
  expires_at       timestamptz NOT NULL,
  decided_at       timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX approval_requests_pending ON approval_requests (tenant_id, organization_id, created_at) WHERE status = 'pending';
CREATE INDEX approval_requests_expiry ON approval_requests (expires_at) WHERE status = 'pending';
CREATE TRIGGER approval_requests_updated_at BEFORE UPDATE ON approval_requests FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ─── Response actions & SOAR execution ───────────────────────────────────────

ALTER TABLE response_actions
  ADD COLUMN approval_id      uuid,
  ADD COLUMN ai_action_id     uuid,
  ADD COLUMN playbook_run_id  uuid,
  ADD COLUMN playbook_step_id text,
  ADD COLUMN integration_id   uuid,
  ADD COLUMN started_at       timestamptz,
  ADD COLUMN finished_at      timestamptz,
  ADD COLUMN error            jsonb;
CREATE INDEX response_actions_approval ON response_actions (tenant_id, approval_id) WHERE approval_id IS NOT NULL;
CREATE UNIQUE INDEX response_actions_ai_action ON response_actions (tenant_id, ai_action_id) WHERE ai_action_id IS NOT NULL;
CREATE INDEX response_actions_incident ON response_actions (tenant_id, incident_id, created_at DESC) WHERE incident_id IS NOT NULL;

ALTER TABLE playbook_versions ADD COLUMN changes jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE playbook_runs DROP CONSTRAINT IF EXISTS playbook_runs_status_check;
ALTER TABLE playbook_runs ADD CONSTRAINT playbook_runs_status_check
  CHECK (status IN ('pending', 'running', 'waiting_approval', 'succeeded', 'partially_succeeded', 'failed', 'rejected', 'cancelled'));
ALTER TABLE playbook_runs
  ADD COLUMN playbook_name text,
  ADD COLUMN initiated_by  jsonb NOT NULL DEFAULT '{}'::jsonb,
  -- Full @bloody/automation PlaybookExecution (frozen playbook, step states, append-only log).
  ADD COLUMN execution     jsonb;
CREATE INDEX playbook_runs_playbook ON playbook_runs (tenant_id, playbook_id, started_at DESC);
CREATE INDEX playbook_runs_steps ON playbook_runs USING gin ((execution -> 'steps') jsonb_path_ops);

-- ─── AI SOC ──────────────────────────────────────────────────────────────────

ALTER TABLE ai_actions
  ADD COLUMN approval_id        uuid,
  ADD COLUMN response_action_id uuid,
  ADD COLUMN provider_id        uuid,
  ADD COLUMN risk               text CHECK (risk IS NULL OR risk IN ('low', 'medium', 'high'));
CREATE INDEX ai_actions_conversation ON ai_actions (tenant_id, conversation_id, at);

-- ─── In-app notifications (Command Center bell) & delivery dead letters ──────

CREATE TABLE notifications (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  organization_id     uuid,
  event               text NOT NULL CHECK (length(event) BETWEEN 1 AND 100),
  severity            text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  title               text NOT NULL CHECK (length(title) BETWEEN 1 AND 500),
  body                text NOT NULL DEFAULT '',
  facts               jsonb NOT NULL DEFAULT '[]'::jsonb,
  link                jsonb,
  recipient_user_ids  uuid[] NOT NULL DEFAULT '{}',
  recipient_roles     text[] NOT NULL DEFAULT '{}',
  read_by             uuid[] NOT NULL DEFAULT '{}',
  source              text NOT NULL DEFAULT 'system' CHECK (source IN ('system', 'channel')),
  subject_kind        text,
  subject_id          text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX notifications_time ON notifications (tenant_id, created_at DESC);
CREATE TRIGGER notifications_updated_at BEFORE UPDATE ON notifications FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE notification_dead_letters (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  organization_id  uuid,
  rule_id          uuid,
  channel_id       uuid NOT NULL,
  channel_kind     text NOT NULL,
  event            text NOT NULL,
  message          jsonb NOT NULL,
  error            jsonb NOT NULL,
  attempts         integer NOT NULL DEFAULT 0,
  status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'redriven', 'discarded')),
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX notification_dead_letters_status ON notification_dead_letters (tenant_id, status, created_at DESC);
CREATE TRIGGER notification_dead_letters_updated_at BEFORE UPDATE ON notification_dead_letters FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Automation throttle windows (key = "<tenant>:<rule>:<subject>").
CREATE TABLE automation_throttle (
  tenant_id          uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  key                text NOT NULL CHECK (length(key) BETWEEN 1 AND 1000),
  window_started_at  timestamptz NOT NULL,
  window_ends_at     timestamptz NOT NULL,
  suppressed         integer NOT NULL DEFAULT 0,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, key)
);
CREATE TRIGGER automation_throttle_updated_at BEFORE UPDATE ON automation_throttle FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ─── Integrations: endpoint, sync state, external references ─────────────────

ALTER TABLE integrations
  ADD COLUMN endpoint          text,
  ADD COLUMN sync_state        jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN last_sync_report  jsonb;
CREATE INDEX integrations_kind ON integrations (tenant_id, kind);

ALTER TABLE alerts ADD COLUMN external_source text, ADD COLUMN external_ref text;
CREATE UNIQUE INDEX alerts_external_ref ON alerts (tenant_id, external_source, external_ref) WHERE external_ref IS NOT NULL;
CREATE UNIQUE INDEX incidents_external_ref ON incidents (tenant_id, external_source, external_ref) WHERE external_ref IS NOT NULL;
ALTER TABLE escalations ADD COLUMN external_source text, ADD COLUMN external_ref text;
CREATE UNIQUE INDEX escalations_external_ref ON escalations (tenant_id, external_source, external_ref) WHERE external_ref IS NOT NULL;
ALTER TABLE users ADD COLUMN external_source text, ADD COLUMN external_ref text;
CREATE UNIQUE INDEX users_external_ref ON users (tenant_id, external_source, external_ref) WHERE external_ref IS NOT NULL;
-- Engine-side identifiers of an agent (Wazuh agent id, Velociraptor client id) for response actions.
ALTER TABLE agents ADD COLUMN engine_refs jsonb NOT NULL DEFAULT '{}'::jsonb;

-- ─── Threat intelligence & vulnerability enrichment ──────────────────────────

ALTER TABLE indicators
  ADD COLUMN description text,
  ADD COLUMN tlp         text CHECK (tlp IS NULL OR tlp IN ('clear', 'green', 'amber', 'amber+strict', 'red')),
  ADD COLUMN attack      jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN scoring     jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN revoked     boolean NOT NULL DEFAULT false;
CREATE INDEX indicators_external_ref ON indicators (tenant_id, external_ref) WHERE external_ref IS NOT NULL;

ALTER TABLE vulnerabilities
  ADD COLUMN kev                   jsonb,
  ADD COLUMN epss_percentile       numeric(6, 5) CHECK (epss_percentile IS NULL OR epss_percentile BETWEEN 0 AND 1),
  ADD COLUMN enrichment            jsonb,
  ADD COLUMN enriched_at           timestamptz,
  ADD COLUMN exception_reason      text,
  ADD COLUMN exception_expires_at  timestamptz;

CREATE TABLE enrichment_runs (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  sources          text[] NOT NULL,
  status           text NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
  stats            jsonb NOT NULL DEFAULT '{}'::jsonb,
  error            text,
  requested_by     text,
  started_at       timestamptz NOT NULL DEFAULT now(),
  finished_at      timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX enrichment_runs_time ON enrichment_runs (tenant_id, started_at DESC);
CREATE TRIGGER enrichment_runs_updated_at BEFORE UPDATE ON enrichment_runs FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ─── Reporting ────────────────────────────────────────────────────────────────

ALTER TABLE report_runs
  ADD COLUMN title     text,
  ADD COLUMN summary   text,
  -- Rendered file for later download (bounded by the API; large files belong in object storage).
  ADD COLUMN content   bytea,
  ADD COLUMN delivery  jsonb;
ALTER TABLE report_runs ADD FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE;
ALTER TABLE report_schedules ADD COLUMN options jsonb NOT NULL DEFAULT '{}'::jsonb;

-- ─── Scheduler ────────────────────────────────────────────────────────────────

-- Platform job bookkeeping (no tenant data): last completed tick per job.
CREATE TABLE scheduler_state (
  job           text PRIMARY KEY CHECK (job ~ '^[a-z0-9_.:-]{1,100}$'),
  last_tick_at  timestamptz,
  last_result   jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER scheduler_state_updated_at BEFORE UPDATE ON scheduler_state FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Tenant directory for platform jobs: the scheduler must enumerate tenants before it has a
-- tenant context. It holds no customer data (id, status, plan, trial end) and is maintained only
-- by a SECURITY DEFINER trigger on accounts; the runtime role can SELECT it, nothing else.
CREATE TABLE account_directory (
  account_id     uuid PRIMARY KEY,
  status         text NOT NULL,
  plan           text NOT NULL,
  trial_ends_at  timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION account_directory_sync() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    DELETE FROM account_directory WHERE account_id = OLD.id;
    RETURN OLD;
  END IF;
  INSERT INTO account_directory (account_id, status, plan, trial_ends_at)
  VALUES (NEW.id, NEW.status, NEW.plan, NEW.trial_ends_at)
  ON CONFLICT (account_id) DO UPDATE SET status = EXCLUDED.status, plan = EXCLUDED.plan, trial_ends_at = EXCLUDED.trial_ends_at, updated_at = now();
  RETURN NEW;
END $$;
CREATE TRIGGER accounts_directory AFTER INSERT OR DELETE OR UPDATE OF status, plan, trial_ends_at ON accounts
  FOR EACH ROW EXECUTE FUNCTION account_directory_sync();
REVOKE ALL ON FUNCTION account_directory_sync() FROM PUBLIC;

-- Backfill. The schema owner is exempt from RLS only while FORCE is off, so lift it for the
-- backfill inside this (transactional) migration and restore it immediately.
ALTER TABLE accounts NO FORCE ROW LEVEL SECURITY;
INSERT INTO account_directory (account_id, status, plan, trial_ends_at)
SELECT id, status, plan, trial_ends_at FROM accounts
ON CONFLICT (account_id) DO NOTHING;
ALTER TABLE accounts FORCE ROW LEVEL SECURITY;

-- ─── Row level security for the new tenant tables ────────────────────────────

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['detection_suppressions', 'detection_feedback', 'approval_requests', 'notifications', 'notification_dead_letters',
                           'automation_throttle', 'enrichment_runs']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid) '
      'WITH CHECK (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)',
      t
    );
  END LOOP;
END $$;
