-- Response actions & SOAR, AI SOC, integrations, secret store, notifications, reporting.

CREATE TABLE response_actions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  organization_id  uuid NOT NULL,
  incident_id      uuid,
  action           text NOT NULL,
  target           jsonb NOT NULL,
  parameters       jsonb NOT NULL DEFAULT '{}'::jsonb,
  reason           text NOT NULL,
  status           text NOT NULL DEFAULT 'pending_approval' CHECK (status IN ('pending_approval', 'approved', 'rejected', 'queued', 'running', 'succeeded', 'failed', 'cancelled')),
  risk             text NOT NULL DEFAULT 'low' CHECK (risk IN ('low', 'medium', 'high')),
  requested_by     text NOT NULL,
  requested_via    text NOT NULL DEFAULT 'user' CHECK (requested_via IN ('user', 'playbook', 'ai')),
  approved_by      text,
  decided_at       timestamptz,
  decision_comment text,
  executor         text,
  result           jsonb,
  idempotency_key  text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents (tenant_id, id) ON DELETE SET NULL (incident_id)
);
CREATE UNIQUE INDEX response_actions_idempotency ON response_actions (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX response_actions_status ON response_actions (tenant_id, organization_id, status, created_at DESC);
CREATE TRIGGER response_actions_updated_at BEFORE UPDATE ON response_actions FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE playbooks (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  -- NULL = global MSSP playbook (overridable per organization by name).
  organization_id  uuid,
  name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  description      text,
  version          integer NOT NULL DEFAULT 1 CHECK (version >= 1),
  enabled          boolean NOT NULL DEFAULT true,
  trigger          jsonb NOT NULL,
  conditions       jsonb NOT NULL DEFAULT '[]'::jsonb,
  steps            jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_by       text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX playbooks_name ON playbooks (tenant_id, org_key(organization_id), lower(name));
CREATE TRIGGER playbooks_updated_at BEFORE UPDATE ON playbooks FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE playbook_versions (
  tenant_id        uuid NOT NULL,
  organization_id  uuid,
  playbook_id      uuid NOT NULL,
  version          integer NOT NULL,
  definition       jsonb NOT NULL,
  comment          text,
  created_by       text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, playbook_id, version),
  FOREIGN KEY (tenant_id, playbook_id) REFERENCES playbooks (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE playbook_runs (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL,
  organization_id   uuid NOT NULL,
  playbook_id       uuid NOT NULL,
  playbook_version  integer NOT NULL,
  status            text NOT NULL CHECK (status IN ('pending', 'running', 'waiting_approval', 'succeeded', 'failed', 'cancelled')),
  trigger_event     text NOT NULL,
  subject           jsonb NOT NULL DEFAULT '{}'::jsonb,
  snapshot          jsonb,
  log               jsonb NOT NULL DEFAULT '[]'::jsonb,
  state_version     integer NOT NULL DEFAULT 0,
  idempotency_key   text,
  started_at        timestamptz NOT NULL DEFAULT now(),
  finished_at       timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, playbook_id) REFERENCES playbooks (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX playbook_runs_idempotency ON playbook_runs (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX playbook_runs_org_time ON playbook_runs (tenant_id, organization_id, started_at DESC);
CREATE TRIGGER playbook_runs_updated_at BEFORE UPDATE ON playbook_runs FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE secrets (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  organization_id  uuid,
  -- Opaque reference handed to other records (credentialRef); the plaintext never leaves the API.
  ref              text NOT NULL,
  name             text NOT NULL,
  purpose          text NOT NULL DEFAULT 'generic',
  key_version      integer NOT NULL,
  ciphertext       text NOT NULL,
  created_by       text,
  rotated_at       timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, ref),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE TRIGGER secrets_updated_at BEFORE UPDATE ON secrets FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE ai_providers (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  organization_id       uuid,
  name                  text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  kind                  text NOT NULL CHECK (kind IN ('ollama', 'vllm', 'lmstudio', 'openai_compatible', 'openai', 'anthropic', 'google', 'azure_openai', 'aws_bedrock', 'mistral')),
  endpoint              text,
  model                 text NOT NULL,
  credential_ref        text,
  context_window        integer NOT NULL DEFAULT 32768,
  temperature           numeric(3, 2) NOT NULL DEFAULT 0.2,
  max_output_tokens     integer NOT NULL DEFAULT 2048,
  system_policy         text,
  max_tool_tier         text NOT NULL DEFAULT 'recommend' CHECK (max_tool_tier IN ('read', 'investigate', 'recommend', 'require_approval', 'execute')),
  is_default            boolean NOT NULL DEFAULT false,
  fallback_provider_id  uuid,
  retention_days        integer NOT NULL DEFAULT 30,
  redact_sensitive      boolean NOT NULL DEFAULT true,
  allow_cloud_data      boolean NOT NULL DEFAULT false,
  enabled               boolean NOT NULL DEFAULT true,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, fallback_provider_id) REFERENCES ai_providers (tenant_id, id) ON DELETE SET NULL (fallback_provider_id)
);
CREATE TRIGGER ai_providers_updated_at BEFORE UPDATE ON ai_providers FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE ai_conversations (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  organization_id  uuid NOT NULL,
  principal_id     text NOT NULL,
  provider_id      uuid,
  title            text,
  context          jsonb NOT NULL DEFAULT '{}'::jsonb,
  state            jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX ai_conversations_principal ON ai_conversations (tenant_id, principal_id, updated_at DESC);
CREATE TRIGGER ai_conversations_updated_at BEFORE UPDATE ON ai_conversations FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE ai_messages (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  organization_id  uuid NOT NULL,
  conversation_id  uuid NOT NULL,
  seq              integer NOT NULL,
  role             text NOT NULL CHECK (role IN ('system', 'user', 'assistant', 'tool')),
  content          text,
  tool_calls       jsonb,
  tool_call_id     text,
  expires_at       timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, conversation_id, seq),
  FOREIGN KEY (tenant_id, conversation_id) REFERENCES ai_conversations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX ai_messages_expiry ON ai_messages (expires_at) WHERE expires_at IS NOT NULL;
CREATE TRIGGER ai_messages_updated_at BEFORE UPDATE ON ai_messages FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE ai_actions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  organization_id  uuid NOT NULL,
  conversation_id  uuid NOT NULL,
  tool             text NOT NULL,
  tier             text NOT NULL CHECK (tier IN ('read', 'investigate', 'recommend', 'require_approval', 'execute')),
  arguments        jsonb NOT NULL DEFAULT '{}'::jsonb,
  status           text NOT NULL CHECK (status IN ('completed', 'pending_approval', 'approved', 'rejected', 'denied', 'failed')),
  result           jsonb,
  requested_by     text NOT NULL,
  approved_by      text,
  at               timestamptz NOT NULL DEFAULT now(),
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, conversation_id) REFERENCES ai_conversations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX ai_actions_status ON ai_actions (tenant_id, organization_id, status, at DESC);
CREATE TRIGGER ai_actions_updated_at BEFORE UPDATE ON ai_actions FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE integrations (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  organization_id  uuid,
  kind             text NOT NULL,
  name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  config           jsonb NOT NULL DEFAULT '{}'::jsonb,
  credential_ref   text,
  enabled          boolean NOT NULL DEFAULT true,
  status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'healthy', 'degraded', 'failing', 'disabled')),
  health           jsonb NOT NULL DEFAULT '{}'::jsonb,
  last_sync_at     timestamptz,
  last_event_at    timestamptz,
  last_error       text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE TRIGGER integrations_updated_at BEFORE UPDATE ON integrations FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE notification_channels (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  organization_id  uuid,
  name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  kind             text NOT NULL CHECK (kind IN ('email', 'webhook', 'slack', 'teams', 'syslog', 'in_app')),
  config           jsonb NOT NULL DEFAULT '{}'::jsonb,
  enabled          boolean NOT NULL DEFAULT true,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE TRIGGER notification_channels_updated_at BEFORE UPDATE ON notification_channels FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE automation_rules (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  organization_id   uuid,
  name              text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  event             text NOT NULL,
  conditions        jsonb NOT NULL DEFAULT '[]'::jsonb,
  channel_ids       uuid[] NOT NULL DEFAULT '{}',
  template          jsonb NOT NULL,
  throttle_minutes  integer NOT NULL DEFAULT 0 CHECK (throttle_minutes BETWEEN 0 AND 10080),
  enabled           boolean NOT NULL DEFAULT true,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE TRIGGER automation_rules_updated_at BEFORE UPDATE ON automation_rules FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE report_schedules (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  organization_id  uuid,
  type             text NOT NULL,
  name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  cron             text NOT NULL,
  timezone         text NOT NULL DEFAULT 'UTC',
  format           text NOT NULL CHECK (format IN ('html', 'pdf', 'csv', 'json')),
  period_days      integer NOT NULL CHECK (period_days BETWEEN 1 AND 366),
  channel_ids      uuid[] NOT NULL DEFAULT '{}',
  enabled          boolean NOT NULL DEFAULT true,
  last_run_at      timestamptz,
  created_by       text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE TRIGGER report_schedules_updated_at BEFORE UPDATE ON report_schedules FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE report_runs (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  organization_id  uuid,
  schedule_id      uuid,
  type             text NOT NULL,
  format           text NOT NULL CHECK (format IN ('html', 'pdf', 'csv', 'json')),
  status           text NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
  period_from      timestamptz NOT NULL,
  period_to        timestamptz NOT NULL,
  filename         text,
  content_type     text,
  size_bytes       bigint,
  sha256           text,
  error            text,
  requested_by     text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, schedule_id) REFERENCES report_schedules (tenant_id, id) ON DELETE SET NULL (schedule_id)
);
CREATE INDEX report_runs_time ON report_runs (tenant_id, created_at DESC);
CREATE TRIGGER report_runs_updated_at BEFORE UPDATE ON report_runs FOR EACH ROW EXECUTE FUNCTION set_updated_at();
