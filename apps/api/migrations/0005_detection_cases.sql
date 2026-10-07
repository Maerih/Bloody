-- Detection content, alerts, incidents, investigations (timeline, evidence, notes, tasks),
-- escalations and threat-intelligence matches.

CREATE TABLE detection_rules (
  id               text NOT NULL CHECK (id ~* '^[a-z0-9][a-z0-9._:-]{2,127}$'),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  -- NULL = applies to every organization of the tenant.
  organization_id  uuid,
  name             text NOT NULL,
  kind             text NOT NULL CHECK (kind IN ('sigma', 'threshold', 'sequence', 'ioc')),
  version          integer NOT NULL CHECK (version >= 1),
  enabled          boolean NOT NULL DEFAULT true,
  severity         text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  -- Validated DetectionRule (engines DetectionRuleSchema).
  definition       jsonb NOT NULL,
  -- True when this row overrides (e.g. disables) a built-in rule with the same id.
  overrides_builtin boolean NOT NULL DEFAULT false,
  created_by       text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE TRIGGER detection_rules_updated_at BEFORE UPDATE ON detection_rules FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE detection_rule_versions (
  tenant_id        uuid NOT NULL,
  organization_id  uuid,
  rule_id          text NOT NULL,
  version          integer NOT NULL,
  definition       jsonb NOT NULL,
  comment          text,
  created_by       text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, rule_id, version),
  FOREIGN KEY (tenant_id, rule_id) REFERENCES detection_rules (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE alerts (
  -- Deterministic DetectionMatch id (rule, version, tenant, org, events) — idempotent persistence.
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL,
  organization_id  uuid NOT NULL,
  title            text NOT NULL,
  severity         text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  status           text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'triaged', 'suppressed', 'promoted', 'false_positive')),
  rule_id          text,
  rule_version     integer,
  rule_kind        text,
  source           text NOT NULL,
  event_ids        uuid[] NOT NULL DEFAULT '{}',
  asset_id         uuid,
  identity_id      uuid,
  incident_id      uuid,
  attack           jsonb NOT NULL DEFAULT '[]'::jsonb,
  confidence       numeric(4, 3) NOT NULL DEFAULT 0.5 CHECK (confidence BETWEEN 0 AND 1),
  risk_score       numeric(5, 2) NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  explanation      jsonb NOT NULL DEFAULT '[]'::jsonb,
  entities         jsonb NOT NULL DEFAULT '[]'::jsonb,
  indicators       jsonb NOT NULL DEFAULT '[]'::jsonb,
  first_seen_at    timestamptz NOT NULL,
  last_seen_at     timestamptz NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE SET NULL (asset_id),
  FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id) ON DELETE SET NULL (identity_id)
);
CREATE INDEX alerts_org_time ON alerts (tenant_id, organization_id, created_at DESC);
CREATE INDEX alerts_incident ON alerts (tenant_id, incident_id);
CREATE INDEX alerts_asset ON alerts (tenant_id, asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX alerts_rule ON alerts (tenant_id, rule_id, created_at DESC);
CREATE TRIGGER alerts_updated_at BEFORE UPDATE ON alerts FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Per-tenant incident numbering (INC-1, INC-2, … per tenant), allocated transactionally.
CREATE TABLE incident_counters (
  tenant_id    uuid PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
  last_number  bigint NOT NULL DEFAULT 0,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION next_incident_number(p_tenant uuid) RETURNS bigint
  LANGUAGE sql
AS $$
  INSERT INTO incident_counters AS c (tenant_id, last_number) VALUES (p_tenant, 1)
  ON CONFLICT (tenant_id) DO UPDATE SET last_number = c.last_number + 1, updated_at = now()
  RETURNING last_number
$$;

CREATE TABLE incidents (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL,
  organization_id     uuid NOT NULL,
  number              bigint NOT NULL,
  title               text NOT NULL CHECK (length(title) BETWEEN 3 AND 300),
  summary             text,
  severity            text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  status              text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'triage', 'investigating', 'contained', 'remediated', 'closed', 'false_positive')),
  risk_score          numeric(5, 2) NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  risk                jsonb,
  assignee_id         uuid,
  attack              jsonb NOT NULL DEFAULT '[]'::jsonb,
  alert_count         integer NOT NULL DEFAULT 0,
  asset_ids           uuid[] NOT NULL DEFAULT '{}',
  identity_ids        uuid[] NOT NULL DEFAULT '{}',
  source              text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'correlation', 'integration')),
  correlation_id      text,
  correlation_keys    text[] NOT NULL DEFAULT '{}',
  correlation_revision integer NOT NULL DEFAULT 0,
  escalation_reasons  text[] NOT NULL DEFAULT '{}',
  merged_into         uuid,
  first_seen_at       timestamptz,
  last_seen_at        timestamptz,
  detected_at         timestamptz NOT NULL DEFAULT now(),
  acknowledged_at     timestamptz,
  contained_at        timestamptz,
  remediated_at       timestamptz,
  closed_at           timestamptz,
  created_by          text,
  external_source     text,
  external_ref        text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, number),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, assignee_id) REFERENCES users (tenant_id, id) ON DELETE SET NULL (assignee_id)
);
CREATE UNIQUE INDEX incidents_correlation ON incidents (tenant_id, correlation_id) WHERE correlation_id IS NOT NULL;
CREATE INDEX incidents_org_status ON incidents (tenant_id, organization_id, status, detected_at DESC);
CREATE INDEX incidents_detected ON incidents (tenant_id, detected_at DESC);
CREATE INDEX incidents_keys ON incidents USING gin (correlation_keys);
CREATE TRIGGER incidents_updated_at BEFORE UPDATE ON incidents FOR EACH ROW EXECUTE FUNCTION set_updated_at();

ALTER TABLE alerts ADD FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents (tenant_id, id) ON DELETE SET NULL (incident_id);

CREATE TABLE incident_alerts (
  incident_id      uuid NOT NULL,
  alert_id         uuid NOT NULL,
  tenant_id        uuid NOT NULL,
  organization_id  uuid NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (incident_id, alert_id),
  FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, alert_id) REFERENCES alerts (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX incident_alerts_alert ON incident_alerts (tenant_id, alert_id);

CREATE TABLE investigations (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  organization_id  uuid NOT NULL,
  incident_id      uuid,
  title            text NOT NULL CHECK (length(title) BETWEEN 3 AND 300),
  status           text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'awaiting_customer', 'closed')),
  lead_id          uuid,
  hypothesis       text,
  closed_at        timestamptz,
  created_by       text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents (tenant_id, id) ON DELETE SET NULL (incident_id),
  FOREIGN KEY (tenant_id, lead_id) REFERENCES users (tenant_id, id) ON DELETE SET NULL (lead_id)
);
CREATE INDEX investigations_org ON investigations (tenant_id, organization_id, created_at DESC);
CREATE INDEX investigations_incident ON investigations (tenant_id, incident_id);
CREATE TRIGGER investigations_updated_at BEFORE UPDATE ON investigations FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE timeline_entries (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL,
  organization_id   uuid NOT NULL,
  investigation_id  uuid NOT NULL,
  kind              text NOT NULL CHECK (kind IN ('event', 'alert', 'note', 'action', 'evidence', 'ai', 'status_change')),
  at                timestamptz NOT NULL DEFAULT now(),
  actor_id          text,
  title             text NOT NULL CHECK (length(title) BETWEEN 1 AND 500),
  body              text,
  ref_id            text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, investigation_id) REFERENCES investigations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX timeline_entries_investigation ON timeline_entries (tenant_id, investigation_id, at);
CREATE TRIGGER timeline_entries_updated_at BEFORE UPDATE ON timeline_entries FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE evidence (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL,
  organization_id   uuid NOT NULL,
  investigation_id  uuid NOT NULL,
  name              text NOT NULL CHECK (length(name) BETWEEN 1 AND 500),
  kind              text NOT NULL CHECK (kind IN ('file', 'memory', 'disk_artifact', 'log_export', 'pcap', 'screenshot', 'note')),
  sha256            text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  size_bytes        bigint NOT NULL CHECK (size_bytes >= 0),
  storage_ref       text NOT NULL,
  tags              text[] NOT NULL DEFAULT '{}',
  collected_by      text NOT NULL,
  -- Append-only chain of custody: [{at, actor, action, hash}], each hash chains the previous.
  custody           jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(custody) = 'array'),
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, investigation_id) REFERENCES investigations (tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX evidence_investigation ON evidence (tenant_id, investigation_id, created_at);
CREATE TRIGGER evidence_updated_at BEFORE UPDATE ON evidence FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Evidence integrity: content identity is immutable and custody can only be appended to.
CREATE OR REPLACE FUNCTION evidence_integrity() RETURNS trigger
  LANGUAGE plpgsql
AS $$
DECLARE
  n integer := jsonb_array_length(OLD.custody);
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'evidence cannot be deleted' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.sha256 <> OLD.sha256 OR NEW.size_bytes <> OLD.size_bytes OR NEW.storage_ref <> OLD.storage_ref
     OR NEW.investigation_id <> OLD.investigation_id OR NEW.tenant_id <> OLD.tenant_id OR NEW.organization_id <> OLD.organization_id THEN
    RAISE EXCEPTION 'evidence content identity is immutable' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF jsonb_array_length(NEW.custody) < n
     OR (SELECT coalesce(jsonb_agg(e ORDER BY i), '[]'::jsonb) FROM jsonb_array_elements(NEW.custody) WITH ORDINALITY AS t(e, i) WHERE i <= n) <> OLD.custody THEN
    RAISE EXCEPTION 'chain of custody is append-only' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER evidence_integrity BEFORE UPDATE OR DELETE ON evidence FOR EACH ROW EXECUTE FUNCTION evidence_integrity();

-- Inline evidence content (small artifacts uploaded through the API). Larger artifacts live in
-- object storage and are referenced by evidence.storage_ref.
CREATE TABLE evidence_blobs (
  evidence_id      uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL,
  organization_id  uuid NOT NULL,
  content          bytea NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, evidence_id) REFERENCES evidence (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE notes (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL,
  organization_id   uuid NOT NULL,
  investigation_id  uuid,
  incident_id       uuid,
  author_id         text NOT NULL,
  author_label      text,
  body              text NOT NULL CHECK (length(body) BETWEEN 1 AND 20000),
  visibility        text NOT NULL DEFAULT 'internal' CHECK (visibility IN ('internal', 'customer')),
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, investigation_id) REFERENCES investigations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents (tenant_id, id) ON DELETE CASCADE,
  CHECK (investigation_id IS NOT NULL OR incident_id IS NOT NULL)
);
CREATE INDEX notes_investigation ON notes (tenant_id, investigation_id, created_at);
CREATE INDEX notes_incident ON notes (tenant_id, incident_id, created_at);
CREATE TRIGGER notes_updated_at BEFORE UPDATE ON notes FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE tasks (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL,
  organization_id   uuid NOT NULL,
  investigation_id  uuid NOT NULL,
  title             text NOT NULL CHECK (length(title) BETWEEN 1 AND 500),
  description       text,
  status            text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'done', 'cancelled')),
  assignee_id       uuid,
  due_at            timestamptz,
  completed_at      timestamptz,
  created_by        text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, investigation_id) REFERENCES investigations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, assignee_id) REFERENCES users (tenant_id, id) ON DELETE SET NULL (assignee_id)
);
CREATE INDEX tasks_investigation ON tasks (tenant_id, investigation_id, created_at);
CREATE TRIGGER tasks_updated_at BEFORE UPDATE ON tasks FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE escalations (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid NOT NULL,
  organization_id   uuid NOT NULL,
  incident_id       uuid,
  title             text NOT NULL CHECK (length(title) BETWEEN 3 AND 300),
  reason            text,
  severity          text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  status            text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
  due_at            timestamptz NOT NULL,
  acknowledged_at   timestamptz,
  acknowledged_by   text,
  resolved_at       timestamptz,
  resolved_by       text,
  resolution_note   text,
  created_by        text,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents (tenant_id, id) ON DELETE SET NULL (incident_id)
);
CREATE INDEX escalations_org_status ON escalations (tenant_id, organization_id, status, due_at);
CREATE UNIQUE INDEX escalations_incident_open ON escalations (tenant_id, incident_id) WHERE incident_id IS NOT NULL AND status <> 'resolved';
CREATE TRIGGER escalations_updated_at BEFORE UPDATE ON escalations FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE indicator_matches (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  organization_id  uuid NOT NULL,
  indicator_id     uuid NOT NULL,
  event_id         uuid NOT NULL,
  alert_id         uuid,
  asset_id         uuid,
  observed_value   text NOT NULL,
  field            text NOT NULL,
  matched_at       timestamptz NOT NULL DEFAULT now(),
  event_time       timestamptz NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, indicator_id) REFERENCES indicators (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE SET NULL (asset_id)
);
CREATE UNIQUE INDEX indicator_matches_natural ON indicator_matches (tenant_id, indicator_id, event_id, field);
CREATE INDEX indicator_matches_org_time ON indicator_matches (tenant_id, organization_id, matched_at DESC);
CREATE TRIGGER indicator_matches_updated_at BEFORE UPDATE ON indicator_matches FOR EACH ROW EXECUTE FUNCTION set_updated_at();
