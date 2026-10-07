-- Canonical security events (Bloody Canonical Event, BCE), range-partitioned by month.
-- `doc` keeps the full validated event; hot fields are extracted into columns for filtering.

CREATE TABLE events (
  tenant_id           uuid NOT NULL,
  organization_id     uuid NOT NULL,
  id                  uuid NOT NULL,
  occurred_at         timestamptz NOT NULL,
  received_at         timestamptz NOT NULL DEFAULT now(),
  category            text NOT NULL,
  event_type          text NOT NULL,
  action              text,
  outcome             text,
  severity            text NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  risk                numeric(5, 2),
  source_kind         text NOT NULL,
  source_product      text NOT NULL,
  sensor_id           text,
  integration_id      uuid,
  asset_hostname      text,
  asset_id            uuid,
  user_name           text,
  identity_principal  text,
  src_ip              text,
  dst_ip              text,
  dns_query           text,
  process_name        text,
  file_sha256         text,
  detection_rule      text,
  attack_ids          text[] NOT NULL DEFAULT '{}',
  doc                 jsonb NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE INDEX events_org_time ON events (tenant_id, organization_id, occurred_at DESC);
CREATE INDEX events_host_time ON events (tenant_id, lower(asset_hostname), occurred_at DESC);
CREATE INDEX events_src_ip ON events (tenant_id, src_ip) WHERE src_ip IS NOT NULL;
CREATE INDEX events_dst_ip ON events (tenant_id, dst_ip) WHERE dst_ip IS NOT NULL;
CREATE INDEX events_source ON events (tenant_id, source_kind, occurred_at DESC);

-- Partition maintenance. SECURITY DEFINER so the runtime role (DML only) can make sure the
-- month of an incoming event exists without holding DDL privileges. Partitions inherit the
-- tenant RLS policy and are never granted to the runtime role directly (only via the parent).
CREATE OR REPLACE FUNCTION ensure_events_partition(p_at timestamptz) RETURNS text
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
  month_start date := date_trunc('month', p_at AT TIME ZONE 'UTC')::date;
  part text := format('events_y%sm%s', to_char(month_start, 'YYYY'), to_char(month_start, 'MM'));
BEGIN
  IF to_regclass(part) IS NOT NULL THEN
    RETURN part;
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('bloody.events.partition.' || part, 0));
  IF to_regclass(part) IS NOT NULL THEN
    RETURN part;
  END IF;
  EXECUTE format(
    'CREATE TABLE %I PARTITION OF events FOR VALUES FROM (%L) TO (%L)',
    part,
    (month_start::timestamp AT TIME ZONE 'UTC'),
    ((month_start + interval '1 month')::timestamp AT TIME ZONE 'UTC')
  );
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', part);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', part);
  EXECUTE format(
    'CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid) '
    'WITH CHECK (tenant_id = nullif(current_setting(''app.tenant_id'', true), '''')::uuid)',
    part
  );
  RETURN part;
END $$;
REVOKE ALL ON FUNCTION ensure_events_partition(timestamptz) FROM PUBLIC;

-- Pre-create a rolling window of partitions around the migration time.
DO $$
DECLARE
  i integer;
BEGIN
  FOR i IN -3..3 LOOP
    PERFORM ensure_events_partition(now() + make_interval(months => i));
  END LOOP;
END $$;
