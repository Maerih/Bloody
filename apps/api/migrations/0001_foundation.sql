-- Bloody control plane — foundation helpers.
-- Proprietary. All tenant data lives in tables that carry tenant_id (hard isolation boundary)
-- and organization_id (delegated-administration boundary). Row-level security is enabled in
-- 0009_rls.sql once every table exists.

-- Tenant of the current transaction, set by the API with set_config('app.tenant_id', $1, true).
-- Returns NULL (never errors) when unset so RLS policies simply match nothing.
CREATE OR REPLACE FUNCTION app_current_tenant() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT nullif(current_setting('app.tenant_id', true), '')::uuid $$;

-- Generic updated_at maintenance.
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger
  LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END $$;

-- Placeholder uuid used where a nullable organization_id participates in a unique key.
CREATE OR REPLACE FUNCTION org_key(org uuid) RETURNS uuid
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT coalesce(org, '00000000-0000-0000-0000-000000000000'::uuid) $$;
