-- Commercial platform: entitlements, usage metering, saved views.

CREATE TABLE entitlements (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  -- NULL = tenant-wide entitlement; set for per-customer module grants in MSSP accounts.
  organization_id  uuid,
  module           text NOT NULL,
  state            text NOT NULL CHECK (state IN ('active', 'trial', 'trial_ended', 'available', 'locked')),
  trial_ends_at    timestamptz,
  uninstall_at     timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX entitlements_unique ON entitlements (tenant_id, org_key(organization_id), module);
CREATE TRIGGER entitlements_updated_at BEFORE UPDATE ON entitlements FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE usage_counters (
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  organization_id  uuid,
  metric           text NOT NULL CHECK (metric ~ '^[a-z0-9_.]{2,64}$'),
  period_start     date NOT NULL,
  value            bigint NOT NULL DEFAULT 0 CHECK (value >= 0),
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX usage_counters_unique ON usage_counters (tenant_id, org_key(organization_id), metric, period_start);
CREATE TRIGGER usage_counters_updated_at BEFORE UPDATE ON usage_counters FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE saved_views (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  organization_id  uuid,
  user_id          uuid NOT NULL,
  scope            text NOT NULL CHECK (scope ~ '^[a-z0-9_.:/-]{1,100}$'),
  name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  state            jsonb NOT NULL DEFAULT '{}'::jsonb,
  shared           boolean NOT NULL DEFAULT false,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX saved_views_name ON saved_views (tenant_id, user_id, scope, lower(name));
CREATE TRIGGER saved_views_updated_at BEFORE UPDATE ON saved_views FOR EACH ROW EXECUTE FUNCTION set_updated_at();
