-- Tenancy, identity & access, sessions, API keys and the append-only audit log.

CREATE TABLE accounts (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name           text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  slug           text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9-]{2,63}$'),
  kind           text NOT NULL CHECK (kind IN ('mssp', 'enterprise')),
  plan           text NOT NULL DEFAULT 'trial' CHECK (plan IN ('trial', 'essentials', 'professional', 'enterprise', 'mssp')),
  data_region    text NOT NULL DEFAULT 'eu-west',
  status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'closed')),
  trial_ends_at  timestamptz,
  settings       jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER accounts_updated_at BEFORE UPDATE ON accounts FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE organizations (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id               uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  parent_organization_id  uuid,
  name                    text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  slug                    text NOT NULL CHECK (slug ~ '^[a-z0-9-]{2,63}$'),
  retention_days          integer NOT NULL DEFAULT 90 CHECK (retention_days BETWEEN 1 AND 3650),
  plan                    text CHECK (plan IN ('trial', 'essentials', 'professional', 'enterprise', 'mssp')),
  mrr                     numeric(14, 2) NOT NULL DEFAULT 0 CHECK (mrr >= 0),
  industry                text,
  status                  text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'onboarding', 'suspended', 'offboarded')),
  external_source         text,
  external_ref            text,
  settings                jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, slug),
  FOREIGN KEY (tenant_id, parent_organization_id) REFERENCES organizations (tenant_id, id),
  CHECK (parent_organization_id IS NULL OR parent_organization_id <> id)
);
CREATE UNIQUE INDEX organizations_external_ref ON organizations (tenant_id, external_source, external_ref) WHERE external_ref IS NOT NULL;
CREATE TRIGGER organizations_updated_at BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE users (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  -- Home organization for customer users; NULL for MSSP/tenant staff.
  organization_id     uuid,
  email               text NOT NULL CHECK (email = lower(email) AND email ~ '^[^@\s]+@[^@\s]+$'),
  display_name        text,
  title               text,
  status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'invited', 'disabled')),
  mfa_enabled         boolean NOT NULL DEFAULT false,
  failed_login_count  integer NOT NULL DEFAULT 0,
  locked_until        timestamptz,
  last_login_at       timestamptz,
  oidc_subject        text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, email),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id)
);
CREATE UNIQUE INDEX users_oidc_subject ON users (tenant_id, oidc_subject) WHERE oidc_subject IS NOT NULL;
CREATE TRIGGER users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE user_credentials (
  user_id              uuid PRIMARY KEY,
  tenant_id            uuid NOT NULL,
  organization_id      uuid,
  password_hash        text NOT NULL,
  password_changed_at  timestamptz NOT NULL DEFAULT now(),
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE TRIGGER user_credentials_updated_at BEFORE UPDATE ON user_credentials FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE mfa_totp (
  user_id          uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL,
  organization_id  uuid,
  -- Encrypted with the secret store (AES-256-GCM, versioned key).
  secret_enc       text NOT NULL,
  confirmed_at     timestamptz,
  -- Highest accepted time step: a code can never be replayed.
  last_used_step   bigint NOT NULL DEFAULT 0,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE TRIGGER mfa_totp_updated_at BEFORE UPDATE ON mfa_totp FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE teams (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  organization_id  uuid,
  name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  description      text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX teams_name ON teams (tenant_id, org_key(organization_id), lower(name));
CREATE TRIGGER teams_updated_at BEFORE UPDATE ON teams FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE team_members (
  team_id          uuid NOT NULL,
  user_id          uuid NOT NULL,
  tenant_id        uuid NOT NULL,
  organization_id  uuid,
  member_role      text NOT NULL DEFAULT 'member' CHECK (member_role IN ('member', 'lead')),
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (team_id, user_id),
  FOREIGN KEY (tenant_id, team_id) REFERENCES teams (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX team_members_user ON team_members (tenant_id, user_id);
CREATE TRIGGER team_members_updated_at BEFORE UPDATE ON team_members FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE api_keys (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  -- When set the key can only ever act inside this organization.
  organization_id  uuid,
  name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  prefix           text NOT NULL UNIQUE CHECK (prefix ~ '^[a-z0-9]{12}$'),
  key_hash         text NOT NULL CHECK (key_hash ~ '^[0-9a-f]{64}$'),
  created_by       uuid,
  last_used_at     timestamptz,
  last_used_ip     text,
  expires_at       timestamptz,
  revoked_at       timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE TRIGGER api_keys_updated_at BEFORE UPDATE ON api_keys FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Role bindings for users, teams and API keys. organization_id NULL = tenant-wide.
CREATE TABLE role_bindings (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  principal_kind   text NOT NULL CHECK (principal_kind IN ('user', 'team', 'api_key')),
  principal_id     uuid NOT NULL,
  role             text NOT NULL CHECK (role IN ('platform_admin', 'mssp_admin', 'org_admin', 'ciso', 'executive', 'soc_analyst_t1',
                                                 'soc_analyst_t2', 'threat_hunter', 'incident_responder', 'security_engineer',
                                                 'customer_viewer', 'api_service')),
  organization_id  uuid,
  created_by       uuid,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, organization_id) REFERENCES organizations (tenant_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX role_bindings_unique ON role_bindings (tenant_id, principal_kind, principal_id, role, org_key(organization_id));
CREATE INDEX role_bindings_principal ON role_bindings (tenant_id, principal_kind, principal_id);
CREATE TRIGGER role_bindings_updated_at BEFORE UPDATE ON role_bindings FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE sessions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL,
  organization_id  uuid,
  user_id          uuid NOT NULL,
  -- sha256 of the rotating refresh secret carried by the bloody_session cookie.
  secret_hash      text NOT NULL CHECK (secret_hash ~ '^[0-9a-f]{64}$'),
  auth_method      text NOT NULL DEFAULT 'password' CHECK (auth_method IN ('password', 'oidc')),
  mfa_verified     boolean NOT NULL DEFAULT false,
  ip               text,
  user_agent       text,
  last_seen_at     timestamptz NOT NULL DEFAULT now(),
  idle_expires_at  timestamptz NOT NULL,
  expires_at       timestamptz NOT NULL,
  revoked_at       timestamptz,
  revoked_reason   text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX sessions_user ON sessions (tenant_id, user_id) WHERE revoked_at IS NULL;
CREATE TRIGGER sessions_updated_at BEFORE UPDATE ON sessions FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ─── Pre-authentication directory ─────────────────────────────────────────────
-- The one privileged path the runtime role has: resolve a login e-mail or an API-key prefix
-- to its tenant BEFORE a tenant context exists. It holds no customer data — only sha256
-- digests of the lookup value — and the runtime role can only SELECT it. Rows are maintained
-- exclusively by SECURITY DEFINER triggers on users / api_keys.
CREATE TABLE auth_lookup (
  lookup_hash  text PRIMARY KEY CHECK (lookup_hash ~ '^[0-9a-f]{64}$'),
  kind         text NOT NULL CHECK (kind IN ('user_email', 'api_key')),
  tenant_id    uuid NOT NULL,
  subject_id   uuid NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX auth_lookup_subject ON auth_lookup (subject_id);

CREATE OR REPLACE FUNCTION auth_lookup_digest(kind text, value text) RETURNS text
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$ SELECT encode(sha256(convert_to(kind || ':' || value, 'UTF8')), 'hex') $$;

CREATE OR REPLACE FUNCTION users_auth_lookup_sync() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
AS $$
BEGIN
  IF TG_OP IN ('UPDATE', 'DELETE') THEN
    DELETE FROM auth_lookup WHERE kind = 'user_email' AND subject_id = OLD.id;
  END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    -- Login e-mails are globally unique: a duplicate raises unique_violation (23505).
    INSERT INTO auth_lookup (lookup_hash, kind, tenant_id, subject_id)
    VALUES (auth_lookup_digest('user_email', NEW.email), 'user_email', NEW.tenant_id, NEW.id);
    RETURN NEW;
  END IF;
  RETURN OLD;
END $$;
CREATE TRIGGER users_auth_lookup AFTER INSERT OR DELETE OR UPDATE OF email ON users
  FOR EACH ROW EXECUTE FUNCTION users_auth_lookup_sync();

CREATE OR REPLACE FUNCTION api_keys_auth_lookup_sync() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    DELETE FROM auth_lookup WHERE kind = 'api_key' AND subject_id = OLD.id;
    RETURN OLD;
  END IF;
  INSERT INTO auth_lookup (lookup_hash, kind, tenant_id, subject_id)
  VALUES (auth_lookup_digest('api_key', NEW.prefix), 'api_key', NEW.tenant_id, NEW.id);
  RETURN NEW;
END $$;
CREATE TRIGGER api_keys_auth_lookup AFTER INSERT OR DELETE ON api_keys
  FOR EACH ROW EXECUTE FUNCTION api_keys_auth_lookup_sync();

-- ─── Audit log (append-only, hash-chained per tenant) ─────────────────────────
CREATE TABLE audit_log (
  id               uuid NOT NULL DEFAULT gen_random_uuid(),
  seq              bigint NOT NULL DEFAULT 0,
  tenant_id        uuid NOT NULL,
  organization_id  uuid,
  actor_kind       text NOT NULL CHECK (actor_kind IN ('user', 'service', 'system', 'anonymous')),
  actor_id         text,
  actor_label      text,
  action           text NOT NULL CHECK (length(action) BETWEEN 1 AND 200),
  target_kind      text,
  target_id        text,
  outcome          text NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
  ip               text,
  user_agent       text,
  request_id       text,
  details          jsonb NOT NULL DEFAULT '{}'::jsonb,
  at               timestamptz NOT NULL DEFAULT now(),
  prev_hash        text,
  hash             text NOT NULL DEFAULT '',
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id)
);
CREATE SEQUENCE audit_log_seq AS bigint;
CREATE UNIQUE INDEX audit_log_tenant_seq ON audit_log (tenant_id, seq);
CREATE INDEX audit_log_tenant_at ON audit_log (tenant_id, at DESC);
CREATE INDEX audit_log_target ON audit_log (tenant_id, target_kind, target_id);

CREATE OR REPLACE FUNCTION audit_log_row_digest(prev text, r audit_log) RETURNS text
  LANGUAGE sql STABLE
AS $$
  SELECT encode(sha256(convert_to(concat_ws('|',
    coalesce(prev, ''), r.seq::text, r.id::text, r.tenant_id::text, coalesce(r.organization_id::text, ''),
    r.actor_kind, coalesce(r.actor_id, ''), r.action, coalesce(r.target_kind, ''), coalesce(r.target_id, ''),
    r.outcome, coalesce(r.request_id, ''), to_char(r.at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    r.details::text), 'UTF8')), 'hex')
$$;

-- Serialize per tenant, assign a gap-free-ordered seq and chain the hash to the previous row.
CREATE OR REPLACE FUNCTION audit_log_chain() RETURNS trigger
  LANGUAGE plpgsql
AS $$
DECLARE
  prev text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('bloody.audit.' || NEW.tenant_id::text, 0));
  SELECT a.hash INTO prev FROM audit_log a WHERE a.tenant_id = NEW.tenant_id ORDER BY a.seq DESC LIMIT 1;
  NEW.seq := nextval('audit_log_seq');
  NEW.prev_hash := prev;
  NEW.created_at := now();
  NEW.updated_at := NEW.created_at;
  NEW.hash := audit_log_row_digest(prev, NEW);
  RETURN NEW;
END $$;
CREATE TRIGGER audit_log_chain BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_log_chain();

CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger
  LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only (% rejected)', TG_OP USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

-- Verify a tenant's chain; returns the seq of the first row whose hash does not verify (NULL = intact).
CREATE OR REPLACE FUNCTION audit_log_verify(p_tenant uuid) RETURNS bigint
  LANGUAGE plpgsql STABLE
AS $$
DECLARE
  r audit_log;
  prev text := NULL;
BEGIN
  FOR r IN SELECT * FROM audit_log WHERE tenant_id = p_tenant ORDER BY seq LOOP
    IF r.prev_hash IS DISTINCT FROM prev OR r.hash <> audit_log_row_digest(prev, r) THEN
      RETURN r.seq;
    END IF;
    prev := r.hash;
  END LOOP;
  RETURN NULL;
END $$;
