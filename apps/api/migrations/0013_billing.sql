-- Commercial billing: profile, subscriptions (pricing model per product), payment methods
-- (provider tokens only — card numbers never reach Bloody), invoices and payment-provider events.

CREATE TABLE billing_profiles (
  tenant_id   uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  profile     jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER billing_profiles_updated_at BEFORE UPDATE ON billing_profiles FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE billing_subscriptions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  product     text NOT NULL CHECK (product IN ('edr', 'itdr', 'siem')),
  model       text NOT NULL CHECK (model IN ('payg', 'monthly_commit', 'annual', 'mssp_partner')),
  interval    text NOT NULL DEFAULT 'monthly' CHECK (interval IN ('monthly', 'annual_upfront')),
  status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'past_due', 'canceled')),
  minimum     integer NOT NULL DEFAULT 0 CHECK (minimum >= 0),
  unit_price  integer NOT NULL CHECK (unit_price >= 0),
  currency    text NOT NULL,
  starts_at   timestamptz NOT NULL DEFAULT now(),
  ends_at     timestamptz,
  auto_renew  boolean NOT NULL DEFAULT true,
  quote       jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by  text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
-- One live subscription per product and account.
CREATE UNIQUE INDEX billing_subscriptions_live ON billing_subscriptions (tenant_id, product) WHERE status <> 'canceled';
CREATE TRIGGER billing_subscriptions_updated_at BEFORE UPDATE ON billing_subscriptions FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE payment_methods (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  kind          text NOT NULL CHECK (kind IN ('card', 'paypal', 'crypto', 'bank_transfer')),
  provider      text NOT NULL CHECK (provider IN ('paddle', 'stripe', 'nowpayments', 'btcpay', 'bank_transfer')),
  label         text NOT NULL,
  brand         text,
  last4         text CHECK (last4 IS NULL OR last4 ~ '^[0-9]{4}$'),
  exp_month     integer CHECK (exp_month IS NULL OR exp_month BETWEEN 1 AND 12),
  exp_year      integer,
  -- Opaque token / customer reference at the provider. Never a card number.
  provider_ref  text,
  is_default    boolean NOT NULL DEFAULT false,
  status        text NOT NULL DEFAULT 'active' CHECK (status IN ('pending', 'active', 'removed')),
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX payment_methods_one_default ON payment_methods (tenant_id) WHERE is_default AND status = 'active';
CREATE TRIGGER payment_methods_updated_at BEFORE UPDATE ON payment_methods FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE invoices (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  number        text NOT NULL,
  period_start  timestamptz NOT NULL,
  period_end    timestamptz NOT NULL,
  currency      text NOT NULL,
  lines         jsonb NOT NULL DEFAULT '[]'::jsonb,
  total         bigint NOT NULL CHECK (total >= 0),
  status        text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'paid', 'void')),
  due_at        timestamptz NOT NULL,
  paid_at       timestamptz,
  paid_via      text CHECK (paid_via IS NULL OR paid_via IN ('paddle', 'stripe', 'nowpayments', 'btcpay', 'bank_transfer')),
  provider_ref  text,
  payment_url   text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, number),
  -- Generating the same period twice can never double-bill.
  UNIQUE (tenant_id, period_start, period_end)
);
CREATE INDEX invoices_open ON invoices (tenant_id, due_at) WHERE status = 'open';
CREATE TRIGGER invoices_updated_at BEFORE UPDATE ON invoices FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Verified provider webhooks, once each (redelivery is a no-op).
CREATE TABLE payment_events (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  provider           text NOT NULL,
  provider_event_id  text NOT NULL,
  kind               text NOT NULL,
  payload            jsonb NOT NULL,
  received_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_event_id)
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['billing_profiles', 'billing_subscriptions', 'payment_methods', 'invoices', 'payment_events']
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
