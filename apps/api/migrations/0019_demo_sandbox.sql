-- Demo sandbox: a read-only "demo_viewer" role and sandbox sessions (a visitor's own session is
-- kept aside and restored on "Return to My Account").
ALTER TABLE role_bindings DROP CONSTRAINT IF EXISTS role_bindings_role_check;
ALTER TABLE role_bindings ADD CONSTRAINT role_bindings_role_check CHECK (role IN ('platform_admin', 'mssp_admin', 'org_admin', 'ciso', 'executive', 'soc_analyst_t1',
  'soc_analyst_t2', 'threat_hunter', 'incident_responder', 'security_engineer', 'customer_viewer', 'api_service', 'demo_viewer'));
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_auth_method_check;
ALTER TABLE sessions ADD CONSTRAINT sessions_auth_method_check CHECK (auth_method IN ('password', 'oidc', 'sandbox'));
