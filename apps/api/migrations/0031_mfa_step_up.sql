-- MFA step-up: when the session last proved a second factor. Dangerous actions (emergency
-- response, approvals, role grants, API keys, password resets…) need it within a few minutes.
ALTER TABLE sessions ADD COLUMN mfa_verified_at timestamptz;
UPDATE sessions SET mfa_verified_at = created_at WHERE mfa_verified;
