-- Endpoint isolation details: mode (lan | full), when, by which response action. NULL = not isolated.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS isolation jsonb;
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_isolation_mode_check;
ALTER TABLE agents ADD CONSTRAINT agents_isolation_mode_check
  CHECK (isolation IS NULL OR (isolation->>'mode') IN ('lan', 'full'));
