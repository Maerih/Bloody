-- Break-glass response actions: executed without prior approval by a responder holding
-- response:emergency, then reviewed after the fact by a different person.
ALTER TABLE response_actions ADD COLUMN IF NOT EXISTS emergency boolean NOT NULL DEFAULT false;
ALTER TABLE response_actions ADD COLUMN IF NOT EXISTS review_status text;
ALTER TABLE response_actions ADD COLUMN IF NOT EXISTS reviewed_by text;
ALTER TABLE response_actions ADD COLUMN IF NOT EXISTS reviewed_at timestamptz;
ALTER TABLE response_actions ADD COLUMN IF NOT EXISTS review_comment text;
ALTER TABLE response_actions DROP CONSTRAINT IF EXISTS response_actions_review_check;
ALTER TABLE response_actions ADD CONSTRAINT response_actions_review_check
  CHECK ((emergency AND review_status IN ('pending', 'reviewed')) OR (NOT emergency AND review_status IS NULL));
CREATE INDEX IF NOT EXISTS response_actions_review_pending ON response_actions (tenant_id, organization_id) WHERE review_status = 'pending';
