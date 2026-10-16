-- Patch Compliance: update status reported with the host inventory, and per computer the time
-- security updates started waiting (cleared when none are left) and the last grade (to alert on
-- the change into "breached" once).
ALTER TABLE agent_inventory ADD COLUMN patches jsonb;
ALTER TABLE agents ADD COLUMN security_pending_since timestamptz;
ALTER TABLE agents ADD COLUMN patch_state text;
