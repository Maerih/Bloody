-- SCIAT Agent commands: built-in Attack Reduction fixes ("harden <check>") besides isolate / release.
ALTER TABLE agent_commands DROP CONSTRAINT agent_commands_kind_check;
ALTER TABLE agent_commands ADD CONSTRAINT agent_commands_kind_check CHECK (kind IN ('isolate', 'release', 'harden'));
