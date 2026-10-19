-- Every SCIAT Agent check-in finds its asset by short host name (before the first dot). Without
-- this index that lookup scans all of the organization's assets on every check-in.
CREATE INDEX IF NOT EXISTS assets_short_hostname ON assets (organization_id, split_part(lower(hostname), '.', 1)) WHERE hostname IS NOT NULL;
