-- Per-agent Archon magic value.
-- NULL for Demon agents; non-NULL for Archon agents (stored at first check-in).
ALTER TABLE ts_agents ADD COLUMN archon_magic INTEGER;
