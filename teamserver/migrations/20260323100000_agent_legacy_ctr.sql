-- Legacy Demon/Archon agents reset AES-CTR to block 0 for every packet.
-- When legacy_ctr = 1 the teamserver mirrors that behaviour (offset always 0).
-- Default is 1 (legacy mode) for backward compatibility with existing Demon agents.
ALTER TABLE ts_agents ADD COLUMN legacy_ctr INTEGER NOT NULL DEFAULT 1;
