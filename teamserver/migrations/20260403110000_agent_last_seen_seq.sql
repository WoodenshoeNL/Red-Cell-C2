-- Add replay-protection state for Specter/Archon agents.
--
-- last_seen_seq: the highest sequence number the teamserver has accepted from
--   this agent.  Incoming callbacks with seq <= last_seen_seq are rejected as
--   replays.  Default 0 means no callback has been accepted yet.
--
-- seq_protected: when 1, the teamserver expects a u64 sequence number at the
--   start of every encrypted callback payload and enforces the monotonic
--   ordering constraint above.  When 0 (default), the agent is exempt (Demon
--   and Archon are frozen and cannot be modified to emit sequence numbers).
ALTER TABLE ts_agents ADD COLUMN last_seen_seq INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ts_agents ADD COLUMN seq_protected INTEGER NOT NULL DEFAULT 0;
