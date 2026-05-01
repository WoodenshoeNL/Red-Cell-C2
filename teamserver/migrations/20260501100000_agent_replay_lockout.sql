-- Add per-agent replay-lockout columns to ts_agents.
--
-- replay_attempt_count: consecutive Replay rejections since the last accepted callback.
--   Reset to 0 on any successful seq advance or agent re-registration.
-- replay_lockout_until: Unix timestamp (seconds) when the lockout expires.
--   NULL means the agent is not currently locked out.
ALTER TABLE ts_agents ADD COLUMN replay_attempt_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ts_agents ADD COLUMN replay_lockout_until INTEGER;
