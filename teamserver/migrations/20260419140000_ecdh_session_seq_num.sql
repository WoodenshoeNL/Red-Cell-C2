-- Add monotonic sequence-number tracking to ECDH sessions.
--
-- last_seq_num stores the highest seq_num accepted from the agent for this
-- connection.  The teamserver rejects any session packet whose seq_num is not
-- strictly greater than this value, preventing packet replay attacks.
--
-- Starts at 0 so the first valid packet (seq_num = 1) is accepted.

ALTER TABLE ts_ecdh_sessions ADD COLUMN last_seq_num INTEGER NOT NULL DEFAULT 0;
