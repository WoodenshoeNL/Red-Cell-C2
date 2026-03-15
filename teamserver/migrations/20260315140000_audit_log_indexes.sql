-- Composite indexes to accelerate filtered audit-log queries on operator, action,
-- and agent dimensions combined with timestamp range scans.
--
-- Queries that filter on (actor + occurred_at range) now hit this index directly
-- rather than performing a full table scan followed by a sort.
CREATE INDEX IF NOT EXISTS idx_ts_audit_log_actor_ts
    ON ts_audit_log (actor, occurred_at);

-- Queries that filter on (action label + occurred_at range) use this index,
-- including the action_in filter path used by session-activity queries.
CREATE INDEX IF NOT EXISTS idx_ts_audit_log_action_ts
    ON ts_audit_log (action, occurred_at);

-- agent_id is stored inside the JSON `details` column.  SQLite supports
-- expression-based indexes, so json_extract() can be indexed directly.
CREATE INDEX IF NOT EXISTS idx_ts_audit_log_agent_id_ts
    ON ts_audit_log (json_extract(details, '$.agent_id'), occurred_at);
