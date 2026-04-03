-- Add agent_type to payload build records so the requested agent is persisted
-- and can be returned by GET /payloads/jobs/{job_id}.

ALTER TABLE ts_payload_builds ADD COLUMN agent_type TEXT NOT NULL DEFAULT 'Demon';
