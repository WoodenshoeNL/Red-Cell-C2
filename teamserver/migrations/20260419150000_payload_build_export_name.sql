-- ARC-12: store the per-build randomized DLL export name for Archon payloads
-- so callers can retrieve it and invoke the correct export rather than the
-- well-known (flagged) "Start" identifier.
ALTER TABLE ts_payload_builds ADD COLUMN export_name TEXT;
