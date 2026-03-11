ALTER TABLE ts_listeners ADD COLUMN status TEXT NOT NULL DEFAULT 'stopped';
ALTER TABLE ts_listeners ADD COLUMN last_error TEXT;
