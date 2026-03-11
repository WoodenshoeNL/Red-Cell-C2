CREATE TABLE IF NOT EXISTS ts_agent_responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL,
    command_id INTEGER NOT NULL,
    request_id INTEGER NOT NULL,
    response_type TEXT NOT NULL,
    message TEXT NOT NULL,
    output TEXT NOT NULL,
    command_line TEXT,
    task_id TEXT,
    operator TEXT,
    received_at TEXT NOT NULL,
    extra TEXT,
    FOREIGN KEY (agent_id) REFERENCES ts_agents(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ts_agent_responses_agent_id ON ts_agent_responses (agent_id, id);
