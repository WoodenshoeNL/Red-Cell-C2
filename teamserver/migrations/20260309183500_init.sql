CREATE TABLE IF NOT EXISTS ts_agents (
    agent_id INTEGER PRIMARY KEY NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    reason TEXT NOT NULL DEFAULT '',
    aes_key TEXT NOT NULL,
    aes_iv TEXT NOT NULL,
    hostname TEXT NOT NULL,
    username TEXT NOT NULL,
    domain_name TEXT NOT NULL,
    external_ip TEXT NOT NULL,
    internal_ip TEXT NOT NULL,
    process_name TEXT NOT NULL,
    base_address INTEGER NOT NULL,
    process_pid INTEGER NOT NULL,
    process_tid INTEGER NOT NULL,
    process_ppid INTEGER NOT NULL,
    process_arch TEXT NOT NULL,
    elevated INTEGER NOT NULL CHECK (elevated IN (0, 1)),
    os_version TEXT NOT NULL,
    os_arch TEXT NOT NULL,
    sleep_delay INTEGER NOT NULL,
    sleep_jitter INTEGER NOT NULL,
    kill_date INTEGER,
    working_hours INTEGER,
    first_call_in TEXT NOT NULL,
    last_call_in TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ts_agents_active ON ts_agents (active);

CREATE TABLE IF NOT EXISTS ts_listeners (
    name TEXT PRIMARY KEY NOT NULL,
    protocol TEXT NOT NULL,
    config TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ts_links (
    parent_agent_id INTEGER NOT NULL,
    link_agent_id INTEGER NOT NULL,
    PRIMARY KEY (parent_agent_id, link_agent_id),
    FOREIGN KEY (parent_agent_id) REFERENCES ts_agents(agent_id) ON DELETE CASCADE,
    FOREIGN KEY (link_agent_id) REFERENCES ts_agents(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ts_links_link_agent_id ON ts_links (link_agent_id);

CREATE TABLE IF NOT EXISTS ts_loot (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    file_path TEXT,
    size_bytes INTEGER,
    captured_at TEXT NOT NULL,
    data BLOB,
    metadata TEXT,
    FOREIGN KEY (agent_id) REFERENCES ts_agents(agent_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ts_loot_agent_id ON ts_loot (agent_id);

CREATE TABLE IF NOT EXISTS ts_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_id TEXT,
    details TEXT,
    occurred_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ts_audit_log_occurred_at ON ts_audit_log (occurred_at);
