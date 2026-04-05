-- Agent group definitions.
CREATE TABLE IF NOT EXISTS ts_agent_groups (
    group_name TEXT PRIMARY KEY NOT NULL
);

-- Many-to-many: agents belong to zero or more named groups.
CREATE TABLE IF NOT EXISTS ts_agent_group_members (
    agent_id   INTEGER NOT NULL,
    group_name TEXT    NOT NULL,
    PRIMARY KEY (agent_id, group_name),
    FOREIGN KEY (agent_id)   REFERENCES ts_agents(agent_id)       ON DELETE CASCADE,
    FOREIGN KEY (group_name) REFERENCES ts_agent_groups(group_name) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ts_agent_group_members_group
    ON ts_agent_group_members (group_name);

-- Per-operator group restrictions.  When NO rows exist for a given operator the
-- operator retains unrestricted TaskAgents access (backwards-compatible default).
-- When one or more rows exist the operator may only task agents that belong to
-- at least one of those groups.
CREATE TABLE IF NOT EXISTS ts_operator_group_access (
    username   TEXT NOT NULL,
    group_name TEXT NOT NULL,
    PRIMARY KEY (username, group_name),
    FOREIGN KEY (group_name) REFERENCES ts_agent_groups(group_name) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ts_operator_group_access_username
    ON ts_operator_group_access (username);

-- Per-listener operator allow-lists.  When NO rows exist for a listener any
-- authenticated operator may interact with it (backwards-compatible default).
-- When one or more rows exist only the listed operators may use that listener.
CREATE TABLE IF NOT EXISTS ts_listener_allowed_operators (
    listener_name TEXT NOT NULL,
    username      TEXT NOT NULL,
    PRIMARY KEY (listener_name, username),
    FOREIGN KEY (listener_name) REFERENCES ts_listeners(name) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ts_listener_allowed_operators_username
    ON ts_listener_allowed_operators (username);
