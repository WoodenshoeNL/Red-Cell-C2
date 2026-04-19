-- ECDH session store for Phantom and Specter new-protocol agents.
--
-- ts_listener_keypairs: one X25519 keypair per listener (generated at first start,
-- persisted so agents can reconnect after server restarts).
--
-- ts_ecdh_sessions: per-agent session negotiated during ECDH registration.
-- connection_id is the 16-byte random routing token returned to the agent and
-- included as a plaintext prefix in every subsequent session packet.

CREATE TABLE IF NOT EXISTS ts_listener_keypairs (
    listener_name TEXT PRIMARY KEY,
    -- AES-GCM encrypted X25519 secret key (base64 nonce || ciphertext || tag)
    secret_key_enc TEXT NOT NULL,
    -- Base64 X25519 public key (sent to agents at build time)
    public_key TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS ts_ecdh_sessions (
    -- 16-byte random routing token
    connection_id BLOB PRIMARY KEY,
    agent_id INTEGER NOT NULL,
    -- AES-GCM encrypted AES-256-GCM session key (base64 nonce || ciphertext || tag)
    session_key_enc TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    last_seen INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_ecdh_sessions_agent_id ON ts_ecdh_sessions(agent_id);
