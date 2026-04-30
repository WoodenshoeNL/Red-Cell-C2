-- Registration-packet replay cache.
--
-- Each row records the 44-byte fingerprint (ephemeral_pubkey[32] || nonce[12])
-- of a successfully verified ECDH registration packet.  A second packet with
-- the same fingerprint is a replay and is rejected before session creation.
--
-- Rows are pruned lazily on each insert: any entry whose expires_at is in the
-- past is deleted.  The TTL is set to the replay-protection window
-- (ECDH_REPLAY_WINDOW_SECS = 300 s), so the table never grows unboundedly.

CREATE TABLE IF NOT EXISTS ts_ecdh_reg_nonces (
    -- First 44 bytes of the registration packet: ephemeral_pubkey[32] || nonce[12]
    fingerprint BLOB    PRIMARY KEY,
    -- Unix timestamp after which this row may be pruned
    expires_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ecdh_reg_nonces_expires ON ts_ecdh_reg_nonces(expires_at);
