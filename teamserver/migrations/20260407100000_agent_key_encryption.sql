-- Add encrypted columns for agent AES session keys.
--
-- aes_key_enc / aes_iv_enc hold AES-256-GCM encrypted blobs (base64-encoded)
-- of the raw session key and IV bytes.  The plaintext aes_key / aes_iv columns
-- are preserved for the legacy read-fallback path (rows written before this
-- migration will be re-encrypted in code on first write after upgrade).
--
-- Wire format for the new columns:
--   base64( nonce[12] || ciphertext || tag[16] )
--
-- Empty string ('') is used as the sentinel value for "not yet encrypted"
-- so that NOT NULL can be enforced without a placeholder.
ALTER TABLE ts_agents ADD COLUMN aes_key_enc TEXT NOT NULL DEFAULT '';
ALTER TABLE ts_agents ADD COLUMN aes_iv_enc  TEXT NOT NULL DEFAULT '';
