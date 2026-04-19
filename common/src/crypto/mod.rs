//! Cryptography helpers for agent transport and operator WebSocket integrity.
//!
//! | Submodule | Responsibility |
//! |-----------|----------------|
//! | [`agent_transport`] | AES-256-CTR, HKDF session derivation, weak-key checks, CTR block math |
//! | [`ecdh`] | X25519 ECDH + AES-256-GCM for Phantom/Specter new-protocol agents |
//! | [`ws_hmac`] | [`WsEnvelope`], HMAC verification, constant-time compare |
//!
//! The crate root re-exports the same symbols as before this split so
//! `red_cell_common::crypto::…` remains stable.

pub mod agent_transport;
pub mod ecdh;
pub mod ws_hmac;

pub use agent_transport::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, AgentCryptoMaterial, CryptoError, ctr_blocks_for_len,
    decrypt_agent_data, decrypt_agent_data_at_offset, derive_session_keys,
    derive_session_keys_for_version, encrypt_agent_data, encrypt_agent_data_at_offset,
    generate_agent_crypto_material, hash_password_sha3, is_weak_aes_iv, is_weak_aes_key,
};
pub use ecdh::{
    CONNECTION_ID_LEN, ConnectionId, ECDH_REG_MIN_LEN, ECDH_RESP_MIN_LEN, ECDH_SESSION_MIN_LEN,
    EcdhError, ListenerKeypair, build_registration_packet, build_registration_response,
    extract_connection_id_candidate, open_registration_packet, open_session_packet,
    open_session_response, parse_registration_response, seal_session_packet, seal_session_response,
};
pub use ws_hmac::{WsEnvelope, WsHmacError, derive_ws_hmac_key, open_ws_frame, seal_ws_frame};
