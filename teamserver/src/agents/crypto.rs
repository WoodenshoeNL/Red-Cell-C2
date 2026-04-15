//! AES-CTR transport crypto for agents: keystream offsets, encrypt/decrypt helpers,
//! and key material decoding.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use red_cell_common::AgentEncryptionInfo;
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset,
    encrypt_agent_data_at_offset, is_weak_aes_key,
};
use red_cell_common::demon::{DemonMessage, DemonPackage};
use tracing::{instrument, warn};
use zeroize::Zeroizing;

use crate::database::{DeferredWrite, TeamserverError};

use super::{AgentEntry, AgentRegistry, Job};

impl AgentRegistry {
    /// Return the current AES key and IV for an agent.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn encryption(&self, agent_id: u32) -> Result<AgentEncryptionInfo, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let info = entry.info.read().await;
        Ok(info.encryption.clone())
    }

    /// Return the current CTR block offset for an agent.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn ctr_offset(&self, agent_id: u32) -> Result<u64, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let offset = entry.ctr_block_offset.lock().await;
        Ok(*offset)
    }

    /// Set the CTR block offset for an agent (e.g. after DEMON_INIT parsing).
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id), offset))]
    pub async fn set_ctr_offset(&self, agent_id: u32, offset: u64) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;

        let deferred = DeferredWrite::AgentSetCtrOffset { agent_id, offset };
        let repo = self.repository.clone();
        self.persist_or_queue(deferred, || async move {
            repo.set_ctr_block_offset(agent_id, offset).await
        })
        .await?;

        *entry.ctr_block_offset.lock().await = offset;
        Ok(())
    }

    /// Query whether an agent uses legacy per-packet CTR reset (Demon/Archon behaviour).
    pub async fn legacy_ctr(&self, agent_id: u32) -> Result<bool, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        Ok(entry.legacy_ctr.load(Ordering::Relaxed))
    }

    /// Set the legacy CTR mode for an agent and persist the change.
    ///
    /// When `legacy` is `true`, AES-CTR resets to block offset 0 for every packet
    /// (Demon/Archon compatibility).  When `false`, the monotonic block offset advances
    /// across packets (Specter behaviour).
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id), legacy))]
    pub async fn set_legacy_ctr(&self, agent_id: u32, legacy: bool) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        self.repository.set_legacy_ctr(agent_id, legacy).await?;
        entry.legacy_ctr.store(legacy, Ordering::Relaxed);
        Ok(())
    }

    /// Encrypt a plaintext payload destined for an agent.
    #[instrument(skip(self, plaintext), fields(agent_id = format_args!("0x{:08X}", agent_id), len = plaintext.len()))]
    pub async fn encrypt_for_agent(
        &self,
        agent_id: u32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let info = entry.info.read().await;
        let (key, iv) = decode_crypto_material(agent_id, &info.encryption)?;
        drop(info);
        self.encrypt_payload_with_ctr_offset(agent_id, &entry, &key, &iv, plaintext, true).await
    }

    /// Encrypt a plaintext payload for an agent without changing registry state.
    #[instrument(skip(self, plaintext), fields(agent_id = format_args!("0x{:08X}", agent_id), len = plaintext.len()))]
    pub(crate) async fn encrypt_for_agent_without_advancing(
        &self,
        agent_id: u32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let info = entry.info.read().await;
        let (key, iv) = decode_crypto_material(agent_id, &info.encryption)?;
        drop(info);
        self.encrypt_payload_with_ctr_offset(agent_id, &entry, &key, &iv, plaintext, false).await
    }

    /// Decrypt a ciphertext payload received from an agent.
    #[instrument(skip(self, ciphertext), fields(agent_id = format_args!("0x{:08X}", agent_id), len = ciphertext.len()))]
    pub async fn decrypt_from_agent(
        &self,
        agent_id: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let info = entry.info.read().await;
        let (key, iv) = decode_crypto_material(agent_id, &info.encryption)?;
        drop(info);
        self.decrypt_payload_with_ctr_offset(agent_id, &entry, &key, &iv, ciphertext, true).await
    }

    /// Decrypt a ciphertext payload without advancing the stored CTR offset.
    ///
    /// Use this when the plaintext must be validated before the offset is committed — for
    /// example when decrypting an agent callback before parsing the Demon protocol, so that a
    /// garbage payload from an attacker cannot permanently desync the keystream offset.
    /// Call [`AgentRegistry::advance_ctr_for_agent`] after successful validation.
    #[instrument(skip(self, ciphertext), fields(agent_id = format_args!("0x{:08X}", agent_id), len = ciphertext.len()))]
    pub(crate) async fn decrypt_from_agent_without_advancing(
        &self,
        agent_id: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let info = entry.info.read().await;
        let (key, iv) = decode_crypto_material(agent_id, &info.encryption)?;
        drop(info);
        self.decrypt_payload_with_ctr_offset(agent_id, &entry, &key, &iv, ciphertext, false).await
    }

    /// Advance the CTR block offset for an agent by `byte_len` bytes.
    ///
    /// Called after [`AgentRegistry::decrypt_from_agent_without_advancing`] succeeds and the
    /// decrypted payload has been validated, so that a failed parse cannot desync the offset.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id), byte_len))]
    pub(crate) async fn advance_ctr_for_agent(
        &self,
        agent_id: u32,
        byte_len: usize,
    ) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        if entry.legacy_ctr.load(Ordering::Relaxed) {
            return Ok(());
        }
        let mut ctr_offset = entry.ctr_block_offset.lock().await;
        let current_offset = *ctr_offset;
        let next_offset = next_ctr_offset(current_offset, byte_len)?;
        if next_offset != current_offset {
            self.repository.set_ctr_block_offset(agent_id, next_offset).await?;
            *ctr_offset = next_offset;
        }
        Ok(())
    }

    /// Update the AES key and IV for an agent and persist the new values.
    #[instrument(skip(self, encryption), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn set_encryption(
        &self,
        agent_id: u32,
        encryption: AgentEncryptionInfo,
    ) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;

        let updated = {
            let info = entry.info.read().await;
            let mut cloned = info.clone();
            cloned.encryption = encryption.clone();
            cloned
        };

        let listener_name = entry.listener_name.read().await.clone();
        self.repository.update_with_listener(&updated, &listener_name).await?;
        entry.info.write().await.encryption = encryption;
        Ok(())
    }

    pub(super) async fn serialize_jobs_for_agent(
        &self,
        agent_id: u32,
        jobs: &[Job],
    ) -> Result<Vec<u8>, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let info = entry.info.read().await;
        let (key, iv) = decode_crypto_material(agent_id, &info.encryption)?;
        drop(info);

        let legacy = entry.legacy_ctr.load(Ordering::Relaxed);
        let mut packages = Vec::with_capacity(jobs.len());

        if legacy {
            for job in jobs {
                let payload = if job.payload.is_empty() {
                    Vec::new()
                } else {
                    encrypt_agent_data_at_offset(&key[..], &iv[..], 0, &job.payload)?
                };
                packages.push(DemonPackage {
                    command_id: job.command,
                    request_id: job.request_id,
                    payload,
                });
            }
        } else {
            let mut ctr_offset = entry.ctr_block_offset.lock().await;
            let starting_offset = *ctr_offset;
            let mut next_offset = starting_offset;

            for job in jobs {
                let payload = if job.payload.is_empty() {
                    Vec::new()
                } else {
                    let encrypted =
                        encrypt_agent_data_at_offset(&key[..], &iv[..], next_offset, &job.payload)?;
                    next_offset = next_ctr_offset(next_offset, job.payload.len())?;
                    encrypted
                };
                packages.push(DemonPackage {
                    command_id: job.command,
                    request_id: job.request_id,
                    payload,
                });
            }

            if next_offset != starting_offset {
                self.repository.set_ctr_block_offset(agent_id, next_offset).await?;
                *ctr_offset = next_offset;
            }
            drop(ctr_offset);
        }

        let bytes = DemonMessage::new(packages).to_bytes().map_err(TeamserverError::from)?;

        Ok(bytes)
    }

    async fn encrypt_payload_with_ctr_offset(
        &self,
        agent_id: u32,
        entry: &Arc<AgentEntry>,
        key: &[u8; AGENT_KEY_LENGTH],
        iv: &[u8; AGENT_IV_LENGTH],
        plaintext: &[u8],
        advance: bool,
    ) -> Result<Vec<u8>, TeamserverError> {
        if entry.legacy_ctr.load(Ordering::Relaxed) {
            return Ok(encrypt_agent_data_at_offset(key, iv, 0, plaintext)?);
        }

        let mut ctr_offset = entry.ctr_block_offset.lock().await;
        let current_offset = *ctr_offset;
        let ciphertext = encrypt_agent_data_at_offset(key, iv, current_offset, plaintext)?;

        if advance {
            let next_offset = next_ctr_offset(current_offset, plaintext.len())?;
            if next_offset != current_offset {
                self.repository.set_ctr_block_offset(agent_id, next_offset).await?;
                *ctr_offset = next_offset;
            }
        }

        Ok(ciphertext)
    }

    async fn decrypt_payload_with_ctr_offset(
        &self,
        agent_id: u32,
        entry: &Arc<AgentEntry>,
        key: &[u8; AGENT_KEY_LENGTH],
        iv: &[u8; AGENT_IV_LENGTH],
        ciphertext: &[u8],
        advance: bool,
    ) -> Result<Vec<u8>, TeamserverError> {
        if entry.legacy_ctr.load(Ordering::Relaxed) {
            return Ok(decrypt_agent_data_at_offset(key, iv, 0, ciphertext)?);
        }

        let mut ctr_offset = entry.ctr_block_offset.lock().await;
        let current_offset = *ctr_offset;
        let plaintext = decrypt_agent_data_at_offset(key, iv, current_offset, ciphertext)?;

        if advance {
            let next_offset = next_ctr_offset(current_offset, ciphertext.len())?;
            if next_offset != current_offset {
                self.repository.set_ctr_block_offset(agent_id, next_offset).await?;
                *ctr_offset = next_offset;
            }
        }

        Ok(plaintext)
    }
}

pub(super) fn decode_crypto_material(
    agent_id: u32,
    encryption: &AgentEncryptionInfo,
) -> Result<(Zeroizing<[u8; AGENT_KEY_LENGTH]>, Zeroizing<[u8; AGENT_IV_LENGTH]>), TeamserverError>
{
    let key = copy_fixed::<AGENT_KEY_LENGTH>(agent_id, "aes_key", &encryption.aes_key)?;
    let iv = copy_fixed::<AGENT_IV_LENGTH>(agent_id, "aes_iv", &encryption.aes_iv)?;
    if is_weak_aes_key(key.as_ref()) {
        warn!(
            agent_id = format_args!("0x{agent_id:08X}"),
            "rejecting stored degenerate AES key for agent transport"
        );
        return Err(TeamserverError::InvalidAgentCrypto {
            agent_id,
            message: "degenerate AES keys are not allowed".to_owned(),
        });
    }
    Ok((key, iv))
}

/// Copy raw bytes from a `Zeroizing<Vec<u8>>` into a fixed-size array.
///
/// Returns an error if the slice length does not match `N`.
fn copy_fixed<const N: usize>(
    agent_id: u32,
    field: &'static str,
    bytes: &Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<[u8; N]>, TeamserverError> {
    let actual = bytes.len();
    let array: [u8; N] =
        bytes.as_slice().try_into().map_err(|_| TeamserverError::InvalidPersistedValue {
            field,
            message: format!("agent 0x{agent_id:08X}: expected {N} bytes, got {actual}"),
        })?;
    Ok(Zeroizing::new(array))
}

pub(super) fn next_ctr_offset(
    current_offset: u64,
    payload_len: usize,
) -> Result<u64, TeamserverError> {
    current_offset.checked_add(ctr_blocks_for_len(payload_len)).ok_or_else(|| {
        TeamserverError::InvalidPersistedValue {
            field: "ctr_block_offset",
            message: "AES-CTR block offset overflow".to_owned(),
        }
    })
}
