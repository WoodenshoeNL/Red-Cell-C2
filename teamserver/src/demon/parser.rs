//! `DemonPacketParser` — request classification and routing for incoming Demon transport.

use std::borrow::Cow;

use red_cell_common::demon::{ArchonEnvelope, DemonCommand, DemonEnvelope, DemonHeader};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::ack::lift_crypto_encoding_error;
use super::callback::{parse_callback_packages, read_u32_be};
use super::init::parse_init_agent;
use super::{DemonInitSecretConfig, DemonParserError, ParsedDemonInit, ParsedDemonPacket};
use crate::{AgentRegistry, TeamserverError};

/// Parser for incoming Demon transport packets backed by the teamserver agent registry.
#[derive(Clone, Debug)]
pub struct DemonPacketParser {
    registry: AgentRegistry,
    /// Server-secret configuration for HKDF-based session key derivation.
    ///
    /// See [`DemonInitSecretConfig`] for the three modes.  When `None`, raw
    /// agent keys are stored directly (Havoc Demon compatibility).
    init_secret_config: DemonInitSecretConfig,
    /// Whether to accept DEMON_INIT registrations that negotiate legacy CTR mode.
    ///
    /// When `false` (the default), any `DEMON_INIT` that does not set the
    /// `INIT_EXT_MONOTONIC_CTR` extension flag is rejected with
    /// [`DemonParserError::LegacyCtrNotAllowed`].  Set to `true` only after the
    /// operator has explicitly opted in via `AllowLegacyCtr = true` in the profile.
    allow_legacy_ctr: bool,
    /// Whether this parser handles legacy Demon (true) or Archon (false) agents.
    ///
    /// `true` — Demon header layout: `size(4) | magic=0xDEADBEEF(4) | agent_id(4)`.
    /// `false` — Archon header layout: `size(4) | agent_id(4) | magic=random(4)`;
    ///   per-agent magic is validated against the value stored at first check-in.
    legacy_mode: bool,
}

impl DemonPacketParser {
    /// Create a packet parser that resolves agent session keys from the provided registry.
    ///
    /// Legacy CTR mode is **disabled** by default; DEMON_INIT packets that do not
    /// negotiate monotonic CTR are rejected.
    #[must_use]
    pub fn new(registry: AgentRegistry) -> Self {
        Self {
            registry,
            init_secret_config: DemonInitSecretConfig::None,
            allow_legacy_ctr: false,
            legacy_mode: true,
        }
    }

    /// Create a packet parser with unversioned HKDF-based session key derivation.
    ///
    /// When `init_secret` is `Some`, the teamserver derives session keys from
    /// agent-supplied material mixed with the secret via HKDF-SHA256.  No version
    /// byte is present in `DEMON_INIT`; this mode is backward-compatible with agents
    /// built against the old single-secret `InitSecret` profile field.
    ///
    /// For zero-downtime rotation support use [`with_init_secrets`](Self::with_init_secrets).
    ///
    /// Legacy CTR mode is **disabled** by default; use
    /// [`with_allow_legacy_ctr`](Self::with_allow_legacy_ctr) to opt in.
    #[must_use]
    pub fn with_init_secret(registry: AgentRegistry, init_secret: Option<Vec<u8>>) -> Self {
        let config = match init_secret {
            Some(s) => DemonInitSecretConfig::Unversioned(Zeroizing::new(s)),
            None => DemonInitSecretConfig::None,
        };
        Self { registry, init_secret_config: config, allow_legacy_ctr: false, legacy_mode: true }
    }

    /// Create a packet parser from an already-constructed [`DemonInitSecretConfig`].
    ///
    /// This is the low-level constructor used internally by the listener manager.
    /// Prefer [`with_init_secret`](Self::with_init_secret) or
    /// [`with_init_secrets`](Self::with_init_secrets) for explicit configuration.
    #[must_use]
    pub fn with_init_secret_config(registry: AgentRegistry, config: DemonInitSecretConfig) -> Self {
        Self { registry, init_secret_config: config, allow_legacy_ctr: false, legacy_mode: true }
    }

    /// Create a packet parser with versioned HKDF-based session key derivation.
    ///
    /// Agents compiled with versioned-secret support emit a 1-byte version field
    /// in the `DEMON_INIT` envelope.  The teamserver looks up the matching entry
    /// in `secrets` and derives session keys with HKDF-SHA256.  Unknown version
    /// bytes are rejected.
    ///
    /// If `secrets` is empty this is equivalent to [`new`](Self::new) (no HKDF).
    ///
    /// Legacy CTR mode is **disabled** by default; use
    /// [`with_allow_legacy_ctr`](Self::with_allow_legacy_ctr) to opt in.
    #[must_use]
    pub fn with_init_secrets(registry: AgentRegistry, secrets: Vec<(u8, Vec<u8>)>) -> Self {
        let config = if secrets.is_empty() {
            DemonInitSecretConfig::None
        } else {
            DemonInitSecretConfig::Versioned(
                secrets.into_iter().map(|(v, s)| (v, Zeroizing::new(s))).collect(),
            )
        };
        Self { registry, init_secret_config: config, allow_legacy_ctr: false, legacy_mode: true }
    }

    /// Enable or disable acceptance of legacy-CTR DEMON_INIT registrations.
    ///
    /// When `false` (the default), any DEMON_INIT that does not set the
    /// `INIT_EXT_MONOTONIC_CTR` flag is rejected immediately.  Set to `true`
    /// only when the operator has explicitly opted in via `AllowLegacyCtr = true`
    /// in the profile `Demon` block.
    #[must_use]
    pub fn with_allow_legacy_ctr(mut self, allow: bool) -> Self {
        self.allow_legacy_ctr = allow;
        self
    }

    /// Set the listener mode for this parser.
    ///
    /// `true` — legacy Demon mode: header layout `size|magic=0xDEADBEEF|agent_id`.
    /// `false` — Archon mode: header layout `size|agent_id|magic=random`; per-agent
    ///   magic is validated on every callback before AES decryption.
    #[must_use]
    pub fn with_legacy_mode(mut self, legacy: bool) -> Self {
        self.legacy_mode = legacy;
        self
    }

    /// Parse an incoming Demon request and update the registry for newly registered agents.
    pub async fn parse(
        &self,
        bytes: &[u8],
        external_ip: impl Into<String>,
    ) -> Result<ParsedDemonPacket, DemonParserError> {
        self.parse_for_listener(bytes, external_ip, "null").await
    }

    /// Parse an incoming Demon request and retain the listener that accepted it.
    pub async fn parse_for_listener(
        &self,
        bytes: &[u8],
        external_ip: impl Into<String>,
        listener_name: &str,
    ) -> Result<ParsedDemonPacket, DemonParserError> {
        let now = OffsetDateTime::now_utc();
        self.parse_at_for_listener(bytes, external_ip.into(), listener_name, now).await
    }

    #[cfg(test)]
    pub(super) async fn parse_at(
        &self,
        bytes: &[u8],
        external_ip: String,
        now: OffsetDateTime,
    ) -> Result<ParsedDemonPacket, DemonParserError> {
        self.parse_at_for_listener(bytes, external_ip, "null", now).await
    }

    async fn parse_at_for_listener(
        &self,
        bytes: &[u8],
        external_ip: String,
        listener_name: &str,
        now: OffsetDateTime,
    ) -> Result<ParsedDemonPacket, DemonParserError> {
        // For non-legacy (Archon) listeners, the header field order differs from Demon.
        // Parse using ArchonEnvelope and synthesise a DemonHeader so the rest of the
        // pipeline can remain header-format agnostic.
        let (envelope, archon_magic_from_packet) = if self.legacy_mode {
            (DemonEnvelope::from_bytes(bytes)?, None)
        } else {
            let archon = ArchonEnvelope::from_bytes(bytes)?;
            let header = DemonHeader::from_raw(
                archon.header.size,
                archon.header.magic,
                archon.header.agent_id,
            );
            let env = DemonEnvelope { header, payload: archon.payload };
            (env, Some(archon.header.magic))
        };
        let mut offset = 0_usize;
        let command_id = read_u32_be(&envelope.payload, &mut offset, "top-level command id")?;
        let request_id = read_u32_be(&envelope.payload, &mut offset, "top-level request id")?;
        let remaining = &envelope.payload[offset..];

        if command_id == u32::from(DemonCommand::DemonInit) {
            if envelope.header.agent_id == 0 {
                warn!(listener_name, "rejecting DEMON_INIT with reserved agent_id 0x00000000");
                return Err(DemonParserError::InvalidInit(
                    "agent_id 0 is reserved and not allowed",
                ));
            }

            if remaining.is_empty() {
                return Ok(ParsedDemonPacket::Reconnect { header: envelope.header, request_id });
            }

            if let Some(existing) = self.registry.get(envelope.header.agent_id).await {
                let (mut agent, legacy_ctr, seq_protected) = parse_init_agent(
                    envelope.header.agent_id,
                    remaining,
                    &external_ip,
                    now,
                    &self.init_secret_config,
                )?;
                // Stamp the per-build Archon magic into the agent record on re-init.
                agent.archon_magic = archon_magic_from_packet;

                // Guard against key-rotation hijack.
                let keys_match = existing.encryption.aes_key.ct_eq(&agent.encryption.aes_key)
                    & existing.encryption.aes_iv.ct_eq(&agent.encryption.aes_iv);
                if keys_match.unwrap_u8() == 0 {
                    warn!(
                        agent_id = format_args!("0x{:08X}", envelope.header.agent_id),
                        listener_name,
                        "rejecting DEMON_INIT re-registration: key material does not match \
                         existing session — possible key-rotation hijack attempt"
                    );
                    return Err(DemonParserError::KeyMismatchOnReInit {
                        agent_id: envelope.header.agent_id,
                    });
                }

                if legacy_ctr && !self.allow_legacy_ctr {
                    warn!(
                        agent_id = format_args!("0x{:08X}", envelope.header.agent_id),
                        listener_name,
                        "rejecting DEMON_INIT re-registration: agent negotiated legacy CTR \
                         mode and AllowLegacyCtr is not enabled"
                    );
                    return Err(DemonParserError::LegacyCtrNotAllowed);
                }

                info!(
                    agent_id = format_args!("0x{:08X}", envelope.header.agent_id),
                    listener_name,
                    "DEMON_INIT re-registration: updating existing agent record (CTR reset to 0)"
                );
                self.registry.reregister_full(agent.clone(), listener_name, legacy_ctr).await?;
                self.registry.set_seq_protected(envelope.header.agent_id, seq_protected).await?;

                return Ok(ParsedDemonPacket::ReInit(Box::new(ParsedDemonInit {
                    header: envelope.header,
                    request_id,
                    agent,
                })));
            }

            let (mut agent, legacy_ctr, seq_protected) = parse_init_agent(
                envelope.header.agent_id,
                remaining,
                &external_ip,
                now,
                &self.init_secret_config,
            )?;
            // Stamp the per-build Archon magic into the agent record on first registration.
            agent.archon_magic = archon_magic_from_packet;

            if legacy_ctr && !self.allow_legacy_ctr {
                warn!(
                    agent_id = format_args!("0x{:08X}", envelope.header.agent_id),
                    listener_name,
                    "rejecting DEMON_INIT: agent negotiated legacy CTR mode and \
                     AllowLegacyCtr is not enabled — set AllowLegacyCtr = true in \
                     the Demon profile block to accept insecure sessions"
                );
                return Err(DemonParserError::LegacyCtrNotAllowed);
            }

            self.registry.insert_full(agent.clone(), listener_name, 0, legacy_ctr).await?;
            if seq_protected {
                self.registry.set_seq_protected(envelope.header.agent_id, seq_protected).await?;
            }

            return Ok(ParsedDemonPacket::Init(Box::new(ParsedDemonInit {
                header: envelope.header,
                request_id,
                agent,
            })));
        }

        // Archon only: validate per-agent magic before AES decryption.
        // This rejects packets whose magic doesn't match the value stored at first check-in,
        // preventing an attacker from probing the CTR keystream with crafted ciphertext.
        if let Some(packet_magic) = archon_magic_from_packet {
            let agent_id = envelope.header.agent_id;
            match self.registry.get(agent_id).await {
                Some(record) => match record.archon_magic {
                    Some(expected) if expected == packet_magic => {}
                    Some(_) => {
                        warn!(
                            agent_id = format_args!("0x{agent_id:08X}"),
                            listener_name,
                            packet_magic = format_args!("0x{packet_magic:08X}"),
                            "rejecting Archon callback: magic mismatch"
                        );
                        return Err(DemonParserError::ArchonMagicMismatch {
                            agent_id,
                            actual: packet_magic,
                        });
                    }
                    None => {
                        warn!(
                            agent_id = format_args!("0x{agent_id:08X}"),
                            listener_name, "rejecting Archon callback: no archon_magic on file"
                        );
                        return Err(DemonParserError::ArchonMagicNotOnFile { agent_id });
                    }
                },
                None => {
                    // Unknown agent — fall through; the registry lookup later will handle it.
                }
            }
        }

        // Decrypt without advancing the CTR offset first.  AES-CTR has no authentication tag, so
        // decryption always "succeeds" regardless of whether the ciphertext is genuine.  If we
        // advanced the offset unconditionally and the Demon protocol parse below then failed (e.g.
        // because an attacker sent a crafted packet with a valid agent_id but garbage payload),
        // the stored offset would be permanently desynced and the real agent's next legitimate
        // callback would be decrypted at the wrong keystream position — breaking the session.
        //
        // By deferring the advance until after a successful parse we ensure the offset is only
        // committed when we have confirmed the payload was valid Demon data.
        let agent_id = envelope.header.agent_id;
        let decrypted = self
            .registry
            .decrypt_from_agent_without_advancing(agent_id, remaining)
            .await
            .map_err(|e| lift_crypto_encoding_error(agent_id, e))?;

        // For seq-protected agents (Specter/Archon with INIT_EXT_SEQ_PROTECTED), extract the
        // 8-byte little-endian sequence number that prefixes the decrypted body.  Validation of
        // the seq is deferred until after `parse_callback_packages` succeeds: because AES-CTR
        // has no authentication tag, a successful seq-advance followed by a parse failure would
        // consume the seq slot against an unauthenticated ciphertext, permanently desyncing the
        // real agent's session (and giving an attacker with a known agent_id a cheap targeted
        // DoS).  The parse step is our authenticator — only a genuine agent can produce a
        // ciphertext that both decrypts to a valid seq and parses as a valid package stream.
        let (seq_to_commit, callback_body): (Option<u64>, Cow<'_, [u8]>) =
            if self.registry.is_seq_protected(agent_id).await {
                use red_cell_common::callback_seq::SEQ_PREFIX_BYTES;

                if decrypted.len() < SEQ_PREFIX_BYTES {
                    return Err(DemonParserError::Registry(
                        TeamserverError::InvalidPersistedValue {
                            field: "callback_seq_prefix",
                            message: format!(
                                "payload too short: {} bytes < {SEQ_PREFIX_BYTES} required",
                                decrypted.len()
                            ),
                        },
                    ));
                }

                let mut seq_bytes = [0u8; SEQ_PREFIX_BYTES];
                seq_bytes.copy_from_slice(&decrypted[..SEQ_PREFIX_BYTES]);
                let incoming_seq = u64::from_le_bytes(seq_bytes);
                let body = decrypted[SEQ_PREFIX_BYTES..].to_vec();
                (Some(incoming_seq), Cow::Owned(body))
            } else {
                (None, Cow::Borrowed(decrypted.as_slice()))
            };

        let packages = parse_callback_packages(command_id, request_id, &callback_body)?;

        // Parse succeeded — the payload is authenticated by having valid Demon structure.
        // Commit the seq advance first (atomic check-and-advance under the per-agent
        // last_seen_seq mutex, so concurrent callbacks with the same seq cannot both pass).
        // If the seq advance fails (replay or out-of-order race with a higher seq that
        // committed between decrypt and here) the CTR offset is *not* advanced and the
        // real agent's keystream state stays intact.
        if let Some(incoming_seq) = seq_to_commit {
            self.registry.check_and_advance_callback_seq(agent_id, incoming_seq).await.map_err(
                |e| {
                    match &e {
                        TeamserverError::CallbackSeqReplay { .. }
                        | TeamserverError::CallbackSeqGapTooLarge { .. } => {
                            warn!(
                                agent_id = format_args!("0x{agent_id:08X}"),
                                "rejecting seq-protected callback: {e}"
                            );
                        }
                        _ => {}
                    }
                    DemonParserError::Registry(e)
                },
            )?;
        }
        self.registry.advance_ctr_for_agent(agent_id, remaining.len()).await?;

        Ok(ParsedDemonPacket::Callback { header: envelope.header, packages })
    }
}
