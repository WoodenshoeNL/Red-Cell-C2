//! DEMON_INIT payload parsing and session key derivation.

use std::borrow::Cow;

use red_cell_common::AgentEncryptionInfo;
use red_cell_common::AgentRecord;
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, CryptoError, decrypt_agent_data, derive_session_keys,
    derive_session_keys_for_version, is_weak_aes_iv, is_weak_aes_key,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;
use zeroize::Zeroizing;

use super::callback::{
    read_fixed, read_length_prefixed_string_be, read_length_prefixed_utf16_be, read_u32_be,
    read_u64_be,
};
use super::{
    DemonInitSecretConfig, DemonParserError, INIT_EXT_MONOTONIC_CTR, INIT_EXT_SEQ_PROTECTED,
};
use crate::dispatch::util::{
    basename, process_arch_label, windows_arch_label, windows_version_label,
};

/// Parse a DEMON_INIT payload into an `AgentRecord` and extension flags.
///
/// Returns `(agent, legacy_ctr, seq_protected)`.
///
/// When the decrypted metadata contains trailing extension flags:
/// - If [`INIT_EXT_MONOTONIC_CTR`] is set, `legacy_ctr` is `false`; otherwise `true`.
/// - If [`INIT_EXT_SEQ_PROTECTED`] is set, `seq_protected` is `true`; otherwise `false`.
///
/// Legacy Demon agents omit the extension flags field entirely; both defaults apply.
pub(crate) fn parse_init_agent(
    agent_id: u32,
    payload: &[u8],
    external_ip: &str,
    now: OffsetDateTime,
    secret_config: &DemonInitSecretConfig,
) -> Result<(AgentRecord, bool, bool), DemonParserError> {
    let mut offset = 0_usize;
    let key = read_fixed::<AGENT_KEY_LENGTH>(payload, &mut offset, "init AES key")?;
    let iv = read_fixed::<AGENT_IV_LENGTH>(payload, &mut offset, "init AES IV")?;

    // Read the 1-byte version field when in Versioned mode.  The version appears
    // between the raw key/IV and the encrypted payload so the teamserver can select
    // the correct HKDF secret before decrypting.
    let secret_version: Option<u8> = if matches!(secret_config, DemonInitSecretConfig::Versioned(_))
    {
        if offset >= payload.len() {
            warn!(
                agent_id = format_args!("0x{agent_id:08X}"),
                "rejecting DEMON_INIT: missing secret-version byte (versioned secrets configured)"
            );
            return Err(DemonParserError::InvalidInit(
                "missing secret-version byte in DEMON_INIT envelope",
            ));
        }
        let v = payload[offset];
        offset += 1;
        Some(v)
    } else {
        None
    };

    let encrypted = &payload[offset..];

    if is_weak_aes_key(&key) {
        warn!(
            agent_id = format_args!("0x{agent_id:08X}"),
            "rejecting DEMON_INIT with degenerate AES key"
        );
        return Err(DemonParserError::InvalidInit("degenerate AES key is not allowed"));
    }

    if is_weak_aes_iv(&iv) {
        warn!(
            agent_id = format_args!("0x{agent_id:08X}"),
            "rejecting DEMON_INIT with degenerate AES IV"
        );
        return Err(DemonParserError::InvalidInit("degenerate AES IV is not allowed"));
    }

    let decrypted = Cow::Owned(decrypt_agent_data(&key, &iv, encrypted)?);

    let mut decrypted_offset = 0_usize;
    let parsed_agent_id = read_u32_be(&decrypted, &mut decrypted_offset, "init agent id")?;
    if parsed_agent_id != agent_id {
        warn!(
            header_agent_id = format_args!("0x{agent_id:08X}"),
            metadata_agent_id = format_args!("0x{parsed_agent_id:08X}"),
            "DEMON_INIT AES metadata agent id does not match transport header (wrong secret, corrupted payload, or mis-parsed header layout)"
        );
        return Err(DemonParserError::InvalidInit("decrypted agent id does not match header"));
    }

    let hostname = read_length_prefixed_string_be(&decrypted, &mut decrypted_offset, "hostname")?;
    let username = read_length_prefixed_string_be(&decrypted, &mut decrypted_offset, "username")?;
    let domain_name =
        read_length_prefixed_string_be(&decrypted, &mut decrypted_offset, "domain name")?;
    let internal_ip =
        read_length_prefixed_string_be(&decrypted, &mut decrypted_offset, "internal ip")?;
    let process_path =
        read_length_prefixed_utf16_be(&decrypted, &mut decrypted_offset, "process path")?;
    let process_pid = read_u32_be(&decrypted, &mut decrypted_offset, "process pid")?;
    let process_tid = read_u32_be(&decrypted, &mut decrypted_offset, "process tid")?;
    let process_ppid = read_u32_be(&decrypted, &mut decrypted_offset, "process ppid")?;
    let process_arch = read_u32_be(&decrypted, &mut decrypted_offset, "process arch")?;
    let elevated = read_u32_be(&decrypted, &mut decrypted_offset, "elevated")? != 0;
    let base_address = read_u64_be(&decrypted, &mut decrypted_offset, "base address")?;
    let os_major = read_u32_be(&decrypted, &mut decrypted_offset, "os major")?;
    let os_minor = read_u32_be(&decrypted, &mut decrypted_offset, "os minor")?;
    let os_product_type = read_u32_be(&decrypted, &mut decrypted_offset, "os product type")?;
    let os_service_pack = read_u32_be(&decrypted, &mut decrypted_offset, "os service pack")?;
    let os_build = read_u32_be(&decrypted, &mut decrypted_offset, "os build")?;
    let os_arch = read_u32_be(&decrypted, &mut decrypted_offset, "os arch")?;
    let sleep_delay = read_u32_be(&decrypted, &mut decrypted_offset, "sleep delay")?;
    let sleep_jitter = read_u32_be(&decrypted, &mut decrypted_offset, "sleep jitter")?;
    let kill_date = read_u64_be(&decrypted, &mut decrypted_offset, "kill date")?;
    let working_hours =
        i32::from_be_bytes(read_fixed::<4>(&decrypted, &mut decrypted_offset, "working hours")?);

    // Optional extension flags — appended by Specter (and future) agents after the
    // standard metadata fields.  Legacy Demon agents omit this, so an absent field
    // means legacy CTR mode and no seq protection.
    let (legacy_ctr, seq_protected) = if decrypted.len() - decrypted_offset >= 4 {
        let ext_flags = read_u32_be(&decrypted, &mut decrypted_offset, "init extension flags")?;
        let monotonic = ext_flags & INIT_EXT_MONOTONIC_CTR != 0;
        let seq_prot = ext_flags & INIT_EXT_SEQ_PROTECTED != 0;
        if monotonic || seq_prot {
            tracing::info!(
                agent_id = format_args!("0x{agent_id:08X}"),
                ext_flags,
                monotonic_ctr = monotonic,
                seq_protected = seq_prot,
                "agent requested protocol extensions via init extension flags"
            );
        }
        (!monotonic, seq_prot)
    } else {
        (true, false)
    };

    // Reject trailing bytes after the last parsed field.
    if decrypted_offset < decrypted.len() {
        let trailing = decrypted.len() - decrypted_offset;
        warn!(
            agent_id = format_args!("0x{agent_id:08X}"),
            trailing_bytes = trailing,
            "rejecting DEMON_INIT with trailing bytes after extension flags"
        );
        return Err(DemonParserError::InvalidInit("trailing bytes after init metadata"));
    }

    let timestamp =
        now.format(&Rfc3339).map_err(|_| DemonParserError::InvalidInit("invalid timestamp"))?;
    let kill_date = parse_kill_date(kill_date)?;

    // Derive session keys via HKDF when a server secret is configured.
    let encryption = match secret_config {
        DemonInitSecretConfig::None => AgentEncryptionInfo {
            aes_key: Zeroizing::new(key.to_vec()),
            aes_iv: Zeroizing::new(iv.to_vec()),
            monotonic_ctr: !legacy_ctr,
        },
        DemonInitSecretConfig::Unversioned(secret) => {
            let derived = derive_session_keys(&key, &iv, secret)
                .map_err(|_| DemonParserError::InvalidInit("HKDF session key derivation failed"))?;
            tracing::info!(
                agent_id = format_args!("0x{parsed_agent_id:08X}"),
                "derived session keys via HKDF (unversioned init_secret)"
            );
            AgentEncryptionInfo {
                aes_key: Zeroizing::new(derived.key.to_vec()),
                aes_iv: Zeroizing::new(derived.iv.to_vec()),
                monotonic_ctr: !legacy_ctr,
            }
        }
        DemonInitSecretConfig::Versioned(secrets) => {
            let version = match secret_version {
                Some(v) => v,
                None => {
                    return Err(DemonParserError::InvalidInit(
                        "internal: missing version byte in Versioned mode",
                    ));
                }
            };
            let secret_refs: Vec<(u8, &[u8])> =
                secrets.iter().map(|(v, s)| (*v, s.as_slice())).collect();
            let derived = derive_session_keys_for_version(&key, &iv, version, &secret_refs)
                .map_err(|err| match err {
                    CryptoError::UnknownSecretVersion { version: v } => {
                        warn!(
                            agent_id = format_args!("0x{parsed_agent_id:08X}"),
                            secret_version = v,
                            "rejecting DEMON_INIT: unknown secret version"
                        );
                        DemonParserError::InvalidInit("unknown secret version in DEMON_INIT")
                    }
                    _ => DemonParserError::InvalidInit("HKDF session key derivation failed"),
                })?;
            tracing::info!(
                agent_id = format_args!("0x{parsed_agent_id:08X}"),
                secret_version = version,
                "derived session keys via HKDF (versioned init_secret)"
            );
            AgentEncryptionInfo {
                aes_key: Zeroizing::new(derived.key.to_vec()),
                aes_iv: Zeroizing::new(derived.iv.to_vec()),
                monotonic_ctr: !legacy_ctr,
            }
        }
    };

    Ok((
        AgentRecord {
            agent_id: parsed_agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption,
            hostname,
            username,
            domain_name,
            external_ip: external_ip.to_owned(),
            internal_ip,
            process_name: basename(&process_path),
            process_path,
            base_address,
            process_pid,
            process_tid,
            process_ppid,
            process_arch: process_arch_label(process_arch).to_owned(),
            elevated,
            os_version: windows_version_label(
                os_major,
                os_minor,
                os_product_type,
                os_service_pack,
                os_build,
            ),
            os_build,
            os_arch: windows_arch_label(os_arch).to_owned(),
            sleep_delay,
            sleep_jitter,
            kill_date,
            working_hours: (working_hours != 0).then_some(working_hours),
            first_call_in: timestamp.clone(),
            last_call_in: timestamp,
            archon_magic: None,
        },
        legacy_ctr,
        seq_protected,
    ))
}

/// Parse ECDH registration metadata (agent → teamserver).
///
/// The metadata bytes are produced by `serialize_init_metadata` and are already
/// decrypted by the ECDH AEAD layer.  No AES key/IV prefix is present — this
/// differs from [`parse_init_agent`] which reads key/IV first then decrypts.
///
/// Returns `(agent_record, legacy_ctr, seq_protected)`.
pub(crate) fn parse_ecdh_agent_metadata(
    metadata: &[u8],
    external_ip: &str,
    now: OffsetDateTime,
) -> Result<(AgentRecord, bool, bool), DemonParserError> {
    let mut offset = 0_usize;

    let agent_id = read_u32_be(metadata, &mut offset, "ecdh init agent_id")?;
    if agent_id == 0 {
        warn!("rejecting ECDH registration with reserved agent_id 0x00000000");
        return Err(DemonParserError::InvalidInit("agent_id 0 is reserved and not allowed"));
    }
    let hostname = read_length_prefixed_string_be(metadata, &mut offset, "hostname")?;
    let username = read_length_prefixed_string_be(metadata, &mut offset, "username")?;
    let domain_name = read_length_prefixed_string_be(metadata, &mut offset, "domain name")?;
    let internal_ip = read_length_prefixed_string_be(metadata, &mut offset, "internal ip")?;
    let process_path = read_length_prefixed_utf16_be(metadata, &mut offset, "process path")?;
    let process_pid = read_u32_be(metadata, &mut offset, "process pid")?;
    let process_tid = read_u32_be(metadata, &mut offset, "process tid")?;
    let process_ppid = read_u32_be(metadata, &mut offset, "process ppid")?;
    let process_arch = read_u32_be(metadata, &mut offset, "process arch")?;
    let elevated = read_u32_be(metadata, &mut offset, "elevated")? != 0;
    let base_address = read_u64_be(metadata, &mut offset, "base address")?;
    let os_major = read_u32_be(metadata, &mut offset, "os major")?;
    let os_minor = read_u32_be(metadata, &mut offset, "os minor")?;
    let os_product_type = read_u32_be(metadata, &mut offset, "os product type")?;
    let os_service_pack = read_u32_be(metadata, &mut offset, "os service pack")?;
    let os_build = read_u32_be(metadata, &mut offset, "os build")?;
    let os_arch = read_u32_be(metadata, &mut offset, "os arch")?;
    let sleep_delay = read_u32_be(metadata, &mut offset, "sleep delay")?;
    let sleep_jitter = read_u32_be(metadata, &mut offset, "sleep jitter")?;
    let kill_date_raw = read_u64_be(metadata, &mut offset, "kill date")?;
    let working_hours =
        i32::from_be_bytes(read_fixed::<4>(metadata, &mut offset, "working hours")?);

    let (legacy_ctr, seq_protected) = if metadata.len() - offset >= 4 {
        let ext_flags = read_u32_be(metadata, &mut offset, "init extension flags")?;
        let monotonic = ext_flags & INIT_EXT_MONOTONIC_CTR != 0;
        let seq_prot = ext_flags & INIT_EXT_SEQ_PROTECTED != 0;
        (!monotonic, seq_prot)
    } else {
        (true, false)
    };

    if offset < metadata.len() {
        let trailing = metadata.len() - offset;
        warn!(
            agent_id = format_args!("0x{agent_id:08X}"),
            trailing_bytes = trailing,
            "rejecting ECDH registration with trailing bytes after extension flags"
        );
        return Err(DemonParserError::InvalidInit("trailing bytes after ECDH init metadata"));
    }

    let timestamp =
        now.format(&Rfc3339).map_err(|_| DemonParserError::InvalidInit("invalid timestamp"))?;
    let kill_date = parse_kill_date(kill_date_raw)?;

    Ok((
        AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo::default(),
            hostname,
            username,
            domain_name,
            external_ip: external_ip.to_owned(),
            internal_ip,
            process_name: basename(&process_path),
            process_path,
            base_address,
            process_pid,
            process_tid,
            process_ppid,
            process_arch: process_arch_label(process_arch).to_owned(),
            elevated,
            os_version: windows_version_label(
                os_major,
                os_minor,
                os_product_type,
                os_service_pack,
                os_build,
            ),
            os_build,
            os_arch: windows_arch_label(os_arch).to_owned(),
            sleep_delay,
            sleep_jitter,
            kill_date,
            working_hours: (working_hours != 0).then_some(working_hours),
            first_call_in: timestamp.clone(),
            last_call_in: timestamp,
            archon_magic: None,
        },
        legacy_ctr,
        seq_protected,
    ))
}

fn parse_kill_date(kill_date: u64) -> Result<Option<i64>, DemonParserError> {
    if kill_date == 0 {
        return Ok(None);
    }

    let parsed = i64::try_from(kill_date)
        .map_err(|_| DemonParserError::InvalidInit("kill date exceeds i64 range"))?;
    Ok(Some(parsed))
}
