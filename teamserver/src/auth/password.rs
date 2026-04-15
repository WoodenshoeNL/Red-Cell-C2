//! Argon2 password hashing, verification, and legacy digest normalization.

use argon2::password_hash::phc::PasswordHash;
use argon2::{Algorithm, Argon2, ParamsBuilder, PasswordHasher, PasswordVerifier, Version};
use uuid::Uuid;

use super::AuthError;
use crate::{OperatorRepository, PersistedOperator, TeamserverError};

/// Construct an [`Argon2`] instance with OWASP-recommended parameters.
///
/// Uses Argon2id with m_cost=65536 (64 MiB), t_cost=3, p_cost=4 — the
/// recommended configuration from the OWASP Password Storage Cheat Sheet.
///
/// In test builds, minimal Argon2 parameters are used instead to keep tests
/// fast. The production-strength parameters are only needed for brute-force
/// resistance; the hashing/verification code paths exercised in tests are
/// identical regardless of cost parameters.
pub(super) fn argon2_hasher() -> Result<Argon2<'static>, AuthError> {
    #[cfg(not(test))]
    let params = ParamsBuilder::new()
        .m_cost(65536)
        .t_cost(3)
        .p_cost(4)
        .build()
        .map_err(|e| AuthError::PasswordVerifier(format!("Argon2 parameter error: {e}")))?;
    #[cfg(test)]
    let params = ParamsBuilder::new()
        .m_cost(256)
        .t_cost(1)
        .p_cost(1)
        .build()
        .map_err(|e| AuthError::PasswordVerifier(format!("Argon2 parameter error: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub(crate) fn password_hashes_match(submitted: &str, expected: &str) -> bool {
    #[cfg(test)]
    return password_hashes_match_cached(submitted, expected);
    #[cfg(not(test))]
    return password_hashes_match_impl(submitted, expected);
}

fn password_hashes_match_impl(submitted: &str, expected: &str) -> bool {
    let submitted = submitted.to_ascii_lowercase();
    let Ok(parsed_hash) = PasswordHash::new(expected) else {
        return false;
    };
    let Ok(hasher) = argon2_hasher() else {
        return false;
    };

    hasher.verify_password(submitted.as_bytes(), &parsed_hash).is_ok()
}

/// Test-only cached wrapper around [`password_hashes_match_impl`].
///
/// Argon2 verification is intentionally slow (~1-2 s per call with production
/// parameters). Tests that create many sessions (e.g. the global session cap
/// test with 64+ verifications) become pathologically slow without caching.
/// The cache key is `(submitted_lowercase, expected_verifier)` and values are
/// append-only, so mutex poisoning is safe to recover from.
#[cfg(test)]
fn password_hashes_match_cached(submitted: &str, expected: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static CACHE: OnceLock<Mutex<HashMap<(String, String), bool>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    let key = (submitted.to_ascii_lowercase(), expected.to_owned());
    {
        let guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&cached) = guard.get(&key) {
            return cached;
        }
    }

    let result = password_hashes_match_impl(submitted, expected);
    cache.lock().unwrap_or_else(|e| e.into_inner()).insert(key, result);
    result
}

pub(crate) fn password_verifier_for_sha3(password_hash: &str) -> Result<String, AuthError> {
    #[cfg(test)]
    return password_verifier_for_sha3_cached(password_hash);
    #[cfg(not(test))]
    return password_verifier_for_sha3_impl(password_hash);
}

fn password_verifier_for_sha3_impl(password_hash: &str) -> Result<String, AuthError> {
    argon2_hasher()?
        .hash_password(password_hash.to_ascii_lowercase().as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|error| AuthError::PasswordVerifier(error.to_string()))
}

/// Test-only cached wrapper around `password_verifier_for_sha3_impl`.
///
/// Argon2 hashing is intentionally slow (memory-hard), which makes full test
/// suite runs infeasible when every `AuthService::from_profile` call hashes
/// N profile operators + 1 dummy verifier. This cache computes each Argon2
/// verifier at most once per unique SHA3 input across the entire test process,
/// keeping individual test setup instantaneous after the first warm-up.
///
/// The production path via `password_verifier_for_sha3_impl` is unaffected.
#[cfg(test)]
fn password_verifier_for_sha3_cached(password_hash: &str) -> Result<String, AuthError> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    let key = password_hash.to_ascii_lowercase();
    {
        let guard = cache.lock().unwrap_or_else(|e| {
            tracing::warn!(
                "password verifier cache mutex poisoned — recovering (append-only cache)"
            );
            e.into_inner()
        });
        if let Some(cached) = guard.get(&key) {
            return Ok(cached.clone());
        }
    }

    let verifier = password_verifier_for_sha3_impl(password_hash)?;
    cache
        .lock()
        .unwrap_or_else(|e| {
            tracing::warn!(
                "password verifier cache mutex poisoned — recovering (append-only cache)"
            );
            e.into_inner()
        })
        .entry(key)
        .or_insert_with(|| verifier.clone());
    Ok(verifier)
}

pub(super) async fn normalize_persisted_verifier(
    runtime_operators: &OperatorRepository,
    operator: &PersistedOperator,
) -> Result<String, AuthError> {
    if is_legacy_sha3_digest(&operator.password_verifier) {
        let password_verifier = password_verifier_for_sha3(&operator.password_verifier)?;
        runtime_operators.update_password_verifier(&operator.username, &password_verifier).await?;
        return Ok(password_verifier);
    }

    PasswordHash::new(&operator.password_verifier).map_err(|error| {
        AuthError::Persistence(TeamserverError::InvalidPersistedValue {
            field: "ts_runtime_operators.password_verifier",
            message: format!("invalid password verifier: {error}"),
        })
    })?;
    Ok(operator.password_verifier.clone())
}

pub(super) fn is_legacy_sha3_digest(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

/// Generate a one-time Argon2id PHC hash from random bytes for timing equalization.
///
/// When a login attempt uses an unknown username the service verifies the submitted
/// credential against this dummy hash instead of returning immediately.  The hash
/// must be a syntactically valid Argon2 PHC string so that [`password_hashes_match`]
/// runs the full Argon2 computation rather than failing on a parse error in
/// microseconds — which would otherwise expose user-enumeration via timing.
///
/// The password material is 16 bytes from the OS CSPRNG (via [`Uuid::new_v4`]), so
/// the resulting hash is unpredictable and cannot be precomputed by an attacker.
pub(super) fn generate_dummy_verifier() -> Result<String, AuthError> {
    #[cfg(test)]
    return generate_dummy_verifier_cached();
    #[cfg(not(test))]
    return generate_dummy_verifier_impl();
}

fn generate_dummy_verifier_impl() -> Result<String, AuthError> {
    let random_bytes = Uuid::new_v4();
    argon2_hasher()?
        .hash_password(random_bytes.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| AuthError::PasswordVerifier(e.to_string()))
}

/// Test-only cached wrapper around [`generate_dummy_verifier_impl`].
///
/// The dummy hash must be a valid Argon2 PHC string, but its exact value is
/// irrelevant for correctness tests — reusing one across the test process avoids
/// paying the Argon2 memory-hard cost on every [`AuthService`] construction.
#[cfg(test)]
fn generate_dummy_verifier_cached() -> Result<String, AuthError> {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<Result<String, String>> = OnceLock::new();
    DUMMY
        .get_or_init(|| generate_dummy_verifier_impl().map_err(|e| e.to_string()))
        .as_ref()
        .cloned()
        .map_err(|e| AuthError::PasswordVerifier(e.clone()))
}

#[cfg(test)]
mod tests {
    use red_cell_common::crypto::hash_password_sha3;

    use super::*;

    #[test]
    fn hash_password_matches_havoc_sha3_256() {
        assert_eq!(
            hash_password_sha3("password1234"),
            "2f7d3e77d0786c5d305c0afadd4c1a2a6869a3210956c963ad2420c52e797022"
        );
    }

    #[test]
    fn argon2_hasher_returns_ok_and_maps_errors_to_auth_error() {
        let hasher = argon2_hasher();
        assert!(hasher.is_ok(), "argon2_hasher() should succeed with valid parameters");

        let err = AuthError::PasswordVerifier("Argon2 parameter error: test".to_owned());
        assert!(
            matches!(err, AuthError::PasswordVerifier(ref msg) if msg.contains("Argon2 parameter")),
            "Argon2 parameter errors should map to AuthError::PasswordVerifier"
        );
    }

    #[test]
    fn dummy_verifier_is_valid_argon2_phc_string() {
        use argon2::password_hash::phc::PasswordHash;

        let verifier = generate_dummy_verifier().expect("dummy verifier should be generated");
        PasswordHash::new(&verifier).expect("dummy verifier must be a valid Argon2 PHC string");
        assert!(
            verifier.starts_with("$argon2"),
            "dummy verifier must use the argon2 algorithm family"
        );
    }

    #[test]
    fn is_legacy_sha3_digest_accepts_valid_64_char_hex() {
        assert!(is_legacy_sha3_digest(
            "2f7d3e77d0786c5d305c0afadd4c1a2a6869a3210956c963ad2420c52e797022"
        ));
    }

    #[test]
    fn is_legacy_sha3_digest_rejects_63_char_hex() {
        assert!(!is_legacy_sha3_digest(
            "2f7d3e77d0786c5d305c0afadd4c1a2a6869a3210956c963ad2420c52e79702"
        ));
    }

    #[test]
    fn is_legacy_sha3_digest_rejects_65_char_hex() {
        assert!(!is_legacy_sha3_digest(
            "2f7d3e77d0786c5d305c0afadd4c1a2a6869a3210956c963ad2420c52e7970220"
        ));
    }

    #[test]
    fn is_legacy_sha3_digest_rejects_non_hex_char_at_position_32() {
        let mut s = "2f7d3e77d0786c5d305c0afadd4c1a2a".to_owned();
        s.push('g');
        s.push_str("869a3210956c963ad2420c52e797022");
        assert_eq!(s.len(), 64);
        assert!(!is_legacy_sha3_digest(&s));
    }

    #[test]
    fn is_legacy_sha3_digest_rejects_argon2_phc_string() {
        assert!(!is_legacy_sha3_digest("$argon2id$v=19$m=19456,t=2,p=1$salt$hash"));
    }

    #[test]
    fn is_legacy_sha3_digest_rejects_empty_string() {
        assert!(!is_legacy_sha3_digest(""));
    }
}
