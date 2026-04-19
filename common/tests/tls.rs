use std::io::BufReader;

use tempfile::TempDir;
use x509_parser::prelude::FromDer;

use red_cell_common::config::HttpListenerCertConfig;
use red_cell_common::tls::{
    PersistTlsError, TlsError, TlsIdentity, TlsKeyAlgorithm, generate_self_signed_tls_identity,
    install_default_crypto_provider, load_tls_identity, load_tls_identity_from_files,
    resolve_or_persist_tls_identity, resolve_tls_identity, validate_tls_not_expired,
};

#[test]
fn generate_self_signed_tls_identity_rejects_empty_subject_alt_names() {
    let error = generate_self_signed_tls_identity(&[], TlsKeyAlgorithm::EcdsaP256)
        .expect_err("empty SAN list must be rejected");

    assert!(matches!(error, TlsError::MissingSubjectAltNames));
}

#[test]
fn generate_self_signed_tls_identity_supports_ecdsa() {
    let subject_alt_names = vec!["teamserver.local".to_owned(), "127.0.0.1".to_owned()];
    let identity =
        generate_self_signed_tls_identity(&subject_alt_names, TlsKeyAlgorithm::EcdsaP256)
            .expect("ECDSA identity generation should succeed");

    assert!(identity.certificate_pem().starts_with(b"-----BEGIN CERTIFICATE-----"));
    assert!(identity.private_key_pem().starts_with(b"-----BEGIN PRIVATE KEY-----"));
    assert_eq!(public_key_algorithm_oid(&identity), "1.2.840.10045.2.1");

    let sans = subject_alt_names_from_identity(&identity);
    assert!(sans.iter().any(|name| name == "DNS:teamserver.local"));
    assert!(sans.iter().any(|name| name == "IP:127.0.0.1"));

    let _ = identity.server_config().expect("generated identity should build a rustls config");
}

#[test]
fn generate_self_signed_tls_identity_supports_rsa() {
    let subject_alt_names = vec!["127.0.0.1".to_owned()];
    let identity = generate_self_signed_tls_identity(&subject_alt_names, TlsKeyAlgorithm::Rsa2048)
        .expect("RSA identity generation should succeed");

    assert!(identity.private_key_pem().starts_with(b"-----BEGIN PRIVATE KEY-----"));
    assert_eq!(public_key_algorithm_oid(&identity), "1.2.840.113549.1.1.1");

    let _ = identity.server_config().expect("generated RSA identity should build a rustls config");
}

#[test]
fn load_tls_identity_round_trips_generated_pem_material() {
    let original =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let loaded = load_tls_identity(original.certificate_pem(), original.private_key_pem())
        .expect("generated PEM material should round-trip");

    assert_eq!(loaded.certificate_pem(), original.certificate_pem());
    assert_eq!(loaded.private_key_pem(), original.private_key_pem());
}

#[test]
fn load_tls_identity_rejects_missing_certificates() {
    let error = load_tls_identity(b"", b"")
        .expect_err("empty PEM inputs must be rejected as missing certificates");

    assert!(matches!(error, TlsError::MissingCertificates));
}

#[test]
fn load_tls_identity_rejects_missing_private_key() {
    let identity =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let error = load_tls_identity(identity.certificate_pem(), b"")
        .expect_err("missing private key must be rejected");

    assert!(matches!(error, TlsError::MissingPrivateKey));
}

#[test]
fn load_tls_identity_rejects_non_pem_input() {
    let error =
        load_tls_identity(b"garbage", b"garbage").expect_err("non-PEM input must be rejected");

    assert!(matches!(error, TlsError::Pem(_)));
}

#[test]
fn load_tls_identity_from_files_reads_existing_pem_material() {
    let temp_dir = TempDir::new().expect("temporary directory should be created");
    let identity =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");
    let cert_path = temp_dir.path().join("server.crt");
    let key_path = temp_dir.path().join("server.key");

    std::fs::write(&cert_path, identity.certificate_pem()).expect("certificate should be written");
    std::fs::write(&key_path, identity.private_key_pem()).expect("private key should be written");

    let loaded = load_tls_identity_from_files(&cert_path, &key_path)
        .expect("PEM files should load successfully");

    assert_eq!(loaded.certificate_pem(), identity.certificate_pem());
    assert_eq!(loaded.private_key_pem(), identity.private_key_pem());
}

#[test]
fn load_tls_identity_from_files_rejects_missing_paths() {
    let temp_dir = TempDir::new().expect("temporary directory should be created");
    let cert_path = temp_dir.path().join("missing.crt");
    let key_path = temp_dir.path().join("missing.key");

    let error = load_tls_identity_from_files(&cert_path, &key_path)
        .expect_err("missing PEM files must be rejected");

    match error {
        TlsError::ReadFile { path, .. } => {
            assert_eq!(path, cert_path.display().to_string());
        }
        other => panic!("expected ReadFile error, got {other:?}"),
    }
}

#[test]
fn load_tls_identity_from_files_rejects_missing_key_when_cert_exists() {
    let temp_dir = TempDir::new().expect("temporary directory should be created");
    let identity =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");
    let cert_path = temp_dir.path().join("server.crt");
    let key_path = temp_dir.path().join("missing.key");

    std::fs::write(&cert_path, identity.certificate_pem()).expect("certificate should be written");
    // key file is intentionally not written

    let error = load_tls_identity_from_files(&cert_path, &key_path)
        .expect_err("missing key file must be rejected");

    match error {
        TlsError::ReadFile { path, .. } => {
            assert_eq!(path, key_path.display().to_string());
        }
        other => panic!("expected ReadFile error for key path, got {other:?}"),
    }
}

#[test]
fn resolve_tls_identity_uses_profile_cert_paths_when_present() {
    let temp_dir = TempDir::new().expect("temporary directory should be created");
    let identity =
        generate_self_signed_tls_identity(&["listener.local".to_owned()], TlsKeyAlgorithm::Rsa2048)
            .expect("identity generation should succeed");
    let cert_path = temp_dir.path().join("listener.crt");
    let key_path = temp_dir.path().join("listener.key");

    std::fs::write(&cert_path, identity.certificate_pem()).expect("certificate should be written");
    std::fs::write(&key_path, identity.private_key_pem()).expect("private key should be written");

    let cert_config = HttpListenerCertConfig {
        cert: cert_path.display().to_string(),
        key: key_path.display().to_string(),
    };

    let resolved = resolve_tls_identity(
        &["ignored.local".to_owned()],
        Some(&cert_config),
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("existing profile PEMs should be preferred");

    assert_eq!(resolved.certificate_pem(), identity.certificate_pem());
    assert_eq!(resolved.private_key_pem(), identity.private_key_pem());
}

#[test]
fn resolve_tls_identity_fails_when_configured_pem_files_are_corrupt() {
    let temp_dir = TempDir::new().expect("temporary directory should be created");
    let cert_path = temp_dir.path().join("listener.crt");
    let key_path = temp_dir.path().join("listener.key");

    std::fs::write(
        &cert_path,
        b"-----BEGIN CERTIFICATE-----\n%%%invalid-base64%%%\n-----END CERTIFICATE-----\n",
    )
    .expect("certificate fixture should write");
    std::fs::write(
        &key_path,
        b"-----BEGIN PRIVATE KEY-----\n%%%invalid-base64%%%\n-----END PRIVATE KEY-----\n",
    )
    .expect("key fixture should write");

    let cert_config = HttpListenerCertConfig {
        cert: cert_path.display().to_string(),
        key: key_path.display().to_string(),
    };

    let error = resolve_tls_identity(
        &["ignored.local".to_owned()],
        Some(&cert_config),
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect_err("corrupt configured PEM should fail without fallback generation");

    assert!(matches!(error, TlsError::Pem(_)), "expected PEM parse error, got: {error:?}");
}

#[test]
fn resolve_tls_identity_generates_material_when_profile_cert_paths_are_absent() {
    let resolved = resolve_tls_identity(&["ws.local".to_owned()], None, TlsKeyAlgorithm::EcdsaP256)
        .expect("missing profile PEMs should trigger generation");

    assert!(resolved.certificate_pem().starts_with(b"-----BEGIN CERTIFICATE-----"));
    assert!(resolved.tls_acceptor().is_ok());
}

#[test]
fn install_default_crypto_provider_allows_tls_identity_creation_after_first_call() {
    install_default_crypto_provider();

    let identity =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed after provider installation");

    assert!(identity.server_config().is_ok());
}

#[test]
fn install_default_crypto_provider_is_idempotent_on_repeated_calls() {
    install_default_crypto_provider();
    install_default_crypto_provider();
    install_default_crypto_provider();

    let identity =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::Rsa2048)
            .expect("identity generation should succeed after repeated provider installation");

    assert!(identity.server_config().is_ok());
}

#[test]
fn install_default_crypto_provider_before_server_config_keeps_rustls_setup_working() {
    let identity = generate_self_signed_tls_identity(
        &["listener.local".to_owned()],
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("identity generation should succeed");

    install_default_crypto_provider();

    assert!(identity.server_config().is_ok());
}

fn public_key_algorithm_oid(identity: &TlsIdentity) -> String {
    let mut reader = BufReader::new(identity.certificate_pem());
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, std::io::Error>>()
        .expect("certificate PEM should parse");
    let certificate =
        certificates.first().expect("certificate PEM should contain at least one certificate");
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(certificate.as_ref())
        .expect("certificate DER should parse");

    parsed.tbs_certificate.subject_pki.algorithm.algorithm.to_id_string()
}

fn subject_alt_names_from_identity(identity: &TlsIdentity) -> Vec<String> {
    let mut reader = BufReader::new(identity.certificate_pem());
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, std::io::Error>>()
        .expect("certificate PEM should parse");
    let certificate =
        certificates.first().expect("certificate PEM should contain at least one certificate");
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(certificate.as_ref())
        .expect("certificate DER should parse");

    parsed
        .subject_alternative_name()
        .expect("certificate extensions should parse")
        .expect("generated certificate should include SANs")
        .value
        .general_names
        .iter()
        .map(|name| match name {
            x509_parser::extensions::GeneralName::DNSName(value) => format!("DNS:{value}"),
            x509_parser::extensions::GeneralName::IPAddress([a, b, c, d]) => {
                format!("IP:{a}.{b}.{c}.{d}")
            }
            other => other.to_string(),
        })
        .collect()
}

#[test]
fn generate_self_signed_tls_identity_has_reasonable_validity_period() {
    let identity = generate_self_signed_tls_identity(
        &["validity-test.local".to_owned()],
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("identity generation should succeed");

    let mut reader = BufReader::new(identity.certificate_pem());
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, std::io::Error>>()
        .expect("certificate PEM should parse");
    let cert_der =
        certificates.first().expect("certificate PEM should contain at least one certificate");
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert_der.as_ref())
        .expect("certificate DER should parse");

    let validity = &parsed.tbs_certificate.validity;
    let now = x509_parser::time::ASN1Time::now();

    assert!(
        validity.not_before <= now,
        "certificate not_before ({:?}) should be in the past or present",
        validity.not_before,
    );
    assert!(
        now <= validity.not_after,
        "certificate not_after ({:?}) should be in the future",
        validity.not_after,
    );

    // Validity span must be between 60 and 120 days to avoid static-fingerprint detection.
    let not_before_secs = validity.not_before.timestamp();
    let not_after_secs = validity.not_after.timestamp();
    let span_secs = not_after_secs - not_before_secs;

    let sixty_days_secs: i64 = 60 * 24 * 60 * 60;
    let one_twenty_days_secs: i64 = 120 * 24 * 60 * 60;

    assert!(
        span_secs >= sixty_days_secs,
        "certificate validity span ({span_secs}s) should be at least 60 days ({sixty_days_secs}s)",
    );
    assert!(
        span_secs <= one_twenty_days_secs,
        "certificate validity span ({span_secs}s) should be at most 120 days ({one_twenty_days_secs}s)",
    );
}

#[test]
fn mismatched_cert_and_key_fails_server_config() {
    let identity_a = generate_self_signed_tls_identity(
        &["identity-a.local".to_owned()],
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("identity A generation should succeed");

    let identity_b = generate_self_signed_tls_identity(
        &["identity-b.local".to_owned()],
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("identity B generation should succeed");

    // Combine cert from A with key from B — a realistic misconfiguration.
    let mismatched = load_tls_identity(identity_a.certificate_pem(), identity_b.private_key_pem())
        .expect("PEM parsing should succeed even with mismatched material");

    let error =
        mismatched.server_config().expect_err("mismatched cert/key must be rejected by rustls");

    assert!(
        matches!(error, TlsError::Rustls(_)),
        "expected TlsError::Rustls for mismatched cert/key, got: {error:?}"
    );
}

#[test]
fn mismatched_cert_and_key_fails_tls_acceptor() {
    let identity_a = generate_self_signed_tls_identity(
        &["acceptor-a.local".to_owned()],
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("identity A generation should succeed");

    let identity_b = generate_self_signed_tls_identity(
        &["acceptor-b.local".to_owned()],
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("identity B generation should succeed");

    let mismatched = load_tls_identity(identity_a.certificate_pem(), identity_b.private_key_pem())
        .expect("PEM parsing should succeed even with mismatched material");

    let error = match mismatched.tls_acceptor() {
        Err(e) => e,
        Ok(_) => panic!("mismatched cert/key must be rejected by tls_acceptor"),
    };

    assert!(
        matches!(error, TlsError::Rustls(_)),
        "expected TlsError::Rustls for mismatched cert/key via tls_acceptor, got: {error:?}"
    );
}

#[test]
fn mismatched_rsa_cert_and_ecdsa_key_fails_server_config() {
    let rsa_identity =
        generate_self_signed_tls_identity(&["rsa.local".to_owned()], TlsKeyAlgorithm::Rsa2048)
            .expect("RSA identity generation should succeed");

    let ecdsa_identity =
        generate_self_signed_tls_identity(&["ecdsa.local".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("ECDSA identity generation should succeed");

    // Cross-algorithm mismatch: RSA cert with ECDSA key.
    let mismatched =
        load_tls_identity(rsa_identity.certificate_pem(), ecdsa_identity.private_key_pem())
            .expect("PEM parsing should succeed even with cross-algorithm material");

    let error = mismatched
        .server_config()
        .expect_err("cross-algorithm cert/key must be rejected by rustls");

    assert!(
        matches!(error, TlsError::Rustls(_)),
        "expected TlsError::Rustls for cross-algorithm mismatch, got: {error:?}"
    );
}

#[test]
fn resolve_or_persist_generates_and_writes_pem_files_on_first_boot() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let cert_path = temp_dir.path().join("teamserver.tls.crt");
    let key_path = temp_dir.path().join("teamserver.tls.key");

    let identity = resolve_or_persist_tls_identity(
        &["teamserver.local".to_owned()],
        None,
        &cert_path,
        &key_path,
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("first-boot generation should succeed");

    assert!(cert_path.exists(), "certificate file should be written to disk");
    assert!(key_path.exists(), "private key file should be written to disk");
    assert!(identity.certificate_pem().starts_with(b"-----BEGIN CERTIFICATE-----"));
    assert!(identity.private_key_pem().starts_with(b"-----BEGIN PRIVATE KEY-----"));
}

#[test]
fn resolve_or_persist_sets_private_key_permissions_to_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let cert_path = temp_dir.path().join("teamserver.tls.crt");
    let key_path = temp_dir.path().join("teamserver.tls.key");

    resolve_or_persist_tls_identity(
        &["teamserver.local".to_owned()],
        None,
        &cert_path,
        &key_path,
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("first-boot generation should succeed");

    let key_mode = std::fs::metadata(&key_path)
        .expect("key file metadata should be readable")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(key_mode, 0o600, "private key file must be owner-only (0600), got {key_mode:o}");
}

#[test]
fn resolve_or_persist_hardens_pre_existing_0644_key_on_reload() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let cert_path = temp_dir.path().join("teamserver.tls.crt");
    let key_path = temp_dir.path().join("teamserver.tls.key");

    // Simulate an older build that wrote the key with permissive 0644 mode.
    let identity = generate_self_signed_tls_identity(
        &["teamserver.local".to_owned()],
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("identity generation should succeed");
    std::fs::write(&cert_path, identity.certificate_pem()).expect("certificate should be written");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&key_path)
            .and_then(|mut f: std::fs::File| f.write_all(identity.private_key_pem()))
            .expect("key should be written with 0644");
    }

    let mode_before =
        std::fs::metadata(&key_path).expect("key metadata should be readable").permissions().mode()
            & 0o777;
    assert_eq!(mode_before, 0o644, "precondition: key file must start with 0644");

    resolve_or_persist_tls_identity(
        &["teamserver.local".to_owned()],
        None,
        &cert_path,
        &key_path,
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("reload of pre-existing files should succeed");

    let mode_after = std::fs::metadata(&key_path)
        .expect("key metadata should be readable after reload")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode_after, 0o600,
        "private key must be hardened to 0600 on reload, was {mode_before:o}"
    );
}

#[test]
fn resolve_or_persist_reloads_existing_pem_files_on_subsequent_boots() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let cert_path = temp_dir.path().join("teamserver.tls.crt");
    let key_path = temp_dir.path().join("teamserver.tls.key");

    // First boot — generates and persists.
    let first = resolve_or_persist_tls_identity(
        &["teamserver.local".to_owned()],
        None,
        &cert_path,
        &key_path,
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("first-boot generation should succeed");

    // Second boot — must reload from disk, not generate a new certificate.
    let second = resolve_or_persist_tls_identity(
        &["teamserver.local".to_owned()],
        None,
        &cert_path,
        &key_path,
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("second-boot reload should succeed");

    assert_eq!(
        first.certificate_pem(),
        second.certificate_pem(),
        "certificate material must be identical across restarts"
    );
    assert_eq!(
        first.private_key_pem(),
        second.private_key_pem(),
        "private key material must be identical across restarts"
    );
}

#[test]
fn resolve_or_persist_prefers_configured_cert_paths_over_persisted_files() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");

    // Write one cert as the "configured" cert.
    let configured_identity = generate_self_signed_tls_identity(
        &["configured.local".to_owned()],
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("identity generation should succeed");
    let configured_cert_path = temp_dir.path().join("configured.crt");
    let configured_key_path = temp_dir.path().join("configured.key");
    std::fs::write(&configured_cert_path, configured_identity.certificate_pem())
        .expect("configured cert should be written");
    std::fs::write(&configured_key_path, configured_identity.private_key_pem())
        .expect("configured key should be written");

    // Auto-persist paths (different files).
    let auto_cert_path = temp_dir.path().join("teamserver.tls.crt");
    let auto_key_path = temp_dir.path().join("teamserver.tls.key");

    let cert_config = HttpListenerCertConfig {
        cert: configured_cert_path.display().to_string(),
        key: configured_key_path.display().to_string(),
    };

    let resolved = resolve_or_persist_tls_identity(
        &["ignored.local".to_owned()],
        Some(&cert_config),
        &auto_cert_path,
        &auto_key_path,
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("configured cert should be preferred");

    assert_eq!(
        resolved.certificate_pem(),
        configured_identity.certificate_pem(),
        "configured cert must be used instead of auto-generated one"
    );
    assert!(
        !auto_cert_path.exists(),
        "auto-persist paths should not be written when explicit cert is configured"
    );
}

#[test]
fn resolve_or_persist_fails_when_configured_pem_files_are_corrupt() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let configured_cert_path = temp_dir.path().join("configured.crt");
    let configured_key_path = temp_dir.path().join("configured.key");
    std::fs::write(
        &configured_cert_path,
        b"-----BEGIN CERTIFICATE-----\n%%%invalid-base64%%%\n-----END CERTIFICATE-----\n",
    )
    .expect("certificate fixture should be written");
    std::fs::write(
        &configured_key_path,
        b"-----BEGIN PRIVATE KEY-----\n%%%invalid-base64%%%\n-----END PRIVATE KEY-----\n",
    )
    .expect("key fixture should be written");

    let auto_cert_path = temp_dir.path().join("teamserver.tls.crt");
    let auto_key_path = temp_dir.path().join("teamserver.tls.key");

    let cert_config = HttpListenerCertConfig {
        cert: configured_cert_path.display().to_string(),
        key: configured_key_path.display().to_string(),
    };

    let error = resolve_or_persist_tls_identity(
        &["ignored.local".to_owned()],
        Some(&cert_config),
        &auto_cert_path,
        &auto_key_path,
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect_err("corrupt configured PEM should fail without writing fallback material");

    assert!(
        matches!(error, PersistTlsError::Tls(TlsError::Pem(_))),
        "expected PersistTlsError::Tls(TlsError::Pem(_)), got: {error:?}"
    );
    assert!(
        !auto_cert_path.exists(),
        "fallback certificate path should remain untouched on PEM parse failure"
    );
    assert!(
        !auto_key_path.exists(),
        "fallback key path should remain untouched on PEM parse failure"
    );
}

#[test]
fn resolve_or_persist_regenerates_both_files_when_only_cert_exists() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let cert_path = temp_dir.path().join("teamserver.tls.crt");
    let key_path = temp_dir.path().join("teamserver.tls.key");

    // Simulate partial state: only the certificate was persisted (e.g. interrupted write).
    let stale_identity =
        generate_self_signed_tls_identity(&["stale.local".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("stale identity generation should succeed");
    std::fs::write(&cert_path, stale_identity.certificate_pem())
        .expect("stale certificate should be written");

    assert!(cert_path.exists(), "precondition: cert file should exist");
    assert!(!key_path.exists(), "precondition: key file should not exist");

    let identity = resolve_or_persist_tls_identity(
        &["teamserver.local".to_owned()],
        None,
        &cert_path,
        &key_path,
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("cert-only partial state should trigger regeneration");

    // Both files must be written and match the returned identity.
    assert!(cert_path.exists(), "certificate file should be written");
    assert!(key_path.exists(), "private key file should be written");
    assert_eq!(
        std::fs::read(&cert_path).expect("cert should be readable"),
        identity.certificate_pem(),
        "on-disk cert must match returned identity"
    );
    assert_eq!(
        std::fs::read(&key_path).expect("key should be readable"),
        identity.private_key_pem(),
        "on-disk key must match returned identity"
    );

    // The stale cert must be overwritten — the new cert/key pair must be consistent.
    assert_ne!(
        identity.certificate_pem(),
        stale_identity.certificate_pem(),
        "stale certificate should be replaced by a fresh one"
    );
    identity.server_config().expect("regenerated identity must produce a valid rustls config");
}

#[test]
fn resolve_or_persist_regenerates_both_files_when_only_key_exists() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");
    let cert_path = temp_dir.path().join("teamserver.tls.crt");
    let key_path = temp_dir.path().join("teamserver.tls.key");

    // Simulate partial state: only the key was persisted (e.g. cert deleted manually).
    let stale_identity =
        generate_self_signed_tls_identity(&["stale.local".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("stale identity generation should succeed");
    std::fs::write(&key_path, stale_identity.private_key_pem())
        .expect("stale private key should be written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&key_path).expect("key metadata").permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&key_path, perms)
            .expect("world-readable key simulates unsafe partial state");
    }

    assert!(!cert_path.exists(), "precondition: cert file should not exist");
    assert!(key_path.exists(), "precondition: key file should exist");

    let identity = resolve_or_persist_tls_identity(
        &["teamserver.local".to_owned()],
        None,
        &cert_path,
        &key_path,
        TlsKeyAlgorithm::EcdsaP256,
    )
    .expect("key-only partial state should trigger regeneration");

    // Both files must be written and match the returned identity.
    assert!(cert_path.exists(), "certificate file should be written");
    assert!(key_path.exists(), "private key file should be written");
    assert_eq!(
        std::fs::read(&cert_path).expect("cert should be readable"),
        identity.certificate_pem(),
        "on-disk cert must match returned identity"
    );
    assert_eq!(
        std::fs::read(&key_path).expect("key should be readable"),
        identity.private_key_pem(),
        "on-disk key must match returned identity"
    );

    // The stale key must be overwritten — the new cert/key pair must be consistent.
    assert_ne!(
        identity.private_key_pem(),
        stale_identity.private_key_pem(),
        "stale private key should be replaced by a fresh one"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path).expect("key metadata").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "regenerated key must be chmod 0600 even when truncating a permissive file"
        );
    }

    identity.server_config().expect("regenerated identity must produce a valid rustls config");
}

#[test]
fn resolve_or_persist_fails_when_write_directory_is_read_only() {
    let temp_dir = tempfile::TempDir::new().expect("temporary directory should be created");

    // Make the directory read-only so writes fail.
    let mut perms = std::fs::metadata(temp_dir.path()).expect("metadata should read").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o555);
    std::fs::set_permissions(temp_dir.path(), perms).expect("permissions should update");

    let cert_path = temp_dir.path().join("teamserver.tls.crt");
    let key_path = temp_dir.path().join("teamserver.tls.key");

    let result = resolve_or_persist_tls_identity(
        &["teamserver.local".to_owned()],
        None,
        &cert_path,
        &key_path,
        TlsKeyAlgorithm::EcdsaP256,
    );

    // Restore permissions so the temp dir can be cleaned up.
    let mut perms = std::fs::metadata(temp_dir.path()).expect("metadata should read").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(temp_dir.path(), perms).expect("permissions should restore");

    assert!(
        matches!(result, Err(PersistTlsError::WriteFile { .. })),
        "write failure should surface as PersistTlsError::WriteFile, got: {result:?}"
    );
}

#[test]
fn validate_tls_not_expired_accepts_fresh_self_signed_cert() {
    install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["test.local".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let result = validate_tls_not_expired(identity.certificate_pem());
    assert!(result.is_ok(), "fresh self-signed cert should be valid, got: {result:?}");
}

#[test]
fn validate_tls_not_expired_rejects_missing_certificate() {
    let result = validate_tls_not_expired(b"not a pem at all");
    assert!(
        matches!(result, Err(TlsError::MissingCertificates)),
        "missing cert should return MissingCertificates, got: {result:?}"
    );
}

#[test]
fn validate_tls_not_expired_rejects_expired_cert() {
    use rcgen::{CertificateParams, DistinguishedName, KeyPair};
    use time::Duration;

    install_default_crypto_provider();
    let not_before = time::OffsetDateTime::now_utc() - Duration::days(30);
    let not_after = time::OffsetDateTime::now_utc() - Duration::days(2);

    let key_pair = KeyPair::generate().expect("key pair generation should succeed");
    let mut params =
        CertificateParams::new(vec!["expired.local".to_owned()]).expect("params should be created");
    params.not_before = not_before;
    params.not_after = not_after;
    params.distinguished_name = DistinguishedName::new();

    let cert = params.self_signed(&key_pair).expect("self-signed cert should be generated");
    let cert_pem = cert.pem();

    let result = validate_tls_not_expired(cert_pem.as_bytes());
    assert!(
        matches!(result, Err(TlsError::CertificateExpired { .. })),
        "expired cert should return CertificateExpired, got: {result:?}"
    );
}

#[test]
fn validate_tls_not_expired_rejects_not_yet_valid_cert() {
    use rcgen::{CertificateParams, DistinguishedName, KeyPair};
    use time::Duration;

    install_default_crypto_provider();
    let not_before = time::OffsetDateTime::now_utc() + Duration::days(1);
    let not_after = time::OffsetDateTime::now_utc() + Duration::days(365);

    let key_pair = KeyPair::generate().expect("key pair generation should succeed");
    let mut params =
        CertificateParams::new(vec!["future.local".to_owned()]).expect("params should be created");
    params.not_before = not_before;
    params.not_after = not_after;
    params.distinguished_name = DistinguishedName::new();

    let cert = params.self_signed(&key_pair).expect("self-signed cert should be generated");
    let cert_pem = cert.pem();

    let result = validate_tls_not_expired(cert_pem.as_bytes());
    assert!(
        matches!(result, Err(TlsError::CertificateNotYetValid { .. })),
        "future cert should return CertificateNotYetValid, got: {result:?}"
    );
}
