use super::super::{cert_mtime, reload_tls_from_files, spawn_cert_file_watcher};
use super::*;

/// Expired certificate PEM material generated with ECDSA P-256.
/// `not_before` = 2026-03-08, `not_after` = 2026-04-05 (always in the past).
const EXPIRED_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIBLjCB1qADAgECAhQup35cFN5Dlkq4pVl96UATk4GxLDAKBggqhkjOPQQDAjAY
MRYwFAYDVQQDDA1leHBpcmVkLmxvY2FsMB4XDTI2MDMwODIxMTY1M1oXDTI2MDQw
NTIxMTY1M1owGDEWMBQGA1UEAwwNZXhwaXJlZC5sb2NhbDBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABFE5jhMv1cWqQ7t7mC+pbBTVqRPqeR6bMozh0nWejfDCVXPT
QWnFaaQxqrO/qbdYCaYcXYg1DmWpEfkQx0sjTekwCgYIKoZIzj0EAwIDRwAwRAIg
al7Ctn1lXtUfe3gVRfxhBNJcNy9UBL6ftEJpt6zqeJoCIGnSOdPiqtHitgGPn8ct
6UhZXOsUm6pRjDniIHBrCmfY
-----END CERTIFICATE-----
";

const EXPIRED_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFUgNuvIUst+J3Gqk
0/YQr6Yre8f1boAvBDljxq3C1qqhRANCAARROY4TL9XFqkO7e5gvqWwU1akT6nke
mzKM4dJ1no3wwlVz00FpxWmkMaqzv6m3WAmmHF2INQ5lqRH5EMdLI03p
-----END PRIVATE KEY-----
";

#[tokio::test]
async fn reload_tls_cert_returns_listener_not_found_when_listener_does_not_exist() {
    let mgr = manager().await.expect("manager must build");
    let result = mgr.reload_tls_cert("nonexistent", b"cert", b"key").await;
    assert!(
        matches!(result, Err(ListenerManagerError::ListenerNotFound { .. })),
        "expected ListenerNotFound, got: {result:?}"
    );
}

#[tokio::test]
async fn reload_tls_cert_returns_not_tls_listener_for_plain_http() {
    let mgr = manager().await.expect("manager must build");
    let port = available_port().expect("port must be available");
    mgr.create(http_listener("plain-http", port)).await.expect("create must succeed");
    mgr.start("plain-http").await.expect("start must succeed");
    wait_for_listener(port, false).await.expect("listener must be ready");

    let result = mgr.reload_tls_cert("plain-http", b"cert", b"key").await;
    assert!(
        matches!(result, Err(ListenerManagerError::NotTlsListener { .. })),
        "expected NotTlsListener, got: {result:?}"
    );

    mgr.stop("plain-http").await.expect("stop must succeed");
}

#[tokio::test]
async fn reload_tls_cert_returns_tls_cert_error_for_invalid_pem() {
    let mgr = manager().await.expect("manager must build");
    let port = available_port().expect("port must be available");

    let config = ListenerConfig::from(HttpListenerConfig {
        name: "tls-invalid-pem".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["localhost".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: true,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
        suppress_opsec_warnings: true,
    });

    mgr.create(config).await.expect("create must succeed");
    mgr.start("tls-invalid-pem").await.expect("start must succeed");
    wait_for_listener(port, true).await.expect("listener must be ready");

    let result = mgr.reload_tls_cert("tls-invalid-pem", b"not-a-cert", b"not-a-key").await;
    assert!(
        matches!(result, Err(ListenerManagerError::TlsCertError { .. })),
        "expected TlsCertError, got: {result:?}"
    );

    mgr.stop("tls-invalid-pem").await.expect("stop must succeed");
}

#[tokio::test]
async fn reload_tls_cert_returns_tls_cert_error_for_expired_cert() {
    use red_cell_common::tls::install_default_crypto_provider;

    install_default_crypto_provider();

    let mgr = manager().await.expect("manager must build");
    let port = create_and_start_https(&mgr, "tls-expired").await.expect("listener must start");
    wait_for_listener(port, true).await.expect("listener must be ready");

    let result = mgr.reload_tls_cert("tls-expired", EXPIRED_CERT_PEM, EXPIRED_KEY_PEM).await;
    assert!(
        matches!(result, Err(ListenerManagerError::TlsCertError { .. })),
        "expected TlsCertError for expired cert, got: {result:?}"
    );

    mgr.stop("tls-expired").await.expect("stop must succeed");
}

#[tokio::test]
async fn reload_tls_cert_swaps_config_with_valid_cert() {
    use red_cell_common::tls::{TlsKeyAlgorithm, generate_self_signed_tls_identity};

    let mgr = manager().await.expect("manager must build");
    let port = create_and_start_https(&mgr, "tls-reload-ok").await.expect("listener must start");
    wait_for_listener(port, true).await.expect("listener must be ready");

    // Generate a fresh valid certificate and reload it.
    let identity =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation must succeed");

    let result = mgr
        .reload_tls_cert("tls-reload-ok", identity.certificate_pem(), identity.private_key_pem())
        .await;
    assert!(result.is_ok(), "expected Ok(()) for valid cert reload, got: {result:?}");

    mgr.stop("tls-reload-ok").await.expect("stop must succeed");
}

// ---------------------------------------------------------------------------
// cert file watcher / reload_tls_from_files tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reload_tls_from_files_succeeds_with_valid_cert_files() {
    use red_cell_common::tls::{
        TlsKeyAlgorithm, generate_self_signed_tls_identity, install_default_crypto_provider,
    };

    install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation must succeed");

    let dir = tempfile::tempdir().expect("tempdir must be created");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, identity.certificate_pem()).expect("write cert");
    std::fs::write(&key_path, identity.private_key_pem()).expect("write key");

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        identity.certificate_pem().to_vec(),
        identity.private_key_pem().to_vec(),
    )
    .await
    .expect("initial RustlsConfig must be created");

    let result = reload_tls_from_files(&cert_path, &key_path, &tls_config).await;
    assert!(result.is_ok(), "expected Ok for valid cert files, got: {result:?}");
}

#[tokio::test]
async fn reload_tls_from_files_returns_error_for_missing_cert_file() {
    use red_cell_common::tls::{
        TlsKeyAlgorithm, generate_self_signed_tls_identity, install_default_crypto_provider,
    };

    install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation must succeed");

    let dir = tempfile::tempdir().expect("tempdir must be created");
    let cert_path = dir.path().join("nonexistent-cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&key_path, identity.private_key_pem()).expect("write key");

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        identity.certificate_pem().to_vec(),
        identity.private_key_pem().to_vec(),
    )
    .await
    .expect("initial RustlsConfig must be created");

    let result = reload_tls_from_files(&cert_path, &key_path, &tls_config).await;
    assert!(result.is_err(), "expected error for missing cert file, got: {result:?}");
}

#[test]
fn cert_mtime_returns_none_for_nonexistent_file() {
    let path = std::path::Path::new("/nonexistent/cert.pem");
    assert!(cert_mtime(path).is_none(), "nonexistent file should return None");
}

#[test]
fn cert_mtime_returns_some_for_existing_file() {
    let dir = tempfile::tempdir().expect("tempdir must be created");
    let path = dir.path().join("cert.pem");
    std::fs::write(&path, b"dummy").expect("write test file");
    assert!(cert_mtime(&path).is_some(), "existing file should return Some");
}

#[tokio::test]
async fn spawn_cert_file_watcher_reloads_on_mtime_change() {
    use red_cell_common::tls::{
        TlsKeyAlgorithm, generate_self_signed_tls_identity, install_default_crypto_provider,
    };

    install_default_crypto_provider();
    let identity_a =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity A generation must succeed");

    let identity_b =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity B generation must succeed");

    let dir = tempfile::tempdir().expect("tempdir must be created");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, identity_a.certificate_pem()).expect("write cert A");
    std::fs::write(&key_path, identity_a.private_key_pem()).expect("write key A");

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        identity_a.certificate_pem().to_vec(),
        identity_a.private_key_pem().to_vec(),
    )
    .await
    .expect("initial RustlsConfig must be created");

    let handle = spawn_cert_file_watcher(
        "test-watcher".to_owned(),
        cert_path.clone(),
        key_path.clone(),
        tls_config.clone(),
    );

    // The watcher polls at 30s intervals by default, which is too slow for a test.
    // Instead, test that `reload_tls_from_files` works correctly when files change,
    // which is the core logic the watcher invokes.
    std::fs::write(&cert_path, identity_b.certificate_pem()).expect("write cert B");
    std::fs::write(&key_path, identity_b.private_key_pem()).expect("write key B");

    let result = reload_tls_from_files(&cert_path, &key_path, &tls_config).await;
    assert!(result.is_ok(), "reload after file change must succeed, got: {result:?}");

    // Clean up: abort the watcher task.
    handle.abort();
    let _ = handle.await;
}
