use super::super::operator_msg::{
    flat_info_string, loot_item_from_flat_info, loot_item_from_response, normalize_agent_id,
    sanitize_text,
};
use super::super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use futures_util::SinkExt;
use red_cell_common::OperatorInfo;
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{
    AgentInfo as OperatorAgentInfo, AgentPivotsInfo, AgentResponseInfo, AgentUpdateInfo,
    BuildPayloadMessageInfo, BuildPayloadResponseInfo, ChatCode, EventCode, FlatInfo,
    InitConnectionCode, ListenerCode, ListenerErrorInfo, ListenerInfo, ListenerMarkInfo, LoginInfo,
    Message, MessageHead, MessageInfo, NameInfo, SessionCode, TeamserverLogInfo,
};
use red_cell_common::tls::{TlsKeyAlgorithm, generate_self_signed_tls_identity};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message as TungsteniteMessage};
fn classify_tls_error_expired() {
    let msg = classify_tls_error("invalid peer certificate: certificate expired: ...");
    assert!(msg.contains("expired"), "expected 'expired' in: {msg}");
}

#[test]
fn classify_tls_error_hostname_mismatch() {
    let msg = classify_tls_error("invalid peer certificate: certificate not valid for name ...");
    assert!(msg.contains("hostname mismatch"), "expected 'hostname mismatch' in: {msg}");
}

#[test]
fn classify_tls_error_unknown_issuer() {
    let msg = classify_tls_error("invalid peer certificate: UnknownIssuer");
    assert!(msg.contains("unknown authority"), "expected 'unknown authority' in: {msg}");
}

#[test]
fn classify_tls_error_connection_refused() {
    let msg = classify_tls_error("tcp connect error: Connection refused (os error 111)");
    assert!(msg.contains("Connection refused"), "expected 'Connection refused' in: {msg}");
}

#[test]
fn classify_tls_error_fingerprint_mismatch() {
    let msg = classify_tls_error("certificate fingerprint mismatch: expected abc, got def");
    assert!(msg.contains("fingerprint"), "expected 'fingerprint' in: {msg}");
}

#[test]
fn classify_tls_failure_kind_fingerprint_mismatch() {
    let kind =
        classify_tls_failure_kind("certificate fingerprint mismatch: expected aabb, got ccdd");
    assert_eq!(
        kind,
        crate::login::TlsFailureKind::CertificateChanged { stored_fingerprint: "aabb".to_owned() },
        "fingerprint mismatch must produce CertificateChanged with the stored fingerprint"
    );
}

#[test]
fn classify_tls_failure_kind_unknown_issuer_uppercase() {
    let kind = classify_tls_failure_kind("invalid peer certificate: UnknownIssuer");
    assert_eq!(
        kind,
        crate::login::TlsFailureKind::UnknownServer,
        "UnknownIssuer must map to UnknownServer"
    );
}

#[test]
fn classify_tls_failure_kind_unknown_issuer_lowercase() {
    let kind = classify_tls_failure_kind("unknown issuer");
    assert_eq!(
        kind,
        crate::login::TlsFailureKind::UnknownServer,
        "lowercase 'unknown issuer' must map to UnknownServer"
    );
}

#[test]
fn classify_tls_failure_kind_generic_fallthrough() {
    let kind = classify_tls_failure_kind("invalid peer certificate: certificate expired");
    assert_eq!(
        kind,
        crate::login::TlsFailureKind::CertificateError,
        "unrecognised error string must fall through to CertificateError"
    );
}

#[test]
fn classify_tls_failure_kind_malformed_mismatch_no_expected_token() {
    // No "expected " token — fingerprint extraction must return empty string, not panic.
    let kind = classify_tls_failure_kind("certificate fingerprint mismatch: no tokens here");
    assert_eq!(
        kind,
        crate::login::TlsFailureKind::CertificateChanged { stored_fingerprint: "".to_owned() },
        "malformed mismatch string must produce CertificateChanged with empty fingerprint"
    );
}

#[test]
fn is_tls_cert_error_detects_invalid_cert() {
    assert!(is_tls_cert_error("invalid peer certificate: UnknownIssuer"));
    assert!(is_tls_cert_error("certificate fingerprint mismatch: expected abc, got def"));
    assert!(!is_tls_cert_error("Connection refused (os error 111)"));
    assert!(!is_tls_cert_error("broken pipe"));
}

#[test]
fn build_tls_connector_rejects_empty_pem_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let empty_pem = dir.path().join("empty.pem");
    std::fs::write(&empty_pem, b"").expect("write empty pem");
    let sink = Arc::new(std::sync::Mutex::new(None));

    let result = build_tls_connector(&TlsVerification::CustomCa(empty_pem.clone()), sink);

    assert!(result.is_err(), "empty PEM file must fail");
    let err = result.err().expect("should be Err");
    assert!(matches!(err, TransportError::CustomCaEmpty(_)), "expected CustomCaEmpty, got: {err}");
}

#[test]
fn build_tls_connector_rejects_malformed_pem_content() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bad_pem = dir.path().join("bad.pem");
    // Write something that looks like PEM structure but has garbage inside.
    std::fs::write(
        &bad_pem,
        b"-----BEGIN CERTIFICATE-----\nNOT-VALID-BASE64!!!@@@\n-----END CERTIFICATE-----\n",
    )
    .expect("write bad pem");
    let sink = Arc::new(std::sync::Mutex::new(None));

    let result = build_tls_connector(&TlsVerification::CustomCa(bad_pem.clone()), sink);

    assert!(result.is_err(), "malformed PEM must fail");
    let err = result.err().expect("should be Err");
    assert!(matches!(err, TransportError::CustomCaParse(_)), "expected CustomCaParse, got: {err}");
}

#[test]
fn build_tls_connector_rejects_nonexistent_ca_file() {
    let sink = Arc::new(std::sync::Mutex::new(None));
    let result = build_tls_connector(
        &TlsVerification::CustomCa(PathBuf::from("/nonexistent/path/ca.pem")),
        sink,
    );

    assert!(result.is_err(), "nonexistent CA file must fail");
    let err = result.err().expect("should be Err");
    assert!(
        matches!(err, TransportError::CustomCaRead { .. }),
        "expected CustomCaRead, got: {err}"
    );
}

#[test]
fn build_tls_connector_succeeds_for_certificate_authority() {
    red_cell_common::tls::install_default_crypto_provider();
    let sink = Arc::new(std::sync::Mutex::new(None));
    let result = build_tls_connector(&TlsVerification::CertificateAuthority, sink);
    assert!(result.is_ok(), "CertificateAuthority mode should build successfully");
}

#[test]
fn build_tls_connector_succeeds_for_fingerprint_mode() {
    red_cell_common::tls::install_default_crypto_provider();
    let sink = Arc::new(std::sync::Mutex::new(None));
    let fingerprint = "ab".repeat(32); // 64 hex chars = SHA-256
    let result = build_tls_connector(&TlsVerification::Fingerprint(fingerprint), sink);
    assert!(result.is_ok(), "Fingerprint mode should build successfully");
}

#[test]
fn build_tls_connector_succeeds_for_dangerous_skip_verify() {
    red_cell_common::tls::install_default_crypto_provider();
    let sink = Arc::new(std::sync::Mutex::new(None));
    let result = build_tls_connector(&TlsVerification::DangerousSkipVerify, sink);
    assert!(result.is_ok(), "DangerousSkipVerify mode should build successfully");
}

#[test]
fn fingerprint_verifier_accepts_matching_cert() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["test.local".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let cert_der = {
        let mut reader = std::io::BufReader::new(identity.certificate_pem());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("cert PEM should parse");
        certs.into_iter().next().expect("should have one cert")
    };
    let fingerprint = certificate_fingerprint(cert_der.as_ref());

    let provider = aws_lc_rs::default_provider();
    let sink = Arc::new(std::sync::Mutex::new(None));
    let verifier = FingerprintCertificateVerifier {
        expected_fingerprint: fingerprint.clone(),
        provider,
        fingerprint_sink: Arc::clone(&sink),
    };

    let result = verifier.verify_server_cert(
        &cert_der,
        &[],
        &ServerName::try_from("test.local").expect("valid server name"),
        &[],
        UnixTime::now(),
    );
    assert!(result.is_ok(), "matching fingerprint should be accepted");
    assert_eq!(
        sink.lock().unwrap().as_deref(),
        Some(fingerprint.as_str()),
        "fingerprint sink should contain the actual fingerprint"
    );
}

#[test]
fn fingerprint_verifier_rejects_mismatched_cert() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["test.local".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let cert_der = {
        let mut reader = std::io::BufReader::new(identity.certificate_pem());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("cert PEM should parse");
        certs.into_iter().next().expect("should have one cert")
    };
    let actual_fingerprint = certificate_fingerprint(cert_der.as_ref());
    let wrong_fingerprint = "00".repeat(32);

    let provider = aws_lc_rs::default_provider();
    let sink = Arc::new(std::sync::Mutex::new(None));
    let verifier = FingerprintCertificateVerifier {
        expected_fingerprint: wrong_fingerprint,
        provider,
        fingerprint_sink: Arc::clone(&sink),
    };

    let result = verifier.verify_server_cert(
        &cert_der,
        &[],
        &ServerName::try_from("test.local").expect("valid server name"),
        &[],
        UnixTime::now(),
    );
    assert!(result.is_err(), "mismatched fingerprint should be rejected");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("fingerprint mismatch"),
        "error should mention fingerprint mismatch, got: {err_msg}"
    );
    assert_eq!(
        sink.lock().unwrap().as_deref(),
        Some(actual_fingerprint.as_str()),
        "fingerprint sink should be populated even on mismatch"
    );
}

#[test]
fn fingerprint_verifier_case_insensitive_match() {
    red_cell_common::tls::install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["test.local".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation should succeed");

    let cert_der = {
        let mut reader = std::io::BufReader::new(identity.certificate_pem());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .expect("cert PEM should parse");
        certs.into_iter().next().expect("should have one cert")
    };
    let fingerprint = certificate_fingerprint(cert_der.as_ref());
    // The expected_fingerprint is lowercased in build_tls_connector, so test
    // that the verifier works when given an already-lowercase fingerprint
    // (which is what build_tls_connector passes).
    assert_eq!(fingerprint, fingerprint.to_ascii_lowercase());

    let provider = aws_lc_rs::default_provider();
    let sink = Arc::new(std::sync::Mutex::new(None));
    let verifier = FingerprintCertificateVerifier {
        expected_fingerprint: fingerprint.to_ascii_uppercase(),
        provider,
        fingerprint_sink: Arc::clone(&sink),
    };

    // Upper-case expected vs lower-case actual — should fail because
    // verify_server_cert does a direct string comparison. The case
    // normalisation happens in build_tls_connector, not in the verifier.
    let result = verifier.verify_server_cert(
        &cert_der,
        &[],
        &ServerName::try_from("test.local").expect("valid server name"),
        &[],
        UnixTime::now(),
    );
    assert!(
        result.is_err(),
        "upper-case expected should not match lower-case actual in the verifier itself"
    );
}

#[test]
fn next_reconnect_delay_initial_value_doubles() {
    let delay = next_reconnect_delay(INITIAL_RECONNECT_DELAY);
    assert_eq!(delay, Duration::from_secs(2));
}

#[test]
fn next_reconnect_delay_doubles_each_step() {
    let mut delay = INITIAL_RECONNECT_DELAY;
    let expected_secs = [2, 4, 8, 16];
    for &expected in &expected_secs {
        delay = next_reconnect_delay(delay);
        assert_eq!(delay, Duration::from_secs(expected));
    }
}

#[test]
fn next_reconnect_delay_saturates_at_max() {
    let mut delay = INITIAL_RECONNECT_DELAY;
    // Run enough iterations to well exceed MAX_RECONNECT_DELAY (30s).
    for _ in 0..20 {
        delay = next_reconnect_delay(delay);
    }
    assert_eq!(delay, MAX_RECONNECT_DELAY);
}

#[test]
fn next_reconnect_delay_at_boundary_does_not_exceed_max() {
    // 16s -> 32s would exceed 30s cap.
    let delay = next_reconnect_delay(Duration::from_secs(16));
    assert_eq!(delay, MAX_RECONNECT_DELAY);
}
