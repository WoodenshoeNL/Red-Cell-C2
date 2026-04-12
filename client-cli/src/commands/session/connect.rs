//! WebSocket URL normalization, TLS connector setup, and authenticated connect.

use tracing::instrument;

use crate::config::{ResolvedConfig, TlsMode};
use crate::error::CliError;
use crate::tls::build_fingerprint_client_config;

/// HTTP header name used by the teamserver for API-key authentication.
pub(crate) const API_KEY_HEADER: &str = "x-api-key";

/// Convert an HTTP(S) server URL to its WebSocket equivalent.
///
/// - `https://…` → `wss://…`
/// - `http://…`  → `ws://…`
/// - Other forms → `ws://…` (safe fallback for bare host:port strings)
///
/// # Examples
///
/// ```ignore
/// assert_eq!(server_to_ws_url("https://ts.example.com:40056"), "wss://ts.example.com:40056");
/// assert_eq!(server_to_ws_url("http://localhost:8080"), "ws://localhost:8080");
/// ```
pub(crate) fn server_to_ws_url(server: &str) -> String {
    if let Some(rest) = server.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = server.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("ws://{server}")
    }
}

/// Build a `tokio_tungstenite::Connector` for the given TLS mode.
///
/// For `wss://` URLs the connector is used to perform the TLS handshake.
/// For `ws://` URLs pass `Connector::Plain` so tungstenite skips TLS.
fn build_connector(
    tls_mode: &TlsMode,
    is_tls: bool,
) -> Result<tokio_tungstenite::Connector, CliError> {
    if !is_tls {
        return Ok(tokio_tungstenite::Connector::Plain);
    }

    match tls_mode {
        TlsMode::SystemRoots => {
            // System roots are handled by the rustls-tls-webpki-roots feature
            // baked into tokio-tungstenite; return Plain so connect_async uses
            // the crate's own default TLS stack.
            Ok(tokio_tungstenite::Connector::Plain)
        }

        TlsMode::CustomCa(path) => {
            let pem = std::fs::read(path).map_err(|e| {
                CliError::General(format!("failed to read CA cert {}: {e}", path.display()))
            })?;

            let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
                rustls_pemfile::certs(&mut &pem[..]).filter_map(|r| r.ok()).collect();

            if certs.is_empty() {
                return Err(CliError::General(format!(
                    "no valid certificates found in CA file {}",
                    path.display()
                )));
            }

            let mut root_store = rustls::RootCertStore::empty();
            for cert in certs {
                root_store
                    .add(cert)
                    .map_err(|e| CliError::General(format!("failed to add CA certificate: {e}")))?;
            }

            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            Ok(tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(config)))
        }

        TlsMode::Fingerprint(fp) => {
            let config = build_fingerprint_client_config(&fp.sha256_hex, fp.pin_mode)?;
            Ok(tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(config)))
        }
    }
}

/// Returns `true` when `tls_err` is a TLS certificate validation failure
/// (unknown issuer, expired cert, name mismatch, etc.) as opposed to a
/// protocol or configuration error.
///
/// Only [`tokio_tungstenite::tungstenite::error::TlsError::Rustls`] is
/// inspected because this crate uses the `rustls-tls-webpki-roots` feature
/// exclusively.
pub(crate) fn is_tls_cert_failure(
    tls_err: &tokio_tungstenite::tungstenite::error::TlsError,
) -> bool {
    use tokio_tungstenite::tungstenite::error::TlsError;
    matches!(
        tls_err,
        TlsError::Rustls(
            rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented
        )
    )
}

/// Map a tungstenite error to a [`CliError`].
pub(crate) fn map_ws_error(e: tokio_tungstenite::tungstenite::Error, url: &str) -> CliError {
    use tokio_tungstenite::tungstenite::Error as WsErr;
    match e {
        WsErr::Io(io_err) if io_err.kind() == std::io::ErrorKind::ConnectionRefused => {
            CliError::ServerUnreachable(format!("cannot connect to {url}: connection refused"))
        }
        WsErr::Io(io_err) => {
            CliError::ServerUnreachable(format!("network error connecting to {url}: {io_err}"))
        }
        WsErr::Tls(tls_err) => {
            // TLS errors are connectivity/trust problems, not authentication failures.
            // Give a more specific message for certificate validation failures so
            // callers do not confuse them with bad credentials (exit code 3).
            if is_tls_cert_failure(&tls_err) {
                CliError::ServerUnreachable(format!(
                    "TLS certificate trust failure for {url}: {tls_err} \
                     — verify the server certificate or configure \
                     --tls-ca / --tls-fingerprint"
                ))
            } else {
                CliError::ServerUnreachable(format!("TLS handshake failed for {url}: {tls_err}"))
            }
        }
        WsErr::Http(ref resp) if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 => {
            CliError::AuthFailure(format!("WebSocket upgrade rejected: {}", resp.status()))
        }
        _ => CliError::ServerUnreachable(format!("failed to connect WebSocket at {url}: {e}")),
    }
}

/// Open an authenticated WebSocket connection to the teamserver session endpoint.
///
/// Converts the configured HTTP(S) server URL to a WS(S) URL, builds the
/// appropriate TLS connector, and performs the HTTP upgrade with the
/// `x-api-key` header set.
#[instrument(skip(config), fields(server = %config.server))]
pub(crate) async fn connect_websocket(
    config: &ResolvedConfig,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    CliError,
> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

    let ws_base = server_to_ws_url(&config.server);
    let ws_url = format!("{ws_base}/api/v1/ws");
    let is_tls = ws_url.starts_with("wss://");

    let mut request = ws_url
        .as_str()
        .into_client_request()
        .map_err(|e| CliError::General(format!("invalid WebSocket URL '{ws_url}': {e}")))?;

    request.headers_mut().insert(
        API_KEY_HEADER,
        config
            .token
            .parse()
            .map_err(|e| CliError::General(format!("invalid token header value: {e}")))?,
    );

    let connector = build_connector(&config.tls_mode, is_tls)?;

    // Use connect_async for SystemRoots (lets the crate's built-in TLS stack
    // run) and connect_async_tls_with_config for custom connectors.
    let (ws, _response) = match connector {
        tokio_tungstenite::Connector::Plain if is_tls => {
            // SystemRoots: delegate to crate default (webpki-roots feature).
            tokio_tungstenite::connect_async(request).await.map_err(|e| map_ws_error(e, &ws_url))?
        }
        connector => {
            tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
                .await
                .map_err(|e| map_ws_error(e, &ws_url))?
        }
    };

    Ok(ws)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_becomes_wss() {
        assert_eq!(server_to_ws_url("https://ts.example.com:40056"), "wss://ts.example.com:40056");
    }

    #[test]
    fn http_becomes_ws() {
        assert_eq!(server_to_ws_url("http://localhost:8080"), "ws://localhost:8080");
    }

    #[test]
    fn bare_host_gets_ws_scheme() {
        assert_eq!(server_to_ws_url("localhost:8080"), "ws://localhost:8080");
    }

    /// `connect_websocket` against an unreachable address must return
    /// `CliError::ServerUnreachable`.
    #[tokio::test]
    async fn connect_websocket_returns_server_unreachable_on_refused() {
        let cfg = crate::config::ResolvedConfig {
            server: "http://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let result = connect_websocket(&cfg).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "unreachable server must return ServerUnreachable, got {result:?}"
        );
    }

    /// A rustls `InvalidCertificate` error must be classified as a cert failure.
    #[test]
    fn is_tls_cert_failure_detects_invalid_certificate() {
        use tokio_tungstenite::tungstenite::error::TlsError;
        let tls_err =
            TlsError::Rustls(rustls::Error::InvalidCertificate(rustls::CertificateError::Expired));
        assert!(is_tls_cert_failure(&tls_err));
    }

    /// `UnknownIssuer` is a certificate validation failure.
    #[test]
    fn is_tls_cert_failure_detects_unknown_issuer() {
        use tokio_tungstenite::tungstenite::error::TlsError;
        let tls_err = TlsError::Rustls(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ));
        assert!(is_tls_cert_failure(&tls_err));
    }

    /// `NoCertificatesPresented` is a certificate validation failure.
    #[test]
    fn is_tls_cert_failure_detects_no_certificates_presented() {
        use tokio_tungstenite::tungstenite::error::TlsError;
        let tls_err = TlsError::Rustls(rustls::Error::NoCertificatesPresented);
        assert!(is_tls_cert_failure(&tls_err));
    }

    /// A protocol error (e.g. no shared cipher suites) is NOT a cert failure.
    #[test]
    fn is_tls_cert_failure_returns_false_for_protocol_error() {
        use tokio_tungstenite::tungstenite::error::TlsError;
        let tls_err = TlsError::Rustls(rustls::Error::DecryptError);
        assert!(!is_tls_cert_failure(&tls_err));
    }

    /// A TLS certificate error must map to `ServerUnreachable`, not `AuthFailure`.
    #[test]
    fn map_ws_error_tls_cert_error_is_server_unreachable_not_auth_failure() {
        use tokio_tungstenite::tungstenite::Error as WsErr;
        use tokio_tungstenite::tungstenite::error::TlsError;
        let err = WsErr::Tls(TlsError::Rustls(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        )));
        let mapped = map_ws_error(err, "wss://ts.example.com");
        assert!(
            matches!(mapped, CliError::ServerUnreachable(_)),
            "TLS cert error must be ServerUnreachable, got {mapped:?}"
        );
        // Exit code must be 4 (server unreachable), not 3 (auth failure).
        assert_eq!(mapped.exit_code(), crate::error::EXIT_SERVER_UNREACHABLE);
    }

    /// The `ServerUnreachable` message for a cert failure must mention TLS trust.
    #[test]
    fn map_ws_error_tls_cert_error_message_mentions_trust() {
        use tokio_tungstenite::tungstenite::Error as WsErr;
        use tokio_tungstenite::tungstenite::error::TlsError;
        let err = WsErr::Tls(TlsError::Rustls(rustls::Error::InvalidCertificate(
            rustls::CertificateError::Expired,
        )));
        let mapped = map_ws_error(err, "wss://ts.example.com");
        let msg = mapped.to_string();
        assert!(
            msg.contains("trust") || msg.contains("certificate"),
            "message must mention trust/certificate, got: {msg}"
        );
    }

    /// A non-cert TLS error must still map to `ServerUnreachable` (not `AuthFailure`).
    #[test]
    fn map_ws_error_non_cert_tls_error_is_server_unreachable() {
        use tokio_tungstenite::tungstenite::Error as WsErr;
        use tokio_tungstenite::tungstenite::error::TlsError;
        let err = WsErr::Tls(TlsError::Rustls(rustls::Error::DecryptError));
        let mapped = map_ws_error(err, "wss://ts.example.com");
        assert!(
            matches!(mapped, CliError::ServerUnreachable(_)),
            "non-cert TLS error must be ServerUnreachable, got {mapped:?}"
        );
        assert_eq!(mapped.exit_code(), crate::error::EXIT_SERVER_UNREACHABLE);
    }
}
