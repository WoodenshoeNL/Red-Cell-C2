//! HTTP transport helpers: TLS client construction, response mapping, and
//! error classification.

use std::fs;
use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;

use crate::config::{ResolvedConfig, TlsMode};
use crate::error::CliError;
use crate::tls::build_fingerprint_client_config;

/// Build a [`reqwest::Client`] with TLS verification configured according to
/// `config.tls_mode`.
pub(super) fn build_http_client(config: &ResolvedConfig) -> Result<Client, CliError> {
    let base = Client::builder().timeout(Duration::from_secs(config.timeout));

    let client = match &config.tls_mode {
        TlsMode::SystemRoots => base
            .build()
            .map_err(|e| CliError::General(format!("failed to build HTTP client: {e}")))?,

        TlsMode::CustomCa(path) => {
            let pem = fs::read(path).map_err(|e| {
                CliError::General(format!("failed to read CA cert {}: {e}", path.display()))
            })?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|e| CliError::General(format!("invalid CA certificate: {e}")))?;
            base.tls_built_in_root_certs(false)
                .add_root_certificate(cert)
                .build()
                .map_err(|e| CliError::General(format!("failed to build HTTP client: {e}")))?
        }

        TlsMode::Fingerprint(fp) => {
            let rustls_config = build_fingerprint_client_config(&fp.sha256_hex, fp.pin_mode)?;
            base.use_preconfigured_tls(rustls_config)
                .build()
                .map_err(|e| CliError::General(format!("failed to build HTTP client: {e}")))?
        }
    };
    Ok(client)
}

/// Classify an HTTP response by status code, converting error codes to
/// [`CliError`] and passing successful responses through unchanged.
///
/// This is the single authoritative place for the status-code → error mapping
/// shared by all endpoints (JSON, raw-bytes, and no-body).  Callers handle
/// only the success body.
pub(super) async fn check_response_status(
    response: reqwest::Response,
    path: &str,
) -> Result<reqwest::Response, CliError> {
    match response.status() {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(CliError::AuthFailure(format!(
            "server rejected credentials ({})",
            response.status()
        ))),
        StatusCode::NOT_FOUND => {
            Err(CliError::NotFound(format!("{path} does not exist on the server")))
        }
        StatusCode::TOO_MANY_REQUESTS => {
            Err(CliError::RateLimited { retry_after_secs: parse_retry_after(&response) })
        }
        s if s.is_success() => Ok(response),
        s if s.is_server_error() => {
            let body = response.text().await.unwrap_or_else(|_| "(unreadable body)".to_owned());
            Err(CliError::ServerError(format!("server returned {s}: {body}")))
        }
        s => {
            let body = response.text().await.unwrap_or_else(|_| "(unreadable body)".to_owned());
            Err(CliError::General(format!("server returned {s}: {body}")))
        }
    }
}

/// Map an HTTP response to `Result<T, CliError>` using the standard status-code
/// convention shared by all JSON endpoints.
pub(super) async fn map_response<T: DeserializeOwned>(
    response: reqwest::Response,
    path: &str,
) -> Result<T, CliError> {
    let response = check_response_status(response, path).await?;
    response
        .json::<T>()
        .await
        .map_err(|e| CliError::General(format!("failed to parse server response: {e}")))
}

/// Extract the numeric value of the `Retry-After` response header.
///
/// Returns `None` when the header is absent, non-UTF-8, or not a plain
/// decimal integer (HTTP dates are not parsed).
pub(super) fn parse_retry_after(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

/// Returns `true` when any error in `e`'s [`std::error::Error::source`] chain
/// contains TLS certificate validation keywords in its `Display` output.
///
/// `reqwest` does not expose a typed TLS predicate, so this inspects the
/// human-readable representation of each layer.  The wording matches rustls
/// certificate error messages as they propagate through reqwest's error chain.
fn error_chain_mentions_cert(e: &dyn std::error::Error) -> bool {
    let mut src: Option<&dyn std::error::Error> = Some(e);
    while let Some(err) = src {
        let msg = err.to_string();
        if msg.contains("certificate") || msg.contains("unknown issuer") {
            return true;
        }
        src = err.source();
    }
    false
}

/// Classify a [`reqwest::Error`] into the appropriate [`CliError`] variant.
pub(super) fn map_reqwest_error(e: reqwest::Error, url: &str) -> CliError {
    if e.is_timeout() {
        CliError::Timeout(format!("request to {url} timed out"))
    } else if error_chain_mentions_cert(&e) {
        CliError::ServerUnreachable(format!(
            "TLS certificate trust failure for {url}: {e} \
             — verify the server certificate or configure \
             --tls-ca / --tls-fingerprint"
        ))
    } else if e.is_connect() {
        CliError::ServerUnreachable(format!("cannot connect to {url}: {e}"))
    } else {
        // All other reqwest errors (redirect loops, decode failures, invalid
        // headers, etc.) are collapsed to ServerUnreachable.  This is
        // intentional: the caller cannot act on the distinction, and the exit
        // code contract (exit 4) covers any situation where a usable response
        // was not obtained.  If a finer-grained mapping is ever needed for a
        // specific error kind (e.g. is_redirect()), add a new branch above
        // this one — the test `map_reqwest_error_else_branch_maps_to_server_unreachable`
        // will catch any accidental change to this fallthrough.
        CliError::ServerUnreachable(format!("network error reaching {url}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResolvedConfig;

    fn test_config(server: &str) -> ResolvedConfig {
        ResolvedConfig {
            server: server.to_owned(),
            token: "test-token".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        }
    }

    // ── parse_retry_after ────────────────────────────────────────────────────

    #[test]
    fn parse_retry_after_returns_none_for_non_numeric_date() {
        let resp = reqwest::Response::from(
            http::Response::builder()
                .status(429)
                .header("retry-after", "Wed, 21 Oct 2026 07:28:00 GMT")
                .body(bytes::Bytes::new())
                .unwrap(),
        );
        assert_eq!(parse_retry_after(&resp), None);
    }

    #[test]
    fn parse_retry_after_returns_seconds_for_integer_value() {
        let resp = reqwest::Response::from(
            http::Response::builder()
                .status(429)
                .header("retry-after", "30")
                .body(bytes::Bytes::new())
                .unwrap(),
        );
        assert_eq!(parse_retry_after(&resp), Some(30));
    }

    #[test]
    fn parse_retry_after_returns_none_when_header_absent() {
        let resp = reqwest::Response::from(
            http::Response::builder().status(429).body(bytes::Bytes::new()).unwrap(),
        );
        assert_eq!(parse_retry_after(&resp), None);
    }

    // ── map_reqwest_error else-branch ────────────────────────────────────────

    /// Verify that the `else` fallthrough branch of `map_reqwest_error` maps
    /// non-timeout, non-connect errors to `CliError::ServerUnreachable`.
    #[tokio::test]
    async fn map_reqwest_error_else_branch_maps_to_server_unreachable() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let response = "HTTP/1.1 301 Moved Permanently\r\n\
                                Location: http://127.0.0.1:1/\r\n\
                                Content-Length: 0\r\n\
                                Connection: close\r\n\
                                \r\n";
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(0))
            .build()
            .unwrap();

        let url = format!("http://{addr}/probe");
        let err = client.get(&url).send().await.unwrap_err();

        assert!(!err.is_timeout(), "expected non-timeout error for else-branch test");
        assert!(!err.is_connect(), "expected non-connect error for else-branch test");

        let mapped = map_reqwest_error(err, &url);
        assert!(
            matches!(mapped, CliError::ServerUnreachable(_)),
            "else branch must map to ServerUnreachable, got: {mapped:?}",
        );
    }

    // ── error_chain_mentions_cert ────────────────────────────────────────────

    #[derive(Debug)]
    struct SimpleErr(String);
    impl std::fmt::Display for SimpleErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }
    impl std::error::Error for SimpleErr {}

    #[test]
    fn error_chain_mentions_cert_detects_certificate_keyword() {
        let e = SimpleErr("invalid certificate: expired".to_owned());
        assert!(error_chain_mentions_cert(&e));
    }

    #[test]
    fn error_chain_mentions_cert_detects_unknown_issuer() {
        let e = SimpleErr("unknown issuer".to_owned());
        assert!(error_chain_mentions_cert(&e));
    }

    #[test]
    fn error_chain_mentions_cert_returns_false_for_connection_refused() {
        let e = SimpleErr("connection refused".to_owned());
        assert!(!error_chain_mentions_cert(&e));
    }

    #[test]
    fn error_chain_mentions_cert_returns_false_for_timeout_message() {
        let e = SimpleErr("request timed out after 30s".to_owned());
        assert!(!error_chain_mentions_cert(&e));
    }

    // ── build_http_client with SystemRoots ───────────────────────────────────

    #[test]
    fn build_http_client_system_roots_succeeds() {
        let cfg = test_config("https://localhost:40056");
        assert!(build_http_client(&cfg).is_ok());
    }
}
