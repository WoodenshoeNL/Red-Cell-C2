//! HTTP API client for the Red Cell teamserver.
//!
//! All requests send the API key in the `x-api-key` header as expected by the
//! teamserver's authentication middleware.  TLS verification mode is controlled
//! by [`crate::config::TlsMode`] — default behaviour is to verify against the
//! system/webpki root CAs.

use std::fs;
use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::instrument;

use crate::config::{ResolvedConfig, TlsMode};
use crate::error::CliError;
use crate::tls::build_fingerprint_client_config;

/// HTTP header name used by the teamserver for API-key authentication.
const API_KEY_HEADER: &str = "x-api-key";

/// Thin wrapper around [`reqwest::Client`] that adds authentication and
/// uniform error mapping for the Red Cell REST API.
#[derive(Debug, Clone)]
pub struct ApiClient {
    inner: Client,
    base_url: String,
    token: String,
}

impl ApiClient {
    /// Build a new client from a resolved configuration.
    ///
    /// The TLS verification mode is controlled by [`ResolvedConfig::tls_mode`]:
    ///
    /// - [`TlsMode::SystemRoots`]: verify against the system/webpki root CAs.
    /// - [`TlsMode::CustomCa`]: load a PEM CA cert and disable built-in roots.
    /// - [`TlsMode::Fingerprint`]: pin against a SHA-256 cert fingerprint (leaf
    ///   or chain per [`crate::config::FingerprintTls::pin_mode`]).
    ///
    /// Returns an error if the underlying HTTP client cannot be constructed
    /// (e.g. the TLS backend is missing or the CA file cannot be read).
    pub fn new(config: &ResolvedConfig) -> Result<Self, CliError> {
        let inner = build_http_client(config)?;
        Ok(Self { inner, base_url: config.server.clone(), token: config.token.clone() })
    }

    /// Issue an authenticated `GET` request to `path` under `/api/v1` and
    /// deserialise the response body as `T`.
    ///
    /// # Errors
    ///
    /// | Server response | Error variant |
    /// |---|---|
    /// | 401 / 403 | [`CliError::AuthFailure`] |
    /// | 404 | [`CliError::NotFound`] |
    /// | Connection refused / DNS failure | [`CliError::ServerUnreachable`] |
    /// | Request timeout | [`CliError::Timeout`] |
    /// | Other non-2xx | [`CliError::General`] |
    #[instrument(skip(self), fields(path = %path))]
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, CliError> {
        let url = format!("{}/api/v1{path}", self.base_url);

        let response = self
            .inner
            .get(&url)
            .header(API_KEY_HEADER, &self.token)
            .send()
            .await
            .map_err(|e| map_reqwest_error(e, &url))?;

        map_response(response, path).await
    }

    /// Issue an authenticated `POST` request to `path` under `/api/v1` with a
    /// JSON body and deserialise the response body as `T`.
    ///
    /// # Errors
    ///
    /// Same mapping as [`ApiClient::get`].
    #[instrument(skip(self, body), fields(path = %path))]
    pub async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let url = format!("{}/api/v1{path}", self.base_url);

        let response = self
            .inner
            .post(&url)
            .header(API_KEY_HEADER, &self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| map_reqwest_error(e, &url))?;

        map_response(response, path).await
    }

    /// Issue an authenticated `GET` to `path` under `/api/v1` and return the
    /// raw response bytes.
    ///
    /// Used for binary downloads.
    #[instrument(skip(self), fields(path = %path))]
    pub async fn get_raw_bytes(&self, path: &str) -> Result<Vec<u8>, CliError> {
        let url = format!("{}/api/v1{path}", self.base_url);

        let response = self
            .inner
            .get(&url)
            .header(API_KEY_HEADER, &self.token)
            .send()
            .await
            .map_err(|e| map_reqwest_error(e, &url))?;

        match response.status() {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(CliError::AuthFailure(
                format!("server rejected credentials ({})", response.status()),
            )),
            StatusCode::NOT_FOUND => {
                Err(CliError::NotFound(format!("{path} does not exist on the server")))
            }
            StatusCode::TOO_MANY_REQUESTS => {
                Err(CliError::RateLimited { retry_after_secs: parse_retry_after(&response) })
            }
            s if s.is_success() => response
                .bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|e| CliError::General(format!("failed to read response body: {e}"))),
            s => {
                let body = response.text().await.unwrap_or_else(|_| "(unreadable)".to_owned());
                Err(CliError::General(format!("server returned {s}: {body}")))
            }
        }
    }

    /// Issue an authenticated `POST` request to `path` under `/api/v1` with
    /// no body and deserialise the response body as `T`.
    ///
    /// Used for action endpoints that carry no request payload (e.g.
    /// `POST /payload-cache` to flush cached build artifacts).
    ///
    /// # Errors
    ///
    /// Same mapping as [`ApiClient::get`].
    #[instrument(skip(self), fields(path = %path))]
    pub async fn post_empty<T: DeserializeOwned>(&self, path: &str) -> Result<T, CliError> {
        let url = format!("{}/api/v1{path}", self.base_url);

        let response = self
            .inner
            .post(&url)
            .header(API_KEY_HEADER, &self.token)
            .send()
            .await
            .map_err(|e| map_reqwest_error(e, &url))?;

        map_response(response, path).await
    }

    /// Issue an authenticated `PUT` request to `path` under `/api/v1` with a
    /// JSON body and deserialise the response body as `T`.
    ///
    /// Used for update endpoints such as `PUT /operators/{name}/role`.
    ///
    /// # Errors
    ///
    /// Same mapping as [`ApiClient::get`].
    #[instrument(skip(self, body), fields(path = %path))]
    pub async fn put<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, CliError> {
        let url = format!("{}/api/v1{path}", self.base_url);

        let response = self
            .inner
            .put(&url)
            .header(API_KEY_HEADER, &self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| map_reqwest_error(e, &url))?;

        map_response(response, path).await
    }

    /// Issue an authenticated `PUT` request to `path` under `/api/v1` with no
    /// body and deserialise the JSON response as `T`.
    ///
    /// Used for state-transition endpoints that take no payload (e.g.
    /// `PUT /listeners/{name}/start`).  A 409 Conflict response is mapped to
    /// [`CliError::General`] with the server error body included in the message
    /// so callers can inspect it for idempotency handling.
    ///
    /// # Errors
    ///
    /// Same mapping as [`ApiClient::get`].
    #[instrument(skip(self), fields(path = %path))]
    pub async fn put_empty<T: DeserializeOwned>(&self, path: &str) -> Result<T, CliError> {
        let url = format!("{}/api/v1{path}", self.base_url);

        let response = self
            .inner
            .put(&url)
            .header(API_KEY_HEADER, &self.token)
            .send()
            .await
            .map_err(|e| map_reqwest_error(e, &url))?;

        map_response(response, path).await
    }

    /// Issue an authenticated `DELETE` request to `path` under `/api/v1`.
    ///
    /// Expects a 204 No Content response.  Any 2xx response is treated as
    /// success; the response body is discarded.
    ///
    /// # Errors
    ///
    /// Same mapping as [`ApiClient::get`].
    #[instrument(skip(self), fields(path = %path))]
    pub async fn delete_no_body(&self, path: &str) -> Result<(), CliError> {
        let url = format!("{}/api/v1{path}", self.base_url);

        let response = self
            .inner
            .delete(&url)
            .header(API_KEY_HEADER, &self.token)
            .send()
            .await
            .map_err(|e| map_reqwest_error(e, &url))?;

        match response.status() {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(CliError::AuthFailure(
                format!("server rejected credentials ({})", response.status()),
            )),
            StatusCode::NOT_FOUND => {
                Err(CliError::NotFound(format!("{path} does not exist on the server")))
            }
            s if s.is_success() => Ok(()),
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

    /// Issue an unauthenticated `GET` to `path` under `/api/v1`.
    ///
    /// Used for endpoints that do not require authentication (e.g. the API
    /// root discovery endpoint).
    #[instrument(skip(self), fields(path = %path))]
    pub async fn get_anon<T: DeserializeOwned>(&self, path: &str) -> Result<T, CliError> {
        let url = format!("{}/api/v1{path}", self.base_url);

        let response = self.inner.get(&url).send().await.map_err(|e| map_reqwest_error(e, &url))?;

        map_response(response, path).await
    }
}

// ── TLS helpers ──────────────────────────────────────────────────────────────

/// Build a [`reqwest::Client`] with TLS verification configured according to
/// `config.tls_mode`.
fn build_http_client(config: &ResolvedConfig) -> Result<Client, CliError> {
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

// ── helpers ─────────────────────────────────────────────────────────────────

async fn map_response<T: DeserializeOwned>(
    response: reqwest::Response,
    path: &str,
) -> Result<T, CliError> {
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
        s if s.is_success() => response
            .json::<T>()
            .await
            .map_err(|e| CliError::General(format!("failed to parse server response: {e}"))),
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

/// Extract the numeric value of the `Retry-After` response header.
///
/// Returns `None` when the header is absent, non-UTF-8, or not a plain
/// decimal integer (HTTP dates are not parsed).
fn parse_retry_after(response: &reqwest::Response) -> Option<u64> {
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

fn map_reqwest_error(e: reqwest::Error, url: &str) -> CliError {
    if e.is_timeout() {
        CliError::Timeout(format!("request to {url} timed out"))
    } else if error_chain_mentions_cert(&e) {
        // TLS certificate errors are connectivity/trust problems, not auth failures.
        // Give a specific message so callers do not confuse them with bad credentials.
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

    #[test]
    fn client_builds_successfully() {
        let cfg = test_config("https://localhost:40056");
        let client = ApiClient::new(&cfg);
        assert!(client.is_ok());
    }

    #[test]
    fn client_stores_base_url() {
        let cfg = test_config("https://localhost:40056");
        let client = ApiClient::new(&cfg).unwrap();
        assert_eq!(client.base_url, "https://localhost:40056");
    }

    #[tokio::test]
    async fn get_returns_server_unreachable_on_connection_refused() {
        let cfg = test_config("https://127.0.0.1:1"); // port 1 is never open
        let client = ApiClient::new(&cfg).unwrap();
        let result: Result<serde_json::Value, _> = client.get("/agents").await;
        assert!(matches!(result, Err(CliError::ServerUnreachable(_))));
    }

    #[tokio::test]
    async fn put_returns_server_unreachable_on_connection_refused() {
        let cfg = test_config("https://127.0.0.1:1");
        let client = ApiClient::new(&cfg).unwrap();
        let body = serde_json::json!({"role": "analyst"});
        let result: Result<serde_json::Value, _> = client.put("/operators/alice/role", &body).await;
        assert!(matches!(result, Err(CliError::ServerUnreachable(_))));
    }

    #[tokio::test]
    async fn put_empty_returns_server_unreachable_on_connection_refused() {
        let cfg = test_config("https://127.0.0.1:1");
        let client = ApiClient::new(&cfg).unwrap();
        let result: Result<serde_json::Value, _> = client.put_empty("/listeners/foo/start").await;
        assert!(matches!(result, Err(CliError::ServerUnreachable(_))));
    }

    #[tokio::test]
    async fn delete_no_body_returns_server_unreachable_on_connection_refused() {
        let cfg = test_config("https://127.0.0.1:1");
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.delete_no_body("/listeners/foo").await;
        assert!(matches!(result, Err(CliError::ServerUnreachable(_))));
    }

    #[tokio::test]
    async fn post_returns_server_unreachable_on_connection_refused() {
        let cfg = test_config("https://127.0.0.1:1");
        let client = ApiClient::new(&cfg).unwrap();
        let body = serde_json::json!({"name": "test"});
        let result: Result<serde_json::Value, _> = client.post("/agents", &body).await;
        assert!(matches!(result, Err(CliError::ServerUnreachable(_))));
    }

    // ── get_raw_bytes ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_raw_bytes_returns_server_unreachable_on_connection_refused() {
        let cfg = test_config("https://127.0.0.1:1");
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.get_raw_bytes("/payload/download").await;
        assert!(matches!(result, Err(CliError::ServerUnreachable(_))));
    }

    #[tokio::test]
    async fn get_raw_bytes_returns_auth_failure_on_401() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payload/download"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.get_raw_bytes("/payload/download").await;
        assert!(matches!(result, Err(CliError::AuthFailure(_))));
    }

    #[tokio::test]
    async fn get_raw_bytes_returns_auth_failure_on_403() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payload/download"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.get_raw_bytes("/payload/download").await;
        assert!(matches!(result, Err(CliError::AuthFailure(_))));
    }

    #[tokio::test]
    async fn get_raw_bytes_returns_not_found_on_404() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payload/download"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.get_raw_bytes("/payload/download").await;
        assert!(matches!(result, Err(CliError::NotFound(_))));
    }

    #[tokio::test]
    async fn get_raw_bytes_returns_bytes_on_200() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let payload = vec![0x01u8, 0x02, 0x03, 0x04];
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payload/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(payload.clone()))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.get_raw_bytes("/payload/download").await;
        assert_eq!(result.unwrap(), payload);
    }

    #[tokio::test]
    async fn get_raw_bytes_returns_general_error_on_5xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payload/download"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.get_raw_bytes("/payload/download").await;
        assert!(matches!(result, Err(CliError::General(_))));
    }

    #[tokio::test]
    async fn get_raw_bytes_returns_rate_limited_on_429_without_header() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payload/download"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.get_raw_bytes("/payload/download").await;
        assert!(matches!(result, Err(CliError::RateLimited { retry_after_secs: None })));
    }

    #[tokio::test]
    async fn get_raw_bytes_returns_rate_limited_on_429_with_retry_after() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payload/download"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "42"))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.get_raw_bytes("/payload/download").await;
        assert!(matches!(result, Err(CliError::RateLimited { retry_after_secs: Some(42) })));
    }

    // ── map_response 429 (via get) ───────────────────────────────────────────

    #[tokio::test]
    async fn get_returns_rate_limited_on_429_without_header() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/agents"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result: Result<serde_json::Value, _> = client.get("/agents").await;
        assert!(matches!(result, Err(CliError::RateLimited { retry_after_secs: None })));
    }

    #[tokio::test]
    async fn get_returns_rate_limited_on_429_with_retry_after() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/agents"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "60"))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result: Result<serde_json::Value, _> = client.get("/agents").await;
        assert!(matches!(result, Err(CliError::RateLimited { retry_after_secs: Some(60) })));
    }

    // ── parse_retry_after ────────────────────────────────────────────────────

    #[test]
    fn parse_retry_after_returns_none_for_non_numeric_date() {
        // HTTP date format should not be parsed as u64 — return None.
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

    // ── get_anon ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_anon_returns_server_unreachable_on_connection_refused() {
        let cfg = test_config("https://127.0.0.1:1");
        let client = ApiClient::new(&cfg).unwrap();
        let result: Result<serde_json::Value, _> = client.get_anon("/").await;
        assert!(matches!(result, Err(CliError::ServerUnreachable(_))));
    }

    /// `get_anon` must NOT send the `x-api-key` header — if it is accidentally
    /// re-added a secured endpoint would silently accept the request.
    #[tokio::test]
    async fn get_anon_does_not_send_api_key_header() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

        struct RejectIfApiKey;

        impl Respond for RejectIfApiKey {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                if request.headers.contains_key("x-api-key") {
                    // Signal the test that the forbidden header was present.
                    ResponseTemplate::new(400).set_body_string("api-key-present")
                } else {
                    ResponseTemplate::new(200)
                        .set_body_string("{\"ok\":true}")
                        .insert_header("content-type", "application/json")
                }
            }
        }

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/"))
            .respond_with(RejectIfApiKey)
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result: Result<serde_json::Value, _> = client.get_anon("/").await;
        // If we get a parse or general error here the header was sent.
        assert!(result.is_ok(), "get_anon must not send x-api-key; got error: {result:?}",);
    }

    // ── map_reqwest_error else-branch ────────────────────────────────────────

    /// Verify that the `else` fallthrough branch of `map_reqwest_error` maps
    /// non-timeout, non-connect errors to `CliError::ServerUnreachable`.
    ///
    /// A redirect error is used as the trigger: a plain TCP listener returns a
    /// 301 response; the reqwest client is configured with
    /// `redirect::Policy::limited(0)` so it immediately refuses to follow the
    /// redirect and returns an error where `is_redirect()` is true while both
    /// `is_timeout()` and `is_connect()` are false.  This is the canonical
    /// "other network error" that exercises the else branch.
    #[tokio::test]
    async fn map_reqwest_error_else_branch_maps_to_server_unreachable() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        // Bind on a random port so the test is parallel-safe.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Serve exactly one connection: read the HTTP request and respond with
        // a 301 redirect (the destination does not need to be reachable).
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

        // Build a client that refuses to follow any redirects so that the
        // 301 response immediately surfaces as a redirect error.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(0))
            .build()
            .unwrap();

        let url = format!("http://{addr}/probe");
        let err = client.get(&url).send().await.unwrap_err();

        // Confirm this exercises the else branch (not timeout, not connect).
        assert!(!err.is_timeout(), "expected non-timeout error for else-branch test");
        assert!(!err.is_connect(), "expected non-connect error for else-branch test");

        let mapped = map_reqwest_error(err, &url);
        assert!(
            matches!(mapped, CliError::ServerUnreachable(_)),
            "else branch must map to ServerUnreachable, got: {mapped:?}",
        );
    }

    // ── error_chain_mentions_cert ────────────────────────────────────────────

    /// A synthetic error type used to construct test error chains without
    /// needing a live HTTP connection.
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
