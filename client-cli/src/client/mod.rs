//! HTTP API client for the Red Cell teamserver.
//!
//! All requests send the API key in the `x-api-key` header as expected by the
//! teamserver's authentication middleware.  TLS verification mode is controlled
//! by [`crate::config::TlsMode`] — default behaviour is to verify against the
//! system/webpki root CAs.

mod http;

use reqwest::Client;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::instrument;

use crate::config::ResolvedConfig;
use crate::error::CliError;

use self::http::{build_http_client, check_response_status, map_reqwest_error, map_response};

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

        let response = check_response_status(response, path).await?;
        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| CliError::General(format!("failed to read response body: {e}")))
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

        check_response_status(response, path).await.map(|_| ())
    }

    /// Issue an authenticated `DELETE` request to `path` under `/api/v1` and
    /// deserialise the JSON response body as `T`.
    ///
    /// Used for delete endpoints that return a JSON summary (e.g.
    /// `DELETE /audit/purge` which returns `{ deleted, cutoff }`).
    ///
    /// # Errors
    ///
    /// Same mapping as [`ApiClient::get`].
    #[instrument(skip(self), fields(path = %path))]
    pub async fn delete_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, CliError> {
        let url = format!("{}/api/v1{path}", self.base_url);

        let response = self
            .inner
            .delete(&url)
            .header(API_KEY_HEADER, &self.token)
            .send()
            .await
            .map_err(|e| map_reqwest_error(e, &url))?;

        map_response(response, path).await
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
    async fn delete_no_body_returns_ok_on_204() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/listeners/foo"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.delete_no_body("/listeners/foo").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn delete_no_body_returns_auth_failure_on_401() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/listeners/foo"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.delete_no_body("/listeners/foo").await;
        assert!(matches!(result, Err(CliError::AuthFailure(_))));
    }

    #[tokio::test]
    async fn delete_no_body_returns_auth_failure_on_403() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/listeners/foo"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.delete_no_body("/listeners/foo").await;
        assert!(matches!(result, Err(CliError::AuthFailure(_))));
    }

    #[tokio::test]
    async fn delete_no_body_returns_not_found_on_404() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/listeners/foo"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.delete_no_body("/listeners/foo").await;
        assert!(matches!(result, Err(CliError::NotFound(_))));
    }

    #[tokio::test]
    async fn delete_no_body_returns_rate_limited_on_429_without_header() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/listeners/foo"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.delete_no_body("/listeners/foo").await;
        assert!(matches!(result, Err(CliError::RateLimited { retry_after_secs: None })));
    }

    #[tokio::test]
    async fn delete_no_body_returns_rate_limited_on_429_with_retry_after() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/listeners/foo"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.delete_no_body("/listeners/foo").await;
        assert!(matches!(result, Err(CliError::RateLimited { retry_after_secs: Some(30) })));
    }

    #[tokio::test]
    async fn delete_no_body_returns_server_error_on_5xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/listeners/foo"))
            .respond_with(ResponseTemplate::new(503).set_body_string("service unavailable"))
            .mount(&server)
            .await;

        let cfg = test_config(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = client.delete_no_body("/listeners/foo").await;
        assert!(matches!(result, Err(CliError::ServerError(_))));
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
    async fn get_raw_bytes_returns_server_error_on_5xx() {
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
        assert!(matches!(result, Err(CliError::ServerError(_))));
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
}
