//! HTTP API client for the Red Cell teamserver.
//!
//! All requests send the API key in the `x-api-key` header as expected by the
//! teamserver's authentication middleware.  TLS certificate verification is
//! intentionally disabled because teamserver deployments commonly use
//! self-signed certificates.

use std::time::Duration;

use reqwest::{Client, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::instrument;

use crate::config::ResolvedConfig;
use crate::error::CliError;

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
    /// Returns an error if the underlying HTTP client cannot be constructed
    /// (e.g. the TLS backend is missing).
    pub fn new(config: &ResolvedConfig) -> Result<Self, CliError> {
        let inner = Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| CliError::General(format!("failed to build HTTP client: {e}")))?;

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

    /// Issue an authenticated `POST` with raw binary body to `path` under
    /// `/api/v1` and deserialise the JSON response as `T`.
    ///
    /// Sends `Content-Type: application/octet-stream`.
    #[instrument(skip(self, data), fields(path = %path, bytes = data.len()))]
    pub async fn post_bytes<T: DeserializeOwned>(
        &self,
        path: &str,
        data: Vec<u8>,
    ) -> Result<T, CliError> {
        let url = format!("{}/api/v1{path}", self.base_url);

        let response = self
            .inner
            .post(&url)
            .header(API_KEY_HEADER, &self.token)
            .header("Content-Type", "application/octet-stream")
            .body(data)
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

fn map_reqwest_error(e: reqwest::Error, url: &str) -> CliError {
    if e.is_timeout() {
        CliError::Timeout(format!("request to {url} timed out"))
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
        ResolvedConfig { server: server.to_owned(), token: "test-token".to_owned(), timeout: 5 }
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
        let body = serde_json::json!({"role": "viewer"});
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

    // ── post_bytes ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn post_bytes_returns_server_unreachable_on_connection_refused() {
        let cfg = test_config("https://127.0.0.1:1");
        let client = ApiClient::new(&cfg).unwrap();
        let result: Result<serde_json::Value, _> =
            client.post_bytes("/payload/upload", vec![0xde, 0xad, 0xbe, 0xef]).await;
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
}
