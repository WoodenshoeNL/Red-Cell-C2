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
}
