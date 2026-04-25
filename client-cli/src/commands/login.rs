//! `red-cell-cli login` — authenticate and persist credentials to config.
//!
//! Validates the provided API token against the teamserver health endpoint,
//! then writes server URL, token, and (optionally) certificate fingerprint to
//! `~/.config/red-cell-cli/config.toml`.

use std::path::Path;

use serde::Serialize;

use crate::client::ApiClient;
use crate::config::{self, FileConfig, ResolvedConfig, TlsMode};
use crate::error::{CliError, EXIT_AUTH_FAILURE, EXIT_GENERAL, EXIT_SUCCESS};
use crate::output::{self, OutputFormat, TextRender};

/// Result payload returned on successful login.
#[derive(Debug, Serialize)]
pub struct LoginResult {
    /// Absolute path where the config was written.
    pub config_path: String,
    /// The server URL stored in the config.
    pub server: String,
    /// Whether a certificate fingerprint was stored.
    pub cert_fingerprint_stored: bool,
}

impl TextRender for LoginResult {
    fn render_text(&self) -> String {
        let mut lines = vec![
            format!("Logged in to {}", self.server),
            format!("Config written to {}", self.config_path),
        ];
        if self.cert_fingerprint_stored {
            lines.push("Certificate fingerprint stored.".to_owned());
        }
        lines.join("\n")
    }
}

/// Execute the `login` subcommand.
///
/// Builds a temporary API client from the provided flags, validates the token
/// against the health endpoint, and writes the config file on success.
pub async fn run(
    server: &str,
    token: &str,
    cert_fingerprint: Option<&str>,
    fmt: &OutputFormat,
) -> i32 {
    let config_path = match config::global_config_path() {
        Some(p) => p,
        None => {
            output::print_error(&CliError::General(
                "cannot determine config directory (HOME not set)".to_owned(),
            ))
            .ok();
            return EXIT_GENERAL;
        }
    };
    run_to(server, token, cert_fingerprint, fmt, &config_path).await
}

/// Inner implementation with an explicit config path (testable without
/// mutating environment variables).
async fn run_to(
    server: &str,
    token: &str,
    cert_fingerprint: Option<&str>,
    fmt: &OutputFormat,
    config_path: &Path,
) -> i32 {
    let server = server.trim_end_matches('/').to_owned();

    let tls_mode = match cert_fingerprint {
        Some(fp) => TlsMode::Fingerprint(config::FingerprintTls {
            sha256_hex: fp.to_owned(),
            pin_mode: config::FingerprintPinMode::Leaf,
        }),
        None => TlsMode::SystemRoots,
    };

    let resolved =
        ResolvedConfig { server: server.clone(), token: token.to_owned(), timeout: 15, tls_mode };

    let client = match ApiClient::new(&resolved) {
        Ok(c) => c,
        Err(e) => {
            output::print_error(&e).ok();
            return e.exit_code();
        }
    };

    // Validate the token by hitting the health endpoint.
    let health_result: Result<serde_json::Value, CliError> = client.get("/health").await;
    match health_result {
        Ok(_) => {}
        Err(CliError::AuthFailure(msg)) => {
            output::print_error(&CliError::AuthFailure(format!(
                "token rejected by teamserver: {msg}"
            )))
            .ok();
            return EXIT_AUTH_FAILURE;
        }
        Err(e) => {
            output::print_error(&e).ok();
            return e.exit_code();
        }
    }

    // Ensure parent directory exists.
    if let Some(parent) = config_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            output::print_error(&CliError::General(format!(
                "failed to create config directory {}: {e}",
                parent.display()
            )))
            .ok();
            return EXIT_GENERAL;
        }
    }

    let file_config = FileConfig {
        server: Some(server.clone()),
        token: Some(token.to_owned()),
        timeout: None,
        cert_fingerprint: cert_fingerprint.map(str::to_owned),
    };

    if let Err(e) = config::write_config_file(config_path, &file_config) {
        let err: CliError = e.into();
        output::print_error(&err).ok();
        return err.exit_code();
    }

    let result = LoginResult {
        config_path: config_path.display().to_string(),
        server,
        cert_fingerprint_stored: cert_fingerprint.is_some(),
    };

    match output::print_success(fmt, &result) {
        Ok(()) => EXIT_SUCCESS,
        Err(e) => {
            output::print_error(&e).ok();
            e.exit_code()
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use tempfile::TempDir;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::config::load_config_file;
    use crate::error::{EXIT_AUTH_FAILURE, EXIT_SUCCESS};
    use crate::output::OutputFormat;

    use super::run_to;

    fn health_json() -> serde_json::Value {
        serde_json::json!({
            "status": "ok",
            "uptime_secs": 1,
            "agents": { "active": 0, "total": 0 },
            "listeners": { "running": 0, "stopped": 0 },
            "database": "ok",
            "plugins": { "loaded": 0, "failed": 0, "disabled": 0 },
            "plugin_health": [],
        })
    }

    fn config_path(dir: &TempDir) -> std::path::PathBuf {
        dir.path().join("red-cell-cli").join("config.toml")
    }

    #[tokio::test]
    async fn login_writes_config_on_valid_token() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/health"))
            .and(header("x-api-key", "good-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(health_json()))
            .mount(&server)
            .await;

        let dir = TempDir::new().expect("tempdir");
        let cp = config_path(&dir);

        let code = run_to(&server.uri(), "good-token", None, &OutputFormat::Json, &cp).await;
        assert_eq!(code, EXIT_SUCCESS);
        assert!(cp.exists(), "config file must be created");

        let loaded = load_config_file(&cp).expect("parse config");
        assert_eq!(loaded.server.as_deref(), Some(server.uri().as_str()));
        assert_eq!(loaded.token.as_deref(), Some("good-token"));
        assert!(loaded.cert_fingerprint.is_none());
    }

    #[tokio::test]
    async fn login_stores_cert_fingerprint() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(health_json()))
            .mount(&server)
            .await;

        let dir = TempDir::new().expect("tempdir");
        let cp = config_path(&dir);

        let fp = "aabbccdd".repeat(8);
        let code = run_to(&server.uri(), "tok", Some(&fp), &OutputFormat::Json, &cp).await;
        assert_eq!(code, EXIT_SUCCESS);

        let loaded = load_config_file(&cp).expect("parse config");
        assert_eq!(loaded.cert_fingerprint.as_deref(), Some(fp.as_str()));
    }

    #[tokio::test]
    async fn login_fails_on_auth_rejection() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/health"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"error": "unauthorized"})),
            )
            .mount(&server)
            .await;

        let dir = TempDir::new().expect("tempdir");
        let cp = config_path(&dir);

        let code = run_to(&server.uri(), "bad-token", None, &OutputFormat::Json, &cp).await;
        assert_eq!(code, EXIT_AUTH_FAILURE);
        assert!(!cp.exists(), "config must not be written on auth failure");
    }

    #[tokio::test]
    async fn login_fails_on_unreachable_server() {
        let dir = TempDir::new().expect("tempdir");
        let cp = config_path(&dir);

        let code =
            run_to("https://127.0.0.1:1", "some-token", None, &OutputFormat::Json, &cp).await;
        assert_ne!(code, EXIT_SUCCESS, "login must fail when server is unreachable");
    }

    #[tokio::test]
    async fn login_strips_trailing_slash_from_server() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(health_json()))
            .mount(&server)
            .await;

        let dir = TempDir::new().expect("tempdir");
        let cp = config_path(&dir);

        let url_with_slash = format!("{}/", server.uri());
        let code = run_to(&url_with_slash, "tok", None, &OutputFormat::Json, &cp).await;
        assert_eq!(code, EXIT_SUCCESS);

        let loaded = load_config_file(&cp).expect("parse config");
        assert_eq!(
            loaded.server.as_deref(),
            Some(server.uri().as_str()),
            "trailing slash must be stripped"
        );
    }

    #[tokio::test]
    async fn login_overwrites_existing_config() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(health_json()))
            .mount(&server)
            .await;

        let dir = TempDir::new().expect("tempdir");
        let cp = config_path(&dir);
        std::fs::create_dir_all(cp.parent().expect("parent")).expect("mkdir");
        std::fs::write(&cp, "server = \"https://old:40056\"\ntoken = \"old-tok\"\n")
            .expect("write old config");

        let code = run_to(&server.uri(), "new-tok", None, &OutputFormat::Json, &cp).await;
        assert_eq!(code, EXIT_SUCCESS);

        let loaded = load_config_file(&cp).expect("parse config");
        assert_eq!(loaded.token.as_deref(), Some("new-tok"));
        assert_eq!(loaded.server.as_deref(), Some(server.uri().as_str()));
    }

    #[tokio::test]
    async fn login_result_json_has_expected_fields() {
        let result = super::LoginResult {
            config_path: "/home/user/.config/red-cell-cli/config.toml".to_owned(),
            server: "https://ts:40056".to_owned(),
            cert_fingerprint_stored: false,
        };
        let json: Value = serde_json::to_value(&result).expect("serialise");
        assert_eq!(json["server"], "https://ts:40056");
        assert_eq!(json["cert_fingerprint_stored"], false);
        assert!(json["config_path"].is_string());
    }

    #[test]
    fn login_result_text_render() {
        use crate::output::TextRender;

        let result = super::LoginResult {
            config_path: "/home/user/.config/red-cell-cli/config.toml".to_owned(),
            server: "https://ts:40056".to_owned(),
            cert_fingerprint_stored: true,
        };
        let text = result.render_text();
        assert!(text.contains("https://ts:40056"));
        assert!(text.contains("config.toml"));
        assert!(text.contains("fingerprint"));
    }
}
