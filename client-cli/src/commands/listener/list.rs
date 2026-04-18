//! `listener list` and `listener show` implementations.

use tracing::instrument;

use crate::client::ApiClient;
use crate::error::CliError;

use super::{ListenerDetail, ListenerRow, RawListenerSummary};

/// `listener list` — fetch all configured listeners.
///
/// # Examples
/// ```text
/// red-cell-cli listener list
/// ```
#[instrument(skip(client))]
pub(super) async fn list(client: &ApiClient) -> Result<Vec<ListenerRow>, CliError> {
    let raw: Vec<RawListenerSummary> = client.get("/listeners").await?;
    Ok(raw.into_iter().map(listener_row_from_raw).collect())
}

/// `listener show <name>` — fetch full details of a single listener.
///
/// # Examples
/// ```text
/// red-cell-cli listener show http1
/// ```
#[instrument(skip(client))]
pub(super) async fn show(client: &ApiClient, name: &str) -> Result<ListenerDetail, CliError> {
    let raw: RawListenerSummary = client.get(&format!("/listeners/{name}")).await?;
    Ok(listener_detail_from_raw(raw))
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Extract a short info string from the raw `ListenerSummary.config` value.
///
/// The config value is the tagged-enum payload:
/// `{"protocol":"http","config":{"port_bind":443,...}}`.
pub(super) fn extract_info(raw: &RawListenerSummary) -> String {
    let inner = raw.config.get("config");

    match raw.protocol.as_str() {
        "http" => {
            let port = inner
                .and_then(|c| c.get("port_bind"))
                .and_then(serde_json::Value::as_u64)
                .map_or_else(|| "?".to_owned(), |p| p.to_string());
            let host = inner
                .and_then(|c| c.get("host_bind"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let secure = inner
                .and_then(|c| c.get("secure"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let scheme = if secure { "https" } else { "http" };
            format!("{scheme}://{host}:{port}")
        }
        "dns" => {
            let domain = inner
                .and_then(|c| c.get("domain"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let port = inner
                .and_then(|c| c.get("port_bind"))
                .and_then(serde_json::Value::as_u64)
                .map_or_else(|| "53".to_owned(), |p| p.to_string());
            format!("domain={domain} port={port}")
        }
        "smb" => {
            let pipe = inner
                .and_then(|c| c.get("pipe_name"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            format!("pipe={pipe}")
        }
        "external" => {
            let ep = inner
                .and_then(|c| c.get("endpoint"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            format!("endpoint={ep}")
        }
        _ => String::new(),
    }
}

pub(super) fn listener_row_from_raw(raw: RawListenerSummary) -> ListenerRow {
    let info = extract_info(&raw);
    ListenerRow { name: raw.name, protocol: raw.protocol, status: raw.state.status, info }
}

pub(super) fn listener_detail_from_raw(raw: RawListenerSummary) -> ListenerDetail {
    ListenerDetail {
        name: raw.name,
        protocol: raw.protocol,
        status: raw.state.status,
        last_error: raw.state.last_error,
        config: raw.config,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::listener::{RawListenerState, RawListenerSummary};

    fn make_raw(protocol: &str, config: serde_json::Value) -> RawListenerSummary {
        RawListenerSummary {
            name: "x".to_owned(),
            protocol: protocol.to_owned(),
            state: RawListenerState { status: "Created".to_owned(), last_error: None },
            config,
        }
    }

    #[test]
    fn extract_info_http() {
        let raw = RawListenerSummary {
            name: "h".to_owned(),
            protocol: "http".to_owned(),
            state: RawListenerState { status: "Running".to_owned(), last_error: None },
            config: serde_json::json!({"protocol":"http","config":{"host_bind":"0.0.0.0","port_bind":443,"secure":false}}),
        };
        let info = extract_info(&raw);
        assert!(info.contains("443"));
        assert!(info.contains("0.0.0.0"));
        assert!(info.starts_with("http://"));
    }

    #[test]
    fn extract_info_https_shows_https_scheme() {
        let raw = RawListenerSummary {
            name: "h".to_owned(),
            protocol: "http".to_owned(),
            state: RawListenerState { status: "Running".to_owned(), last_error: None },
            config: serde_json::json!({"protocol":"http","config":{"host_bind":"0.0.0.0","port_bind":443,"secure":true}}),
        };
        let info = extract_info(&raw);
        assert!(info.starts_with("https://"));
    }

    #[test]
    fn extract_info_dns() {
        let raw = RawListenerSummary {
            name: "d".to_owned(),
            protocol: "dns".to_owned(),
            state: RawListenerState { status: "Stopped".to_owned(), last_error: None },
            config: serde_json::json!({"protocol":"dns","config":{"domain":"c2.evil.example","port_bind":53}}),
        };
        let info = extract_info(&raw);
        assert!(info.contains("c2.evil.example"));
        assert!(info.contains("53"));
    }

    #[test]
    fn extract_info_smb() {
        let raw = RawListenerSummary {
            name: "s".to_owned(),
            protocol: "smb".to_owned(),
            state: RawListenerState { status: "Created".to_owned(), last_error: None },
            config: serde_json::json!({"protocol":"smb","config":{"name":"s","pipe_name":"my-pipe"}}),
        };
        let info = extract_info(&raw);
        assert!(info.contains("my-pipe"));
    }

    #[test]
    fn extract_info_external() {
        let raw = RawListenerSummary {
            name: "e".to_owned(),
            protocol: "external".to_owned(),
            state: RawListenerState { status: "Created".to_owned(), last_error: None },
            config: serde_json::json!({"protocol":"external","config":{"name":"e","endpoint":"/bridge"}}),
        };
        let info = extract_info(&raw);
        assert!(info.contains("/bridge"));
    }

    #[test]
    fn extract_info_http_missing_host_bind_shows_question_mark() {
        let raw = make_raw(
            "http",
            serde_json::json!({"protocol":"http","config":{"port_bind":443,"secure":false}}),
        );
        let info = extract_info(&raw);
        assert!(info.contains('?'), "expected '?' in info, got: {info}");
        assert!(info.contains("443"));
    }

    #[test]
    fn extract_info_http_missing_port_bind_shows_question_mark() {
        let raw = make_raw(
            "http",
            serde_json::json!({"protocol":"http","config":{"host_bind":"0.0.0.0","secure":false}}),
        );
        let info = extract_info(&raw);
        assert!(info.contains('?'), "expected '?' in info, got: {info}");
        assert!(info.contains("0.0.0.0"));
    }

    #[test]
    fn extract_info_http_empty_config_shows_question_marks() {
        let raw = make_raw("http", serde_json::json!({}));
        let info = extract_info(&raw);
        assert!(info.contains('?'), "expected '?' in info, got: {info}");
    }

    #[test]
    fn extract_info_dns_missing_domain_shows_question_mark() {
        let raw = make_raw("dns", serde_json::json!({"protocol":"dns","config":{"port_bind":53}}));
        let info = extract_info(&raw);
        assert!(info.contains('?'), "expected '?' in info, got: {info}");
        assert!(info.contains("53"));
    }

    #[test]
    fn extract_info_dns_empty_config_shows_question_mark() {
        let raw = make_raw("dns", serde_json::json!({}));
        let info = extract_info(&raw);
        assert!(info.contains('?'), "expected '?' in info, got: {info}");
    }

    #[test]
    fn extract_info_smb_missing_pipe_name_shows_question_mark() {
        let raw = make_raw("smb", serde_json::json!({"protocol":"smb","config":{"name":"s"}}));
        let info = extract_info(&raw);
        assert!(info.contains('?'), "expected '?' in info, got: {info}");
    }

    #[test]
    fn extract_info_smb_empty_config_shows_question_mark() {
        let raw = make_raw("smb", serde_json::json!({}));
        let info = extract_info(&raw);
        assert!(info.contains('?'), "expected '?' in info, got: {info}");
    }

    #[test]
    fn extract_info_unknown_protocol_returns_empty_string() {
        let raw = make_raw("grpc", serde_json::json!({"protocol":"grpc","config":{}}));
        let info = extract_info(&raw);
        assert_eq!(info, "", "unknown protocol should return empty string, got: {info}");
    }

    #[test]
    fn listener_row_from_raw_maps_all_fields() {
        let raw = RawListenerSummary {
            name: "http1".to_owned(),
            protocol: "http".to_owned(),
            state: RawListenerState { status: "Running".to_owned(), last_error: None },
            config: serde_json::json!({"protocol":"http","config":{"host_bind":"0.0.0.0","port_bind":443,"secure":false}}),
        };
        let row = listener_row_from_raw(raw);
        assert_eq!(row.name, "http1");
        assert_eq!(row.protocol, "http");
        assert_eq!(row.status, "Running");
        assert!(!row.info.is_empty());
    }

    #[test]
    fn listener_detail_from_raw_preserves_last_error() {
        let raw = RawListenerSummary {
            name: "bad".to_owned(),
            protocol: "http".to_owned(),
            state: RawListenerState {
                status: "Error".to_owned(),
                last_error: Some("bind failed: address in use".to_owned()),
            },
            config: serde_json::json!({}),
        };
        let detail = listener_detail_from_raw(raw);
        assert_eq!(detail.status, "Error");
        assert_eq!(detail.last_error.as_deref(), Some("bind failed: address in use"));
    }
}
