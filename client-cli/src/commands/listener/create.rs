//! `listener create` implementation and request-body builder.

use red_cell_common::{
    DnsListenerConfig, ExternalListenerConfig, HttpListenerConfig, SmbListenerConfig,
};
use tracing::instrument;

use crate::client::ApiClient;
use crate::error::CliError;

use super::{ListenerDetail, RawListenerSummary, list::listener_detail_from_raw};

/// `listener create` — create a new listener from flags or raw JSON.
///
/// When `config_json` is supplied it is used as the inner config body and all
/// other per-type flags are ignored.  Otherwise a minimal config is assembled
/// from the flag values and sensible defaults.
///
/// # Examples
/// ```text
/// red-cell-cli listener create --name http1 --type http --port 443
/// red-cell-cli listener create --name dns1  --type dns  --domain c2.example.com
/// red-cell-cli listener create --name smb1  --type smb  --pipe-name my-pipe
/// red-cell-cli listener create --name ext1  --type external --endpoint /bridge
/// ```
#[allow(clippy::too_many_arguments)]
#[instrument(skip(client))]
pub(super) async fn create(
    client: &ApiClient,
    name: &str,
    listener_type: &str,
    port: Option<u16>,
    host: &str,
    domain: Option<&str>,
    pipe_name: Option<&str>,
    endpoint: Option<&str>,
    secure: bool,
    legacy_mode: bool,
    config_json: Option<&str>,
) -> Result<ListenerDetail, CliError> {
    let body = build_create_body(
        name,
        listener_type,
        port,
        host,
        domain,
        pipe_name,
        endpoint,
        secure,
        legacy_mode,
        config_json,
    )?;
    let raw: RawListenerSummary = client.post("/listeners", &body).await?;
    Ok(listener_detail_from_raw(raw))
}

/// Build the `POST /listeners` request body from CLI flags or raw JSON.
///
/// The server expects a tagged-enum envelope:
/// ```json
/// {"protocol": "http", "config": { <inner config fields> }}
/// ```
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_create_body(
    name: &str,
    listener_type: &str,
    port: Option<u16>,
    host: &str,
    domain: Option<&str>,
    pipe_name: Option<&str>,
    endpoint: Option<&str>,
    secure: bool,
    legacy_mode: bool,
    config_json: Option<&str>,
) -> Result<serde_json::Value, CliError> {
    let protocol = listener_type.to_lowercase();
    let protocol = match protocol.as_str() {
        "https" => "http",
        other => other,
    };

    if let Some(raw_json) = config_json {
        let inner: serde_json::Value = serde_json::from_str(raw_json)
            .map_err(|e| CliError::InvalidArgs(format!("--config-json is not valid JSON: {e}")))?;
        validate_inner_config_json_for_protocol(protocol, &inner)?;
        return Ok(serde_json::json!({
            "protocol": protocol,
            "config": inner,
        }));
    }

    let inner: serde_json::Value = match protocol {
        "http" => {
            let port_bind = port.unwrap_or(443);
            serde_json::json!({
                "name": name,
                "host_bind": host,
                "port_bind": port_bind,
                "host_rotation": "round-robin",
                "secure": secure,
                "legacy_mode": legacy_mode,
            })
        }
        "dns" => {
            let dom = domain.ok_or_else(|| {
                CliError::InvalidArgs("--domain is required for --type dns".to_owned())
            })?;
            let port_bind = port.unwrap_or(53);
            serde_json::json!({
                "name": name,
                "host_bind": host,
                "port_bind": port_bind,
                "domain": dom,
            })
        }
        "smb" => {
            let pipe = pipe_name.ok_or_else(|| {
                CliError::InvalidArgs("--pipe-name is required for --type smb".to_owned())
            })?;
            serde_json::json!({
                "name": name,
                "pipe_name": pipe,
            })
        }
        "external" => {
            let ep = endpoint.ok_or_else(|| {
                CliError::InvalidArgs("--endpoint is required for --type external".to_owned())
            })?;
            serde_json::json!({
                "name": name,
                "endpoint": ep,
            })
        }
        other => {
            return Err(CliError::InvalidArgs(format!(
                "unknown listener type '{other}': expected http, dns, smb, or external"
            )));
        }
    };

    Ok(serde_json::json!({
        "protocol": protocol,
        "config": inner,
    }))
}

/// Best-effort check that `--config-json` matches the schema for `--type` /
/// `--protocol` before sending `POST /listeners`.
fn validate_inner_config_json_for_protocol(
    protocol: &str,
    inner: &serde_json::Value,
) -> Result<(), CliError> {
    match protocol {
        "http" => serde_json::from_value::<HttpListenerConfig>(inner.clone())
            .map_err(|e| {
                CliError::InvalidArgs(format!(
                    "--config-json does not match HTTP listener schema: {e}"
                ))
            })
            .map(|_| ()),
        "dns" => serde_json::from_value::<DnsListenerConfig>(inner.clone())
            .map_err(|e| {
                CliError::InvalidArgs(format!(
                    "--config-json does not match DNS listener schema: {e}"
                ))
            })
            .map(|_| ()),
        "smb" => serde_json::from_value::<SmbListenerConfig>(inner.clone())
            .map_err(|e| {
                CliError::InvalidArgs(format!(
                    "--config-json does not match SMB listener schema: {e}"
                ))
            })
            .map(|_| ()),
        "external" => serde_json::from_value::<ExternalListenerConfig>(inner.clone())
            .map_err(|e| {
                CliError::InvalidArgs(format!(
                    "--config-json does not match external listener schema: {e}"
                ))
            })
            .map(|_| ()),
        _ => Ok(()),
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_create_body_http_uses_default_port_443() {
        let body = build_create_body(
            "http1", "http", None, "0.0.0.0", None, None, None, false, false, None,
        )
        .expect("build");
        assert_eq!(body["protocol"], "http");
        assert_eq!(body["config"]["port_bind"], 443);
        assert_eq!(body["config"]["name"], "http1");
    }

    #[test]
    fn build_create_body_http_respects_explicit_port() {
        let body = build_create_body(
            "h2",
            "http",
            Some(8080),
            "10.0.0.1",
            None,
            None,
            None,
            true,
            false,
            None,
        )
        .expect("build");
        assert_eq!(body["config"]["port_bind"], 8080);
        assert_eq!(body["config"]["secure"], true);
        assert_eq!(body["config"]["host_bind"], "10.0.0.1");
    }

    #[test]
    fn build_create_body_https_maps_to_http_protocol() {
        let body = build_create_body(
            "h1",
            "https",
            Some(443),
            "0.0.0.0",
            None,
            None,
            None,
            true,
            false,
            None,
        )
        .expect("build");
        assert_eq!(body["protocol"], "http");
    }

    #[test]
    fn build_create_body_http_legacy_mode_true() {
        let body = build_create_body(
            "h1",
            "http",
            Some(8080),
            "0.0.0.0",
            None,
            None,
            None,
            false,
            true,
            None,
        )
        .expect("build");
        assert_eq!(body["config"]["legacy_mode"], true);
    }

    #[test]
    fn build_create_body_dns_requires_domain() {
        let err =
            build_create_body("dns1", "dns", None, "0.0.0.0", None, None, None, false, false, None)
                .expect_err("should fail without domain");
        assert!(matches!(err, CliError::InvalidArgs(_)));
    }

    #[test]
    fn build_create_body_dns_with_domain() {
        let body = build_create_body(
            "dns1",
            "dns",
            Some(53),
            "0.0.0.0",
            Some("c2.evil.example"),
            None,
            None,
            false,
            false,
            None,
        )
        .expect("build");
        assert_eq!(body["protocol"], "dns");
        assert_eq!(body["config"]["domain"], "c2.evil.example");
        assert_eq!(body["config"]["port_bind"], 53);
    }

    #[test]
    fn build_create_body_dns_defaults_to_port_53() {
        let body = build_create_body(
            "dns1",
            "dns",
            None,
            "0.0.0.0",
            Some("c2.evil.example"),
            None,
            None,
            false,
            false,
            None,
        )
        .expect("build");
        assert_eq!(body["config"]["port_bind"], 53);
    }

    #[test]
    fn build_create_body_smb_requires_pipe_name() {
        let err =
            build_create_body("smb1", "smb", None, "0.0.0.0", None, None, None, false, false, None)
                .expect_err("should fail without pipe_name");
        assert!(matches!(err, CliError::InvalidArgs(_)));
    }

    #[test]
    fn build_create_body_smb_with_pipe_name() {
        let body = build_create_body(
            "smb1",
            "smb",
            None,
            "0.0.0.0",
            None,
            Some("my-pipe"),
            None,
            false,
            false,
            None,
        )
        .expect("build");
        assert_eq!(body["protocol"], "smb");
        assert_eq!(body["config"]["name"], "smb1");
        assert_eq!(body["config"]["pipe_name"], "my-pipe");
    }

    #[test]
    fn build_create_body_external_requires_endpoint() {
        let err = build_create_body(
            "ext1", "external", None, "0.0.0.0", None, None, None, false, false, None,
        )
        .expect_err("should fail without endpoint");
        assert!(matches!(err, CliError::InvalidArgs(_)));
    }

    #[test]
    fn build_create_body_external_with_endpoint() {
        let body = build_create_body(
            "ext1",
            "external",
            None,
            "0.0.0.0",
            None,
            None,
            Some("/bridge"),
            false,
            false,
            None,
        )
        .expect("build");
        assert_eq!(body["protocol"], "external");
        assert_eq!(body["config"]["endpoint"], "/bridge");
    }

    #[test]
    fn build_create_body_unknown_type_returns_invalid_args() {
        let err =
            build_create_body("x", "grpc", None, "0.0.0.0", None, None, None, false, false, None)
                .expect_err("unknown type should fail");
        assert!(matches!(err, CliError::InvalidArgs(_)));
    }

    #[test]
    fn build_create_body_config_json_overrides_flags() {
        let raw = r#"{"name":"http1","host_bind":"1.2.3.4","port_bind":9000,"host_rotation":"round-robin"}"#;
        let body = build_create_body(
            "ignored",
            "http",
            Some(80),
            "0.0.0.0",
            None,
            None,
            None,
            false,
            false,
            Some(raw),
        )
        .expect("build");
        assert_eq!(body["protocol"], "http");
        assert_eq!(body["config"]["port_bind"], 9000);
        assert_eq!(body["config"]["host_bind"], "1.2.3.4");
    }

    #[test]
    fn build_create_body_config_json_invalid_returns_error() {
        let err = build_create_body(
            "x",
            "http",
            None,
            "0.0.0.0",
            None,
            None,
            None,
            false,
            false,
            Some("{not json"),
        )
        .expect_err("bad json");
        assert!(matches!(err, CliError::InvalidArgs(_)));
    }

    #[test]
    fn build_create_body_config_json_dns_shape_rejected_for_http_type() {
        let raw =
            r#"{"name":"dns1","host_bind":"0.0.0.0","port_bind":53,"domain":"c2.example.com"}"#;
        let err = build_create_body(
            "x",
            "http",
            None,
            "0.0.0.0",
            None,
            None,
            None,
            false,
            false,
            Some(raw),
        )
        .expect_err("wrong schema for --type http");
        let CliError::InvalidArgs(msg) = err else {
            panic!("expected InvalidArgs, got {err:?}");
        };
        assert!(msg.contains("HTTP listener schema"), "expected HTTP schema hint, got: {msg}");
    }

    #[test]
    fn build_create_body_config_json_http_shape_rejected_for_dns_type() {
        let raw = r#"{"name":"h1","host_bind":"0.0.0.0","port_bind":443,"host_rotation":"round-robin","secure":false}"#;
        let err = build_create_body(
            "x",
            "dns",
            None,
            "0.0.0.0",
            None,
            None,
            None,
            false,
            false,
            Some(raw),
        )
        .expect_err("wrong schema for --type dns");
        let CliError::InvalidArgs(msg) = err else {
            panic!("expected InvalidArgs, got {err:?}");
        };
        assert!(msg.contains("DNS listener schema"), "expected DNS schema hint, got: {msg}");
    }

    #[test]
    fn build_create_body_config_json_unknown_protocol_skips_local_schema_validation() {
        let raw = r#"{"name":"x","host_bind":"0.0.0.0","port_bind":443}"#;
        let body = build_create_body(
            "ignored",
            "future_proto",
            None,
            "0.0.0.0",
            None,
            None,
            None,
            false,
            false,
            Some(raw),
        )
        .expect("unknown protocol should not run local serde validation");
        assert_eq!(body["protocol"], "future_proto");
        assert_eq!(body["config"]["port_bind"], 443);
    }
}
