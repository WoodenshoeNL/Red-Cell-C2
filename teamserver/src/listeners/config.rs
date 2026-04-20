//! Conversion helpers between operator/profile listener payloads and the shared
//! [`ListenerConfig`] type used by the listener runtimes.
//!
//! These helpers split into three groups:
//! - [`listener_config_from_operator`] / [`profile_listener_configs`] — the top
//!   level converters.
//! - [`validated_kill_date`] — shared validation that applies to both sources.
//! - A collection of small parsers (`parse_u16`, `parse_bool`, `split_csv`, …)
//!   used to lift the loosely typed [`ListenerInfo`] extras map into strongly
//!   typed config structs.

use std::collections::BTreeMap;

use red_cell_common::config::Profile;
use red_cell_common::operator::ListenerInfo;
use red_cell_common::{
    DnsListenerConfig, ExternalListenerConfig, HttpListenerConfig, HttpListenerProxyConfig,
    HttpListenerResponseConfig, ListenerConfig, ListenerProtocol, SmbListenerConfig,
};
use zeroize::Zeroizing;

use super::ListenerManagerError;

pub(super) const EXTRA_METHOD: &str = "Method";
pub(super) const EXTRA_BEHIND_REDIRECTOR: &str = "BehindRedirector";
pub(super) const EXTRA_TRUSTED_PROXY_PEERS: &str = "TrustedProxyPeers";
pub(super) const EXTRA_CERT_PATH: &str = "Cert";
pub(super) const EXTRA_KEY_PATH: &str = "Key";
pub(super) const EXTRA_RESPONSE_BODY: &str = "ResponseBody";
pub(super) const EXTRA_KILL_DATE: &str = "KillDate";
pub(super) const EXTRA_WORKING_HOURS: &str = "WorkingHours";
pub(super) const EXTRA_JA3_RANDOMIZE: &str = "Ja3Randomize";
pub(super) const EXTRA_LEGACY_MODE: &str = "LegacyMode";
pub(super) const EXTRA_SUPPRESS_OPSEC_WARNINGS: &str = "SuppressOpsecWarnings";

/// Validate and normalise an optional KillDate string from operator input,
/// converting it from the raw extra-field value into a unix-timestamp string.
pub(super) fn validated_kill_date(
    raw: Option<String>,
) -> Result<Option<String>, ListenerManagerError> {
    red_cell_common::validate_kill_date(raw.as_deref())
        .map_err(|err| ListenerManagerError::InvalidConfig { message: err.to_string() })
}

/// Convert a Havoc operator listener payload into a shared listener config.
pub fn listener_config_from_operator(
    info: &ListenerInfo,
) -> Result<ListenerConfig, ListenerManagerError> {
    let name = required_field("Name", info.name.as_deref())?;
    let protocol = required_field("Protocol", info.protocol.as_deref())?;

    match ListenerProtocol::try_from_str(protocol) {
        Ok(ListenerProtocol::Http) => Ok(ListenerConfig::from(HttpListenerConfig {
            name: name.to_owned(),
            kill_date: validated_kill_date(optional_extra_string(info, EXTRA_KILL_DATE))?,
            working_hours: optional_extra_string(info, EXTRA_WORKING_HOURS),
            hosts: split_csv(info.hosts.as_deref()),
            host_bind: required_field("HostBind", info.host_bind.as_deref())?.to_owned(),
            host_rotation: required_field("HostRotation", info.host_rotation.as_deref())?
                .to_owned(),
            port_bind: parse_u16("PortBind", info.port_bind.as_deref())?,
            port_conn: parse_optional_u16("PortConn", info.port_conn.as_deref())?,
            method: optional_extra_string(info, EXTRA_METHOD),
            behind_redirector: parse_extra_bool(info, EXTRA_BEHIND_REDIRECTOR)?,
            trusted_proxy_peers: split_csv(extra_value_as_str(info, EXTRA_TRUSTED_PROXY_PEERS)),
            user_agent: optional_trimmed(info.user_agent.as_deref()),
            headers: split_csv(info.headers.as_deref()),
            uris: split_csv(info.uris.as_deref()),
            host_header: info
                .extra
                .get("HostHeader")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| optional_trimmed(Some(value))),
            secure: parse_bool("Secure", info.secure.as_deref())?,
            cert: tls_config_from_operator(info),
            response: http_response_from_operator(info),
            proxy: proxy_from_operator(info)?,
            ja3_randomize: parse_optional_extra_bool(info, EXTRA_JA3_RANDOMIZE)?,
            doh_domain: None,
            doh_provider: None,
            legacy_mode: parse_extra_bool(info, EXTRA_LEGACY_MODE)?,
            suppress_opsec_warnings: parse_extra_bool(info, EXTRA_SUPPRESS_OPSEC_WARNINGS)?,
        })),
        Ok(ListenerProtocol::Smb) => Ok(ListenerConfig::from(SmbListenerConfig {
            name: name.to_owned(),
            pipe_name: required_extra_string(info, "PipeName")?,
            kill_date: validated_kill_date(optional_extra_string(info, EXTRA_KILL_DATE))?,
            working_hours: optional_extra_string(info, EXTRA_WORKING_HOURS),
        })),
        Ok(ListenerProtocol::Dns) => Ok(ListenerConfig::from(DnsListenerConfig {
            name: name.to_owned(),
            host_bind: info
                .host_bind
                .as_deref()
                .and_then(|value| optional_trimmed(Some(value)))
                .unwrap_or_else(|| "0.0.0.0".to_owned()),
            port_bind: parse_u16("PortBind", info.port_bind.as_deref())?,
            domain: required_extra_string(info, "Domain")?,
            record_types: split_csv(
                info.extra.get("RecordTypes").and_then(serde_json::Value::as_str),
            ),
            kill_date: validated_kill_date(optional_extra_string(info, EXTRA_KILL_DATE))?,
            working_hours: optional_extra_string(info, EXTRA_WORKING_HOURS),
            suppress_opsec_warnings: parse_extra_bool(info, EXTRA_SUPPRESS_OPSEC_WARNINGS)?,
        })),
        Ok(ListenerProtocol::External) => Ok(ListenerConfig::from(ExternalListenerConfig {
            name: name.to_owned(),
            endpoint: required_extra_string(info, "Endpoint")?,
        })),
        Err(error) => Err(ListenerManagerError::InvalidConfig { message: error.to_string() }),
    }
}

pub(crate) fn profile_listener_configs(
    profile: &Profile,
) -> Result<Vec<ListenerConfig>, ListenerManagerError> {
    let mut listeners = Vec::new();
    for config in profile.listeners.http.iter().cloned() {
        listeners.push(ListenerConfig::from(HttpListenerConfig {
            name: config.name,
            kill_date: validated_kill_date(config.kill_date)?,
            working_hours: config.working_hours,
            hosts: config.hosts,
            host_bind: config.host_bind,
            host_rotation: config.host_rotation,
            port_bind: config.port_bind,
            port_conn: config.port_conn,
            method: config.method,
            behind_redirector: profile.demon.trust_x_forwarded_for,
            trusted_proxy_peers: profile.demon.trusted_proxy_peers.clone(),
            user_agent: config.user_agent,
            headers: config.headers,
            uris: config.uris,
            host_header: config.host_header,
            secure: config.secure,
            cert: config
                .cert
                .map(|cert| red_cell_common::ListenerTlsConfig { cert: cert.cert, key: cert.key }),
            response: config.response.map(Into::into),
            proxy: config.proxy.map(Into::into),
            ja3_randomize: config.ja3_randomize,
            doh_domain: config.doh_domain,
            doh_provider: config.doh_provider,
            legacy_mode: config.legacy_mode,
            suppress_opsec_warnings: config.suppress_opsec_warnings,
        }));
    }
    for config in profile.listeners.smb.iter().cloned() {
        listeners.push(ListenerConfig::from(SmbListenerConfig {
            name: config.name,
            pipe_name: config.pipe_name,
            kill_date: validated_kill_date(config.kill_date)?,
            working_hours: config.working_hours,
        }));
    }
    for config in profile.listeners.dns.iter().cloned() {
        listeners.push(ListenerConfig::from(DnsListenerConfig {
            name: config.name,
            host_bind: config.host_bind,
            port_bind: config.port_bind,
            domain: config.domain,
            record_types: config.record_types,
            kill_date: validated_kill_date(config.kill_date)?,
            working_hours: config.working_hours,
            suppress_opsec_warnings: config.suppress_opsec_warnings,
        }));
    }
    listeners.extend(profile.listeners.external.iter().cloned().map(|config| {
        ListenerConfig::from(ExternalListenerConfig {
            name: config.name,
            endpoint: config.endpoint,
        })
    }));
    Ok(listeners)
}

pub(super) fn required_field<'a>(
    field: &'static str,
    value: Option<&'a str>,
) -> Result<&'a str, ListenerManagerError> {
    value.map(str::trim).filter(|value| !value.is_empty()).ok_or_else(|| {
        ListenerManagerError::InvalidConfig { message: format!("{field} is required") }
    })
}

pub(super) fn required_extra_string(
    info: &ListenerInfo,
    field: &'static str,
) -> Result<String, ListenerManagerError> {
    match info.extra.get(field).and_then(serde_json::Value::as_str).map(str::trim) {
        Some(value) if !value.is_empty() => Ok(value.to_owned()),
        _ => Err(ListenerManagerError::InvalidConfig { message: format!("{field} is required") }),
    }
}

pub(super) fn optional_extra_string(info: &ListenerInfo, field: &'static str) -> Option<String> {
    extra_value_as_str(info, field).and_then(|value| optional_trimmed(Some(value)))
}

pub(super) fn extra_value_as_str<'a>(
    info: &'a ListenerInfo,
    field: &'static str,
) -> Option<&'a str> {
    info.extra.get(field).and_then(serde_json::Value::as_str)
}

pub(super) fn parse_extra_bool(
    info: &ListenerInfo,
    field: &'static str,
) -> Result<bool, ListenerManagerError> {
    match info.extra.get(field) {
        Some(serde_json::Value::Bool(b)) => Ok(*b),
        _ => parse_bool(field, extra_value_as_str(info, field)),
    }
}

pub(super) fn parse_optional_extra_bool(
    info: &ListenerInfo,
    field: &'static str,
) -> Result<Option<bool>, ListenerManagerError> {
    match info.extra.get(field) {
        None => Ok(None),
        Some(serde_json::Value::Bool(b)) => Ok(Some(*b)),
        _ => match extra_value_as_str(info, field) {
            None => Ok(None),
            Some(value) => parse_bool(field, Some(value)).map(Some),
        },
    }
}

pub(super) fn insert_optional_extra_string(
    extra: &mut BTreeMap<String, serde_json::Value>,
    field: &'static str,
    value: Option<&str>,
) {
    if let Some(value) = optional_trimmed(value) {
        extra.insert(field.to_owned(), serde_json::Value::String(value));
    }
}

pub(super) fn parse_u16(
    field: &'static str,
    value: Option<&str>,
) -> Result<u16, ListenerManagerError> {
    let value = required_field(field, value)?;
    value.parse::<u16>().map_err(|error| ListenerManagerError::InvalidConfig {
        message: format!("{field} must be a valid port: {error}"),
    })
}

pub(super) fn parse_optional_u16(
    field: &'static str,
    value: Option<&str>,
) -> Result<Option<u16>, ListenerManagerError> {
    match optional_trimmed(value) {
        Some(value) => {
            value.parse::<u16>().map(Some).map_err(|error| ListenerManagerError::InvalidConfig {
                message: format!("{field} must be a valid port: {error}"),
            })
        }
        None => Ok(None),
    }
}

pub(super) fn parse_bool(
    field: &'static str,
    value: Option<&str>,
) -> Result<bool, ListenerManagerError> {
    match optional_trimmed(value) {
        Some(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        Some(value) => Err(ListenerManagerError::InvalidConfig {
            message: format!("{field} must be `true` or `false`, got `{value}`"),
        }),
        None => Ok(false),
    }
}

pub(super) fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value.map(str::trim).filter(|value| !value.is_empty()).map(ToOwned::to_owned)
}

pub(super) fn split_csv(value: Option<&str>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn proxy_from_operator(
    info: &ListenerInfo,
) -> Result<Option<HttpListenerProxyConfig>, ListenerManagerError> {
    if !parse_bool("Proxy Enabled", info.proxy_enabled.as_deref())? {
        return Ok(None);
    }

    Ok(Some(HttpListenerProxyConfig {
        enabled: true,
        proxy_type: optional_trimmed(info.proxy_type.as_deref()),
        host: required_field("Proxy Host", info.proxy_host.as_deref())?.to_owned(),
        port: parse_u16("Proxy Port", info.proxy_port.as_deref())?,
        username: optional_trimmed(info.proxy_username.as_deref()),
        password: optional_trimmed(info.proxy_password.as_deref()).map(Zeroizing::new),
    }))
}

pub(super) fn tls_config_from_operator(
    info: &ListenerInfo,
) -> Option<red_cell_common::ListenerTlsConfig> {
    match (
        optional_extra_string(info, EXTRA_CERT_PATH),
        optional_extra_string(info, EXTRA_KEY_PATH),
    ) {
        (Some(cert), Some(key)) => Some(red_cell_common::ListenerTlsConfig { cert, key }),
        _ => None,
    }
}

pub(super) fn http_response_from_operator(
    info: &ListenerInfo,
) -> Option<HttpListenerResponseConfig> {
    let headers = split_csv(info.response_headers.as_deref());
    let body = optional_extra_string(info, EXTRA_RESPONSE_BODY);
    (!headers.is_empty() || body.is_some()).then_some(HttpListenerResponseConfig { headers, body })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use red_cell_common::operator::ListenerInfo;

    use super::{EXTRA_LEGACY_MODE, parse_extra_bool, parse_optional_extra_bool};

    fn info_with_extra(key: &str, value: serde_json::Value) -> ListenerInfo {
        let mut extra = BTreeMap::new();
        extra.insert(key.to_owned(), value);
        ListenerInfo { extra, ..Default::default() }
    }

    #[test]
    fn parse_extra_bool_json_bool_true() {
        let info = info_with_extra(EXTRA_LEGACY_MODE, serde_json::Value::Bool(true));
        assert!(parse_extra_bool(&info, EXTRA_LEGACY_MODE).unwrap());
    }

    #[test]
    fn parse_extra_bool_json_bool_false() {
        let info = info_with_extra(EXTRA_LEGACY_MODE, serde_json::Value::Bool(false));
        assert!(!parse_extra_bool(&info, EXTRA_LEGACY_MODE).unwrap());
    }

    #[test]
    fn parse_extra_bool_json_string_true() {
        let info = info_with_extra(EXTRA_LEGACY_MODE, serde_json::Value::String("true".into()));
        assert!(parse_extra_bool(&info, EXTRA_LEGACY_MODE).unwrap());
    }

    #[test]
    fn parse_extra_bool_json_string_false() {
        let info = info_with_extra(EXTRA_LEGACY_MODE, serde_json::Value::String("false".into()));
        assert!(!parse_extra_bool(&info, EXTRA_LEGACY_MODE).unwrap());
    }

    #[test]
    fn parse_extra_bool_missing_defaults_false() {
        let info = ListenerInfo { extra: BTreeMap::new(), ..Default::default() };
        assert!(!parse_extra_bool(&info, EXTRA_LEGACY_MODE).unwrap());
    }

    #[test]
    fn parse_optional_extra_bool_json_bool_true() {
        let info = info_with_extra(EXTRA_LEGACY_MODE, serde_json::Value::Bool(true));
        assert_eq!(parse_optional_extra_bool(&info, EXTRA_LEGACY_MODE).unwrap(), Some(true));
    }

    #[test]
    fn parse_optional_extra_bool_json_bool_false() {
        let info = info_with_extra(EXTRA_LEGACY_MODE, serde_json::Value::Bool(false));
        assert_eq!(parse_optional_extra_bool(&info, EXTRA_LEGACY_MODE).unwrap(), Some(false));
    }

    #[test]
    fn parse_optional_extra_bool_missing_is_none() {
        let info = ListenerInfo { extra: BTreeMap::new(), ..Default::default() };
        assert_eq!(parse_optional_extra_bool(&info, EXTRA_LEGACY_MODE).unwrap(), None);
    }

    #[test]
    fn parse_optional_extra_bool_json_string_true() {
        let info = info_with_extra(EXTRA_LEGACY_MODE, serde_json::Value::String("true".into()));
        assert_eq!(parse_optional_extra_bool(&info, EXTRA_LEGACY_MODE).unwrap(), Some(true));
    }

    #[test]
    fn parse_optional_extra_bool_json_string_false() {
        let info = info_with_extra(EXTRA_LEGACY_MODE, serde_json::Value::String("false".into()));
        assert_eq!(parse_optional_extra_bool(&info, EXTRA_LEGACY_MODE).unwrap(), Some(false));
    }
}
