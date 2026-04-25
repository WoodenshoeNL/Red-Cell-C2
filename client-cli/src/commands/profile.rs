//! Handlers for `red-cell-cli profile validate` and `red-cell-cli profile show`.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::client::ApiClient;
use crate::error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};
use crate::output::{OutputFormat, TextRender, print_error, print_success};

/// Individual validation error with an optional line reference.
#[derive(Debug, Serialize)]
struct ValidationEntry {
    message: String,
}

/// Output for a valid profile.
#[derive(Debug, Serialize)]
struct ValidResult {
    ok: bool,
}

impl TextRender for ValidResult {
    fn render_text(&self) -> String {
        "profile is valid".to_owned()
    }
}

/// Output for a profile with errors.
#[derive(Debug, Serialize)]
struct InvalidResult {
    ok: bool,
    errors: Vec<ValidationEntry>,
}

impl TextRender for InvalidResult {
    fn render_text(&self) -> String {
        let mut out = String::from("profile validation failed:\n");
        for entry in &self.errors {
            out.push_str("  - ");
            out.push_str(&entry.message);
            out.push('\n');
        }
        out
    }
}

/// Validate a YAOTL profile file locally (no server connection needed).
pub fn validate_local(path: &Path, fmt: &OutputFormat) -> i32 {
    let profile = match red_cell_common::config::Profile::from_file(path) {
        Ok(p) => p,
        Err(e) => {
            let errors = vec![ValidationEntry { message: e.to_string() }];
            let result = InvalidResult { ok: false, errors };
            match print_success(fmt, &result) {
                Ok(()) => return EXIT_GENERAL,
                Err(e) => {
                    print_error(&e).ok();
                    return e.exit_code();
                }
            }
        }
    };

    match profile.validate() {
        Ok(()) => match print_success(fmt, &ValidResult { ok: true }) {
            Ok(()) => EXIT_SUCCESS,
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },
        Err(validation_err) => {
            let errors = validation_err
                .errors
                .into_iter()
                .map(|message| ValidationEntry { message })
                .collect();
            let result = InvalidResult { ok: false, errors };
            match print_success(fmt, &result) {
                Ok(()) => EXIT_GENERAL,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }
    }
}

// ── profile show ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileOperatorEntry {
    name: String,
    role: String,
    has_password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileApiKeyEntry {
    name: String,
    role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileHttpListenerEntry {
    name: String,
    protocol: String,
    host_bind: String,
    port_bind: u16,
    port_conn: Option<u16>,
    hosts: Vec<String>,
    secure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileSmbListenerEntry {
    name: String,
    protocol: String,
    pipe_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileDnsListenerEntry {
    name: String,
    protocol: String,
    host_bind: String,
    port_bind: u16,
    domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileExternalListenerEntry {
    name: String,
    protocol: String,
    endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileListeners {
    http: Vec<ProfileHttpListenerEntry>,
    smb: Vec<ProfileSmbListenerEntry>,
    dns: Vec<ProfileDnsListenerEntry>,
    external: Vec<ProfileExternalListenerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileDemonDefaults {
    sleep: Option<u64>,
    jitter: Option<u8>,
    indirect_syscall: bool,
    stack_duplication: bool,
    sleep_technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileWebhookStatus {
    discord_configured: bool,
}

/// Server profile response (secrets redacted by the server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileShowData {
    path: String,
    host: String,
    port: u16,
    operators: Vec<ProfileOperatorEntry>,
    api_keys: Vec<ProfileApiKeyEntry>,
    api_rate_limit_per_minute: Option<u32>,
    listeners: ProfileListeners,
    demon: ProfileDemonDefaults,
    service_configured: bool,
    webhook: Option<ProfileWebhookStatus>,
}

impl TextRender for ProfileShowData {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("Profile: {}\n", self.path));
        out.push_str(&format!("Teamserver: {}:{}\n", self.host, self.port));

        out.push_str("\nOperators:\n");
        for op in &self.operators {
            out.push_str(&format!(
                "  {} (role: {}, password: {})\n",
                op.name,
                op.role,
                if op.has_password { "set" } else { "missing" }
            ));
        }

        if !self.api_keys.is_empty() {
            out.push_str("\nAPI Keys:\n");
            for key in &self.api_keys {
                out.push_str(&format!("  {} (role: {})\n", key.name, key.role));
            }
        }

        if let Some(rate) = self.api_rate_limit_per_minute {
            out.push_str(&format!("\nAPI Rate Limit: {}/min\n", rate));
        }

        let total_listeners = self.listeners.http.len()
            + self.listeners.smb.len()
            + self.listeners.dns.len()
            + self.listeners.external.len();
        out.push_str(&format!("\nListeners ({total_listeners}):\n"));
        for l in &self.listeners.http {
            out.push_str(&format!("  {} ({}, {}:{}", l.name, l.protocol, l.host_bind, l.port_bind));
            if let Some(conn) = l.port_conn {
                out.push_str(&format!(", conn:{conn}"));
            }
            out.push_str(")\n");
        }
        for l in &self.listeners.smb {
            out.push_str(&format!("  {} (smb, pipe: {})\n", l.name, l.pipe_name));
        }
        for l in &self.listeners.dns {
            out.push_str(&format!(
                "  {} (dns, {}:{}, domain: {})\n",
                l.name, l.host_bind, l.port_bind, l.domain
            ));
        }
        for l in &self.listeners.external {
            out.push_str(&format!("  {} (external, {})\n", l.name, l.endpoint));
        }

        out.push_str("\nDemon Defaults:\n");
        if let Some(sleep) = self.demon.sleep {
            out.push_str(&format!("  sleep: {sleep}s\n"));
        }
        if let Some(jitter) = self.demon.jitter {
            out.push_str(&format!("  jitter: {jitter}%\n"));
        }
        out.push_str(&format!("  indirect_syscall: {}\n", self.demon.indirect_syscall));
        out.push_str(&format!("  stack_duplication: {}\n", self.demon.stack_duplication));
        if let Some(ref tech) = self.demon.sleep_technique {
            out.push_str(&format!("  sleep_technique: {tech}\n"));
        }

        out.push_str(&format!(
            "\nService: {}\n",
            if self.service_configured { "configured" } else { "not configured" }
        ));

        if let Some(ref wh) = self.webhook {
            out.push_str(&format!(
                "Webhook: discord={}\n",
                if wh.discord_configured { "configured" } else { "not configured" }
            ));
        }

        out
    }
}

/// Fetch the effective profile from the running teamserver.
///
/// # Errors
///
/// Returns a [`CliError`] if the API call fails.
pub async fn show_server(client: &ApiClient) -> Result<ProfileShowData, CliError> {
    client.get("/profile").await
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn valid_profile_returns_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("good.yaotl");
        let mut f = std::fs::File::create(&path).expect("create");
        write!(
            f,
            r#"
Teamserver {{
    Host = "0.0.0.0"
    Port = 40056
}}

Operators {{
    user "admin" {{
        Password = "secret123"
    }}
}}

Listeners {{}}

Demon {{
    Sleep  = 2
    Jitter = 10
}}
"#
        )
        .expect("write");
        drop(f);

        let code = validate_local(&path, &OutputFormat::Json);
        assert_eq!(code, EXIT_SUCCESS);
    }

    #[test]
    fn invalid_profile_returns_general_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.yaotl");
        let mut f = std::fs::File::create(&path).expect("create");
        write!(
            f,
            r#"
Teamserver {{
    Host = ""
    Port = 0
}}

Operators {{}}

Listeners {{}}

Demon {{
    Sleep  = 2
    Jitter = 10
}}
"#
        )
        .expect("write");
        drop(f);

        let code = validate_local(&path, &OutputFormat::Json);
        assert_eq!(code, EXIT_GENERAL);
    }

    #[test]
    fn missing_file_returns_general_error() {
        let path = Path::new("/tmp/does-not-exist-red-cell-test.yaotl");
        let code = validate_local(path, &OutputFormat::Json);
        assert_eq!(code, EXIT_GENERAL);
    }

    #[test]
    fn parse_error_returns_general_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("malformed.yaotl");
        std::fs::write(&path, "this is not valid HCL {{{{").expect("write");

        let code = validate_local(&path, &OutputFormat::Json);
        assert_eq!(code, EXIT_GENERAL);
    }

    #[test]
    fn valid_result_text_render() {
        let result = ValidResult { ok: true };
        assert_eq!(result.render_text(), "profile is valid");
    }

    #[test]
    fn invalid_result_text_render() {
        let result = InvalidResult {
            ok: false,
            errors: vec![
                ValidationEntry { message: "Host must not be empty".to_owned() },
                ValidationEntry { message: "Port must be > 0".to_owned() },
            ],
        };
        let text = result.render_text();
        assert!(text.contains("Host must not be empty"));
        assert!(text.contains("Port must be > 0"));
    }

    fn sample_profile_data() -> ProfileShowData {
        ProfileShowData {
            path: "profiles/test.yaotl".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: 40056,
            operators: vec![ProfileOperatorEntry {
                name: "admin".to_owned(),
                role: "Admin".to_owned(),
                has_password: true,
            }],
            api_keys: vec![ProfileApiKeyEntry {
                name: "test-key".to_owned(),
                role: "Operator".to_owned(),
            }],
            api_rate_limit_per_minute: Some(60),
            listeners: ProfileListeners {
                http: vec![ProfileHttpListenerEntry {
                    name: "http1".to_owned(),
                    protocol: "http".to_owned(),
                    host_bind: "0.0.0.0".to_owned(),
                    port_bind: 19100,
                    port_conn: None,
                    hosts: vec!["10.0.0.1".to_owned()],
                    secure: false,
                }],
                smb: vec![],
                dns: vec![],
                external: vec![],
            },
            demon: ProfileDemonDefaults {
                sleep: Some(5),
                jitter: Some(20),
                indirect_syscall: false,
                stack_duplication: false,
                sleep_technique: None,
            },
            service_configured: false,
            webhook: None,
        }
    }

    #[test]
    fn profile_show_data_serialises_correctly() {
        let data = sample_profile_data();
        let json = serde_json::to_value(&data).expect("serialize");
        assert_eq!(json["path"], "profiles/test.yaotl");
        assert_eq!(json["host"], "127.0.0.1");
        assert_eq!(json["port"], 40056);
        assert_eq!(json["operators"][0]["name"], "admin");
        assert_eq!(json["operators"][0]["has_password"], true);
        assert_eq!(json["api_keys"][0]["name"], "test-key");
        assert_eq!(json["listeners"]["http"][0]["name"], "http1");
        assert_eq!(json["demon"]["sleep"], 5);
        assert_eq!(json["demon"]["jitter"], 20);
    }

    #[test]
    fn profile_show_data_deserialises_round_trip() {
        let data = sample_profile_data();
        let json_str = serde_json::to_string(&data).expect("serialize");
        let parsed: ProfileShowData = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(parsed.path, "profiles/test.yaotl");
        assert_eq!(parsed.operators.len(), 1);
        assert_eq!(parsed.listeners.http.len(), 1);
    }

    #[test]
    fn profile_show_text_render_contains_core_fields() {
        let data = sample_profile_data();
        let text = data.render_text();
        for needle in [
            "profiles/test.yaotl",
            "127.0.0.1:40056",
            "admin",
            "Admin",
            "http1",
            "0.0.0.0:19100",
            "sleep: 5s",
            "jitter: 20%",
            "60/min",
        ] {
            assert!(text.contains(needle), "expected {needle:?} in:\n{text}");
        }
    }

    #[test]
    fn profile_show_text_render_with_port_conn() {
        let mut data = sample_profile_data();
        data.listeners.http[0].port_conn = Some(443);
        let text = data.render_text();
        assert!(text.contains("conn:443"), "expected port_conn in:\n{text}");
    }

    #[tokio::test]
    async fn show_server_calls_profile_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = serde_json::to_value(&sample_profile_data()).expect("serialize");

        Mock::given(method("GET"))
            .and(path("/api/v1/profile"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("client");
        let result = show_server(&client).await.expect("show_server");
        assert_eq!(result.host, "127.0.0.1");
        assert_eq!(result.port, 40056);
        assert_eq!(result.operators.len(), 1);
    }
}
