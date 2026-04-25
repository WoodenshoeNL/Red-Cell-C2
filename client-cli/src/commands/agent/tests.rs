use std::sync::{Arc, Mutex};

use crate::AgentId;
use crate::error::CliError;
use crate::output::{OutputFormat, TextRender, TextRow};

use super::exec::{command_id_for, exec_wait};
use super::list::agent_summary_from_raw;
use super::output_cmd::{
    fetch_output, render_output_stream_line, take_cursor_reset_warning, watch_output,
};
use super::show::agent_detail_from_raw;
use super::transfer::upload;
use super::types::RawAgentGroupsResponse;
use super::types::{
    AgentDetail, AgentGroupsInfo, AgentSummary, ExecResult, JobSubmitted, KillResult, OutputEntry,
    TransferResult,
};
use super::wire::RawAgent;

fn agent_id(value: u32) -> AgentId {
    AgentId::new(value)
}

// ── AgentSummary ──────────────────────────────────────────────────────────

#[test]
fn agent_summary_serialises_required_fields() {
    let s = AgentSummary {
        id: agent_id(0xABC),
        hostname: "WIN10".to_owned(),
        os: "Windows 10".to_owned(),
        last_seen: "2026-01-01T00:00:00Z".to_owned(),
        status: "alive".to_owned(),
    };
    let v = serde_json::to_value(&s).expect("serialise");
    assert_eq!(v["id"], "00000ABC");
    assert_eq!(v["hostname"], "WIN10");
    assert_eq!(v["status"], "alive");
}

#[test]
fn agent_summary_text_row_headers_match_row_length() {
    let s = AgentSummary {
        id: agent_id(0xA),
        hostname: "h".to_owned(),
        os: "linux".to_owned(),
        last_seen: "t".to_owned(),
        status: "alive".to_owned(),
    };
    assert_eq!(AgentSummary::headers().len(), s.row().len());
}

#[test]
fn vec_agent_summary_renders_table() {
    let items = vec![AgentSummary {
        id: agent_id(0xABC),
        hostname: "WIN10".to_owned(),
        os: "Windows 10".to_owned(),
        last_seen: "2026-01-01T00:00:00Z".to_owned(),
        status: "alive".to_owned(),
    }];
    let rendered = items.render_text();
    assert!(rendered.contains("00000ABC"));
    assert!(rendered.contains("WIN10"));
    assert!(rendered.contains("alive"));
}

// ── AgentDetail ───────────────────────────────────────────────────────────

#[test]
fn agent_detail_serialises_optional_fields_as_null() {
    let d = AgentDetail {
        id: agent_id(0xA),
        hostname: "h".to_owned(),
        os: "linux".to_owned(),
        arch: None,
        username: None,
        domain: None,
        external_ip: None,
        internal_ip: None,
        process_name: None,
        pid: None,
        elevated: None,
        first_seen: "t0".to_owned(),
        last_seen: "t".to_owned(),
        status: "alive".to_owned(),
        sleep_interval: None,
        jitter: None,
    };
    let v = serde_json::to_value(&d).expect("serialise");
    assert!(v["arch"].is_null());
    assert!(v["pid"].is_null());
    assert!(v["external_ip"].is_null());
    assert!(v["elevated"].is_null());
}

#[test]
fn agent_detail_render_text_contains_key_fields() {
    let d = AgentDetail {
        id: agent_id(0xABC123),
        hostname: "myhost".to_owned(),
        os: "Windows".to_owned(),
        arch: Some("x86_64".to_owned()),
        username: Some("DOMAIN\\alice".to_owned()),
        domain: Some("CORP".to_owned()),
        external_ip: Some("203.0.113.1".to_owned()),
        internal_ip: Some("10.0.0.1".to_owned()),
        process_name: Some("svchost.exe".to_owned()),
        pid: Some(1234),
        elevated: Some(true),
        first_seen: "2026-01-01T00:00:00Z".to_owned(),
        last_seen: "2026-01-02T00:00:00Z".to_owned(),
        status: "alive".to_owned(),
        sleep_interval: Some(60),
        jitter: Some(10),
    };
    let rendered = d.render_text();
    assert!(rendered.contains("00ABC123"));
    assert!(rendered.contains("myhost"));
    assert!(rendered.contains("x86_64"));
    assert!(rendered.contains("1234"));
    assert!(rendered.contains("203.0.113.1"));
    assert!(rendered.contains("true"));
}

// ── JobSubmitted ──────────────────────────────────────────────────────────

#[test]
fn job_submitted_serialises_job_id() {
    let j = JobSubmitted { job_id: "job_abc".to_owned() };
    let v = serde_json::to_value(&j).expect("serialise");
    assert_eq!(v["job_id"], "job_abc");
}

#[test]
fn job_submitted_render_text_contains_job_id() {
    let j = JobSubmitted { job_id: "job_abc".to_owned() };
    assert!(j.render_text().contains("job_abc"));
}

// ── ExecResult ────────────────────────────────────────────────────────────

#[test]
fn exec_result_serialises_all_fields() {
    let r = ExecResult { job_id: "j1".to_owned(), output: "root\n".to_owned(), exit_code: Some(0) };
    let v = serde_json::to_value(&r).expect("serialise");
    assert_eq!(v["job_id"], "j1");
    assert_eq!(v["output"], "root\n");
    assert_eq!(v["exit_code"], 0);
}

#[test]
fn exec_result_render_text_contains_output_and_exit() {
    let r = ExecResult { job_id: "j1".to_owned(), output: "root\n".to_owned(), exit_code: Some(0) };
    let rendered = r.render_text();
    assert!(rendered.contains("root"));
    assert!(rendered.contains('0'));
}

// ── OutputEntry ───────────────────────────────────────────────────────────

#[test]
fn output_entry_text_row_headers_match_row_length() {
    let e = OutputEntry {
        entry_id: 1,
        job_id: "j".to_owned(),
        command: None,
        output: "out".to_owned(),
        exit_code: Some(0),
        created_at: "t".to_owned(),
    };
    assert_eq!(OutputEntry::headers().len(), e.row().len());
}

#[test]
fn output_entry_row_79_chars_not_truncated() {
    let output: String = "x".repeat(79);
    let e = OutputEntry {
        entry_id: 1,
        job_id: "j".to_owned(),
        command: None,
        output: output.clone(),
        exit_code: None,
        created_at: "t".to_owned(),
    };
    let row = e.row();
    assert_eq!(row[4], output);
    assert_eq!(row[4].chars().count(), 79);
}

#[test]
fn output_entry_row_80_chars_not_truncated() {
    let output: String = "x".repeat(80);
    let e = OutputEntry {
        entry_id: 1,
        job_id: "j".to_owned(),
        command: None,
        output: output.clone(),
        exit_code: None,
        created_at: "t".to_owned(),
    };
    let row = e.row();
    assert_eq!(row[4], output);
    assert_eq!(row[4].chars().count(), 80);
}

#[test]
fn output_entry_row_81_chars_truncated_to_80() {
    let output: String = "x".repeat(81);
    let e = OutputEntry {
        entry_id: 1,
        job_id: "j".to_owned(),
        command: None,
        output,
        exit_code: None,
        created_at: "t".to_owned(),
    };
    let row = e.row();
    assert_eq!(row[4].chars().count(), 80);
    assert_eq!(row[4], "x".repeat(80));
}

#[test]
fn output_entry_row_truncation_counts_unicode_chars_not_bytes() {
    // Each 'é' is 2 bytes but 1 Unicode scalar value.
    // 81 such chars should be truncated to 80 chars (not 80 bytes).
    let output: String = "é".repeat(81);
    let e = OutputEntry {
        entry_id: 1,
        job_id: "j".to_owned(),
        command: None,
        output,
        exit_code: None,
        created_at: "t".to_owned(),
    };
    let row = e.row();
    assert_eq!(row[4].chars().count(), 80);
    assert_eq!(row[4], "é".repeat(80));
}

// ── KillResult ────────────────────────────────────────────────────────────

#[test]
fn kill_result_render_text_contains_id_and_status() {
    let k = KillResult { agent_id: agent_id(0xABC), status: "dead".to_owned() };
    let rendered = k.render_text();
    assert!(rendered.contains("00000ABC"));
    assert!(rendered.contains("dead"));
}

#[test]
fn kill_result_deregistered_render_text() {
    let k = KillResult { agent_id: agent_id(0xBEEF), status: "deregistered".to_owned() };
    let rendered = k.render_text();
    assert!(rendered.contains("0000BEEF"));
    assert!(rendered.contains("deregistered"));
}

#[test]
fn kill_result_kill_sent_render_text() {
    let k = KillResult { agent_id: agent_id(0x1234), status: "kill_sent".to_owned() };
    let rendered = k.render_text();
    assert!(rendered.contains("00001234"));
    assert!(rendered.contains("kill_sent"));
}

// ── TransferResult ────────────────────────────────────────────────────────

#[test]
fn transfer_result_upload_render_contains_job_id() {
    let t = TransferResult {
        agent_id: agent_id(0xABC),
        job_id: Some("j1".to_owned()),
        local_path: "/tmp/f".to_owned(),
        remote_path: "C:\\f".to_owned(),
    };
    assert!(t.render_text().contains("j1"));
}

#[test]
fn transfer_result_download_render_no_job_id() {
    let t = TransferResult {
        agent_id: agent_id(0xABC),
        job_id: None,
        local_path: "/tmp/f".to_owned(),
        remote_path: "/etc/passwd".to_owned(),
    };
    let rendered = t.render_text();
    assert!(rendered.contains("complete"));
    assert!(rendered.contains("/etc/passwd"));
}

// ── from_raw helpers ──────────────────────────────────────────────────────

#[test]
fn agent_summary_from_raw_maps_all_fields() {
    let raw = RawAgent {
        id: agent_id(0x1D1),
        hostname: "host".to_owned(),
        os: "linux".to_owned(),
        last_seen: "ts".to_owned(),
        first_seen: "ts0".to_owned(),
        status: "alive".to_owned(),
        arch: None,
        username: None,
        domain: None,
        external_ip: None,
        internal_ip: None,
        process_name: None,
        pid: None,
        elevated: None,
        sleep_interval: None,
        jitter: None,
    };
    let s = agent_summary_from_raw(raw);
    assert_eq!(s.id, agent_id(0x1D1));
    assert_eq!(s.hostname, "host");
    assert_eq!(s.status, "alive");
}

#[test]
fn agent_detail_from_raw_preserves_optional_fields() {
    let raw = RawAgent {
        id: agent_id(0x1D2),
        hostname: "h".to_owned(),
        os: "win".to_owned(),
        last_seen: "t".to_owned(),
        first_seen: "t0".to_owned(),
        status: "dead".to_owned(),
        arch: Some("x86".to_owned()),
        username: Some("user".to_owned()),
        domain: None,
        external_ip: Some("1.2.3.4".to_owned()),
        internal_ip: None,
        process_name: None,
        pid: Some(42),
        elevated: Some(false),
        sleep_interval: Some(30),
        jitter: None,
    };
    let d = agent_detail_from_raw(raw);
    assert_eq!(d.arch, Some("x86".to_owned()));
    assert_eq!(d.pid, Some(42));
    assert_eq!(d.domain, None);
    assert_eq!(d.external_ip, Some("1.2.3.4".to_owned()));
    assert_eq!(d.elevated, Some(false));
}

// ── ApiAgentWire deserialization (matches real ApiAgentInfo schema) ───────

/// Full `ApiAgentInfo`-shaped JSON (as the teamserver serialises it)
/// deserialized into `RawAgent` via `ApiAgentWire`.  Field names are
/// PascalCase to match `ApiAgentInfo`'s `#[serde(rename)]` attributes.
#[test]
fn api_agent_wire_deserialises_full_api_agent_info_payload() {
    let json = serde_json::json!({
        "AgentID":      3735928559u32,  // 0xDEADBEEF
        "Active":       true,
        "Reason":       "http",
        "Note":         "",
        "Hostname":     "WORKSTATION01",
        "Username":     "CORP\\alice",
        "DomainName":   "CORP",
        "ExternalIP":   "203.0.113.10",
        "InternalIP":   "10.0.0.10",
        "ProcessName":  "demon.exe",
        "BaseAddress":  0x1400_0000u64,
        "ProcessPID":   4444u32,
        "ProcessTID":   4445u32,
        "ProcessPPID":  1000u32,
        "ProcessArch":  "x64",
        "Elevated":     true,
        "OSVersion":    "Windows 11",
        "OSBuild":      22000u32,
        "OSArch":       "x64",
        "SleepDelay":   5u32,
        "SleepJitter":  10u32,
        "KillDate":     null,
        "WorkingHours": null,
        "FirstCallIn":  "2026-03-01T00:00:00Z",
        "LastCallIn":   "2026-03-01T00:05:00Z"
    });

    let raw: RawAgent = serde_json::from_value(json).expect("deserialise RawAgent");

    assert_eq!(raw.id, agent_id(0xDEADBEEF));
    assert_eq!(raw.hostname, "WORKSTATION01");
    assert_eq!(raw.os, "Windows 11 x64");
    assert_eq!(raw.last_seen, "2026-03-01T00:05:00Z");
    assert_eq!(raw.first_seen, "2026-03-01T00:00:00Z");
    assert_eq!(raw.status, "alive");
    assert_eq!(raw.username, Some("CORP\\alice".to_owned()));
    assert_eq!(raw.domain, Some("CORP".to_owned()));
    assert_eq!(raw.external_ip, Some("203.0.113.10".to_owned()));
    assert_eq!(raw.internal_ip, Some("10.0.0.10".to_owned()));
    assert_eq!(raw.process_name, Some("demon.exe".to_owned()));
    assert_eq!(raw.pid, Some(4444));
    assert_eq!(raw.elevated, Some(true));
    assert_eq!(raw.sleep_interval, Some(5));
    assert_eq!(raw.jitter, Some(10));
}

/// Inactive agent (`Active = false`) maps to `status = "dead"`.
#[test]
fn api_agent_wire_inactive_agent_maps_status_to_dead() {
    let json = serde_json::json!({
        "AgentID":      1u32,
        "Active":       false,
        "Reason":       "killed",
        "Note":         "",
        "Hostname":     "HOST",
        "Username":     "user",
        "DomainName":   ".",
        "ExternalIP":   "1.2.3.4",
        "InternalIP":   "10.0.0.1",
        "ProcessName":  "a.exe",
        "BaseAddress":  0u64,
        "ProcessPID":   100u32,
        "ProcessTID":   101u32,
        "ProcessPPID":  1u32,
        "ProcessArch":  "x86",
        "Elevated":     false,
        "OSVersion":    "Windows 10",
        "OSBuild":      19045u32,
        "OSArch":       "x64",
        "SleepDelay":   60u32,
        "SleepJitter":  0u32,
        "KillDate":     null,
        "WorkingHours": null,
        "FirstCallIn":  "2026-01-01T00:00:00Z",
        "LastCallIn":   "2026-01-02T00:00:00Z"
    });

    let raw: RawAgent = serde_json::from_value(json).expect("deserialise");
    assert_eq!(raw.status, "dead");
    assert_eq!(raw.id, agent_id(1));
    assert_eq!(raw.os, "Windows 10 x64");
}

/// `Vec<RawAgent>` (the list-endpoint shape) deserializes from a JSON
/// array of `ApiAgentInfo` objects.
#[test]
fn api_agent_wire_vec_deserialises_list_endpoint_shape() {
    let json = serde_json::json!([{
        "AgentID":      1u32,
        "Active":       true,
        "Reason":       "http",
        "Note":         "",
        "Hostname":     "HOST-A",
        "Username":     "admin",
        "DomainName":   "LAB",
        "ExternalIP":   "5.6.7.8",
        "InternalIP":   "192.168.1.1",
        "ProcessName":  "b.exe",
        "BaseAddress":  0u64,
        "ProcessPID":   200u32,
        "ProcessTID":   201u32,
        "ProcessPPID":  2u32,
        "ProcessArch":  "x64",
        "Elevated":     false,
        "OSVersion":    "Windows Server 2022",
        "OSBuild":      20348u32,
        "OSArch":       "x64",
        "SleepDelay":   30u32,
        "SleepJitter":  5u32,
        "KillDate":     null,
        "WorkingHours": null,
        "FirstCallIn":  "2026-02-01T00:00:00Z",
        "LastCallIn":   "2026-02-01T00:01:00Z"
    }]);

    let agents: Vec<RawAgent> = serde_json::from_value(json).expect("deserialise list");
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].hostname, "HOST-A");
    assert_eq!(agents[0].status, "alive");
    assert_eq!(agents[0].os, "Windows Server 2022 x64");
}

// ── command_id_for ────────────────────────────────────────────────────────

#[test]
fn command_id_for_screenshot_returns_2510() {
    assert_eq!(command_id_for("screenshot"), "2510");
}

#[test]
fn command_id_for_screenshot_is_case_insensitive() {
    assert_eq!(command_id_for("SCREENSHOT"), "2510");
    assert_eq!(command_id_for("ScreenShot"), "2510");
    assert_eq!(command_id_for("SCREENSHOT C:\\out.png"), "2510");
}

#[test]
fn command_id_for_shell_cmd_returns_proc_create() {
    assert_eq!(command_id_for("whoami"), "4112");
    assert_eq!(command_id_for("dir C:\\"), "4112");
    assert_eq!(command_id_for("ps aux"), "4112");
}

#[test]
fn command_id_for_empty_returns_proc_create() {
    assert_eq!(command_id_for(""), "4112");
}

// ── output cursor stale warning ─────────────────────────────────────────────

#[test]
fn cursor_reset_warning_triggers_when_since_cursor_positive_and_empty_poll() {
    let mut warned = false;
    assert_eq!(take_cursor_reset_warning(Some(42), false, &mut warned), Some(42));
    assert!(warned);
}

#[test]
fn cursor_reset_warning_skipped_when_cursor_none_or_zero() {
    let mut w1 = false;
    assert_eq!(take_cursor_reset_warning(None, false, &mut w1), None);
    assert!(!w1);

    let mut w2 = false;
    assert_eq!(take_cursor_reset_warning(Some(0), false, &mut w2), None);
    assert!(!w2);
}

#[test]
fn cursor_reset_warning_emitted_at_most_once_until_output_seen() {
    let mut warned = false;
    assert_eq!(take_cursor_reset_warning(Some(99), false, &mut warned), Some(99));
    assert_eq!(take_cursor_reset_warning(Some(99), false, &mut warned), None);
}

#[test]
fn cursor_reset_warning_suppressed_after_output_seen() {
    let mut warned = false;
    assert_eq!(take_cursor_reset_warning(Some(5), true, &mut warned), None);
    assert!(!warned);
}

/// Simulates `--since` beyond every retained row: empty page with a positive cursor.
#[test]
fn cursor_reset_warning_models_stale_cursor_beyond_available_entries() {
    let mut warned = false;
    assert_eq!(take_cursor_reset_warning(Some(10_000), false, &mut warned), Some(10_000));
    assert!(warned, "stale high cursor must trigger one warning");
}

// ── exec_wait / fetch_output / watch_output ────────────────────────────────

/// Build a `ResolvedConfig` pointing at the given mock server URI.
fn mock_cfg(server_uri: &str) -> crate::config::ResolvedConfig {
    crate::config::ResolvedConfig {
        server: server_uri.to_owned(),
        token: "test-token".to_owned(),
        timeout: 5,
        tls_mode: crate::config::TlsMode::SystemRoots,
    }
}

/// `exec_wait` submits a task then polls for output — against an
/// unreachable server it returns `ServerUnreachable`.
#[tokio::test]
async fn exec_wait_returns_error_when_server_unreachable() {
    let cfg = mock_cfg("http://127.0.0.1:1");
    let client = crate::client::ApiClient::new(&cfg).expect("build client");
    let result = exec_wait(&client, agent_id(0xA001), "whoami", 30).await;
    assert!(
        matches!(result, Err(crate::error::CliError::ServerUnreachable(_))),
        "exec_wait against unreachable server must return ServerUnreachable; got: {result:?}"
    );
}

/// `fetch_output` calls `GET /agents/{id}/output` — against an unreachable
/// server it returns `ServerUnreachable`.
#[tokio::test]
async fn fetch_output_returns_error_when_server_unreachable() {
    let cfg = mock_cfg("http://127.0.0.1:1");
    let client = crate::client::ApiClient::new(&cfg).expect("build client");
    let result = fetch_output(&client, agent_id(0xA001), None).await;
    assert!(
        matches!(result, Err(crate::error::CliError::ServerUnreachable(_))),
        "fetch_output against unreachable server must return ServerUnreachable; got: {result:?}"
    );
}

/// `fetch_output` with a `since` cursor also returns an error when the
/// server is unreachable.
#[tokio::test]
async fn fetch_output_with_since_cursor_returns_error_when_unreachable() {
    let cfg = mock_cfg("http://127.0.0.1:1");
    let client = crate::client::ApiClient::new(&cfg).expect("build client");
    let result = fetch_output(&client, agent_id(0xA001), Some(42)).await;
    assert!(
        matches!(result, Err(crate::error::CliError::ServerUnreachable(_))),
        "fetch_output with cursor must return ServerUnreachable; got: {result:?}"
    );
}

/// `exec_wait` must advance the incremental polling cursor with the
/// numeric output entry id, not a string task id from the payload.
#[tokio::test]
async fn exec_wait_polls_output_with_numeric_entry_cursor() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    #[derive(Clone)]
    struct PollResponder {
        output_queries: Arc<Mutex<Vec<Option<String>>>>,
    }

    impl Respond for PollResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            match (request.method.as_str(), request.url.path()) {
                ("POST", "/api/v1/agents/0000A001/task") => ResponseTemplate::new(202)
                    .set_body_json(serde_json::json!({
                        "agent_id": "AGENT1",
                        "task_id": "submitted_task",
                        "queued_jobs": 1
                    }))
                    .insert_header("content-type", "application/json"),
                ("GET", "/api/v1/agents/0000A001/output") => {
                    let query = request.url.query().map(ToOwned::to_owned);
                    self.output_queries.lock().expect("lock output_queries").push(query.clone());

                    match query.as_deref() {
                        None => ResponseTemplate::new(200)
                            .set_body_json(serde_json::json!({
                                "total": 1,
                                "entries": [{
                                    "id": 42,
                                    "task_id": "other_task",
                                    "command_id": 21,
                                    "request_id": 1,
                                    "response_type": "output",
                                    "message": "",
                                    "output": "unrelated output",
                                    "command_line": "hostname",
                                    "operator": null,
                                    "received_at": "2026-04-01T00:00:00Z"
                                }]
                            }))
                            .insert_header("content-type", "application/json"),
                        Some("since=42") => ResponseTemplate::new(200)
                            .set_body_json(serde_json::json!({
                                "total": 1,
                                "entries": [{
                                    "id": 43,
                                    "task_id": "submitted_task",
                                    "command_id": 21,
                                    "request_id": 2,
                                    "response_type": "output",
                                    "message": "",
                                    "output": "DOMAIN\\\\user",
                                    "command_line": "whoami",
                                    "operator": null,
                                    "received_at": "2026-04-01T00:00:01Z"
                                }]
                            }))
                            .insert_header("content-type", "application/json"),
                        Some(other) => ResponseTemplate::new(400)
                            .set_body_string(format!("unexpected query: {other}")),
                    }
                }
                _ => ResponseTemplate::new(404),
            }
        }
    }

    let server = MockServer::start().await;
    let output_queries = Arc::new(Mutex::new(Vec::new()));

    Mock::given(method("POST"))
        .and(path("/api/v1/agents/0000A001/task"))
        .respond_with(PollResponder { output_queries: Arc::clone(&output_queries) })
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/agents/0000A001/output"))
        .respond_with(PollResponder { output_queries: Arc::clone(&output_queries) })
        .expect(2)
        .mount(&server)
        .await;

    let client = crate::client::ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
    let result =
        exec_wait(&client, agent_id(0xA001), "whoami", 5).await.expect("exec_wait succeeds");

    assert_eq!(result.job_id, "submitted_task");
    assert_eq!(result.output, "DOMAIN\\\\user");

    let queries = output_queries.lock().expect("lock output_queries").clone();
    assert_eq!(queries, vec![None, Some("since=42".to_owned())]);
}

#[test]
fn render_output_stream_line_uses_unknown_marker_without_exit_code() {
    let entry = OutputEntry {
        entry_id: 7,
        job_id: "job_abc".to_owned(),
        command: Some("whoami".to_owned()),
        output: "DOMAIN\\user".to_owned(),
        exit_code: None,
        created_at: "2026-04-01T00:00:00Z".to_owned(),
    };

    assert_eq!(render_output_stream_line(&entry), "[job_abc  exit ?]  DOMAIN\\user");
}

#[test]
fn render_output_stream_line_includes_numeric_exit_code() {
    let entry = OutputEntry {
        entry_id: 8,
        job_id: "job_def".to_owned(),
        command: Some("id".to_owned()),
        output: "uid=1000(user) gid=1000(user)".to_owned(),
        exit_code: Some(0),
        created_at: "2026-04-01T00:00:01Z".to_owned(),
    };

    assert_eq!(
        render_output_stream_line(&entry),
        "[job_def  exit 0]  uid=1000(user) gid=1000(user)"
    );
}

#[test]
fn output_stream_entry_json_mode_emits_shared_ok_true_envelope() {
    let entry = OutputEntry {
        entry_id: 42,
        job_id: "job_xyz".to_owned(),
        command: Some("whoami".to_owned()),
        output: "DOMAIN\\user".to_owned(),
        exit_code: Some(0),
        created_at: "2026-04-01T00:00:02Z".to_owned(),
    };
    let text_line = render_output_stream_line(&entry);
    let mut out = Vec::new();
    let mut err_out = Vec::new();

    crate::output::write_stream_entry(
        &mut out,
        &mut err_out,
        &OutputFormat::Json,
        &entry,
        &text_line,
    )
    .expect("no write error");

    let line = String::from_utf8(out).expect("utf-8");
    let v: serde_json::Value = serde_json::from_str(line.trim()).expect("single JSON line");
    assert_eq!(v["ok"], true, "ok must be true");
    assert_eq!(v["data"]["entry_id"], 42);
    assert_eq!(v["data"]["job_id"], "job_xyz");
    assert_eq!(v["data"]["command"], "whoami");
    assert_eq!(v["data"]["output"], "DOMAIN\\user");
    assert_eq!(v["data"]["exit_code"], 0);
    assert!(err_out.is_empty());

    let obj = v.as_object().expect("root is object");
    let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    assert!(keys.contains(&"ok"), "root must have 'ok'");
    assert!(keys.contains(&"data"), "root must have 'data'");
    assert!(!keys.contains(&"entry_id"), "'entry_id' must not appear at root level");
    assert!(!keys.contains(&"job_id"), "'job_id' must not appear at root level");
}

#[test]
fn output_stream_entry_text_mode_uses_rendered_line_verbatim() {
    let entry = OutputEntry {
        entry_id: 43,
        job_id: "job_abc".to_owned(),
        command: Some("hostname".to_owned()),
        output: "ubuntu-host".to_owned(),
        exit_code: None,
        created_at: "2026-04-01T00:00:03Z".to_owned(),
    };
    let text_line = render_output_stream_line(&entry);
    let mut out = Vec::new();
    let mut err_out = Vec::new();

    crate::output::write_stream_entry(
        &mut out,
        &mut err_out,
        &OutputFormat::Text,
        &entry,
        &text_line,
    )
    .expect("no write error");

    let line = String::from_utf8(out).expect("utf-8");
    assert_eq!(line.trim_end(), text_line);
    assert!(err_out.is_empty());
}

/// `watch_output` exits immediately with a non-zero code because the first
/// call to `fetch_output` fails against an unreachable server.
#[tokio::test]
async fn watch_output_exits_immediately_with_error() {
    let cfg = mock_cfg("http://127.0.0.1:1");
    let client = crate::client::ApiClient::new(&cfg).expect("build client");

    let exit_code =
        watch_output(&client, &crate::output::OutputFormat::Json, agent_id(0xA001), None).await;
    assert_ne!(
        exit_code,
        crate::error::EXIT_SUCCESS,
        "watch_output must exit with non-zero code when server is unreachable"
    );
}

// ── upload size-limit ─────────────────────────────────────────────────────

/// A file that exceeds the limit must be rejected before any bytes are read.
/// We use limit = 0 MB (0 bytes) so even a 2-byte file triggers the guard.
#[tokio::test]
async fn upload_rejects_file_exceeding_size_limit() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().expect("tempfile");
    f.write_all(b"ab").expect("write");
    let path = f.path().to_str().expect("path utf-8").to_owned();

    let cfg = mock_cfg("http://127.0.0.1:1");
    let client = crate::client::ApiClient::new(&cfg).expect("build client");

    let err = upload(&client, agent_id(0xA001), &path, "/dst", 0)
        .await
        .expect_err("should reject oversized file");

    assert!(matches!(err, CliError::InvalidArgs(_)), "expected InvalidArgs, got {err:?}");
    assert!(err.to_string().contains("too large"), "message must mention 'too large': {err}");
    assert!(
        err.to_string().contains("chunked transfer"),
        "message must mention 'chunked transfer': {err}"
    );
}

/// A file within the limit must not be rejected by the size check; the
/// error must come from the HTTP layer (server unreachable), not from us.
#[tokio::test]
async fn upload_accepts_file_at_or_below_size_limit() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut f = NamedTempFile::new().expect("tempfile");
    f.write_all(b"x").expect("write");
    let path = f.path().to_str().expect("path utf-8").to_owned();

    let cfg = mock_cfg("http://127.0.0.1:1");
    let client = crate::client::ApiClient::new(&cfg).expect("build client");

    let err = upload(&client, agent_id(0xA001), &path, "/dst", 1)
        .await
        .expect_err("should fail on HTTP, not size check");

    // The size guard must NOT have fired — only the HTTP layer failed.
    assert!(
        !matches!(err, CliError::InvalidArgs(_)),
        "should not reject file within size limit, got {err:?}"
    );
}

// ── AgentGroupsInfo / RawAgentGroupsResponse ──────────────────────────────

#[test]
fn raw_agent_groups_response_deserialises_server_shape() {
    let json = r#"{"agent_id":"DEADBEEF","groups":["corp","tier1"]}"#;
    let raw: RawAgentGroupsResponse = serde_json::from_str(json).expect("deserialise");
    assert_eq!(raw.agent_id, "DEADBEEF");
    assert_eq!(raw.groups, vec!["corp", "tier1"]);
}

#[test]
fn agent_groups_info_serialises_and_renders_text() {
    let info = AgentGroupsInfo {
        agent_id: "00AABBCC".to_owned(),
        groups: vec!["g1".to_owned(), "g2".to_owned()],
    };
    let v = serde_json::to_value(&info).expect("serialise");
    assert_eq!(v["agent_id"], "00AABBCC");
    assert_eq!(v["groups"], serde_json::json!(["g1", "g2"]));
    let t = info.render_text();
    assert!(t.contains("00AABBCC"));
    assert!(t.contains("g1"));
}

#[test]
fn agent_groups_info_empty_groups_renders_text() {
    let info = AgentGroupsInfo { agent_id: "BADF00D".to_owned(), groups: vec![] };
    assert!(info.render_text().contains("no RBAC groups"));
}
