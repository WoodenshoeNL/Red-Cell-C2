//! Spawn the real `red-cell-cli` binary and assert exit codes plus stdout/stderr behaviour.
//!
//! `CARGO_BIN_EXE_red-cell-cli` is set by Cargo for integration tests.

use std::process::Command;

use serde_json::Value;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn red_cell_cli() -> std::path::PathBuf {
    std::env::var_os("CARGO_BIN_EXE_red-cell-cli")
        .expect("CARGO_BIN_EXE_red-cell-cli must be set by cargo test")
        .into()
}

/// Child environment: avoid picking up operator config from the workspace tree and silence tracing.
fn base_cmd() -> Command {
    let mut c = Command::new(red_cell_cli());
    c.env_remove("RC_SERVER").env_remove("RC_TOKEN").env("RUST_LOG", "off");
    c
}

fn first_json_object(s: &str) -> Value {
    let trimmed = s.trim();
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        return v;
    }
    for line in s.lines() {
        let t = line.trim();
        if t.starts_with('{') {
            if let Ok(v) = serde_json::from_str::<Value>(t) {
                return v;
            }
        }
    }
    panic!("expected JSON object in: {s:?}");
}

#[tokio::test]
async fn status_success_exits_0_json_on_stdout() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"version": "v1"})),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/listeners"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;

    let out = base_cmd()
        .args(["--server", &server.uri(), "--token", "tok", "status"])
        .output()
        .expect("spawn red-cell-cli");

    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v = first_json_object(&stdout);
    assert_eq!(v["ok"], true);
    assert!(v.get("data").is_some());
}

#[tokio::test]
async fn status_invalid_token_exits_3_not_0_or_4() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"version": "v1"})),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let out = base_cmd()
        .args(["--server", &server.uri(), "--token", "bad-token", "status"])
        .output()
        .expect("spawn red-cell-cli");

    assert_eq!(out.status.code(), Some(3), "stderr={}", String::from_utf8_lossy(&out.stderr));
    assert_ne!(out.status.code(), Some(0));
    assert_ne!(out.status.code(), Some(4));

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.trim().is_empty(), "errors must not write JSON to stdout, got: {stdout:?}");

    let err = first_json_object(&String::from_utf8_lossy(&out.stderr));
    assert_eq!(err["ok"], false);
    assert_eq!(err["error"], "AUTH_FAILURE");
}

#[tokio::test]
async fn status_success_output_text_not_json_envelope() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"version": "v1"})),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/listeners"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;

    let out = base_cmd()
        .args(["--server", &server.uri(), "--token", "tok", "--output", "text", "status"])
        .output()
        .expect("spawn red-cell-cli");

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.trim().starts_with("{\"ok\""),
        "text mode must not emit the JSON success envelope on stdout: {stdout:?}"
    );
    assert!(
        stdout.contains("version") || stdout.contains("Version"),
        "expected human-readable status output: {stdout:?}"
    );
}

#[test]
fn missing_required_positional_exits_1() {
    let out = base_cmd().args(["agent", "show"]).output().expect("spawn red-cell-cli");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn help_flag_exits_0() {
    let out = base_cmd().args(["--help"]).output().expect("spawn red-cell-cli");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("red-cell-cli") || stdout.contains("Red Cell"));
}
