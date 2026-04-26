//! `red-cell-cli payload` subcommands.
//!
//! # Subcommands
//!
//! | Command | API call | Notes |
//! |---|---|---|
//! | `payload list` | `GET /payloads` | table of all built payloads |
//! | `payload build` | `POST /payloads/build` | submit build job; `--wait` polls until done |
//! | `payload download <id>` | `GET /payloads/{id}/download` | saves raw bytes to disk |
//! | `payload cache-flush` | `POST /payload-cache` | flush all cached build artifacts (admin) |

mod build;
mod download;
pub mod inspect;
mod types;

pub use inspect::inspect_local;

use crate::PayloadCommands;
use crate::client::ApiClient;
use crate::defaults::PAYLOAD_BUILD_WAIT_TIMEOUT_SECS;
use crate::error::EXIT_SUCCESS;
use crate::output::{OutputFormat, print_error, print_success};

use build::BuildOutcome;

// ── top-level dispatcher ──────────────────────────────────────────────────────

/// Dispatch a [`PayloadCommands`] variant and return a process exit code.
pub async fn run(client: &ApiClient, fmt: &OutputFormat, action: PayloadCommands) -> i32 {
    match action {
        PayloadCommands::List => match build::list(client).await {
            Ok(data) => match print_success(fmt, &data) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },

        PayloadCommands::Build {
            listener,
            arch,
            format,
            agent,
            sleep: sleep_secs,
            wait,
            wait_timeout,
            detach,
        } => {
            let effective_wait = wait && !detach;
            let build_timeout_secs = wait_timeout.unwrap_or(PAYLOAD_BUILD_WAIT_TIMEOUT_SECS);
            match build::build(
                client,
                &listener,
                &arch,
                &format,
                &agent,
                sleep_secs,
                effective_wait,
                build_timeout_secs,
            )
            .await
            {
                Ok(outcome) => match outcome {
                    BuildOutcome::Submitted(job) => match print_success(fmt, &job) {
                        Ok(()) => EXIT_SUCCESS,
                        Err(e) => {
                            print_error(&e).ok();
                            e.exit_code()
                        }
                    },
                    BuildOutcome::Completed(done) => match print_success(fmt, &done) {
                        Ok(()) => EXIT_SUCCESS,
                        Err(e) => {
                            print_error(&e).ok();
                            e.exit_code()
                        }
                    },
                },
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }

        PayloadCommands::BuildStatus { job_id } => {
            match build::build_status(client, &job_id).await {
                Ok(result) => match print_success(fmt, &result) {
                    Ok(()) => EXIT_SUCCESS,
                    Err(e) => {
                        print_error(&e).ok();
                        e.exit_code()
                    }
                },
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }

        PayloadCommands::BuildWait { job_id, output, wait_timeout } => {
            let timeout_secs = wait_timeout.unwrap_or(PAYLOAD_BUILD_WAIT_TIMEOUT_SECS);
            match build::build_wait(client, &job_id, output.as_deref(), timeout_secs).await {
                Ok(result) => match print_success(fmt, &result) {
                    Ok(()) => EXIT_SUCCESS,
                    Err(e) => {
                        print_error(&e).ok();
                        e.exit_code()
                    }
                },
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }

        PayloadCommands::Download { id, dst } => {
            match download::download(client, &id, &dst).await {
                Ok(result) => match print_success(fmt, &result) {
                    Ok(()) => EXIT_SUCCESS,
                    Err(e) => {
                        print_error(&e).ok();
                        e.exit_code()
                    }
                },
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            }
        }

        PayloadCommands::CacheFlush => match build::cache_flush(client).await {
            Ok(result) => match print_success(fmt, &result) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                print_error(&e).ok();
                e.exit_code()
            }
        },

        // Handled before config resolution in dispatch.rs; this arm exists
        // only for exhaustiveness.
        PayloadCommands::Inspect { .. } => EXIT_SUCCESS,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::build::validate_format;
    use super::inspect::InspectResult;
    use super::types::{
        BuildCompleted, BuildJobSubmitted, BuildJobStatusResult, BuildWaitCompleted,
        CacheFlushResult, DownloadResult, PayloadRow,
    };
    use crate::defaults::PAYLOAD_BUILD_WAIT_TIMEOUT_SECS;
    use crate::error::CliError;
    use crate::output::{OutputFormat, TextRender, TextRow};

    // ── PayloadRow ────────────────────────────────────────────────────────────

    #[test]
    fn payload_row_headers_match_row_length() {
        let row = PayloadRow {
            id: "abc123".to_owned(),
            name: "demon_x64.exe".to_owned(),
            arch: "x86_64".to_owned(),
            format: "exe".to_owned(),
            built_at: "2026-03-21T00:00:00Z".to_owned(),
        };
        assert_eq!(PayloadRow::headers().len(), row.row().len());
    }

    #[test]
    fn payload_row_serialises_all_fields() {
        let row = PayloadRow {
            id: "xyz".to_owned(),
            name: "demon.bin".to_owned(),
            arch: "aarch64".to_owned(),
            format: "bin".to_owned(),
            built_at: "2026-03-21T12:00:00Z".to_owned(),
        };
        let v = serde_json::to_value(&row).expect("serialise");
        assert_eq!(v["id"], "xyz");
        assert_eq!(v["arch"], "aarch64");
        assert_eq!(v["format"], "bin");
    }

    #[test]
    fn vec_payload_row_renders_table_with_data() {
        let rows = vec![PayloadRow {
            id: "abc".to_owned(),
            name: "demon.exe".to_owned(),
            arch: "x86_64".to_owned(),
            format: "exe".to_owned(),
            built_at: "2026-03-21T00:00:00Z".to_owned(),
        }];
        let rendered = rows.render_text();
        assert!(rendered.contains("abc"));
        assert!(rendered.contains("x86_64"));
        assert!(rendered.contains("exe"));
    }

    #[test]
    fn vec_payload_row_empty_renders_none() {
        let rows: Vec<PayloadRow> = vec![];
        assert_eq!(rows.render_text(), "(none)");
    }

    // ── BuildJobSubmitted ─────────────────────────────────────────────────────

    #[test]
    fn build_job_submitted_render_contains_job_id() {
        let r = BuildJobSubmitted { job_id: "job-001".to_owned() };
        assert!(r.render_text().contains("job-001"));
    }

    #[test]
    fn build_job_submitted_serialises_job_id() {
        let r = BuildJobSubmitted { job_id: "j1".to_owned() };
        let v = serde_json::to_value(&r).expect("serialise");
        assert_eq!(v["job_id"], "j1");
    }

    // ── BuildCompleted ────────────────────────────────────────────────────────

    #[test]
    fn build_completed_render_contains_id_and_size() {
        let r = BuildCompleted { id: "p1".to_owned(), size_bytes: 12345 };
        let rendered = r.render_text();
        assert!(rendered.contains("p1"));
        assert!(rendered.contains("12345"));
    }

    #[test]
    fn build_completed_serialises_id_and_size() {
        let r = BuildCompleted { id: "p1".to_owned(), size_bytes: 99 };
        let v = serde_json::to_value(&r).expect("serialise");
        assert_eq!(v["id"], "p1");
        assert_eq!(v["size_bytes"], 99);
    }

    // ── DownloadResult ────────────────────────────────────────────────────────

    #[test]
    fn download_result_render_contains_all_fields() {
        let r =
            DownloadResult { id: "p2".to_owned(), dst: "./out.exe".to_owned(), size_bytes: 65536 };
        let rendered = r.render_text();
        assert!(rendered.contains("p2"));
        assert!(rendered.contains("./out.exe"));
        assert!(rendered.contains("65536"));
    }

    #[test]
    fn download_result_serialises_correctly() {
        let r = DownloadResult { id: "p3".to_owned(), dst: "/tmp/x.bin".to_owned(), size_bytes: 1 };
        let v = serde_json::to_value(&r).expect("serialise");
        assert_eq!(v["id"], "p3");
        assert_eq!(v["dst"], "/tmp/x.bin");
        assert_eq!(v["size_bytes"], 1);
    }

    // ── payload_row_from_raw ──────────────────────────────────────────────────

    #[test]
    fn payload_row_from_raw_maps_all_fields() {
        let raw = types::RawPayloadSummary {
            id: "id1".to_owned(),
            name: "n".to_owned(),
            arch: "x86_64".to_owned(),
            format: "dll".to_owned(),
            built_at: "2026-01-01T00:00:00Z".to_owned(),
        };
        let row = types::payload_row_from_raw(raw);
        assert_eq!(row.id, "id1");
        assert_eq!(row.format, "dll");
        assert_eq!(row.arch, "x86_64");
    }

    // ── build sends agent field ──────────────────────────────────────────────

    #[tokio::test]
    async fn build_sends_agent_field_in_request_body() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/payloads/build"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "job_id": "test-job-1"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let result = build::build(
            &client,
            "http1",
            "x64",
            "exe",
            "phantom",
            None,
            false,
            PAYLOAD_BUILD_WAIT_TIMEOUT_SECS,
        )
        .await;
        assert!(result.is_ok(), "build must succeed: {result:?}");

        // Verify the request body contained the agent field.
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("parse body");
        assert_eq!(body["agent"], "phantom", "request body must include agent field");
        assert_eq!(body["listener"], "http1");
        assert_eq!(body["arch"], "x64");
        assert_eq!(body["format"], "exe");
    }

    #[tokio::test]
    async fn build_sends_default_demon_agent() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/payloads/build"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "job_id": "test-job-2"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let _ = build::build(
            &client,
            "http1",
            "x64",
            "exe",
            "demon",
            None,
            false,
            PAYLOAD_BUILD_WAIT_TIMEOUT_SECS,
        )
        .await;

        let requests = server.received_requests().await.expect("requests");
        let body: serde_json::Value =
            serde_json::from_slice(&requests[0].body).expect("parse body");
        assert_eq!(body["agent"], "demon", "default agent must be 'demon'");
    }

    // ── format validation ─────────────────────────────────────────────────────

    #[test]
    fn validate_format_rejects_unknown_format() {
        assert!(matches!(validate_format("elf"), Err(CliError::InvalidArgs(_))));
        assert!(matches!(validate_format("shellcode"), Err(CliError::InvalidArgs(_))));
        assert!(matches!(validate_format(""), Err(CliError::InvalidArgs(_))));
    }

    #[test]
    fn validate_format_accepts_valid_formats() {
        for fmt in ["exe", "dll", "bin"] {
            assert!(validate_format(fmt).is_ok(), "format '{fmt}' should be accepted");
        }
    }

    // ── download writes file to disk ──────────────────────────────────────────

    #[tokio::test]
    async fn download_writes_bytes_to_path() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let payload_bytes = b"HELLO WORLD PAYLOAD";
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/test-id/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(payload_bytes.as_ref()))
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let tmp = tempfile::tempdir().expect("tempdir");
        let dst = tmp.path().join("payload.bin");
        let dst_str = dst.to_str().expect("valid path");

        let result = download::download(&client, "test-id", dst_str).await.expect("download");

        assert_eq!(result.id, "test-id");
        assert_eq!(result.dst, dst_str);
        assert_eq!(result.size_bytes, payload_bytes.len() as u64);
        assert_eq!(std::fs::read(&dst).expect("read file"), payload_bytes);
    }

    #[tokio::test]
    async fn download_creates_parent_directory() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/nested-id/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"DATA".as_ref()))
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("a").join("b").join("payload.exe");
        let dst_str = nested.to_str().expect("valid path");

        let result = download::download(&client, "nested-id", dst_str).await.expect("download");

        assert!(nested.exists(), "download must create parent directories");
        assert_eq!(result.size_bytes, 4);
    }

    // ── CacheFlushResult ──────────────────────────────────────────────────────

    #[test]
    fn cache_flush_result_render_contains_count() {
        let r = CacheFlushResult { flushed: 7 };
        let text = r.render_text();
        assert!(text.contains("7"), "render must include flushed count");
        assert!(text.to_lowercase().contains("flush"), "render must mention flush");
    }

    #[test]
    fn cache_flush_result_render_zero() {
        let r = CacheFlushResult { flushed: 0 };
        let text = r.render_text();
        assert!(text.contains("0"));
    }

    #[test]
    fn cache_flush_result_serialises_flushed_field() {
        let r = CacheFlushResult { flushed: 42 };
        let v = serde_json::to_value(&r).expect("serialise");
        assert_eq!(v["flushed"], 42);
    }

    // ── cache_flush HTTP call ─────────────────────────────────────────────────

    #[tokio::test]
    async fn cache_flush_calls_post_payload_cache_and_returns_count() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/payload-cache"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "flushed": 3 })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let result = build::cache_flush(&client).await.expect("cache_flush must succeed");
        assert_eq!(result.flushed, 3);
    }

    #[tokio::test]
    async fn cache_flush_returns_auth_failure_on_403() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/payload-cache"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "non-admin-token".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let err = build::cache_flush(&client).await.expect_err("must fail with 403");
        assert!(matches!(err, CliError::AuthFailure(_)), "expected AuthFailure, got {err:?}");
    }

    // ── inspect_local ────────────────────────────────────────────────────────

    #[test]
    fn inspect_local_returns_success_for_valid_manifest() {
        use red_cell_common::payload_manifest::{PayloadManifest, encode_manifest};

        let manifest = PayloadManifest {
            agent_type: "Demon".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            hosts: vec!["192.168.1.100".to_owned()],
            port: Some(443),
            secure: true,
            callback_url: Some("https://192.168.1.100:443/".to_owned()),
            sleep_ms: Some(5000),
            jitter: Some(20),
            init_secret_hash: Some("abc123def4567890".to_owned()),
            kill_date: None,
            working_hours_mask: None,
            listener_name: "http1".to_owned(),
            export_name: None,
            built_at: "2026-04-25T12:00:00Z".to_owned(),
        };

        let mut payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        payload.extend_from_slice(&[0u8; 100]);
        payload.extend_from_slice(&encode_manifest(&manifest).expect("encode"));

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.exe");
        std::fs::write(&path, &payload).expect("write");

        let code = inspect_local(path.to_str().expect("path"), &OutputFormat::Json);
        assert_eq!(code, EXIT_SUCCESS);
    }

    #[test]
    fn inspect_local_returns_error_for_missing_file() {
        let code = inspect_local("/nonexistent/file.exe", &OutputFormat::Json);
        assert_ne!(code, EXIT_SUCCESS);
    }

    #[test]
    fn inspect_local_returns_error_for_no_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bare.bin");
        std::fs::write(&path, b"no manifest here").expect("write");

        let code = inspect_local(path.to_str().expect("path"), &OutputFormat::Json);
        assert_ne!(code, EXIT_SUCCESS);
    }

    #[test]
    fn inspect_result_text_render_includes_key_fields() {
        let result = InspectResult {
            agent_type: "Phantom".to_owned(),
            arch: "x64".to_owned(),
            format: "elf".to_owned(),
            callback_url: Some("https://10.0.0.1:8443/".to_owned()),
            hosts: vec!["10.0.0.1".to_owned()],
            port: Some(8443),
            secure: true,
            sleep_ms: Some(10000),
            jitter: Some(50),
            init_secret_hash: Some("0123456789abcdef".to_owned()),
            kill_date: Some("2027-01-01T00:00:00Z".to_owned()),
            working_hours_mask: Some(0x00FF_FF00),
            listener_name: "https-main".to_owned(),
            export_name: None,
            built_at: "2026-04-25T12:00:00Z".to_owned(),
        };

        let text = result.render_text();
        assert!(text.contains("Phantom"), "agent_type");
        assert!(text.contains("https://10.0.0.1:8443/"), "callback_url");
        assert!(text.contains("10000 ms"), "sleep");
        assert!(text.contains("50%"), "jitter");
        assert!(text.contains("0123456789abcdef"), "init_secret_hash");
        assert!(text.contains("2027-01-01"), "kill_date");
        assert!(text.contains("0x00FFFF00"), "working_hours_mask");
    }

    #[test]
    fn inspect_result_serialises_to_json() {
        let result = InspectResult {
            agent_type: "Demon".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            callback_url: None,
            hosts: vec!["c2.example.com".to_owned()],
            port: Some(443),
            secure: true,
            sleep_ms: None,
            jitter: None,
            init_secret_hash: None,
            kill_date: None,
            working_hours_mask: None,
            listener_name: "http1".to_owned(),
            export_name: None,
            built_at: "2026-04-25T00:00:00Z".to_owned(),
        };
        let json = serde_json::to_value(&result).expect("serialize");
        assert_eq!(json["agent_type"], "Demon");
        assert_eq!(json["hosts"][0], "c2.example.com");
        assert!(json["callback_url"].is_null());
    }

    // ── BuildJobStatusResult ─────────────────────────────────────────────────

    #[test]
    fn build_job_status_result_render_contains_job_id_and_status() {
        let r = BuildJobStatusResult {
            job_id: "job-42".to_owned(),
            status: "running".to_owned(),
            agent_type: Some("Demon".to_owned()),
            payload_id: None,
            size_bytes: None,
            error: None,
        };
        let text = r.render_text();
        assert!(text.contains("job-42"));
        assert!(text.contains("running"));
        assert!(text.contains("Demon"));
    }

    #[test]
    fn build_job_status_result_render_done_includes_payload_id() {
        let r = BuildJobStatusResult {
            job_id: "job-99".to_owned(),
            status: "done".to_owned(),
            agent_type: None,
            payload_id: Some("pay-123".to_owned()),
            size_bytes: Some(65536),
            error: None,
        };
        let text = r.render_text();
        assert!(text.contains("pay-123"));
        assert!(text.contains("65536"));
    }

    #[test]
    fn build_job_status_result_render_error_includes_message() {
        let r = BuildJobStatusResult {
            job_id: "job-err".to_owned(),
            status: "error".to_owned(),
            agent_type: None,
            payload_id: None,
            size_bytes: None,
            error: Some("linker failed".to_owned()),
        };
        let text = r.render_text();
        assert!(text.contains("linker failed"));
    }

    #[test]
    fn build_job_status_result_serialises_all_fields() {
        let r = BuildJobStatusResult {
            job_id: "j1".to_owned(),
            status: "done".to_owned(),
            agent_type: Some("Phantom".to_owned()),
            payload_id: Some("p1".to_owned()),
            size_bytes: Some(100),
            error: None,
        };
        let v = serde_json::to_value(&r).expect("serialise");
        assert_eq!(v["job_id"], "j1");
        assert_eq!(v["status"], "done");
        assert_eq!(v["agent_type"], "Phantom");
        assert_eq!(v["payload_id"], "p1");
        assert_eq!(v["size_bytes"], 100);
        assert!(v["error"].is_null());
    }

    // ── BuildWaitCompleted ───────────────────────────────────────────────────

    #[test]
    fn build_wait_completed_render_without_output() {
        let r =
            BuildWaitCompleted { payload_id: "pay-1".to_owned(), size_bytes: 2048, output: None };
        let text = r.render_text();
        assert!(text.contains("pay-1"));
        assert!(text.contains("2048"));
        assert!(!text.contains("→"));
    }

    #[test]
    fn build_wait_completed_render_with_output() {
        let r = BuildWaitCompleted {
            payload_id: "pay-2".to_owned(),
            size_bytes: 4096,
            output: Some("./out.exe".to_owned()),
        };
        let text = r.render_text();
        assert!(text.contains("pay-2"));
        assert!(text.contains("./out.exe"));
        assert!(text.contains("→"));
    }

    #[test]
    fn build_wait_completed_serialises_all_fields() {
        let r = BuildWaitCompleted {
            payload_id: "p99".to_owned(),
            size_bytes: 512,
            output: Some("/tmp/a.bin".to_owned()),
        };
        let v = serde_json::to_value(&r).expect("serialise");
        assert_eq!(v["payload_id"], "p99");
        assert_eq!(v["size_bytes"], 512);
        assert_eq!(v["output"], "/tmp/a.bin");
    }

    #[test]
    fn build_wait_completed_serialises_null_output() {
        let r = BuildWaitCompleted { payload_id: "p100".to_owned(), size_bytes: 1, output: None };
        let v = serde_json::to_value(&r).expect("serialise");
        assert!(v["output"].is_null());
    }

    // ── build_status HTTP call ───────────────────────────────────────────────

    #[tokio::test]
    async fn build_status_returns_pending_job() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/jobs/job-s1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "job_id": "job-s1",
                "status": "pending",
                "agent_type": "Demon"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let result = build::build_status(&client, "job-s1").await.expect("build_status");
        assert_eq!(result.job_id, "job-s1");
        assert_eq!(result.status, "pending");
        assert_eq!(result.agent_type.as_deref(), Some("Demon"));
        assert!(result.payload_id.is_none());
    }

    #[tokio::test]
    async fn build_status_returns_done_job() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/jobs/job-s2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "job_id": "job-s2",
                "status": "done",
                "agent_type": "Phantom",
                "payload_id": "pay-done",
                "size_bytes": 99999
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let result = build::build_status(&client, "job-s2").await.expect("build_status");
        assert_eq!(result.status, "done");
        assert_eq!(result.payload_id.as_deref(), Some("pay-done"));
        assert_eq!(result.size_bytes, Some(99999));
    }

    #[tokio::test]
    async fn build_status_returns_not_found() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/jobs/no-such-job"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let err =
            build::build_status(&client, "no-such-job").await.expect_err("must fail with 404");
        assert!(matches!(err, CliError::NotFound(_)), "expected NotFound, got {err:?}");
    }

    // ── build_wait HTTP call ─────────────────────────────────────────────────

    #[tokio::test]
    async fn build_wait_polls_until_done() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        let call_count = Arc::new(AtomicU32::new(0));
        let counter = call_count.clone();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/jobs/job-w1"))
            .respond_with(move |_req: &Request| {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "job_id": "job-w1",
                        "status": "running",
                        "agent_type": "Demon"
                    }))
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "job_id": "job-w1",
                        "status": "done",
                        "agent_type": "Demon",
                        "payload_id": "pay-w1",
                        "size_bytes": 8192
                    }))
                }
            })
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let result = build::build_wait(&client, "job-w1", None, 30).await.expect("build_wait");
        assert_eq!(result.payload_id, "pay-w1");
        assert_eq!(result.size_bytes, 8192);
        assert!(result.output.is_none());
        assert!(call_count.load(Ordering::SeqCst) >= 3, "must have polled at least 3 times");
    }

    #[tokio::test]
    async fn build_wait_returns_error_on_build_failure() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/jobs/job-fail"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "job_id": "job-fail",
                "status": "error",
                "agent_type": "Demon",
                "error": "compilation failed"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let err = build::build_wait(&client, "job-fail", None, 30)
            .await
            .expect_err("must fail on build error");
        let msg = format!("{err}");
        assert!(msg.contains("compilation failed"), "error must include message: {msg}");
    }

    #[tokio::test]
    async fn build_wait_downloads_on_output() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        let call_count = Arc::new(AtomicU32::new(0));
        let counter = call_count.clone();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/jobs/job-dl"))
            .respond_with(move |_req: &Request| {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "job_id": "job-dl",
                        "status": "pending",
                        "agent_type": "Demon"
                    }))
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "job_id": "job-dl",
                        "status": "done",
                        "agent_type": "Demon",
                        "payload_id": "pay-dl",
                        "size_bytes": 5
                    }))
                }
            })
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/payloads/pay-dl/download"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ABCDE".as_ref()))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let tmp = tempfile::tempdir().expect("tempdir");
        let dst = tmp.path().join("out.bin");
        let dst_str = dst.to_str().expect("valid path");

        let result =
            build::build_wait(&client, "job-dl", Some(dst_str), 30).await.expect("build_wait");
        assert_eq!(result.payload_id, "pay-dl");
        assert_eq!(result.output.as_deref(), Some(dst_str));
        assert_eq!(std::fs::read(&dst).expect("read file"), b"ABCDE");
    }
}
