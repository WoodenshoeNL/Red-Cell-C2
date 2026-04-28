//! Polling loop for `agent.exec` with `wait=true`.

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request as HttpRequest;
use serde_json::Value;
use tokio::time::Instant;

use super::SESSION_MAX_RESPONSE_BODY;
use super::builders::{
    SessionBuildError, build_session_rest_request, session_build_error_envelope,
};
use super::dispatch::dispatch_one;
use super::session_ws_envelope_response;

/// Default timeout (in seconds) for `agent.exec` with `wait=true`.
const SESSION_EXEC_WAIT_DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Maximum timeout (in seconds) allowed for `agent.exec` with `wait=true`.
const SESSION_EXEC_WAIT_MAX_TIMEOUT_SECS: u64 = 300;

/// Base poll interval for `agent.exec` wait mode.
const SESSION_EXEC_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Handle `agent.exec` with `wait=true`: submit the task, then poll for output
/// until an entry matching the submitted `task_id` appears or the timeout expires.
pub(super) async fn session_exec_wait(
    app: &Router,
    value: &Value,
    client_ip: SocketAddr,
    api_key: &str,
) -> String {
    let cmd = "agent.exec";

    // Build and dispatch the task submission request.
    let submit_req = match build_session_rest_request(cmd, value) {
        Ok(r) => r,
        Err(e) => return session_build_error_envelope(cmd, &e),
    };

    let submit_resp = match dispatch_one(app, submit_req, cmd, api_key, client_ip).await {
        Ok(r) => r,
        Err(envelope) => return envelope,
    };

    if !submit_resp.status().is_success() {
        return session_ws_envelope_response(cmd, submit_resp).await;
    }

    // Parse the submission response to extract task_id and agent_id.
    let submit_bytes = match to_bytes(submit_resp.into_body(), SESSION_MAX_RESPONSE_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return serde_json::json!({
                "ok": false,
                "cmd": cmd,
                "error": "RESPONSE_TOO_LARGE",
                "message": "task submission response too large"
            })
            .to_string();
        }
    };
    let submit_data: Value = match serde_json::from_slice(submit_bytes.as_ref()) {
        Ok(v) => v,
        Err(_) => {
            return serde_json::json!({
                "ok": false,
                "cmd": cmd,
                "error": "INVALID_SUBMIT_RESPONSE",
                "message": "could not parse task submission response"
            })
            .to_string();
        }
    };

    let task_id = submit_data["task_id"].as_str().unwrap_or_default().to_owned();
    let want_request_id = u32::from_str_radix(task_id.as_str(), 16).ok();
    let agent_id = match value.get("id").and_then(|v| v.as_str()) {
        Some(id) => id.to_owned(),
        None => {
            return session_build_error_envelope(cmd, &SessionBuildError::missing(cmd, "id"));
        }
    };

    // Determine timeout from `timeout` field (seconds), clamped to max.
    let timeout_secs = value
        .get("timeout")
        .and_then(|v| v.as_u64())
        .unwrap_or(SESSION_EXEC_WAIT_DEFAULT_TIMEOUT_SECS)
        .min(SESSION_EXEC_WAIT_MAX_TIMEOUT_SECS);
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);

    let mut cursor: Option<i64> = None;
    let mut boundary_established = false;

    loop {
        if Instant::now() >= deadline {
            return serde_json::json!({
                "ok": false,
                "cmd": cmd,
                "error": "EXEC_TIMEOUT",
                "message": format!(
                    "timed out waiting for output from task `{task_id}` after {timeout_secs}s"
                ),
                "data": {
                    "task_id": task_id,
                    "agent_id": agent_id,
                }
            })
            .to_string();
        }

        tokio::time::sleep(SESSION_EXEC_WAIT_POLL_INTERVAL).await;

        // Build the output poll request.
        let uri = match cursor {
            Some(since) => format!("/agents/{agent_id}/output?since={since}"),
            None => format!("/agents/{agent_id}/output"),
        };
        let poll_req = match HttpRequest::builder().method("GET").uri(&uri).body(Body::empty()) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let poll_resp = match dispatch_one(app, poll_req, cmd, api_key, client_ip).await {
            Ok(r) => r,
            Err(_) => continue,
        };

        if !poll_resp.status().is_success() {
            // Transient failure — retry on next poll.
            continue;
        }

        let poll_bytes = match to_bytes(poll_resp.into_body(), SESSION_MAX_RESPONSE_BODY).await {
            Ok(b) => b,
            Err(_) => continue,
        };
        let poll_data: Value = match serde_json::from_slice(poll_bytes.as_ref()) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(entries) = poll_data["entries"].as_array() {
            for entry in entries {
                if let Some(id) = entry["id"].as_i64() {
                    cursor = Some(id);
                }
                let matches_task_id =
                    !task_id.is_empty() && entry["task_id"].as_str() == Some(task_id.as_str());
                // Only fall back to request_id after a cursor boundary is
                // established, so historical rows from older tasks that happen
                // to share the same request_id are not treated as matches.
                let matches_request_id = boundary_established
                    && want_request_id
                        .is_some_and(|rid| entry["request_id"].as_u64() == Some(u64::from(rid)));
                if matches_task_id || matches_request_id {
                    return serde_json::json!({
                        "ok": true,
                        "cmd": cmd,
                        "data": {
                            "task_id": task_id,
                            "agent_id": agent_id,
                            "output": entry["output"],
                            "exit_code": entry["exit_code"],
                        }
                    })
                    .to_string();
                }
            }
            boundary_established = true;
        }
    }
}
