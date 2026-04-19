//! Session WebSocket dispatch — maps session NDJSON commands to internal REST requests.

pub(super) mod builders;
pub(super) mod dispatch;
pub(super) mod exec_wait;

use axum::body::to_bytes;
use axum::http::header::CONTENT_TYPE;
use serde_json::Value;

pub(crate) use dispatch::session_api_dispatch_line;

/// Maximum response body size (in bytes) that session WebSocket dispatch will buffer.
///
/// Responses exceeding this limit are rejected with a `RESPONSE_TOO_LARGE` error
/// instead of being buffered into memory. 50 MiB is generous for normal API
/// responses while preventing unbounded allocation from large binary downloads.
pub(crate) const SESSION_MAX_RESPONSE_BODY: usize = 50 * 1024 * 1024;

pub(crate) async fn session_ws_envelope_response(
    cmd: &str,
    response: axum::response::Response,
) -> String {
    use base64::Engine as _;

    let status = response.status();
    let headers = response.headers().clone();
    let ct = headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let bytes = match to_bytes(response.into_body(), SESSION_MAX_RESPONSE_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return serde_json::json!({
                "ok": false,
                "cmd": cmd,
                "error": "RESPONSE_TOO_LARGE",
                "message": format!(
                    "response body exceeds session limit of {} bytes — use the REST API directly for large downloads",
                    SESSION_MAX_RESPONSE_BODY,
                ),
            })
            .to_string();
        }
    };

    if status.is_success() {
        let data: Value = if bytes.is_empty() {
            Value::Null
        } else if ct.contains("octet-stream") {
            serde_json::json!({
                "encoding": "base64",
                "data": base64::engine::general_purpose::STANDARD.encode(bytes.as_ref()),
            })
        } else {
            serde_json::from_slice(bytes.as_ref()).unwrap_or_else(|_| {
                Value::String(String::from_utf8_lossy(bytes.as_ref()).into_owned())
            })
        };
        serde_json::json!({ "ok": true, "cmd": cmd, "data": data }).to_string()
    } else {
        let parsed: Value = serde_json::from_slice(bytes.as_ref()).unwrap_or(Value::Null);
        let code = parsed["error"]["code"]
            .as_str()
            .unwrap_or("HTTP_ERROR")
            .to_ascii_uppercase()
            .replace('.', "_");
        let message = parsed["error"]["message"].as_str().unwrap_or("request failed").to_owned();
        serde_json::json!({
            "ok": false,
            "cmd": cmd,
            "error": code,
            "message": message,
        })
        .to_string()
    }
}
