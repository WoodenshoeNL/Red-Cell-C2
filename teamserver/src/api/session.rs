//! Session WebSocket dispatch — maps session NDJSON commands to internal REST requests.

use std::net::SocketAddr;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::HeaderValue;
use axum::http::Request as HttpRequest;
use axum::http::header::CONTENT_TYPE;
use red_cell_common::ListenerConfig;
use serde_json::Value;
use tower::ServiceExt as _;

use super::auth::API_KEY_HEADER;

/// Errors while mapping a session `cmd` to an internal REST request.
#[derive(Debug, thiserror::Error)]
enum SessionBuildError {
    #[error("unknown session command `{0}`")]
    UnknownCommand(String),
    #[error("missing field `{field}` for command `{cmd}`")]
    MissingField { cmd: String, field: String },
    #[error("invalid session request: {0}")]
    InvalidBody(String),
}

impl SessionBuildError {
    fn missing(cmd: &str, field: &str) -> Self {
        Self::MissingField { cmd: cmd.to_owned(), field: field.to_owned() }
    }
}

/// Build `application/x-www-form-urlencoded` query string from a JSON object,
/// skipping meta keys (`cmd`, `wait`, `timeout`) and null values.
fn session_query_string_from_value(val: &Value) -> Result<String, SessionBuildError> {
    use std::collections::BTreeMap as SortedMap;
    let obj = val
        .as_object()
        .ok_or_else(|| SessionBuildError::InvalidBody("expected JSON object".to_owned()))?;
    let mut map = SortedMap::<String, String>::new();
    for (k, v) in obj {
        if matches!(k.as_str(), "cmd" | "wait" | "timeout") {
            continue;
        }
        match v {
            Value::String(s) => {
                map.insert(k.clone(), s.clone());
            }
            Value::Number(n) => {
                map.insert(k.clone(), n.to_string());
            }
            Value::Bool(b) => {
                map.insert(k.clone(), b.to_string());
            }
            Value::Null => {}
            _ => {}
        }
    }
    if map.is_empty() {
        Ok(String::new())
    } else {
        serde_urlencoded::to_string(&map).map_err(|e| SessionBuildError::InvalidBody(e.to_string()))
    }
}

fn session_strip_meta_object(val: &Value) -> Result<Value, SessionBuildError> {
    let mut v = val.clone();
    let Some(obj) = v.as_object_mut() else {
        return Err(SessionBuildError::InvalidBody("expected JSON object".to_owned()));
    };
    obj.remove("cmd");
    obj.remove("wait");
    obj.remove("timeout");
    Ok(Value::Object(std::mem::take(obj)))
}

fn build_session_rest_request(
    cmd: &str,
    val: &Value,
) -> Result<HttpRequest<Body>, SessionBuildError> {
    let build = |method: &str, uri: &str, body: Body| {
        HttpRequest::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))
    };

    match cmd {
        "status" => {
            let req = HttpRequest::builder()
                .method("GET")
                .uri("/")
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?;
            Ok(req)
        }
        "agent.list" => Ok(HttpRequest::builder()
            .method("GET")
            .uri("/agents")
            .body(Body::empty())
            .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?),
        "agent.show" => {
            let id = val
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "id"))?;
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(format!("/agents/{id}"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "agent.exec" => {
            let id = val
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "id"))?;
            let command_line = val
                .get("command")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "command"))?;
            let command_id = val.get("command_id").and_then(|v| v.as_str()).unwrap_or("21");
            let body = serde_json::json!({
                "CommandLine": command_line,
                "CommandID": command_id,
                "DemonID": id,
                "TaskID": "",
            });
            let bytes = serde_json::to_vec(&body)
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?;
            build("POST", &format!("/agents/{id}/task"), Body::from(bytes))
        }
        "agent.output" => {
            let id = val
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "id"))?;
            let since = val.get("since").and_then(|v| v.as_i64());
            let uri = match since {
                Some(s) => format!("/agents/{id}/output?since={s}"),
                None => format!("/agents/{id}/output"),
            };
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "agent.kill" => {
            let id = val
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "id"))?;
            Ok(HttpRequest::builder()
                .method("DELETE")
                .uri(format!("/agents/{id}"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "agent.upload" => {
            let id = val
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "id"))?;
            let body_val = session_strip_meta_object(val)?;
            let bytes = serde_json::to_vec(&body_val)
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?;
            build("POST", &format!("/agents/{id}/upload"), Body::from(bytes))
        }
        "agent.download" => {
            let id = val
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "id"))?;
            let body_val = session_strip_meta_object(val)?;
            let bytes = serde_json::to_vec(&body_val)
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?;
            build("POST", &format!("/agents/{id}/download"), Body::from(bytes))
        }
        "listener.list" => Ok(HttpRequest::builder()
            .method("GET")
            .uri("/listeners")
            .body(Body::empty())
            .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?),
        "listener.show" => {
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "name"))?;
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(format!("/listeners/{name}"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "listener.create" => {
            let body_val = session_strip_meta_object(val)?;
            let cfg: ListenerConfig = serde_json::from_value(body_val)
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?;
            let bytes = serde_json::to_vec(&cfg)
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?;
            build("POST", "/listeners", Body::from(bytes))
        }
        "listener.update" => {
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "name"))?;
            let mut body_val = session_strip_meta_object(val)?;
            if let Some(obj) = body_val.as_object_mut() {
                obj.remove("name");
            }
            let cfg: ListenerConfig = serde_json::from_value(body_val)
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?;
            let bytes = serde_json::to_vec(&cfg)
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?;
            build("PUT", &format!("/listeners/{name}"), Body::from(bytes))
        }
        "listener.start" => {
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "name"))?;
            Ok(HttpRequest::builder()
                .method("PUT")
                .uri(format!("/listeners/{name}/start"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "listener.stop" => {
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "name"))?;
            Ok(HttpRequest::builder()
                .method("PUT")
                .uri(format!("/listeners/{name}/stop"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "listener.delete" => {
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "name"))?;
            Ok(HttpRequest::builder()
                .method("DELETE")
                .uri(format!("/listeners/{name}"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "listener.mark" => {
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "name"))?;
            let mark = val
                .get("mark")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "mark"))?;
            let body = serde_json::to_vec(&crate::listeners::ListenerMarkRequest {
                mark: mark.to_owned(),
            })
            .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?;
            build("POST", &format!("/listeners/{name}/mark"), Body::from(body))
        }
        "operator.list" => Ok(HttpRequest::builder()
            .method("GET")
            .uri("/operators")
            .body(Body::empty())
            .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?),
        "operator.create" => {
            let body_val = session_strip_meta_object(val)?;
            let bytes = serde_json::to_vec(&body_val)
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?;
            build("POST", "/operators", Body::from(bytes))
        }
        "operator.delete" => {
            let username = val
                .get("username")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "username"))?;
            Ok(HttpRequest::builder()
                .method("DELETE")
                .uri(format!("/operators/{username}"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "operator.set_role" => {
            let username = val
                .get("username")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "username"))?;
            let mut body_val = session_strip_meta_object(val)?;
            if let Some(obj) = body_val.as_object_mut() {
                obj.remove("username");
            }
            let bytes = serde_json::to_vec(&body_val)
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?;
            build("PUT", &format!("/operators/{username}/role"), Body::from(bytes))
        }
        "audit.list" | "log.list" => {
            let qs = session_query_string_from_value(val)?;
            let uri = if qs.is_empty() { "/audit".to_owned() } else { format!("/audit?{qs}") };
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "session_activity.list" => {
            let qs = session_query_string_from_value(val)?;
            let uri = if qs.is_empty() {
                "/session-activity".to_owned()
            } else {
                format!("/session-activity?{qs}")
            };
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "credential.list" => {
            let qs = session_query_string_from_value(val)?;
            let uri = if qs.is_empty() {
                "/credentials".to_owned()
            } else {
                format!("/credentials?{qs}")
            };
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "credential.show" => {
            let id = val
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "id"))?;
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(format!("/credentials/{id}"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "job.list" => {
            let qs = session_query_string_from_value(val)?;
            let uri = if qs.is_empty() { "/jobs".to_owned() } else { format!("/jobs?{qs}") };
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "job.show" => {
            let agent_id = val
                .get("agent_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "agent_id"))?;
            let request_id = val
                .get("request_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "request_id"))?;
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(format!("/jobs/{agent_id}/{request_id}"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "loot.list" => {
            let qs = session_query_string_from_value(val)?;
            let uri = if qs.is_empty() { "/loot".to_owned() } else { format!("/loot?{qs}") };
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "loot.download" | "loot.show" => {
            let id = val
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "id"))?;
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(format!("/loot/{id}"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "payload.list" => Ok(HttpRequest::builder()
            .method("GET")
            .uri("/payloads")
            .body(Body::empty())
            .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?),
        "payload.build" => {
            let body_val = session_strip_meta_object(val)?;
            let bytes = serde_json::to_vec(&body_val)
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?;
            build("POST", "/payloads/build", Body::from(bytes))
        }
        "payload.job" => {
            let job_id = val
                .get("job_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "job_id"))?;
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(format!("/payloads/jobs/{job_id}"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "payload.download" => {
            let id = val
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "id"))?;
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(format!("/payloads/{id}/download"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "payload_cache.flush" | "payload-cache.flush" => Ok(HttpRequest::builder()
            .method("POST")
            .uri("/payload-cache")
            .body(Body::empty())
            .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?),
        "webhooks.stats" => Ok(HttpRequest::builder()
            .method("GET")
            .uri("/webhooks/stats")
            .body(Body::empty())
            .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?),
        other => Err(SessionBuildError::UnknownCommand(other.to_owned())),
    }
}

fn session_build_error_envelope(cmd: &str, err: &SessionBuildError) -> String {
    let (code, message) = match err {
        SessionBuildError::UnknownCommand(c) => {
            ("UNKNOWN_COMMAND", format!("unknown command `{c}`"))
        }
        SessionBuildError::MissingField { field, .. } => {
            ("MISSING_FIELD", format!("missing required field `{field}`"))
        }
        SessionBuildError::InvalidBody(msg) => ("INVALID_REQUEST", msg.clone()),
    };
    serde_json::json!({
        "ok": false,
        "cmd": cmd,
        "error": code,
        "message": message,
    })
    .to_string()
}

async fn session_ws_envelope_response(cmd: &str, response: axum::response::Response) -> String {
    use base64::Engine as _;

    let status = response.status();
    let headers = response.headers().clone();
    let ct = headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let bytes = match to_bytes(response.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(_) => {
            return serde_json::json!({
                "ok": false,
                "cmd": cmd,
                "error": "BODY_READ_FAILED",
                "message": "failed to read response body"
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

/// Dispatch one session NDJSON command through the same REST [`super::api_routes`] router.
pub(crate) async fn session_api_dispatch_line(
    app: &Router,
    cmd: &str,
    value: &Value,
    client_ip: SocketAddr,
    api_key: &str,
) -> String {
    let inner = match build_session_rest_request(cmd, value) {
        Ok(r) => r,
        Err(e) => return session_build_error_envelope(cmd, &e),
    };
    let mut req = inner;
    match HeaderValue::from_str(api_key) {
        Ok(hv) => {
            req.headers_mut().insert(API_KEY_HEADER, hv);
        }
        Err(_) => {
            return serde_json::json!({
                "ok": false,
                "cmd": cmd,
                "error": "INVALID_API_KEY_HEADER",
                "message": "API key header value is not valid HTTP"
            })
            .to_string();
        }
    }
    req.extensions_mut().insert(ConnectInfo(client_ip));

    let response = match app.clone().oneshot(req).await {
        Ok(r) => r,
        Err(_) => {
            return serde_json::json!({
                "ok": false,
                "cmd": cmd,
                "error": "DISPATCH_FAILED",
                "message": "failed to dispatch session request"
            })
            .to_string();
        }
    };
    session_ws_envelope_response(cmd, response).await
}
