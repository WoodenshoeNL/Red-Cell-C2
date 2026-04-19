//! Per-command HTTP request builders for session WebSocket dispatch.

use axum::body::Body;
use axum::http::Request as HttpRequest;
use axum::http::header::CONTENT_TYPE;
use red_cell_common::ListenerConfig;
use serde_json::Value;

/// Errors while mapping a session `cmd` to an internal REST request.
#[derive(Debug, thiserror::Error)]
pub(super) enum SessionBuildError {
    #[error("unknown session command `{0}`")]
    UnknownCommand(String),
    #[error("missing field `{field}` for command `{cmd}`")]
    MissingField { cmd: String, field: String },
    #[error("invalid session request: {0}")]
    InvalidBody(String),
}

impl SessionBuildError {
    pub(super) fn missing(cmd: &str, field: &str) -> Self {
        Self::MissingField { cmd: cmd.to_owned(), field: field.to_owned() }
    }
}

/// Build `application/x-www-form-urlencoded` query string from a JSON object,
/// skipping meta keys (`cmd`, `wait`, `timeout`) and null values.
pub(super) fn session_query_string_from_value(val: &Value) -> Result<String, SessionBuildError> {
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

pub(super) fn session_strip_meta_object(val: &Value) -> Result<Value, SessionBuildError> {
    let mut v = val.clone();
    let Some(obj) = v.as_object_mut() else {
        return Err(SessionBuildError::InvalidBody("expected JSON object".to_owned()));
    };
    obj.remove("cmd");
    obj.remove("wait");
    obj.remove("timeout");
    Ok(Value::Object(std::mem::take(obj)))
}

pub(super) fn build_session_rest_request(
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
                .uri("/health")
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
        "agent.groups" => {
            let id = val
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "id"))?;
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(format!("/agents/{id}/groups"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "agent.set_groups" => {
            let id = val
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "id"))?;
            let mut body_val = session_strip_meta_object(val)?;
            if let Some(obj) = body_val.as_object_mut() {
                obj.remove("id");
            }
            let bytes = serde_json::to_vec(&body_val)
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?;
            build("PUT", &format!("/agents/{id}/groups"), Body::from(bytes))
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
        "listener.access" => {
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "name"))?;
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(format!("/listeners/{name}/access"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "listener.set_access" => {
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "name"))?;
            let mut body_val = session_strip_meta_object(val)?;
            if let Some(obj) = body_val.as_object_mut() {
                obj.remove("name");
            }
            let bytes = serde_json::to_vec(&body_val)
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?;
            build("PUT", &format!("/listeners/{name}/access"), Body::from(bytes))
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
        "operator.show_agent_groups" => {
            let username = val
                .get("username")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SessionBuildError::missing(cmd, "username"))?;
            Ok(HttpRequest::builder()
                .method("GET")
                .uri(format!("/operators/{username}/agent-groups"))
                .body(Body::empty())
                .map_err(|e| SessionBuildError::InvalidBody(e.to_string()))?)
        }
        "operator.set_agent_groups" => {
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
            build("PUT", &format!("/operators/{username}/agent-groups"), Body::from(bytes))
        }
        "audit.list" | "log.list" | "log.tail" => {
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

pub(super) fn session_build_error_envelope(cmd: &str, err: &SessionBuildError) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Source text of the client-cli session allowlist, included at compile
    /// time so this test tracks the actual CLI file rather than a local copy.
    /// If the file moves or is renamed, update this path and the parser below.
    const CLIENT_CLI_SESSION_ALLOWLIST_SRC: &str =
        include_str!("../../../../client-cli/src/commands/session/normalize.rs");

    /// Extract the string literals inside the `HashSet::from([...])` block that
    /// initialises `SESSION_KNOWN_COMMANDS` in the client-cli source.  The
    /// parser is intentionally strict: it fails loudly if the file's shape
    /// changes in a way the test can no longer understand, so drift between
    /// the allowlist definition and this parity check is surfaced immediately.
    fn parse_client_allowlist(src: &str) -> Vec<String> {
        let anchor = "SESSION_KNOWN_COMMANDS";
        let anchor_pos =
            src.find(anchor).unwrap_or_else(|| panic!("`{anchor}` not found in client-cli source"));
        let after_anchor = &src[anchor_pos..];
        let open = after_anchor
            .find("HashSet::from([")
            .unwrap_or_else(|| panic!("`HashSet::from([` not found after `{anchor}`"));
        let tail = &after_anchor[open + "HashSet::from([".len()..];
        let close = tail
            .find("])")
            .unwrap_or_else(|| panic!("`])` closing `HashSet::from([` not found in client-cli"));
        let block = &tail[..close];

        let mut out = Vec::new();
        let mut rest = block;
        while let Some(start) = rest.find('"') {
            let after = &rest[start + 1..];
            let end = after
                .find('"')
                .expect("unterminated string literal in client-cli SESSION_KNOWN_COMMANDS");
            out.push(after[..end].to_owned());
            rest = &after[end + 1..];
        }
        out
    }

    /// Every command that the client-cli advertises in `SESSION_KNOWN_COMMANDS`
    /// must be handled by `build_session_rest_request` (i.e. must not return
    /// `SessionBuildError::UnknownCommand`).  The advertised list is parsed
    /// directly from the client-cli source at compile time, so adding a
    /// command to the CLI allowlist without a matching server match arm fails
    /// this test — preventing contract drift between the two sides.
    #[test]
    fn session_router_handles_all_advertised_commands() {
        let advertised = parse_client_allowlist(CLIENT_CLI_SESSION_ALLOWLIST_SRC);
        assert!(
            !advertised.is_empty(),
            "parsed empty allowlist from client-cli source — parser likely broken",
        );

        let empty = serde_json::json!({});
        let mut unknown = Vec::new();
        for cmd in &advertised {
            if let Err(SessionBuildError::UnknownCommand(_)) =
                build_session_rest_request(cmd, &empty)
            {
                unknown.push(cmd.clone());
            }
        }

        assert!(
            unknown.is_empty(),
            "session router does not handle commands advertised by client-cli: {unknown:?}\n\
             Add match arms in `build_session_rest_request` for each missing command.",
        );
    }

    #[test]
    fn client_allowlist_parser_finds_known_sentinels() {
        let advertised = parse_client_allowlist(CLIENT_CLI_SESSION_ALLOWLIST_SRC);
        for expected in [
            "status",
            "agent.list",
            "agent.groups",
            "listener.access",
            "operator.show_agent_groups",
            "log.tail",
            "payload-cache.flush",
            "webhooks.stats",
        ] {
            assert!(
                advertised.iter().any(|c| c == expected),
                "expected `{expected}` in parsed client allowlist, got {advertised:?}",
            );
        }
    }

    #[test]
    fn agent_groups_produces_correct_request() {
        let val = serde_json::json!({"id": "DEADBEEF"});
        let req = build_session_rest_request("agent.groups", &val).unwrap();
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), "/agents/DEADBEEF/groups");
    }

    #[test]
    fn agent_set_groups_produces_correct_request() {
        let val = serde_json::json!({"id": "DEADBEEF", "groups": ["red", "blue"]});
        let req = build_session_rest_request("agent.set_groups", &val).unwrap();
        assert_eq!(req.method(), "PUT");
        assert_eq!(req.uri(), "/agents/DEADBEEF/groups");
    }

    #[test]
    fn listener_access_produces_correct_request() {
        let val = serde_json::json!({"name": "http-1"});
        let req = build_session_rest_request("listener.access", &val).unwrap();
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), "/listeners/http-1/access");
    }

    #[test]
    fn listener_set_access_produces_correct_request() {
        let val = serde_json::json!({"name": "http-1", "allowed_operators": ["alice"]});
        let req = build_session_rest_request("listener.set_access", &val).unwrap();
        assert_eq!(req.method(), "PUT");
        assert_eq!(req.uri(), "/listeners/http-1/access");
    }

    #[test]
    fn operator_show_agent_groups_produces_correct_request() {
        let val = serde_json::json!({"username": "alice"});
        let req = build_session_rest_request("operator.show_agent_groups", &val).unwrap();
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), "/operators/alice/agent-groups");
    }

    #[test]
    fn operator_set_agent_groups_produces_correct_request() {
        let val = serde_json::json!({"username": "alice", "allowed_groups": ["ops"]});
        let req = build_session_rest_request("operator.set_agent_groups", &val).unwrap();
        assert_eq!(req.method(), "PUT");
        assert_eq!(req.uri(), "/operators/alice/agent-groups");
    }

    #[test]
    fn log_tail_maps_to_audit_endpoint() {
        let val = serde_json::json!({});
        let req = build_session_rest_request("log.tail", &val).unwrap();
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), "/audit");
    }

    #[test]
    fn log_tail_with_params_passes_query_string() {
        let val = serde_json::json!({"limit": 10});
        let req = build_session_rest_request("log.tail", &val).unwrap();
        assert_eq!(req.method(), "GET");
        assert!(req.uri().to_string().starts_with("/audit?"));
        assert!(req.uri().to_string().contains("limit=10"));
    }

    #[test]
    fn status_routes_to_health_endpoint() {
        let val = serde_json::json!({});
        let req = build_session_rest_request("status", &val).unwrap();
        assert_eq!(req.method(), "GET");
        assert_eq!(req.uri(), "/health");
    }
}
