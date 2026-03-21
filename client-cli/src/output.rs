//! Output formatting helpers for `red-cell-cli`.
//!
//! All commands must write success payloads to **stdout** in the envelope:
//!
//! ```json
//! {"ok": true, "data": <payload>}
//! ```
//!
//! Errors are written to **stderr**:
//!
//! ```json
//! {"ok": false, "error": "ERROR_CODE", "message": "human text"}
//! ```

use serde::Serialize;

use crate::error::CliError;

/// Write a successful JSON response envelope to stdout.
///
/// The `data` field contains the serialised `payload`.
pub fn print_success<T: Serialize>(payload: &T) {
    let envelope = serde_json::json!({"ok": true, "data": payload});
    match serde_json::to_string_pretty(&envelope) {
        Ok(s) => println!("{s}"),
        Err(_) => println!(r#"{{"ok":true}}"#),
    }
}

/// Write an error JSON envelope to stderr.
///
/// The envelope contains `ok: false`, a stable machine-readable `error` code,
/// and a human-readable `message`.
pub fn print_error(err: &CliError) {
    let envelope = serde_json::json!({
        "ok": false,
        "error": err.error_code(),
        "message": err.to_string(),
    });
    match serde_json::to_string_pretty(&envelope) {
        Ok(s) => eprintln!("{s}"),
        Err(_) => eprintln!(r#"{{"ok":false,"error":"ERROR","message":"unknown error"}}"#),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::error::CliError;

    fn make_success_envelope<T: Serialize>(payload: &T) -> Value {
        serde_json::json!({"ok": true, "data": payload})
    }

    fn make_error_envelope(err: &CliError) -> Value {
        serde_json::json!({
            "ok": false,
            "error": err.error_code(),
            "message": err.to_string(),
        })
    }

    #[test]
    fn success_envelope_has_ok_true_and_data() {
        let env = make_success_envelope(&serde_json::json!({"agents": 3}));
        assert_eq!(env["ok"], true);
        assert_eq!(env["data"]["agents"], 3);
    }

    #[test]
    fn error_envelope_has_ok_false_and_code() {
        let err = CliError::AuthFailure("401".to_owned());
        let env = make_error_envelope(&err);
        assert_eq!(env["ok"], false);
        assert_eq!(env["error"], "AUTH_FAILURE");
        let msg = env["message"].as_str().unwrap_or("");
        assert!(msg.contains("auth failure"));
    }

    #[test]
    fn error_envelope_server_unreachable() {
        let err = CliError::ServerUnreachable("refused".to_owned());
        let env = make_error_envelope(&err);
        assert_eq!(env["error"], "SERVER_UNREACHABLE");
    }

    #[test]
    fn error_envelope_not_found() {
        let err = CliError::NotFound("agent".to_owned());
        let env = make_error_envelope(&err);
        assert_eq!(env["error"], "NOT_FOUND");
    }

    #[test]
    fn error_envelope_timeout() {
        let err = CliError::Timeout("30s".to_owned());
        let env = make_error_envelope(&err);
        assert_eq!(env["error"], "TIMEOUT");
    }
}
