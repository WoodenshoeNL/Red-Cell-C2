//! Payload-build request, response, and diagnostic structs for the operator protocol.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Build payload request payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildPayloadRequestInfo {
    /// Requested agent type.
    #[serde(rename = "AgentType")]
    pub agent_type: String,
    /// Listener name.
    #[serde(rename = "Listener")]
    pub listener: String,
    /// Target architecture.
    #[serde(rename = "Arch")]
    pub arch: String,
    /// Output format.
    #[serde(rename = "Format")]
    pub format: String,
    /// Serialized build configuration document.
    #[serde(rename = "Config")]
    pub config: String,
}

/// Build payload success payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildPayloadResponseInfo {
    /// Base64-encoded payload bytes.
    #[serde(rename = "PayloadArray")]
    pub payload_array: String,
    /// Output format string.
    #[serde(rename = "Format")]
    pub format: String,
    /// Suggested output filename.
    #[serde(rename = "FileName")]
    pub file_name: String,
}

/// Build payload console/log message payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildPayloadMessageInfo {
    /// Message severity.
    #[serde(rename = "MessageType")]
    pub message_type: String,
    /// Human-readable build message.
    #[serde(rename = "Message")]
    pub message: String,
}

/// A single structured diagnostic extracted from compiler (GCC or NASM) output.
///
/// Used to return machine-readable build errors to the operator client so they
/// can be displayed with file/line source context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CompilerDiagnostic {
    /// Source file name as reported by the compiler.
    pub filename: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number, if reported by the compiler.
    pub column: Option<u32>,
    /// Severity label: `error`, `fatal error`, `warning`, or `note`.
    pub severity: String,
    /// Optional flag or code associated with the diagnostic (e.g. `-Wunused-variable`).
    pub error_code: Option<String>,
    /// Diagnostic message text.
    pub message: String,
}
