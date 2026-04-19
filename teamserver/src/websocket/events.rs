//! Event-builder helpers that translate teamserver state changes into
//! [`OperatorMessage`] values for broadcast to connected operators.
//!
//! Each function returns a fully-formed message; the caller is responsible
//! for dispatching it via the [`crate::EventBus`] or sending it directly on
//! a socket.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::operator::{
    BuildPayloadMessageInfo, BuildPayloadResponseInfo, ChatUserInfo, CompilerDiagnostic, EventCode,
    FlatInfo, Message, MessageHead, OperatorMessage, TeamserverLogInfo,
};
use red_cell_common::{AgentRecord, OperatorInfo};
use serde_json::Value;
use time::OffsetDateTime;

use crate::sockets::AgentSocketSnapshot;
use crate::{PivotInfo, agent_events::agent_new_event};

/// Build a `TeamserverLog` event from free-form text.
pub(super) fn teamserver_log_event(user: &str, text: &str) -> OperatorMessage {
    OperatorMessage::TeamserverLog(Message {
        head: MessageHead {
            event: EventCode::Teamserver,
            user: user.to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: TeamserverLogInfo { text: text.to_owned() },
    })
}

/// Format a [`CompilerDiagnostic`] as a single human-readable string.
///
/// Produces output compatible with what GCC/NASM print natively:
/// `filename:line[:col]: severity: message`
pub(super) fn format_diagnostic(diag: &CompilerDiagnostic) -> String {
    let loc = match diag.column {
        Some(col) => format!("{}:{}:{}", diag.filename, diag.line, col),
        None => format!("{}:{}", diag.filename, diag.line),
    };
    let code_suffix = diag.error_code.as_deref().map(|c| format!(" [{c}]")).unwrap_or_default();
    format!("{loc}: {}: {}{code_suffix}", diag.severity, diag.message)
}

/// Build a `BuildPayloadMessage` event carrying a log line emitted during
/// payload compilation.
pub(super) fn build_payload_message_event(user: &str, level: &str, text: &str) -> OperatorMessage {
    OperatorMessage::BuildPayloadMessage(Message {
        head: MessageHead {
            event: EventCode::Gate,
            user: user.to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: BuildPayloadMessageInfo { message_type: level.to_owned(), message: text.to_owned() },
    })
}

/// Build a `BuildPayloadResponse` event carrying the finished payload bytes.
pub(super) fn build_payload_response_event(
    user: &str,
    file_name: &str,
    format: &str,
    bytes: &[u8],
) -> OperatorMessage {
    OperatorMessage::BuildPayloadResponse(Message {
        head: MessageHead {
            event: EventCode::Gate,
            user: user.to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: BuildPayloadResponseInfo {
            payload_array: BASE64_STANDARD.encode(bytes),
            format: format.to_owned(),
            file_name: file_name.to_owned(),
        },
    })
}

/// Build an `AgentNew` event describing a freshly-registered or replayed agent.
pub(super) fn agent_snapshot_event(
    listener_name: &str,
    agent: &AgentRecord,
    pivots: &PivotInfo,
    sockets: AgentSocketSnapshot,
) -> OperatorMessage {
    agent_new_event(
        listener_name,
        red_cell_common::demon::DEMON_MAGIC_VALUE,
        agent,
        pivots,
        sockets,
    )
}

/// Build an `InitConnection` event containing the operator roster.
pub(super) fn operator_snapshot_event(
    operators: Vec<OperatorInfo>,
) -> Result<OperatorMessage, serde_json::Error> {
    Ok(OperatorMessage::InitConnectionInfo(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: String::new(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: FlatInfo {
            fields: BTreeMap::from([("Operators".to_owned(), serde_json::to_value(operators)?)]),
        },
    }))
}

/// Build a chat presence event signalling that `user` connected or disconnected.
pub(super) fn chat_presence_event(user: &str, online: bool) -> OperatorMessage {
    let message = Message {
        head: MessageHead {
            event: EventCode::Chat,
            user: "teamserver".to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: ChatUserInfo { user: user.to_owned() },
    };

    if online {
        OperatorMessage::ChatUserConnected(message)
    } else {
        OperatorMessage::ChatUserDisconnected(message)
    }
}

/// Build a `ChatMessage` event for broadcast to the operator chat.
pub(super) fn chat_message_event(user: &str, text: &str) -> OperatorMessage {
    OperatorMessage::ChatMessage(Message {
        head: MessageHead {
            event: EventCode::Chat,
            user: user.to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: FlatInfo {
            fields: BTreeMap::from([
                ("User".to_owned(), Value::String(user.to_owned())),
                ("Message".to_owned(), Value::String(text.to_owned())),
            ]),
        },
    })
}

/// Build the final `TeamserverLog` event emitted before the teamserver exits.
pub(super) fn teamserver_shutdown_event() -> OperatorMessage {
    OperatorMessage::TeamserverLog(Message {
        head: MessageHead {
            event: EventCode::Teamserver,
            user: "teamserver".to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: TeamserverLogInfo { text: "teamserver shutting down".to_owned() },
    })
}
