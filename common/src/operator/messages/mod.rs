//! JSON-over-WebSocket operator protocol types (`OperatorMessage`) and wire envelopes.
//!
//! Submodules group tests and implementation pieces by protocol domain; the public
//! surface remains the re-exports below (unchanged for `crate::operator` users).

mod agent;
mod codes;
mod deserialize;
mod envelope;
mod listener;
mod loot;
mod operator;
mod other;
mod serialize;

pub use codes::*;
pub use envelope::*;

use crate::operator::agents::{AgentInfo, AgentResponseInfo, AgentTaskInfo, AgentUpdateInfo};
use crate::operator::build::{
    BuildPayloadMessageInfo, BuildPayloadRequestInfo, BuildPayloadResponseInfo,
};
use crate::operator::listeners::{ListenerErrorInfo, ListenerInfo, ListenerMarkInfo, NameInfo};
use crate::operator::misc::{
    ChatUserInfo, DatabaseStatusInfo, InitProfileInfo, LoginInfo, ServiceAgentRegistrationInfo,
    ServiceListenerRegistrationInfo, TeamserverLogInfo, TeamserverProfileInfo,
};
use crate::operator::operators::{CreateOperatorInfo, RemoveOperatorInfo};

/// Semantic operator protocol messages mapped onto Havoc wire event/subevent codes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperatorMessage {
    InitConnectionSuccess(Message<MessageInfo>),
    InitConnectionError(Message<MessageInfo>),
    Login(Message<LoginInfo>),
    InitConnectionInfo(Message<FlatInfo>),
    InitConnectionProfile(Message<InitProfileInfo>),
    ListenerNew(Message<ListenerInfo>),
    ListenerEdit(Message<ListenerInfo>),
    ListenerRemove(Message<NameInfo>),
    ListenerMark(Message<ListenerMarkInfo>),
    ListenerError(Message<ListenerErrorInfo>),
    CredentialsAdd(Message<FlatInfo>),
    CredentialsEdit(Message<FlatInfo>),
    CredentialsRemove(Message<FlatInfo>),
    ChatMessage(Message<FlatInfo>),
    ChatListener(Message<FlatInfo>),
    ChatAgent(Message<FlatInfo>),
    ChatUserConnected(Message<ChatUserInfo>),
    ChatUserDisconnected(Message<ChatUserInfo>),
    BuildPayloadStaged(Message<FlatInfo>),
    BuildPayloadRequest(Message<BuildPayloadRequestInfo>),
    BuildPayloadResponse(Message<BuildPayloadResponseInfo>),
    BuildPayloadMessage(Message<BuildPayloadMessageInfo>),
    BuildPayloadMsOffice(Message<FlatInfo>),
    HostFileAdd(Message<FlatInfo>),
    HostFileRemove(Message<FlatInfo>),
    AgentNew(Box<Message<AgentInfo>>),
    AgentRemove(Message<FlatInfo>),
    AgentTask(Message<AgentTaskInfo>),
    AgentResponse(Message<AgentResponseInfo>),
    AgentUpdate(Message<AgentUpdateInfo>),
    AgentReregistered(Box<Message<AgentInfo>>),
    ServiceAgentRegister(Message<ServiceAgentRegistrationInfo>),
    ServiceListenerRegister(Message<ServiceListenerRegistrationInfo>),
    TeamserverLog(Message<TeamserverLogInfo>),
    TeamserverProfile(Message<TeamserverProfileInfo>),
    DatabaseDegraded(Message<DatabaseStatusInfo>),
    DatabaseRecovered(Message<DatabaseStatusInfo>),
    /// Red Cell extension: create a new operator account.
    OperatorCreate(Message<CreateOperatorInfo>),
    /// Red Cell extension: remove an operator account.
    OperatorRemove(Message<RemoveOperatorInfo>),
}

impl OperatorMessage {
    /// Returns the numeric event code for the message.
    #[must_use]
    pub const fn event_code(&self) -> EventCode {
        match self {
            Self::InitConnectionSuccess(_)
            | Self::InitConnectionError(_)
            | Self::Login(_)
            | Self::InitConnectionInfo(_)
            | Self::InitConnectionProfile(_) => EventCode::InitConnection,
            Self::ListenerNew(_)
            | Self::ListenerEdit(_)
            | Self::ListenerRemove(_)
            | Self::ListenerMark(_)
            | Self::ListenerError(_) => EventCode::Listener,
            Self::CredentialsAdd(_) | Self::CredentialsEdit(_) | Self::CredentialsRemove(_) => {
                EventCode::Credentials
            }
            Self::ChatMessage(_)
            | Self::ChatListener(_)
            | Self::ChatAgent(_)
            | Self::ChatUserConnected(_)
            | Self::ChatUserDisconnected(_) => EventCode::Chat,
            Self::BuildPayloadStaged(_)
            | Self::BuildPayloadRequest(_)
            | Self::BuildPayloadResponse(_)
            | Self::BuildPayloadMessage(_)
            | Self::BuildPayloadMsOffice(_) => EventCode::Gate,
            Self::HostFileAdd(_) | Self::HostFileRemove(_) => EventCode::HostFile,
            Self::AgentNew(_)
            | Self::AgentRemove(_)
            | Self::AgentTask(_)
            | Self::AgentResponse(_)
            | Self::AgentUpdate(_)
            | Self::AgentReregistered(_) => EventCode::Session,
            Self::ServiceAgentRegister(_) | Self::ServiceListenerRegister(_) => EventCode::Service,
            Self::TeamserverLog(_)
            | Self::TeamserverProfile(_)
            | Self::DatabaseDegraded(_)
            | Self::DatabaseRecovered(_) => EventCode::Teamserver,
            Self::OperatorCreate(_) | Self::OperatorRemove(_) => EventCode::OperatorManagement,
        }
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::{EventCode, MessageHead};

    pub fn head(event: EventCode) -> MessageHead {
        MessageHead {
            event,
            user: "operator".to_string(),
            timestamp: "09/03/2026 19:00:00".to_string(),
            one_time: String::new(),
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use std::collections::BTreeMap;

    use super::test_support::head;
    use super::*;
    use serde_json::json;

    #[test]
    fn operator_message_exposes_expected_event_codes() {
        let messages = [
            (
                OperatorMessage::InitConnectionSuccess(Message {
                    head: head(EventCode::InitConnection),
                    info: MessageInfo { message: "ok".to_string() },
                }),
                EventCode::InitConnection,
            ),
            (
                OperatorMessage::ListenerMark(Message {
                    head: head(EventCode::Listener),
                    info: ListenerMarkInfo { name: "http".to_string(), mark: "good".to_string() },
                }),
                EventCode::Listener,
            ),
            (
                OperatorMessage::CredentialsRemove(Message {
                    head: head(EventCode::Credentials),
                    info: FlatInfo { fields: BTreeMap::new() },
                }),
                EventCode::Credentials,
            ),
            (
                OperatorMessage::ChatAgent(Message {
                    head: head(EventCode::Chat),
                    info: FlatInfo { fields: BTreeMap::new() },
                }),
                EventCode::Chat,
            ),
            (
                OperatorMessage::BuildPayloadMsOffice(Message {
                    head: head(EventCode::Gate),
                    info: FlatInfo { fields: BTreeMap::new() },
                }),
                EventCode::Gate,
            ),
            (
                OperatorMessage::HostFileRemove(Message {
                    head: head(EventCode::HostFile),
                    info: FlatInfo { fields: BTreeMap::new() },
                }),
                EventCode::HostFile,
            ),
            (
                OperatorMessage::AgentUpdate(Message {
                    head: head(EventCode::Session),
                    info: AgentUpdateInfo {
                        agent_id: "ABCD1234".to_string(),
                        marked: "Alive".to_string(),
                    },
                }),
                EventCode::Session,
            ),
            (
                OperatorMessage::ServiceListenerRegister(Message {
                    head: head(EventCode::Service),
                    info: ServiceListenerRegistrationInfo { listener: "{}".to_string() },
                }),
                EventCode::Service,
            ),
            (
                OperatorMessage::TeamserverLog(Message {
                    head: head(EventCode::Teamserver),
                    info: TeamserverLogInfo { text: "log".to_string() },
                }),
                EventCode::Teamserver,
            ),
        ];

        for (message, expected) in messages {
            assert_eq!(message.event_code(), expected);
        }
    }

    #[test]
    fn flat_info_variants_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            // --- already-covered variants ---
            // InitConnectionInfo (Event=1, SE=4)
            json!({
                "Head": { "Event": 1, "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 4, "Info": { "Version": "0.1.0", "Motd": "hello" } }
            }),
            // CredentialsAdd (Event=3, SE=1)
            json!({
                "Head": { "Event": 3, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 1, "Info": { "Realm": "LAB", "Username": "neo" } }
            }),
            // ChatListener (Event=4, SE=2; ChatCode::Listener=0x2)
            json!({
                "Head": { "Event": 4, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 2, "Info": { "Name": "http", "Text": "listener online" } }
            }),
            // BuildPayloadStaged (Event=5, SE=1; GateCode::Staged=0x1)
            json!({
                "Head": { "Event": 5, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 1, "Info": { "Listener": "http" } }
            }),
            // HostFileRemove (Event=6, SE=2; HostFileCode::Remove=0x2)
            json!({
                "Head": { "Event": 6, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 2, "Info": { "Path": "tmp.txt" } }
            }),
            // AgentRemove (Event=7, SE=2; SessionCode::AgentRemove=0x2)
            json!({
                "Head": { "Event": 7, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 2, "Info": { "AgentID": "ABCD1234" } }
            }),
            // --- previously uncovered variants ---
            // ListenerEdit (Event=2, SE=2; ListenerCode::Edit=0x2)
            json!({
                "Head": { "Event": 2, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 2, "Info": { "Name": "http", "Protocol": "Http", "Status": "Online" } }
            }),
            // CredentialsEdit (Event=3, SE=2; CredentialsCode::Edit=0x2)
            json!({
                "Head": { "Event": 3, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 2, "Info": { "Realm": "LAB", "Username": "neo", "Password": "secret" } }
            }),
            // CredentialsRemove (Event=3, SE=3; CredentialsCode::Remove=0x3)
            json!({
                "Head": { "Event": 3, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 3, "Info": { "Realm": "LAB", "Username": "neo" } }
            }),
            // ChatMessage (Event=4, SE=1; ChatCode::Message=0x1)
            json!({
                "Head": { "Event": 4, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 1, "Info": { "Text": "hello world" } }
            }),
            // ChatAgent (Event=4, SE=3; ChatCode::Agent=0x3)
            json!({
                "Head": { "Event": 4, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 3, "Info": { "AgentID": "ABCD1234", "Text": "new agent checked in" } }
            }),
            // BuildPayloadMsOffice (Event=5, SE=3; GateCode::MsOffice=0x3)
            json!({
                "Head": { "Event": 5, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 3, "Info": { "Listener": "http", "Template": "default" } }
            }),
            // HostFileAdd (Event=6, SE=1; HostFileCode::Add=0x1)
            json!({
                "Head": { "Event": 6, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 1, "Info": { "Path": "payload.exe", "Size": 4096 } }
            }),
        ];

        for value in &cases {
            let message: OperatorMessage = serde_json::from_value(value.clone())?;
            let encoded = serde_json::to_value(&message)?;
            let reparsed: OperatorMessage = serde_json::from_value(encoded.clone())?;
            assert_eq!(reparsed, message);
            // Symmetry: Event and SubEvent codes must survive the encode/decode round-trip unchanged.
            assert_eq!(
                encoded["Head"]["Event"], value["Head"]["Event"],
                "Event code mismatch for {value}"
            );
            assert_eq!(
                encoded["Body"]["SubEvent"], value["Body"]["SubEvent"],
                "SubEvent code mismatch for {value}"
            );
        }

        Ok(())
    }

    /// A JSON payload that carries the correct `EventCode` but the `SubEvent` of a *sibling*
    /// variant must not silently decode as the wrong variant.
    #[test]
    fn flat_info_sibling_subevent_rejected() -> Result<(), Box<dyn std::error::Error>> {
        // Credentials family: Add=1, Edit=2, Remove=3.
        // SubEvent=1 must decode as CredentialsAdd, not CredentialsEdit.
        let add_payload = json!({
            "Head": { "Event": 3, "Time": "09/03/2026 19:00:00" },
            "Body": { "SubEvent": 1, "Info": { "Realm": "LAB" } }
        });
        assert!(
            matches!(
                serde_json::from_value::<OperatorMessage>(add_payload)?,
                OperatorMessage::CredentialsAdd(_)
            ),
            "SE=1 within Credentials must be CredentialsAdd"
        );

        // HostFile family: Add=1, Remove=2.
        // SubEvent=1 must decode as HostFileAdd, not HostFileRemove.
        let host_add = json!({
            "Head": { "Event": 6, "Time": "09/03/2026 19:00:00" },
            "Body": { "SubEvent": 1, "Info": { "Path": "shell.exe" } }
        });
        assert!(
            matches!(
                serde_json::from_value::<OperatorMessage>(host_add)?,
                OperatorMessage::HostFileAdd(_)
            ),
            "SE=1 within HostFile must be HostFileAdd"
        );

        // SubEvent=2 must decode as HostFileRemove, not HostFileAdd.
        let host_remove = json!({
            "Head": { "Event": 6, "Time": "09/03/2026 19:00:00" },
            "Body": { "SubEvent": 2, "Info": { "Path": "shell.exe" } }
        });
        assert!(
            matches!(
                serde_json::from_value::<OperatorMessage>(host_remove)?,
                OperatorMessage::HostFileRemove(_)
            ),
            "SE=2 within HostFile must be HostFileRemove"
        );

        // Chat family: Message=1, Listener=2, Agent=3.
        // SE=1 must be ChatMessage, not ChatListener or ChatAgent.
        let chat_msg = json!({
            "Head": { "Event": 4, "User": "operator", "Time": "09/03/2026 19:00:00" },
            "Body": { "SubEvent": 1, "Info": { "Text": "hi" } }
        });
        assert!(
            matches!(
                serde_json::from_value::<OperatorMessage>(chat_msg)?,
                OperatorMessage::ChatMessage(_)
            ),
            "SE=1 within Chat must be ChatMessage"
        );

        // SE=3 must be ChatAgent, not ChatMessage or ChatListener.
        let chat_agent = json!({
            "Head": { "Event": 4, "User": "operator", "Time": "09/03/2026 19:00:00" },
            "Body": { "SubEvent": 3, "Info": { "AgentID": "ABCD1234" } }
        });
        assert!(
            matches!(
                serde_json::from_value::<OperatorMessage>(chat_agent)?,
                OperatorMessage::ChatAgent(_)
            ),
            "SE=3 within Chat must be ChatAgent"
        );

        // Listener family: New=1, Edit=2.
        // SE=1 must be ListenerNew, not ListenerEdit.
        let listener_new = json!({
            "Head": { "Event": 2, "Time": "09/03/2026 19:00:00" },
            "Body": { "SubEvent": 1, "Info": { "Name": "http" } }
        });
        assert!(
            matches!(
                serde_json::from_value::<OperatorMessage>(listener_new)?,
                OperatorMessage::ListenerNew(_)
            ),
            "SE=1 within Listener must be ListenerNew"
        );

        // SE=2 must be ListenerEdit, not ListenerNew.
        let listener_edit = json!({
            "Head": { "Event": 2, "Time": "09/03/2026 19:00:00" },
            "Body": { "SubEvent": 2, "Info": { "Name": "http" } }
        });
        assert!(
            matches!(
                serde_json::from_value::<OperatorMessage>(listener_edit)?,
                OperatorMessage::ListenerEdit(_)
            ),
            "SE=2 within Listener must be ListenerEdit"
        );

        Ok(())
    }

    /// A full OperatorMessage round-trip must preserve the EventCode numeric
    /// value in the Head.Event JSON field.
    #[test]
    fn operator_message_event_code_wire_value_survives_round_trip()
    -> Result<(), Box<dyn std::error::Error>> {
        let cases: &[(OperatorMessage, u32)] = &[
            (
                OperatorMessage::InitConnectionSuccess(Message {
                    head: head(EventCode::InitConnection),
                    info: MessageInfo { message: "ok".to_string() },
                }),
                1,
            ),
            (
                OperatorMessage::ListenerNew(Message {
                    head: head(EventCode::Listener),
                    info: ListenerInfo::default(),
                }),
                2,
            ),
            (
                OperatorMessage::CredentialsAdd(Message {
                    head: head(EventCode::Credentials),
                    info: FlatInfo::default(),
                }),
                3,
            ),
            (
                OperatorMessage::ChatMessage(Message {
                    head: head(EventCode::Chat),
                    info: FlatInfo::default(),
                }),
                4,
            ),
            (
                OperatorMessage::BuildPayloadStaged(Message {
                    head: head(EventCode::Gate),
                    info: FlatInfo::default(),
                }),
                5,
            ),
            (
                OperatorMessage::HostFileAdd(Message {
                    head: head(EventCode::HostFile),
                    info: FlatInfo::default(),
                }),
                6,
            ),
            (
                OperatorMessage::AgentTask(Message {
                    head: head(EventCode::Session),
                    info: AgentTaskInfo::default(),
                }),
                7,
            ),
            (
                OperatorMessage::ServiceAgentRegister(Message {
                    head: head(EventCode::Service),
                    info: ServiceAgentRegistrationInfo::default(),
                }),
                9,
            ),
            (
                OperatorMessage::TeamserverLog(Message {
                    head: head(EventCode::Teamserver),
                    info: TeamserverLogInfo::default(),
                }),
                16,
            ),
        ];

        for (message, expected_event_wire) in cases {
            let encoded = serde_json::to_value(message)?;
            assert_eq!(
                encoded["Head"]["Event"],
                json!(*expected_event_wire),
                "event code on wire for {message:?}"
            );
            let decoded: OperatorMessage = serde_json::from_value(encoded)?;
            assert_eq!(&decoded, message);
        }
        Ok(())
    }
}
