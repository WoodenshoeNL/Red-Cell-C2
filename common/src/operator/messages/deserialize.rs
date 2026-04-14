//! `Deserialize` implementation for [`super::OperatorMessage`].

use serde::{Deserialize, Deserializer};

use crate::operator::build::{BuildPayloadRequestInfo, BuildPayloadResponseInfo};

use super::OperatorMessage;
use super::codes::*;
use super::envelope::{IncomingMessage, Message, parse_info};

impl<'de> Deserialize<'de> for OperatorMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let incoming = IncomingMessage::deserialize(deserializer)?;
        let head = incoming.head;
        let info = incoming.body.info;

        match (head.event, incoming.body.sub_event) {
            (EventCode::InitConnection, x) if x == InitConnectionCode::Success.as_u32() => {
                Ok(Self::InitConnectionSuccess(Message { head, info: parse_info(info)? }))
            }
            (EventCode::InitConnection, x) if x == InitConnectionCode::Error.as_u32() => {
                Ok(Self::InitConnectionError(Message { head, info: parse_info(info)? }))
            }
            (EventCode::InitConnection, x) if x == InitConnectionCode::Login.as_u32() => {
                Ok(Self::Login(Message { head, info: parse_info(info)? }))
            }
            (EventCode::InitConnection, x) if x == InitConnectionCode::InitInfo.as_u32() => {
                Ok(Self::InitConnectionInfo(Message { head, info: parse_info(info)? }))
            }
            (EventCode::InitConnection, x) if x == InitConnectionCode::Profile.as_u32() => {
                Ok(Self::InitConnectionProfile(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Listener, x) if x == ListenerCode::New.as_u32() => {
                Ok(Self::ListenerNew(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Listener, x) if x == ListenerCode::Edit.as_u32() => {
                Ok(Self::ListenerEdit(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Listener, x) if x == ListenerCode::Remove.as_u32() => {
                Ok(Self::ListenerRemove(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Listener, x) if x == ListenerCode::Mark.as_u32() => {
                Ok(Self::ListenerMark(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Listener, x) if x == ListenerCode::Error.as_u32() => {
                Ok(Self::ListenerError(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Credentials, x) if x == CredentialsCode::Add.as_u32() => {
                Ok(Self::CredentialsAdd(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Credentials, x) if x == CredentialsCode::Edit.as_u32() => {
                Ok(Self::CredentialsEdit(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Credentials, x) if x == CredentialsCode::Remove.as_u32() => {
                Ok(Self::CredentialsRemove(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Chat, x) if x == ChatCode::Message.as_u32() => {
                Ok(Self::ChatMessage(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Chat, x) if x == ChatCode::Listener.as_u32() => {
                Ok(Self::ChatListener(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Chat, x) if x == ChatCode::Agent.as_u32() => {
                Ok(Self::ChatAgent(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Chat, x) if x == ChatCode::UserConnected.as_u32() => {
                Ok(Self::ChatUserConnected(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Chat, x) if x == ChatCode::UserDisconnected.as_u32() => {
                Ok(Self::ChatUserDisconnected(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Gate, x) if x == GateCode::Staged.as_u32() => {
                Ok(Self::BuildPayloadStaged(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Gate, x) if x == GateCode::BuildPayload.as_u32() => {
                if let Ok(parsed) = serde_json::from_value::<BuildPayloadRequestInfo>(info.clone())
                {
                    return Ok(Self::BuildPayloadRequest(Message { head, info: parsed }));
                }
                if let Ok(parsed) = serde_json::from_value::<BuildPayloadResponseInfo>(info.clone())
                {
                    return Ok(Self::BuildPayloadResponse(Message { head, info: parsed }));
                }
                Ok(Self::BuildPayloadMessage(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Gate, x) if x == GateCode::MsOffice.as_u32() => {
                Ok(Self::BuildPayloadMsOffice(Message { head, info: parse_info(info)? }))
            }
            (EventCode::HostFile, x) if x == HostFileCode::Add.as_u32() => {
                Ok(Self::HostFileAdd(Message { head, info: parse_info(info)? }))
            }
            (EventCode::HostFile, x) if x == HostFileCode::Remove.as_u32() => {
                Ok(Self::HostFileRemove(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Session, x) if x == SessionCode::AgentNew.as_u32() => {
                Ok(Self::AgentNew(Box::new(Message { head, info: parse_info(info)? })))
            }
            (EventCode::Session, x) if x == SessionCode::AgentRemove.as_u32() => {
                Ok(Self::AgentRemove(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Session, x) if x == SessionCode::AgentTask.as_u32() => {
                Ok(Self::AgentTask(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Session, x) if x == SessionCode::AgentResponse.as_u32() => {
                Ok(Self::AgentResponse(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Session, x) if x == SessionCode::AgentUpdate.as_u32() => {
                Ok(Self::AgentUpdate(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Session, x) if x == SessionCode::AgentReregistered.as_u32() => {
                Ok(Self::AgentReregistered(Box::new(Message { head, info: parse_info(info)? })))
            }
            (EventCode::Service, x) if x == ServiceCode::RegisterAgent.as_u32() => {
                Ok(Self::ServiceAgentRegister(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Service, x) if x == ServiceCode::RegisterListener.as_u32() => {
                Ok(Self::ServiceListenerRegister(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Teamserver, x) if x == TeamserverCode::Profile.as_u32() => {
                Ok(Self::TeamserverProfile(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Teamserver, x) if x == TeamserverCode::Log.as_u32() => {
                if info.get("profile").is_some() {
                    return Ok(Self::TeamserverProfile(Message { head, info: parse_info(info)? }));
                }
                Ok(Self::TeamserverLog(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Teamserver, x) if x == TeamserverCode::DatabaseDegraded.as_u32() => {
                Ok(Self::DatabaseDegraded(Message { head, info: parse_info(info)? }))
            }
            (EventCode::Teamserver, x) if x == TeamserverCode::DatabaseRecovered.as_u32() => {
                Ok(Self::DatabaseRecovered(Message { head, info: parse_info(info)? }))
            }
            (event, sub_event) => Err(serde::de::Error::custom(format!(
                "unsupported operator message event={event:?} sub_event={sub_event:#x}"
            ))),
        }
    }
}
