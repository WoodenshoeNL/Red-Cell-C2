//! `Serialize` implementation for [`super::OperatorMessage`].

use serde::{Serialize, Serializer};

use super::OperatorMessage;
use super::codes::*;
use super::envelope::serialize_message;

impl Serialize for OperatorMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::InitConnectionSuccess(message) => serialize_message(
                serializer,
                &message.head,
                InitConnectionCode::Success.as_u32(),
                &message.info,
            ),
            Self::InitConnectionError(message) => serialize_message(
                serializer,
                &message.head,
                InitConnectionCode::Error.as_u32(),
                &message.info,
            ),
            Self::Login(message) => serialize_message(
                serializer,
                &message.head,
                InitConnectionCode::Login.as_u32(),
                &message.info,
            ),
            Self::InitConnectionInfo(message) => serialize_message(
                serializer,
                &message.head,
                InitConnectionCode::InitInfo.as_u32(),
                &message.info,
            ),
            Self::InitConnectionProfile(message) => serialize_message(
                serializer,
                &message.head,
                InitConnectionCode::Profile.as_u32(),
                &message.info,
            ),
            Self::ListenerNew(message) => serialize_message(
                serializer,
                &message.head,
                ListenerCode::New.as_u32(),
                &message.info,
            ),
            Self::ListenerEdit(message) => serialize_message(
                serializer,
                &message.head,
                ListenerCode::Edit.as_u32(),
                &message.info,
            ),
            Self::ListenerRemove(message) => serialize_message(
                serializer,
                &message.head,
                ListenerCode::Remove.as_u32(),
                &message.info,
            ),
            Self::ListenerMark(message) => serialize_message(
                serializer,
                &message.head,
                ListenerCode::Mark.as_u32(),
                &message.info,
            ),
            Self::ListenerError(message) => serialize_message(
                serializer,
                &message.head,
                ListenerCode::Error.as_u32(),
                &message.info,
            ),
            Self::CredentialsAdd(message) => serialize_message(
                serializer,
                &message.head,
                CredentialsCode::Add.as_u32(),
                &message.info,
            ),
            Self::CredentialsEdit(message) => serialize_message(
                serializer,
                &message.head,
                CredentialsCode::Edit.as_u32(),
                &message.info,
            ),
            Self::CredentialsRemove(message) => serialize_message(
                serializer,
                &message.head,
                CredentialsCode::Remove.as_u32(),
                &message.info,
            ),
            Self::ChatMessage(message) => serialize_message(
                serializer,
                &message.head,
                ChatCode::Message.as_u32(),
                &message.info,
            ),
            Self::ChatListener(message) => serialize_message(
                serializer,
                &message.head,
                ChatCode::Listener.as_u32(),
                &message.info,
            ),
            Self::ChatAgent(message) => serialize_message(
                serializer,
                &message.head,
                ChatCode::Agent.as_u32(),
                &message.info,
            ),
            Self::ChatUserConnected(message) => serialize_message(
                serializer,
                &message.head,
                ChatCode::UserConnected.as_u32(),
                &message.info,
            ),
            Self::ChatUserDisconnected(message) => serialize_message(
                serializer,
                &message.head,
                ChatCode::UserDisconnected.as_u32(),
                &message.info,
            ),
            Self::BuildPayloadStaged(message) => serialize_message(
                serializer,
                &message.head,
                GateCode::Staged.as_u32(),
                &message.info,
            ),
            Self::BuildPayloadRequest(message) => serialize_message(
                serializer,
                &message.head,
                GateCode::BuildPayload.as_u32(),
                &message.info,
            ),
            Self::BuildPayloadResponse(message) => serialize_message(
                serializer,
                &message.head,
                GateCode::BuildPayload.as_u32(),
                &message.info,
            ),
            Self::BuildPayloadMessage(message) => serialize_message(
                serializer,
                &message.head,
                GateCode::BuildPayload.as_u32(),
                &message.info,
            ),
            Self::BuildPayloadMsOffice(message) => serialize_message(
                serializer,
                &message.head,
                GateCode::MsOffice.as_u32(),
                &message.info,
            ),
            Self::HostFileAdd(message) => serialize_message(
                serializer,
                &message.head,
                HostFileCode::Add.as_u32(),
                &message.info,
            ),
            Self::HostFileRemove(message) => serialize_message(
                serializer,
                &message.head,
                HostFileCode::Remove.as_u32(),
                &message.info,
            ),
            Self::AgentNew(message) => serialize_message(
                serializer,
                &message.head,
                SessionCode::AgentNew.as_u32(),
                &message.info,
            ),
            Self::AgentRemove(message) => serialize_message(
                serializer,
                &message.head,
                SessionCode::AgentRemove.as_u32(),
                &message.info,
            ),
            Self::AgentTask(message) => serialize_message(
                serializer,
                &message.head,
                SessionCode::AgentTask.as_u32(),
                &message.info,
            ),
            Self::AgentResponse(message) => serialize_message(
                serializer,
                &message.head,
                SessionCode::AgentResponse.as_u32(),
                &message.info,
            ),
            Self::AgentUpdate(message) => serialize_message(
                serializer,
                &message.head,
                SessionCode::AgentUpdate.as_u32(),
                &message.info,
            ),
            Self::AgentReregistered(message) => serialize_message(
                serializer,
                &message.head,
                SessionCode::AgentReregistered.as_u32(),
                &message.info,
            ),
            Self::ServiceAgentRegister(message) => serialize_message(
                serializer,
                &message.head,
                ServiceCode::RegisterAgent.as_u32(),
                &message.info,
            ),
            Self::ServiceListenerRegister(message) => serialize_message(
                serializer,
                &message.head,
                ServiceCode::RegisterListener.as_u32(),
                &message.info,
            ),
            Self::TeamserverLog(message) => serialize_message(
                serializer,
                &message.head,
                TeamserverCode::Log.as_u32(),
                &message.info,
            ),
            Self::TeamserverProfile(message) => serialize_message(
                serializer,
                &message.head,
                TeamserverCode::Profile.as_u32(),
                &message.info,
            ),
            Self::DatabaseDegraded(message) => serialize_message(
                serializer,
                &message.head,
                TeamserverCode::DatabaseDegraded.as_u32(),
                &message.info,
            ),
            Self::DatabaseRecovered(message) => serialize_message(
                serializer,
                &message.head,
                TeamserverCode::DatabaseRecovered.as_u32(),
                &message.info,
            ),
        }
    }
}
