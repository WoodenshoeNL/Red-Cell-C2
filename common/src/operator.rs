//! JSON-over-WebSocket operator protocol types.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use utoipa::ToSchema;

macro_rules! numeric_code {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($variant:ident = $value:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        $vis enum $name {
            $($variant),+
        }

        impl $name {
            /// Returns the numeric code used on the wire.
            #[must_use]
            pub const fn as_u32(self) -> u32 {
                match self {
                    $(Self::$variant => $value),+
                }
            }

            fn from_u32(value: u32) -> Option<Self> {
                match value {
                    $($value => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_u32(self.as_u32())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = u32::deserialize(deserializer)?;
                Self::from_u32(value).ok_or_else(|| {
                    serde::de::Error::custom(format!(
                        "unsupported {} code {value:#x}",
                        stringify!($name)
                    ))
                })
            }
        }
    };
}

numeric_code! {
    /// Top-level Havoc operator protocol event family.
    pub enum EventCode {
        InitConnection = 0x1,
        Listener = 0x2,
        Credentials = 0x3,
        Chat = 0x4,
        Gate = 0x5,
        HostFile = 0x6,
        Session = 0x7,
        Service = 0x9,
        Teamserver = 0x10,
    }
}

numeric_code! {
    /// `InitConnection` subevents.
    pub enum InitConnectionCode {
        Success = 0x1,
        Error = 0x2,
        Login = 0x3,
        InitInfo = 0x4,
        Profile = 0x5,
    }
}

numeric_code! {
    /// `Listener` subevents.
    pub enum ListenerCode {
        New = 0x1,
        Edit = 0x2,
        Remove = 0x3,
        Mark = 0x4,
        Error = 0x5,
    }
}

numeric_code! {
    /// `Credentials` subevents.
    pub enum CredentialsCode {
        Add = 0x1,
        Edit = 0x2,
        Remove = 0x3,
    }
}

numeric_code! {
    /// `Chat` subevents.
    pub enum ChatCode {
        Message = 0x1,
        Listener = 0x2,
        Agent = 0x3,
        UserConnected = 0x4,
        UserDisconnected = 0x5,
    }
}

numeric_code! {
    /// `Gate` subevents.
    pub enum GateCode {
        Staged = 0x1,
        BuildPayload = 0x2,
        MsOffice = 0x3,
    }
}

numeric_code! {
    /// `HostFile` subevents.
    pub enum HostFileCode {
        Add = 0x1,
        Remove = 0x2,
    }
}

numeric_code! {
    /// `Session` subevents.
    pub enum SessionCode {
        AgentNew = 0x1,
        AgentRemove = 0x2,
        AgentTask = 0x3,
        AgentResponse = 0x4,
        AgentUpdate = 0x5,
    }
}

numeric_code! {
    /// `Service` subevents.
    pub enum ServiceCode {
        RegisterAgent = 0x1,
        RegisterListener = 0x2,
    }
}

numeric_code! {
    /// `Teamserver` subevents.
    pub enum TeamserverCode {
        Log = 0x1,
        Profile = 0x2,
    }
}

numeric_code! {
    /// `Misc` subevents.
    pub enum MiscCode {
        MessageBox = 0x1,
    }
}

/// Shared operator protocol message header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageHead {
    /// Numeric event family.
    #[serde(rename = "Event")]
    pub event: EventCode,
    /// Username associated with the message, when present.
    #[serde(rename = "User", default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    /// Timestamp string used by the legacy Havoc protocol.
    #[serde(
        rename = "Time",
        alias = "Timestamp",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub timestamp: String,
    /// Optional Havoc one-shot flag.
    #[serde(rename = "OneTime", default, skip_serializing_if = "String::is_empty")]
    pub one_time: String,
}

/// Shared typed message payload wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message<T> {
    /// Shared message header.
    pub head: MessageHead,
    /// Typed `Info` payload.
    pub info: T,
}

/// Unstructured `Info` payload for message types that are not yet strongly typed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatInfo {
    /// Extra protocol fields preserved verbatim.
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
}

/// Simple `{ "Message": ... }` payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageInfo {
    /// Human-readable status or error message.
    #[serde(rename = "Message")]
    pub message: String,
}

/// Login request payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginInfo {
    /// Operator username.
    #[serde(rename = "User")]
    pub user: String,
    /// SHA3-256 password hash, hex encoded.
    #[serde(rename = "Password", alias = "Password_SHA3")]
    pub password: String,
}

/// Initial profile transfer payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitProfileInfo {
    /// Serialized Demon profile JSON.
    #[serde(rename = "Demon")]
    pub demon: String,
    /// Comma-separated teamserver IP list.
    #[serde(rename = "TeamserverIPs")]
    pub teamserver_ips: String,
}

/// Listener create or edit payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerInfo {
    #[serde(rename = "Name", default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "Protocol", default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(rename = "Status", default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "Hosts", default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<String>,
    #[serde(rename = "HostBind", default, skip_serializing_if = "Option::is_none")]
    pub host_bind: Option<String>,
    #[serde(rename = "HostRotation", default, skip_serializing_if = "Option::is_none")]
    pub host_rotation: Option<String>,
    #[serde(rename = "PortBind", default, skip_serializing_if = "Option::is_none")]
    pub port_bind: Option<String>,
    #[serde(rename = "PortConn", default, skip_serializing_if = "Option::is_none")]
    pub port_conn: Option<String>,
    #[serde(rename = "Headers", default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<String>,
    #[serde(rename = "Uris", default, skip_serializing_if = "Option::is_none")]
    pub uris: Option<String>,
    #[serde(rename = "UserAgent", default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(rename = "Proxy Enabled", default, skip_serializing_if = "Option::is_none")]
    pub proxy_enabled: Option<String>,
    #[serde(rename = "Proxy Type", default, skip_serializing_if = "Option::is_none")]
    pub proxy_type: Option<String>,
    #[serde(rename = "Proxy Host", default, skip_serializing_if = "Option::is_none")]
    pub proxy_host: Option<String>,
    #[serde(rename = "Proxy Port", default, skip_serializing_if = "Option::is_none")]
    pub proxy_port: Option<String>,
    #[serde(rename = "Proxy Username", default, skip_serializing_if = "Option::is_none")]
    pub proxy_username: Option<String>,
    #[serde(rename = "Proxy Password", default, skip_serializing_if = "Option::is_none")]
    pub proxy_password: Option<String>,
    #[serde(rename = "Secure", default, skip_serializing_if = "Option::is_none")]
    pub secure: Option<String>,
    #[serde(rename = "Response Headers", default, skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// `{ "Name": ... }` payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameInfo {
    /// The named object identifier.
    #[serde(rename = "Name")]
    pub name: String,
}

/// Listener mark payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerMarkInfo {
    /// Listener name.
    #[serde(rename = "Name")]
    pub name: String,
    /// Desired mark.
    #[serde(rename = "Mark")]
    pub mark: String,
}

/// Listener error payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerErrorInfo {
    /// Listener creation or start error.
    #[serde(rename = "Error")]
    pub error: String,
    /// Listener name.
    #[serde(rename = "Name")]
    pub name: String,
}

/// Chat connection payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatUserInfo {
    /// Operator username.
    #[serde(rename = "User")]
    pub user: String,
}

/// Agent pivot metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPivotsInfo {
    /// Parent agent id, if present.
    #[serde(rename = "Parent", default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Child pivot links.
    #[serde(rename = "Links", default)]
    pub links: Vec<String>,
}

/// New agent/session payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInfo {
    #[serde(rename = "Active")]
    pub active: String,
    #[serde(rename = "BackgroundCheck")]
    pub background_check: bool,
    #[serde(rename = "DomainName")]
    pub domain_name: String,
    #[serde(rename = "Elevated")]
    pub elevated: bool,
    #[serde(rename = "InternalIP")]
    pub internal_ip: String,
    #[serde(rename = "ExternalIP")]
    pub external_ip: String,
    #[serde(rename = "FirstCallIn")]
    pub first_call_in: String,
    #[serde(rename = "LastCallIn")]
    pub last_call_in: String,
    #[serde(rename = "Hostname")]
    pub hostname: String,
    #[serde(rename = "Listener")]
    pub listener: String,
    #[serde(rename = "MagicValue")]
    pub magic_value: String,
    #[serde(rename = "NameID")]
    pub name_id: String,
    #[serde(rename = "OSArch")]
    pub os_arch: String,
    #[serde(rename = "OSBuild")]
    pub os_build: String,
    #[serde(rename = "OSVersion")]
    pub os_version: String,
    #[serde(rename = "Pivots")]
    pub pivots: AgentPivotsInfo,
    #[serde(rename = "PortFwds", default)]
    pub port_fwds: Vec<String>,
    #[serde(rename = "ProcessArch")]
    pub process_arch: String,
    #[serde(rename = "ProcessName")]
    pub process_name: String,
    #[serde(rename = "ProcessPID")]
    pub process_pid: String,
    #[serde(rename = "ProcessPPID")]
    pub process_ppid: String,
    #[serde(rename = "ProcessPath")]
    pub process_path: String,
    #[serde(rename = "Reason")]
    pub reason: String,
    #[serde(rename = "Note", default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    #[serde(rename = "SleepDelay")]
    pub sleep_delay: Value,
    #[serde(rename = "SleepJitter")]
    pub sleep_jitter: Value,
    #[serde(rename = "KillDate")]
    pub kill_date: Value,
    #[serde(rename = "WorkingHours")]
    pub working_hours: Value,
    #[serde(rename = "SocksCli", default)]
    pub socks_cli: Vec<String>,
    #[serde(rename = "SocksCliMtx", default, skip_serializing_if = "Option::is_none")]
    pub socks_cli_mtx: Option<Value>,
    #[serde(rename = "SocksSvr", default)]
    pub socks_svr: Vec<String>,
    #[serde(rename = "TaskedOnce")]
    pub tasked_once: bool,
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "PivotParent")]
    pub pivot_parent: String,
}

/// Agent task request payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AgentTaskInfo {
    #[serde(rename = "TaskID")]
    pub task_id: String,
    #[serde(rename = "CommandLine")]
    pub command_line: String,
    #[serde(rename = "DemonID")]
    pub demon_id: String,
    #[serde(rename = "CommandID")]
    pub command_id: String,
    #[serde(rename = "AgentType", default, skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    #[serde(rename = "TaskMessage", default, skip_serializing_if = "Option::is_none")]
    pub task_message: Option<String>,
    #[serde(rename = "Command", default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(rename = "SubCommand", default, skip_serializing_if = "Option::is_none")]
    pub sub_command: Option<String>,
    #[serde(rename = "Arguments", default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Agent output payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentResponseInfo {
    /// Target agent id.
    #[serde(rename = "DemonID")]
    pub demon_id: String,
    /// Command id or callback id.
    #[serde(rename = "CommandID")]
    pub command_id: String,
    /// Base64-encoded or raw output blob.
    #[serde(rename = "Output")]
    pub output: String,
    #[serde(rename = "CommandLine", default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Agent update payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentUpdateInfo {
    /// Target agent id.
    #[serde(rename = "AgentID")]
    pub agent_id: String,
    /// Update marker, usually `Alive` or `Dead`.
    #[serde(rename = "Marked")]
    pub marked: String,
}

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

/// Service agent registration payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAgentRegistrationInfo {
    /// Serialized service agent definition.
    #[serde(rename = "Agent")]
    pub agent: String,
}

/// Service listener registration payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceListenerRegistrationInfo {
    /// Serialized listener definition.
    #[serde(rename = "Listener")]
    pub listener: String,
}

/// Teamserver log payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamserverLogInfo {
    /// Log message text.
    #[serde(rename = "Text")]
    pub text: String,
}

/// Teamserver profile payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamserverProfileInfo {
    /// Serialized teamserver profile.
    #[serde(rename = "profile")]
    pub profile: String,
}

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
    ServiceAgentRegister(Message<ServiceAgentRegistrationInfo>),
    ServiceListenerRegister(Message<ServiceListenerRegistrationInfo>),
    TeamserverLog(Message<TeamserverLogInfo>),
    TeamserverProfile(Message<TeamserverProfileInfo>),
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
            | Self::AgentUpdate(_) => EventCode::Session,
            Self::ServiceAgentRegister(_) | Self::ServiceListenerRegister(_) => EventCode::Service,
            Self::TeamserverLog(_) | Self::TeamserverProfile(_) => EventCode::Teamserver,
        }
    }
}

#[derive(Serialize)]
struct RawBody<'a, T> {
    #[serde(rename = "SubEvent")]
    sub_event: u32,
    #[serde(rename = "Info")]
    info: &'a T,
}

#[derive(Serialize)]
struct RawMessage<'a, T> {
    #[serde(rename = "Head")]
    head: &'a MessageHead,
    #[serde(rename = "Body")]
    body: RawBody<'a, T>,
}

#[derive(Deserialize)]
struct IncomingBody {
    #[serde(rename = "SubEvent")]
    sub_event: u32,
    #[serde(rename = "Info", default)]
    info: Value,
}

#[derive(Deserialize)]
struct IncomingMessage {
    #[serde(rename = "Head")]
    head: MessageHead,
    #[serde(rename = "Body")]
    body: IncomingBody,
}

fn serialize_message<S, T>(
    serializer: S,
    head: &MessageHead,
    sub_event: u32,
    info: &T,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    RawMessage { head, body: RawBody { sub_event, info } }.serialize(serializer)
}

fn parse_info<T, E>(info: Value) -> Result<T, E>
where
    T: DeserializeOwned,
    E: serde::de::Error,
{
    serde_json::from_value(info).map_err(E::custom)
}

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
        }
    }
}

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
            (event, sub_event) => Err(serde::de::Error::custom(format!(
                "unsupported operator message event={event:?} sub_event={sub_event:#x}"
            ))),
        }
    }
}

impl fmt::Display for EventCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn head(event: EventCode) -> MessageHead {
        MessageHead {
            event,
            user: "operator".to_string(),
            timestamp: "09/03/2026 19:00:00".to_string(),
            one_time: String::new(),
        }
    }

    #[test]
    fn login_message_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let message = OperatorMessage::Login(Message {
            head: head(EventCode::InitConnection),
            info: LoginInfo { user: "operator".to_string(), password: "deadbeef".to_string() },
        });

        let value = serde_json::to_value(&message)?;
        assert_eq!(value["Head"]["Event"], json!(1));
        assert_eq!(value["Body"]["SubEvent"], json!(3));

        let decoded: OperatorMessage = serde_json::from_value(value)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    #[test]
    fn listener_message_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let message = OperatorMessage::ListenerNew(Message {
            head: head(EventCode::Listener),
            info: ListenerInfo {
                name: Some("http".to_string()),
                protocol: Some("Http".to_string()),
                status: Some("Online".to_string()),
                headers: Some("X-Test: 1".to_string()),
                host_bind: Some("0.0.0.0".to_string()),
                ..ListenerInfo::default()
            },
        });

        let decoded: OperatorMessage = serde_json::from_value(serde_json::to_value(&message)?)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    #[test]
    fn agent_task_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let message = OperatorMessage::AgentTask(Message {
            head: head(EventCode::Session),
            info: AgentTaskInfo {
                task_id: "task-1".to_string(),
                command_line: "sleep 5".to_string(),
                demon_id: "ABCD1234".to_string(),
                command_id: "11".to_string(),
                arguments: Some("5".to_string()),
                extra: BTreeMap::from([(String::from("FromProcessManager"), json!("false"))]),
                ..AgentTaskInfo::default()
            },
        });

        let decoded: OperatorMessage = serde_json::from_value(serde_json::to_value(&message)?)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    #[test]
    fn agent_new_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let message = OperatorMessage::AgentNew(Box::new(Message {
            head: MessageHead {
                event: EventCode::Session,
                user: String::new(),
                timestamp: "09/03/2026 19:05:00".to_string(),
                one_time: "true".to_string(),
            },
            info: AgentInfo {
                active: "true".to_string(),
                background_check: false,
                domain_name: "LAB".to_string(),
                elevated: true,
                internal_ip: "10.0.0.10".to_string(),
                external_ip: "203.0.113.10".to_string(),
                first_call_in: "09/03/2026 19:04:00".to_string(),
                last_call_in: "09/03/2026 19:05:00".to_string(),
                hostname: "wkstn-1".to_string(),
                listener: "null".to_string(),
                magic_value: "deadbeef".to_string(),
                name_id: "ABCD1234".to_string(),
                os_arch: "x64".to_string(),
                os_build: "19045".to_string(),
                os_version: "Windows 10".to_string(),
                pivots: AgentPivotsInfo { parent: None, links: Vec::new() },
                port_fwds: Vec::new(),
                process_arch: "x64".to_string(),
                process_name: "explorer.exe".to_string(),
                process_pid: "1234".to_string(),
                process_ppid: "1000".to_string(),
                process_path: "C:\\Windows\\explorer.exe".to_string(),
                reason: "manual".to_string(),
                note: "vpn foothold".to_string(),
                sleep_delay: json!(5),
                sleep_jitter: json!(10),
                kill_date: Value::Null,
                working_hours: Value::Null,
                socks_cli: Vec::new(),
                socks_cli_mtx: None,
                socks_svr: Vec::new(),
                tasked_once: false,
                username: "operator".to_string(),
                pivot_parent: String::new(),
            },
        }));

        let encoded = serde_json::to_value(&message)?;
        assert!(encoded.pointer("/Body/Info/Encryption").is_none());

        let decoded: OperatorMessage = serde_json::from_value(encoded)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    #[test]
    fn build_payload_variants_deserialize_by_shape() -> Result<(), Box<dyn std::error::Error>> {
        let request = json!({
            "Head": { "Event": 5, "User": "operator", "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 2,
                "Info": {
                    "AgentType": "Demon",
                    "Listener": "http",
                    "Arch": "x64",
                    "Format": "Windows Exe",
                    "Config": "{\"Sleep\":5}"
                }
            }
        });
        let response = json!({
            "Head": { "Event": 5, "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 2,
                "Info": {
                    "PayloadArray": "QUJD",
                    "Format": "Windows Exe",
                    "FileName": "payload.exe"
                }
            }
        });

        assert!(matches!(
            serde_json::from_value::<OperatorMessage>(request)?,
            OperatorMessage::BuildPayloadRequest(_)
        ));
        assert!(matches!(
            serde_json::from_value::<OperatorMessage>(response)?,
            OperatorMessage::BuildPayloadResponse(_)
        ));
        Ok(())
    }

    #[test]
    fn accepts_legacy_teamserver_profile_shape() -> Result<(), Box<dyn std::error::Error>> {
        let value = json!({
            "Head": { "Event": 16, "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 1,
                "Info": { "profile": "profile-data" }
            }
        });

        let decoded: OperatorMessage = serde_json::from_value(value)?;
        assert!(matches!(decoded, OperatorMessage::TeamserverProfile(_)));
        Ok(())
    }

    #[test]
    fn accepts_timestamp_alias() -> Result<(), Box<dyn std::error::Error>> {
        let value = json!({
            "Head": { "Event": 4, "User": "operator", "Timestamp": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 4,
                "Info": { "User": "alice" }
            }
        });

        let decoded: OperatorMessage = serde_json::from_value(value)?;
        assert!(matches!(decoded, OperatorMessage::ChatUserConnected(_)));
        Ok(())
    }

    #[test]
    fn message_head_skips_empty_optional_fields() -> Result<(), Box<dyn std::error::Error>> {
        let value = serde_json::to_value(MessageHead {
            event: EventCode::Chat,
            user: String::new(),
            timestamp: String::new(),
            one_time: String::new(),
        })?;

        assert_eq!(value, json!({ "Event": 4 }));
        Ok(())
    }

    #[test]
    fn numeric_codes_reject_unknown_values() {
        let error = serde_json::from_value::<EventCode>(json!(0xff))
            .expect_err("unknown event code must fail");

        assert!(error.to_string().contains("unsupported EventCode code"));
    }

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
            json!({
                "Head": { "Event": 1, "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 4, "Info": { "Version": "0.1.0", "Motd": "hello" } }
            }),
            json!({
                "Head": { "Event": 3, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 1, "Info": { "Realm": "LAB", "Username": "neo" } }
            }),
            json!({
                "Head": { "Event": 4, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 2, "Info": { "Name": "http", "Text": "listener online" } }
            }),
            json!({
                "Head": { "Event": 5, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 1, "Info": { "Listener": "http" } }
            }),
            json!({
                "Head": { "Event": 6, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 2, "Info": { "Path": "tmp.txt" } }
            }),
            json!({
                "Head": { "Event": 7, "User": "operator", "Time": "09/03/2026 19:00:00" },
                "Body": { "SubEvent": 2, "Info": { "AgentID": "ABCD1234" } }
            }),
        ];

        for value in cases {
            let message: OperatorMessage = serde_json::from_value(value.clone())?;
            let encoded = serde_json::to_value(&message)?;
            let reparsed: OperatorMessage = serde_json::from_value(encoded.clone())?;
            assert_eq!(reparsed, message);
            assert_eq!(encoded["Head"]["Event"], value["Head"]["Event"]);
        }

        Ok(())
    }

    #[test]
    fn remaining_typed_variants_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            OperatorMessage::InitConnectionError(Message {
                head: head(EventCode::InitConnection),
                info: MessageInfo { message: "denied".to_string() },
            }),
            OperatorMessage::InitConnectionProfile(Message {
                head: head(EventCode::InitConnection),
                info: InitProfileInfo {
                    demon: "{\"Sleep\":5}".to_string(),
                    teamserver_ips: "127.0.0.1".to_string(),
                },
            }),
            OperatorMessage::ListenerRemove(Message {
                head: head(EventCode::Listener),
                info: NameInfo { name: "http".to_string() },
            }),
            OperatorMessage::ListenerError(Message {
                head: head(EventCode::Listener),
                info: ListenerErrorInfo {
                    error: "bind failed".to_string(),
                    name: "http".to_string(),
                },
            }),
            OperatorMessage::ChatUserDisconnected(Message {
                head: head(EventCode::Chat),
                info: ChatUserInfo { user: "alice".to_string() },
            }),
            OperatorMessage::BuildPayloadMessage(Message {
                head: head(EventCode::Gate),
                info: BuildPayloadMessageInfo {
                    message_type: "Info".to_string(),
                    message: "staging".to_string(),
                },
            }),
            OperatorMessage::AgentResponse(Message {
                head: head(EventCode::Session),
                info: AgentResponseInfo {
                    demon_id: "ABCD1234".to_string(),
                    command_id: "94".to_string(),
                    output: "hello".to_string(),
                    command_line: Some("whoami".to_string()),
                    extra: BTreeMap::from([(String::from("Type"), json!("stdout"))]),
                },
            }),
            OperatorMessage::ServiceAgentRegister(Message {
                head: head(EventCode::Service),
                info: ServiceAgentRegistrationInfo { agent: "{}".to_string() },
            }),
            OperatorMessage::TeamserverLog(Message {
                head: head(EventCode::Teamserver),
                info: TeamserverLogInfo { text: "started".to_string() },
            }),
        ];

        for message in cases {
            let decoded: OperatorMessage = serde_json::from_value(serde_json::to_value(&message)?)?;
            assert_eq!(decoded, message);
        }

        Ok(())
    }

    #[test]
    fn rejects_unknown_operator_sub_event() {
        let value = json!({
            "Head": { "Event": 7, "Time": "09/03/2026 19:00:00" },
            "Body": { "SubEvent": 255, "Info": {} }
        });

        let error = serde_json::from_value::<OperatorMessage>(value)
            .expect_err("unsupported subevent must fail");

        assert!(error.to_string().contains("unsupported operator message"));
    }
}
