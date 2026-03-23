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
    use base64::Engine as _;
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

    /// Verifies that `ListenerInfo` extra fields (via `#[serde(flatten)]`) survive
    /// a JSON round-trip and appear at the top level alongside named fields.
    #[test]
    fn listener_info_extra_fields_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let info = ListenerInfo {
            name: Some("smb-pivot".to_string()),
            protocol: Some("Smb".to_string()),
            extra: BTreeMap::from([
                ("CustomField".to_string(), json!("custom_value")),
                ("PipeName".to_string(), json!("\\\\.\\pipe\\demon")),
            ]),
            ..ListenerInfo::default()
        };

        // Serialize and verify extra fields appear at the top level
        let json_value = serde_json::to_value(&info)?;
        let obj = json_value.as_object().expect("serialized ListenerInfo should be an object");
        assert_eq!(obj.get("CustomField"), Some(&json!("custom_value")));
        assert_eq!(obj.get("PipeName"), Some(&json!("\\\\.\\pipe\\demon")));
        assert_eq!(obj.get("Name"), Some(&json!("smb-pivot")));
        assert_eq!(obj.get("Protocol"), Some(&json!("Smb")));

        // Deserialize back and verify extra fields are preserved
        let decoded: ListenerInfo = serde_json::from_value(json_value)?;
        assert_eq!(decoded.name, Some("smb-pivot".to_string()));
        assert_eq!(decoded.protocol, Some("Smb".to_string()));
        assert_eq!(decoded.extra.get("CustomField"), Some(&json!("custom_value")));
        assert_eq!(decoded.extra.get("PipeName"), Some(&json!("\\\\.\\pipe\\demon")));
        // Named fields must not leak into extra
        assert!(!decoded.extra.contains_key("Name"));
        assert!(!decoded.extra.contains_key("Protocol"));

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
    fn build_payload_request_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let message = OperatorMessage::BuildPayloadRequest(Message {
            head: MessageHead {
                event: EventCode::Gate,
                user: "operator".to_string(),
                timestamp: "09/03/2026 19:00:00".to_string(),
                one_time: String::new(),
            },
            info: BuildPayloadRequestInfo {
                agent_type: "Demon".to_string(),
                listener: "http-listener".to_string(),
                arch: "x64".to_string(),
                format: "Windows Exe".to_string(),
                config: r#"{"Sleep":5,"Jitter":10}"#.to_string(),
            },
        });

        let encoded = serde_json::to_value(&message)?;

        // All renamed fields must survive serialization.
        assert_eq!(encoded.pointer("/Body/Info/AgentType"), Some(&json!("Demon")));
        assert_eq!(encoded.pointer("/Body/Info/Listener"), Some(&json!("http-listener")));
        assert_eq!(encoded.pointer("/Body/Info/Arch"), Some(&json!("x64")));
        assert_eq!(encoded.pointer("/Body/Info/Format"), Some(&json!("Windows Exe")));
        assert_eq!(
            encoded.pointer("/Body/Info/Config"),
            Some(&json!(r#"{"Sleep":5,"Jitter":10}"#))
        );

        let decoded: OperatorMessage = serde_json::from_value(encoded)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    #[test]
    fn build_payload_response_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let payload_bytes = b"binary payload data";
        let encoded_payload = base64::engine::general_purpose::STANDARD.encode(payload_bytes);

        let message = OperatorMessage::BuildPayloadResponse(Message {
            head: MessageHead {
                event: EventCode::Gate,
                user: String::new(),
                timestamp: "09/03/2026 19:00:00".to_string(),
                one_time: String::new(),
            },
            info: BuildPayloadResponseInfo {
                payload_array: encoded_payload.clone(),
                format: "Windows Exe".to_string(),
                file_name: "demon.exe".to_string(),
            },
        });

        let encoded = serde_json::to_value(&message)?;

        // All renamed fields must survive serialization.
        assert_eq!(encoded.pointer("/Body/Info/PayloadArray"), Some(&json!(encoded_payload)));
        assert_eq!(encoded.pointer("/Body/Info/Format"), Some(&json!("Windows Exe")));
        assert_eq!(encoded.pointer("/Body/Info/FileName"), Some(&json!("demon.exe")));

        let decoded: OperatorMessage = serde_json::from_value(encoded)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    #[test]
    fn build_payload_response_partial_fields() -> Result<(), Box<dyn std::error::Error>> {
        // All three fields are required; a message with only them (no extras) must decode cleanly.
        let value = json!({
            "Head": { "Event": 5, "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 2,
                "Info": {
                    "PayloadArray": "QUJD",
                    "Format": "shellcode",
                    "FileName": "payload.bin"
                }
            }
        });

        let decoded: OperatorMessage = serde_json::from_value(value)?;
        let OperatorMessage::BuildPayloadResponse(msg) = decoded else {
            panic!("expected BuildPayloadResponse");
        };
        assert_eq!(msg.info.payload_array, "QUJD");
        assert_eq!(msg.info.format, "shellcode");
        assert_eq!(msg.info.file_name, "payload.bin");
        Ok(())
    }

    #[test]
    fn build_payload_missing_request_fields_falls_through_to_message()
    -> Result<(), Box<dyn std::error::Error>> {
        // Info has neither request nor response fields — should fall through
        // to BuildPayloadMessage.
        let value = json!({
            "Head": { "Event": 5, "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 2,
                "Info": {
                    "MessageType": "Info",
                    "Message": "building payload..."
                }
            }
        });

        let decoded: OperatorMessage = serde_json::from_value(value)?;
        assert!(
            matches!(decoded, OperatorMessage::BuildPayloadMessage(_)),
            "payload with only message fields should decode as BuildPayloadMessage, got {decoded:?}"
        );
        Ok(())
    }

    #[test]
    fn build_payload_wrong_type_in_response_fields_rejects_cleanly() {
        // PayloadArray is a number instead of string — response parsing fails,
        // request parsing fails (missing required fields), and fallback message
        // parsing also fails (missing MessageType/Message). The entire
        // deserialization must fail rather than silently accepting the wrong variant.
        let value = json!({
            "Head": { "Event": 5, "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 2,
                "Info": {
                    "PayloadArray": 12345,
                    "Format": "shellcode",
                    "FileName": "payload.bin"
                }
            }
        });

        let result = serde_json::from_value::<OperatorMessage>(value);
        assert!(
            result.is_err(),
            "wrong-typed fields matching no variant must fail deserialization"
        );
    }

    #[test]
    fn build_payload_empty_info_rejects_cleanly() {
        // Empty Info object — neither request, response, nor message fields present.
        // All three try-parses fail, returning a clean deserialization error.
        let value = json!({
            "Head": { "Event": 5, "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 2,
                "Info": {}
            }
        });

        let result = serde_json::from_value::<OperatorMessage>(value);
        assert!(
            result.is_err(),
            "empty Info matching no BuildPayload variant must fail deserialization"
        );
    }

    #[test]
    fn build_payload_request_rejects_wrong_type_for_required_field() {
        // AgentType as a number instead of string — should fail direct deserialization.
        let value = json!({
            "AgentType": 42,
            "Listener": "http",
            "Arch": "x64",
            "Format": "Windows Exe",
            "Config": "{}"
        });

        let result = serde_json::from_value::<BuildPayloadRequestInfo>(value);
        assert!(result.is_err(), "BuildPayloadRequestInfo must reject non-string AgentType");
    }

    #[test]
    fn build_payload_response_rejects_missing_required_field() {
        // Missing FileName — should fail deserialization.
        let value = json!({
            "PayloadArray": "QUJD",
            "Format": "shellcode"
        });

        let result = serde_json::from_value::<BuildPayloadResponseInfo>(value);
        assert!(result.is_err(), "BuildPayloadResponseInfo must reject missing FileName");
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
    fn numeric_codes_reject_unknown_values_during_deserialization() {
        let cases = [
            (
                serde_json::from_value::<EventCode>(json!(0xffff_u32))
                    .expect_err("unknown EventCode must fail"),
                "EventCode",
            ),
            (
                serde_json::from_value::<InitConnectionCode>(json!(0xffff_u32))
                    .expect_err("unknown InitConnectionCode must fail"),
                "InitConnectionCode",
            ),
            (
                serde_json::from_value::<SessionCode>(json!(0xffff_u32))
                    .expect_err("unknown SessionCode must fail"),
                "SessionCode",
            ),
            (
                serde_json::from_value::<ListenerCode>(json!(0xffff_u32))
                    .expect_err("unknown ListenerCode must fail"),
                "ListenerCode",
            ),
        ];

        for (error, enum_name) in cases {
            assert!(error.to_string().contains(&format!("unsupported {enum_name} code")));
        }
    }

    #[test]
    fn rejects_unknown_operator_event_code() {
        let value = json!({
            "Head": { "Event": 255, "Time": "09/03/2026 19:00:00" },
            "Body": { "SubEvent": 1, "Info": {} }
        });

        let error = serde_json::from_value::<OperatorMessage>(value)
            .expect_err("unsupported event code must fail");

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
            "Head": { "Event": 1, "Time": "09/03/2026 19:00:00" },
            "Body": { "SubEvent": 255, "Info": {} }
        });

        let error = serde_json::from_value::<OperatorMessage>(value)
            .expect_err("unsupported subevent must fail");

        assert!(error.to_string().contains("unsupported operator message"));
    }

    // ── numeric_code! macro round-trip tests ────────────────────────────────

    /// Every variant of every numeric_code! enum must satisfy:
    ///   as_u32() returns the declared literal, and
    ///   from_u32(as_u32(v)) == Some(v)
    #[test]
    fn event_code_as_u32_and_round_trip() {
        let cases = [
            (EventCode::InitConnection, 0x1_u32),
            (EventCode::Listener, 0x2),
            (EventCode::Credentials, 0x3),
            (EventCode::Chat, 0x4),
            (EventCode::Gate, 0x5),
            (EventCode::HostFile, 0x6),
            (EventCode::Session, 0x7),
            (EventCode::Service, 0x9),
            (EventCode::Teamserver, 0x10),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.as_u32(), expected, "EventCode::{variant:?} wire value");
            assert_eq!(EventCode::from_u32(expected), Some(variant));
        }
    }

    #[test]
    fn init_connection_code_as_u32_and_round_trip() {
        let cases = [
            (InitConnectionCode::Success, 0x1_u32),
            (InitConnectionCode::Error, 0x2),
            (InitConnectionCode::Login, 0x3),
            (InitConnectionCode::InitInfo, 0x4),
            (InitConnectionCode::Profile, 0x5),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.as_u32(), expected, "InitConnectionCode::{variant:?} wire value");
            assert_eq!(InitConnectionCode::from_u32(expected), Some(variant));
        }
    }

    #[test]
    fn listener_code_as_u32_and_round_trip() {
        let cases = [
            (ListenerCode::New, 0x1_u32),
            (ListenerCode::Edit, 0x2),
            (ListenerCode::Remove, 0x3),
            (ListenerCode::Mark, 0x4),
            (ListenerCode::Error, 0x5),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.as_u32(), expected, "ListenerCode::{variant:?} wire value");
            assert_eq!(ListenerCode::from_u32(expected), Some(variant));
        }
    }

    #[test]
    fn credentials_code_as_u32_and_round_trip() {
        let cases = [
            (CredentialsCode::Add, 0x1_u32),
            (CredentialsCode::Edit, 0x2),
            (CredentialsCode::Remove, 0x3),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.as_u32(), expected, "CredentialsCode::{variant:?} wire value");
            assert_eq!(CredentialsCode::from_u32(expected), Some(variant));
        }
    }

    #[test]
    fn chat_code_as_u32_and_round_trip() {
        let cases = [
            (ChatCode::Message, 0x1_u32),
            (ChatCode::Listener, 0x2),
            (ChatCode::Agent, 0x3),
            (ChatCode::UserConnected, 0x4),
            (ChatCode::UserDisconnected, 0x5),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.as_u32(), expected, "ChatCode::{variant:?} wire value");
            assert_eq!(ChatCode::from_u32(expected), Some(variant));
        }
    }

    #[test]
    fn gate_code_as_u32_and_round_trip() {
        let cases =
            [(GateCode::Staged, 0x1_u32), (GateCode::BuildPayload, 0x2), (GateCode::MsOffice, 0x3)];
        for (variant, expected) in cases {
            assert_eq!(variant.as_u32(), expected, "GateCode::{variant:?} wire value");
            assert_eq!(GateCode::from_u32(expected), Some(variant));
        }
    }

    #[test]
    fn host_file_code_as_u32_and_round_trip() {
        let cases = [(HostFileCode::Add, 0x1_u32), (HostFileCode::Remove, 0x2)];
        for (variant, expected) in cases {
            assert_eq!(variant.as_u32(), expected, "HostFileCode::{variant:?} wire value");
            assert_eq!(HostFileCode::from_u32(expected), Some(variant));
        }
    }

    #[test]
    fn session_code_as_u32_and_round_trip() {
        let cases = [
            (SessionCode::AgentNew, 0x1_u32),
            (SessionCode::AgentRemove, 0x2),
            (SessionCode::AgentTask, 0x3),
            (SessionCode::AgentResponse, 0x4),
            (SessionCode::AgentUpdate, 0x5),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.as_u32(), expected, "SessionCode::{variant:?} wire value");
            assert_eq!(SessionCode::from_u32(expected), Some(variant));
        }
    }

    #[test]
    fn service_code_as_u32_and_round_trip() {
        let cases = [(ServiceCode::RegisterAgent, 0x1_u32), (ServiceCode::RegisterListener, 0x2)];
        for (variant, expected) in cases {
            assert_eq!(variant.as_u32(), expected, "ServiceCode::{variant:?} wire value");
            assert_eq!(ServiceCode::from_u32(expected), Some(variant));
        }
    }

    #[test]
    fn teamserver_code_as_u32_and_round_trip() {
        let cases = [(TeamserverCode::Log, 0x1_u32), (TeamserverCode::Profile, 0x2)];
        for (variant, expected) in cases {
            assert_eq!(variant.as_u32(), expected, "TeamserverCode::{variant:?} wire value");
            assert_eq!(TeamserverCode::from_u32(expected), Some(variant));
        }
    }

    #[test]
    fn misc_code_as_u32_and_round_trip() {
        assert_eq!(MiscCode::MessageBox.as_u32(), 0x1_u32);
        assert_eq!(MiscCode::from_u32(0x1), Some(MiscCode::MessageBox));
    }

    // ── from_u32 unknown-value rejection ────────────────────────────────────

    /// from_u32 must return None (not panic) for values that have no matching variant.
    #[test]
    fn from_u32_returns_none_for_unknown_values() {
        assert_eq!(EventCode::from_u32(0), None);
        assert_eq!(EventCode::from_u32(u32::MAX), None);
        assert_eq!(InitConnectionCode::from_u32(0), None);
        assert_eq!(InitConnectionCode::from_u32(u32::MAX), None);
        assert_eq!(ListenerCode::from_u32(0), None);
        assert_eq!(ListenerCode::from_u32(u32::MAX), None);
        assert_eq!(CredentialsCode::from_u32(0), None);
        assert_eq!(CredentialsCode::from_u32(u32::MAX), None);
        assert_eq!(ChatCode::from_u32(0), None);
        assert_eq!(ChatCode::from_u32(u32::MAX), None);
        assert_eq!(GateCode::from_u32(0), None);
        assert_eq!(GateCode::from_u32(u32::MAX), None);
        assert_eq!(HostFileCode::from_u32(0), None);
        assert_eq!(HostFileCode::from_u32(u32::MAX), None);
        assert_eq!(SessionCode::from_u32(0), None);
        assert_eq!(SessionCode::from_u32(u32::MAX), None);
        assert_eq!(ServiceCode::from_u32(0), None);
        assert_eq!(ServiceCode::from_u32(u32::MAX), None);
        assert_eq!(TeamserverCode::from_u32(0), None);
        assert_eq!(TeamserverCode::from_u32(u32::MAX), None);
        assert_eq!(MiscCode::from_u32(0), None);
        assert_eq!(MiscCode::from_u32(u32::MAX), None);
    }

    // ── JSON wire-value assertions ───────────────────────────────────────────

    /// Serializing a numeric_code! enum via serde_json must produce the correct
    /// integer literal on the wire, and deserializing that integer must recover
    /// the original variant.
    #[test]
    fn event_code_json_wire_values() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (EventCode::InitConnection, json!(1_u32)),
            (EventCode::Listener, json!(2_u32)),
            (EventCode::Credentials, json!(3_u32)),
            (EventCode::Chat, json!(4_u32)),
            (EventCode::Gate, json!(5_u32)),
            (EventCode::HostFile, json!(6_u32)),
            (EventCode::Session, json!(7_u32)),
            (EventCode::Service, json!(9_u32)),
            (EventCode::Teamserver, json!(16_u32)),
        ];
        for (variant, expected_wire) in cases {
            let serialized = serde_json::to_value(variant)?;
            assert_eq!(serialized, expected_wire, "EventCode::{variant:?} JSON wire value");
            let deserialized: EventCode = serde_json::from_value(expected_wire)?;
            assert_eq!(deserialized, variant);
        }
        Ok(())
    }

    #[test]
    fn sub_event_codes_json_wire_values() -> Result<(), Box<dyn std::error::Error>> {
        // Spot-check one variant per sub-code enum to verify the serializer
        // emits the correct integer rather than a string or object.
        assert_eq!(serde_json::to_value(InitConnectionCode::Login)?, json!(3_u32));
        assert_eq!(serde_json::to_value(ListenerCode::Mark)?, json!(4_u32));
        assert_eq!(serde_json::to_value(CredentialsCode::Edit)?, json!(2_u32));
        assert_eq!(serde_json::to_value(ChatCode::UserDisconnected)?, json!(5_u32));
        assert_eq!(serde_json::to_value(GateCode::BuildPayload)?, json!(2_u32));
        assert_eq!(serde_json::to_value(HostFileCode::Remove)?, json!(2_u32));
        assert_eq!(serde_json::to_value(SessionCode::AgentResponse)?, json!(4_u32));
        assert_eq!(serde_json::to_value(ServiceCode::RegisterListener)?, json!(2_u32));
        assert_eq!(serde_json::to_value(TeamserverCode::Profile)?, json!(2_u32));
        assert_eq!(serde_json::to_value(MiscCode::MessageBox)?, json!(1_u32));
        Ok(())
    }

    // ── AgentInfo deserialization edge cases ─────────────────────────────────

    /// An `AgentNew` message whose `Info` object is completely empty must fail
    /// deserialization — all non-`#[serde(default)]` fields are required.
    #[test]
    fn agent_info_empty_info_object_fails_deserialization() {
        let value = json!({
            "Head": { "Event": 7, "Time": "09/03/2026 19:05:00" },
            "Body": { "SubEvent": 1, "Info": {} }
        });

        serde_json::from_value::<OperatorMessage>(value)
            .expect_err("empty Info object must fail: all AgentInfo fields are required");
    }

    /// `SleepDelay: null` and `KillDate: null` (both `serde_json::Value`) must
    /// survive a serialize → deserialize round-trip as `Value::Null`.
    #[test]
    fn agent_info_null_value_fields_round_trip() -> Result<(), Box<dyn std::error::Error>> {
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
                elevated: false,
                internal_ip: "10.0.0.1".to_string(),
                external_ip: "203.0.113.1".to_string(),
                first_call_in: "09/03/2026 19:04:00".to_string(),
                last_call_in: "09/03/2026 19:05:00".to_string(),
                hostname: "host".to_string(),
                listener: "http".to_string(),
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
                reason: String::new(),
                note: String::new(),
                sleep_delay: Value::Null,
                sleep_jitter: Value::Null,
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

        // All four Value::Null fields must appear as JSON null on the wire.
        assert_eq!(encoded.pointer("/Body/Info/SleepDelay"), Some(&Value::Null));
        assert_eq!(encoded.pointer("/Body/Info/SleepJitter"), Some(&Value::Null));
        assert_eq!(encoded.pointer("/Body/Info/KillDate"), Some(&Value::Null));
        assert_eq!(encoded.pointer("/Body/Info/WorkingHours"), Some(&Value::Null));

        let decoded: OperatorMessage = serde_json::from_value(encoded)?;
        assert_eq!(decoded, message);
        Ok(())
    }

    /// A minimal `AgentNew` JSON message that omits every `#[serde(default)]`
    /// field must deserialize successfully, with all omitted fields receiving
    /// their default values.
    #[test]
    fn agent_info_minimal_fields_defaults_optional() -> Result<(), Box<dyn std::error::Error>> {
        let value = json!({
            "Head": { "Event": 7, "Time": "09/03/2026 19:05:00" },
            "Body": {
                "SubEvent": 1,
                "Info": {
                    "Active": "",
                    "BackgroundCheck": false,
                    "DomainName": "",
                    "Elevated": false,
                    "InternalIP": "",
                    "ExternalIP": "",
                    "FirstCallIn": "",
                    "LastCallIn": "",
                    "Hostname": "",
                    "Listener": "",
                    "MagicValue": "",
                    "NameID": "",
                    "OSArch": "",
                    "OSBuild": "",
                    "OSVersion": "",
                    "Pivots": {},
                    "ProcessArch": "",
                    "ProcessName": "",
                    "ProcessPID": "",
                    "ProcessPPID": "",
                    "ProcessPath": "",
                    "Reason": "",
                    "SleepDelay": null,
                    "SleepJitter": null,
                    "KillDate": null,
                    "WorkingHours": null,
                    "TaskedOnce": false,
                    "Username": "",
                    "PivotParent": ""
                    // PortFwds, Note, SocksCli, SocksCliMtx, SocksSvr are intentionally absent.
                }
            }
        });

        let decoded: OperatorMessage = serde_json::from_value(value)?;
        let OperatorMessage::AgentNew(msg) = decoded else {
            panic!("expected AgentNew variant");
        };

        // Fields absent from the JSON must have their serde default values.
        assert_eq!(msg.info.port_fwds, Vec::<String>::new(), "PortFwds must default to []");
        assert_eq!(msg.info.note, "", "Note must default to empty string");
        assert_eq!(msg.info.socks_cli, Vec::<String>::new(), "SocksCli must default to []");
        assert_eq!(msg.info.socks_cli_mtx, None, "SocksCliMtx must default to None");
        assert_eq!(msg.info.socks_svr, Vec::<String>::new(), "SocksSvr must default to []");

        // Required fields must match exactly what was sent.
        assert_eq!(msg.info.active, "");
        assert_eq!(msg.info.magic_value, "");
        assert_eq!(msg.info.sleep_delay, Value::Null);
        assert_eq!(msg.info.kill_date, Value::Null);
        Ok(())
    }

    /// Deserialization must fail with a clear error when `Head` is missing.
    #[test]
    fn operator_message_rejects_missing_head() {
        let value = json!({
            "Body": { "SubEvent": 3, "Info": { "User": "operator", "Password": "secret" } }
        });

        let err = serde_json::from_value::<OperatorMessage>(value)
            .expect_err("missing Head must fail deserialization");
        assert!(
            err.to_string().contains("Head"),
            "error should mention the missing field 'Head', got: {err}"
        );
    }

    /// Deserialization must fail with a clear error when `Body` is missing.
    #[test]
    fn operator_message_rejects_missing_body() {
        let value = json!({
            "Head": { "Event": 1, "User": "operator", "Time": "09/03/2026 19:00:00" }
        });

        let err = serde_json::from_value::<OperatorMessage>(value)
            .expect_err("missing Body must fail deserialization");
        assert!(
            err.to_string().contains("Body"),
            "error should mention the missing field 'Body', got: {err}"
        );
    }

    /// Deserialization must fail when the JSON object is completely empty.
    #[test]
    fn operator_message_rejects_empty_object() {
        let value = json!({});

        let err = serde_json::from_value::<OperatorMessage>(value)
            .expect_err("empty object must fail deserialization");
        // serde will complain about the first missing required field.
        let msg = err.to_string();
        assert!(
            msg.contains("Head") || msg.contains("Body"),
            "error should mention a missing top-level key, got: {err}"
        );
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

    /// Extra unknown top-level JSON keys (beyond `Head` and `Body`) must be
    /// silently ignored for forward-compatibility with newer Havoc clients.
    #[test]
    fn extra_top_level_keys_are_silently_ignored() -> Result<(), Box<dyn std::error::Error>> {
        let value = json!({
            "Head": { "Event": 1, "User": "operator", "Time": "09/03/2026 19:00:00" },
            "Body": {
                "SubEvent": 3,
                "Info": { "User": "operator", "Password": "deadbeef" }
            },
            "Debug": true,
            "Version": 42,
            "Extra": { "nested": "data" }
        });

        let decoded: OperatorMessage = serde_json::from_value(value)?;
        let expected = OperatorMessage::Login(Message {
            head: head(EventCode::InitConnection),
            info: LoginInfo { user: "operator".to_string(), password: "deadbeef".to_string() },
        });
        assert_eq!(decoded, expected);
        Ok(())
    }

    /// Verify that `AgentResponseInfo` with `command_line: None` omits the
    /// `CommandLine` key entirely (via `skip_serializing_if`) and round-trips
    /// correctly.
    #[test]
    fn agent_response_info_none_command_line_skipped() -> Result<(), Box<dyn std::error::Error>> {
        let info = AgentResponseInfo {
            demon_id: "DEAD0001".to_string(),
            command_id: "10".to_string(),
            output: "data".to_string(),
            command_line: None,
            extra: BTreeMap::new(),
        };

        let json = serde_json::to_value(&info)?;
        let obj = json.as_object().expect("must be an object");

        // The key must be absent, not present-as-null.
        assert!(
            !obj.contains_key("CommandLine"),
            "CommandLine key must be omitted when command_line is None, got: {json}"
        );

        // Round-trip: deserializing back must yield the same value.
        let deserialized: AgentResponseInfo = serde_json::from_value(json)?;
        assert_eq!(deserialized.command_line, None);
        assert_eq!(deserialized, info);

        Ok(())
    }
}
