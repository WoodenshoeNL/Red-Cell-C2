//! Shared operator message envelope and JSON wire helpers.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

use super::codes::EventCode;

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
pub(super) struct IncomingBody {
    #[serde(rename = "SubEvent")]
    pub(super) sub_event: u32,
    #[serde(rename = "Info", default)]
    pub(super) info: Value,
}

#[derive(Deserialize)]
pub(super) struct IncomingMessage {
    #[serde(rename = "Head")]
    pub(super) head: MessageHead,
    #[serde(rename = "Body")]
    pub(super) body: IncomingBody,
}

pub(super) fn serialize_message<S, T>(
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

pub(super) fn parse_info<T, E>(info: Value) -> Result<T, E>
where
    T: DeserializeOwned,
    E: serde::de::Error,
{
    serde_json::from_value(info).map_err(E::custom)
}
