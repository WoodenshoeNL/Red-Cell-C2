//! Havoc wire numeric event and subevent codes.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
        OperatorManagement = 0x11,
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
        AgentReregistered = 0x6,
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
        DatabaseDegraded = 0x3,
        DatabaseRecovered = 0x4,
    }
}

numeric_code! {
    /// `Misc` subevents.
    pub enum MiscCode {
        MessageBox = 0x1,
    }
}

numeric_code! {
    /// `OperatorManagement` subevents (Red Cell extension).
    pub enum OperatorManagementCode {
        Create = 0x1,
        Remove = 0x2,
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
            (EventCode::OperatorManagement, 0x11),
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
            (SessionCode::AgentReregistered, 0x6),
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
}
