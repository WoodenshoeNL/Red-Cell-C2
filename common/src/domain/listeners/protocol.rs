//! Listener protocol enum and parsing logic.

use std::fmt;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::CommonError;

/// Supported listener transport families.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ListenerProtocol {
    /// HTTP or HTTPS transport.
    Http,
    /// SMB pivot transport.
    Smb,
    /// DNS C2 transport.
    Dns,
    /// External C2 bridge transport.
    External,
}

impl ListenerProtocol {
    /// Parse a listener protocol string using Havoc-compatible names.
    pub fn try_from_str(protocol: &str) -> Result<Self, CommonError> {
        match protocol {
            value if value.eq_ignore_ascii_case("http") || value.eq_ignore_ascii_case("https") => {
                Ok(Self::Http)
            }
            value if value.eq_ignore_ascii_case("smb") => Ok(Self::Smb),
            value if value.eq_ignore_ascii_case("dns") => Ok(Self::Dns),
            value if value.eq_ignore_ascii_case("external") => Ok(Self::External),
            _ => Err(CommonError::UnsupportedListenerProtocol { protocol: protocol.to_string() }),
        }
    }

    /// Return the canonical protocol label used by Red Cell.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Smb => "smb",
            Self::Dns => "dns",
            Self::External => "external",
        }
    }
}

impl fmt::Display for ListenerProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
