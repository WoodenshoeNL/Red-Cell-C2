//! Shared error types used by teamserver and client domain models.

use thiserror::Error;

/// Errors returned by common-domain parsing and validation helpers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommonError {
    /// A listener protocol string did not match a supported variant.
    #[error("unsupported listener protocol `{protocol}`")]
    UnsupportedListenerProtocol { protocol: String },
    /// An agent identifier could not be parsed from a decimal or hex string.
    #[error("invalid agent identifier `{value}`")]
    InvalidAgentId { value: String },
}
