//! Error types for the Specter agent.

use red_cell_common::crypto::CryptoError;
use red_cell_common::demon::DemonProtocolError;
use thiserror::Error;

/// Top-level errors returned by the Specter agent.
#[derive(Debug, Error)]
pub enum SpecterError {
    /// A protocol encoding or decoding error occurred.
    #[error("protocol error: {0}")]
    Protocol(#[from] DemonProtocolError),

    /// A cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// An HTTP transport error occurred.
    #[error("transport error: {0}")]
    Transport(String),

    /// The teamserver returned an unexpected or invalid response.
    #[error("invalid server response: {0}")]
    InvalidResponse(&'static str),

    /// The agent configuration is invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),

    /// A command-line argument or environment variable was invalid.
    #[error("argument error: {0}")]
    Argument(String),
}
