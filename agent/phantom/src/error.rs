//! Error types returned by the Phantom agent.

use std::path::PathBuf;

use red_cell_common::agent_protocol::AgentProtocolError;
use red_cell_common::crypto::CryptoError;
use red_cell_common::demon::DemonProtocolError;
use thiserror::Error;

/// Top-level error type for Phantom.
#[derive(Debug, Error)]
pub enum PhantomError {
    /// Command-line argument parsing failed.
    #[error("argument error: {0}")]
    Argument(String),

    /// Protocol encoding or decoding failed.
    #[error("protocol error: {0}")]
    Protocol(#[from] DemonProtocolError),

    /// Session crypto failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// HTTP transport failed.
    #[error("transport error: {0}")]
    Transport(String),

    /// The agent received malformed task data.
    #[error("task parse error: {0}")]
    TaskParse(&'static str),

    /// A required operating-system operation failed.
    #[error("io error on {path:?}: {message}")]
    Io {
        /// Path involved in the operation.
        path: PathBuf,
        /// Source error text.
        message: String,
    },

    /// A child process operation failed.
    #[error("process error: {0}")]
    Process(String),

    /// A socket operation failed.
    #[error("socket error: {0}")]
    Socket(String),

    /// Configuration is invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),

    /// Teamserver response did not match the expected wire format.
    #[error("invalid teamserver response: {0}")]
    InvalidResponse(&'static str),

    /// Screenshot capture failed.
    #[error("screenshot error: {0}")]
    Screenshot(String),
}

impl From<AgentProtocolError> for PhantomError {
    fn from(e: AgentProtocolError) -> Self {
        match e {
            AgentProtocolError::Protocol(inner) => PhantomError::Protocol(inner),
            AgentProtocolError::Crypto(inner) => PhantomError::Crypto(inner),
            AgentProtocolError::InvalidResponse(msg) => PhantomError::InvalidResponse(msg),
        }
    }
}
