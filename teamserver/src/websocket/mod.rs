//! Operator WebSocket endpoint and connection tracking.

mod auth;
mod command_enc;
mod connection;
mod dispatch;
mod events;
mod handler;
mod lifecycle;
mod snapshot;
mod upload;

#[cfg(test)]
use crate::MAX_AGENT_MESSAGE_LEN;
#[cfg(test)]
use command_enc::{build_job, build_jobs, encode_utf16, write_len_prefixed_bytes, write_u32};

#[cfg(test)]
use connection::{
    AUTHENTICATION_FRAME_TIMEOUT, LOGIN_WINDOW_DURATION, MAX_FAILED_LOGIN_ATTEMPTS,
    MAX_LOGIN_ATTEMPT_WINDOWS, OPERATOR_MAX_MESSAGE_SIZE,
};
pub use connection::{ActiveOperatorInfo, LoginRateLimiter, OperatorConnectionManager};
#[cfg(test)]
use connection::DisconnectKind;
#[cfg(test)]
use dispatch::serialize_for_audit;
pub(crate) use dispatch::{AgentCommandError, execute_agent_task};
#[cfg(test)]
use events::teamserver_log_event;
pub use handler::{routes, websocket_handler};

#[cfg(test)]
mod tests;
