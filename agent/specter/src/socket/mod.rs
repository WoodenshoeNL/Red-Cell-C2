//! Socket state management for SOCKS5 proxy and reverse port forwarding.
//!
//! This module implements the `CommandSocket` (ID 2540) handler for the Specter
//! agent. The wire protocol is identical to Phantom's implementation — all
//! response payloads use big-endian encoding, matching the teamserver's
//! socket callback parser.

mod socket_io;
pub mod socket_state;
mod types;

pub use socket_state::{SocketError, SocketState};

#[cfg(test)]
#[path = "socket_tests.rs"]
mod tests;
