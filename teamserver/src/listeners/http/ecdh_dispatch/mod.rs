//! ECDH packet processing for Phantom and Specter new-protocol agents.
//!
//! Incoming packets are classified as:
//! - **Registration**: first 16 bytes do NOT match a known `connection_id` in the DB,
//!   and length ≥ `ECDH_REG_MIN_LEN`. The server performs ECDH, registers the agent,
//!   and returns a response containing a new `ConnectionId` + encrypted ack.
//! - **Session**: first 16 bytes match a `connection_id` in the DB. The server decrypts
//!   the payload with the session key, routes to the command dispatcher, and returns
//!   an encrypted response.

mod classify;
mod parse;
mod registration;
mod session;
mod types;

pub(crate) use classify::process_ecdh_packet;
pub(crate) use types::EcdhOutcome;

#[cfg(test)]
mod tests;
