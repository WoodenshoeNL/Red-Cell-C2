//! Incoming Havoc Demon transport parsing for the teamserver.

mod ack;
pub(crate) mod callback;
mod init;
mod parser;
mod types;

pub use ack::{build_init_ack, build_reconnect_ack};
pub use parser::DemonPacketParser;
pub use types::{
    DemonCallbackPackage, DemonInitSecretConfig, DemonParserError, INIT_EXT_MONOTONIC_CTR,
    INIT_EXT_SEQ_PROTECTED, ParsedDemonInit, ParsedDemonPacket,
};

#[cfg(test)]
mod tests;
