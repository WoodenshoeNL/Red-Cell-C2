//! Phantom library surface for tests and alternate entrypoints.

pub mod agent;
mod command;
pub mod config;
pub mod ecdh;
pub mod error;
pub(crate) mod kerberos;
mod parser;
pub mod protocol;
pub mod sleep_obfuscate;
pub mod transport;

pub use agent::PhantomAgent;
pub use config::PhantomConfig;
pub use error::PhantomError;
pub use sleep_obfuscate::SleepMode;
