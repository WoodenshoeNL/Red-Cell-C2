//! Phantom library surface for tests and alternate entrypoints.

pub mod agent;
mod command;
pub mod config;
pub mod error;
mod parser;
pub mod protocol;
pub mod transport;

pub use agent::PhantomAgent;
pub use config::PhantomConfig;
pub use error::PhantomError;
