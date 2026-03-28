//! Specter library surface for tests and alternate entrypoints.

pub mod agent;
pub mod config;
pub mod dispatch;
pub mod error;
pub mod protocol;
pub mod transport;

pub use agent::SpecterAgent;
pub use config::SpecterConfig;
pub use error::SpecterError;
