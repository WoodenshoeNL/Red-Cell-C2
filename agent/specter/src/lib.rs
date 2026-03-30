//! Specter library surface for tests and alternate entrypoints.

pub mod agent;
pub mod config;
pub mod dispatch;
pub mod download;
pub mod error;
pub mod platform;
pub mod protocol;
pub mod socket;
pub mod token;
pub mod transport;

pub use agent::SpecterAgent;
pub use config::SpecterConfig;
pub use error::SpecterError;
