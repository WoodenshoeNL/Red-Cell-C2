//! Specter library surface for tests and alternate entrypoints.

pub mod agent;
pub mod coffeeldr;
pub mod config;
pub mod dispatch;
pub mod dotnet;
pub mod download;
pub mod error;
pub mod job;
pub mod kerberos;
pub mod pivot;
pub mod platform;
pub mod protocol;
pub mod socket;
pub mod token;
pub mod transport;

pub use agent::SpecterAgent;
pub use config::SpecterConfig;
pub use error::SpecterError;
