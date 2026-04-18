//! Specter library surface for tests and alternate entrypoints.

pub mod agent;
pub mod beacon_api;
pub mod bof_context;
pub mod bypass;
pub mod coffeeldr;
pub mod config;
pub mod dispatch;
pub mod doh_transport;
pub mod dotnet;
pub mod download;
pub mod error;
pub mod job;
pub mod kerberos;
pub mod pe_stomp;
pub mod pivot;
pub mod platform;
pub mod protocol;
pub mod sleep_obf;
pub mod socket;
pub mod spoof;
pub mod syscall;
pub mod token;
pub mod transport;

pub use agent::SpecterAgent;
pub use config::SpecterConfig;
pub use error::SpecterError;
