//! Stub implementations for non-Windows platforms.
//!
//! Token manipulation is a Windows-only capability.  These stubs allow the
//! code to compile on Linux/macOS for cross-compile testing, but all
//! operations return errors.

use super::TokenEntry;

/// Windows error code for "not supported".
const ERROR_NOT_SUPPORTED: u32 = 50;

/// Stub: always returns `Err`.
pub fn steal_token(_target_pid: u32, _target_handle: u32) -> Result<TokenEntry, u32> {
    Err(ERROR_NOT_SUPPORTED)
}

/// Stub: always returns `Err`.
pub fn make_token(
    _domain: &str,
    _user: &str,
    _password: &str,
    _logon_type: u32,
) -> Result<TokenEntry, u32> {
    Err(ERROR_NOT_SUPPORTED)
}

/// Stub: always returns `Err`.
pub fn impersonate_token(_handle: usize) -> Result<(), u32> {
    Err(ERROR_NOT_SUPPORTED)
}

/// Stub: always returns `Err`.
pub fn revert_to_self() -> Result<(), u32> {
    Err(ERROR_NOT_SUPPORTED)
}

/// Stub: always returns `false`.
pub fn is_token_elevated(_handle: usize) -> bool {
    false
}

/// Stub: get current user identity.
pub fn get_uid() -> Result<(bool, String), u32> {
    let user = std::env::var("USER").unwrap_or_else(|_| String::from("unknown"));
    Ok((false, format!("WORKGROUP\\{user}")))
}

/// Stub: always returns empty list.
pub fn list_privileges() -> Result<Vec<(String, u32)>, u32> {
    Ok(Vec::new())
}

/// Stub: always returns `Err`.
pub fn enable_privilege(_priv_name: &str) -> Result<bool, u32> {
    Err(ERROR_NOT_SUPPORTED)
}

/// Stub: no-op.
pub fn close_token_handle(_handle: usize) {}

/// Stub: returns an empty list (token enumeration is Windows-only).
pub fn list_found_tokens() -> Vec<super::FoundToken> {
    Vec::new()
}
