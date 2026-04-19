//! Token type definitions for the Specter agent.

/// How a token was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TokenType {
    /// Stolen from a remote process via `OpenProcessToken` + `DuplicateTokenEx`.
    Stolen = 0x1,
    /// Created via `LogonUserW` (network logon).
    MakeNetwork = 0x2,
}

impl TokenType {
    /// Convert from the wire representation.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x1 => Some(Self::Stolen),
            0x2 => Some(Self::MakeNetwork),
            _ => None,
        }
    }
}

/// A single entry in the token vault.
#[derive(Debug, Clone)]
pub struct TokenEntry {
    /// Opaque token handle. On Windows this is a `HANDLE` (pointer-sized),
    /// on non-Windows stubs it is always zero.
    pub handle: usize,
    /// `DOMAIN\User` display string.
    pub domain_user: String,
    /// PID of the process the token was stolen from (0 for make tokens).
    pub process_id: u32,
    /// How the token was obtained.
    pub token_type: TokenType,
    /// Credentials stored for make tokens (domain, user, password).
    pub credentials: Option<MakeCredentials>,
}

/// Credentials used to create a make-token via `LogonUserW`.
#[derive(Debug, Clone)]
pub struct MakeCredentials {
    pub domain: String,
    pub user: String,
    pub password: String,
}

/// A token found during system-wide handle enumeration.
#[derive(Debug, Clone)]
pub struct FoundToken {
    /// `DOMAIN\User` display string.
    pub domain_user: String,
    /// PID of the owning process.
    pub process_id: u32,
    /// Handle value inside the owning process (0 for the primary token path).
    pub handle: u32,
    /// Mandatory-label integrity level (e.g. `SECURITY_MANDATORY_HIGH_RID`).
    pub integrity_level: u32,
    /// Security-impersonation level for impersonation tokens; 0 for primary.
    pub impersonation_level: u32,
    /// `TokenPrimary` (1) or `TokenImpersonation` (2).
    pub token_type: u32,
}
