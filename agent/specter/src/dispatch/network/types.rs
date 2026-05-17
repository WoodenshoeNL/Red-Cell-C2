//! Network discovery DTOs used across platform implementations.

/// An active network session entry (maps to `SESSION_INFO_10` on Windows).
pub(super) struct NetSession {
    pub(super) client: String,
    pub(super) user: String,
    pub(super) active_secs: u32,
    pub(super) idle_secs: u32,
}

/// A network share entry (maps to `SHARE_INFO_502` on Windows).
pub(super) struct NetShare {
    pub(super) name: String,
    pub(super) path: String,
    pub(super) remark: String,
    pub(super) permissions: u32,
}

/// A group entry with name and description.
pub(super) struct NetGroup {
    pub(super) name: String,
    pub(super) description: String,
}

/// A user entry with an admin flag.
pub(super) struct NetUser {
    pub(super) name: String,
    pub(super) is_admin: bool,
}
