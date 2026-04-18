use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::demon::{DemonCommand, DemonKerberosCommand};
use time::OffsetDateTime;

use crate::EventBus;

use super::{CallbackParser, CommandDispatchError, agent_response_event};

pub(super) async fn handle_kerberos_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandKerberos));
    let subcommand = parser.read_u32("kerberos subcommand")?;

    match DemonKerberosCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandKerberos),
            message: error.to_string(),
        }
    })? {
        DemonKerberosCommand::Luid => {
            let success = parser.read_u32("kerberos luid success")?;
            if success == 0 {
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandKerberos),
                    request_id,
                    "Error",
                    "Failed to obtain the current logon ID",
                    None,
                )?);
                return Ok(None);
            }

            let high = parser.read_u32("kerberos luid high part")?;
            let low = parser.read_u32("kerberos luid low part")?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandKerberos),
                request_id,
                "Good",
                &format!("Current LogonId: {high:x}:0x{low:x}"),
                None,
            )?);
        }
        DemonKerberosCommand::Klist => {
            let success = parser.read_u32("kerberos klist success")?;
            if success == 0 {
                events.broadcast(agent_response_event(
                    agent_id,
                    u32::from(DemonCommand::CommandKerberos),
                    request_id,
                    "Error",
                    "Failed to list all kerberos tickets",
                    None,
                )?);
                return Ok(None);
            }

            let output = format_kerberos_klist(&mut parser)?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandKerberos),
                request_id,
                "Info",
                "Kerberos tickets:",
                Some(output),
            )?);
        }
        DemonKerberosCommand::Purge => {
            let success = parser.read_u32("kerberos purge success")?;
            let (kind, message) = if success != 0 {
                ("Good", "Successfully purged the Kerberos ticket")
            } else {
                ("Error", "Failed to purge the kerberos ticket")
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandKerberos),
                request_id,
                kind,
                message,
                None,
            )?);
        }
        DemonKerberosCommand::Ptt => {
            let success = parser.read_u32("kerberos ptt success")?;
            let (kind, message) = if success != 0 {
                ("Good", "Successfully imported the Kerberos ticket")
            } else {
                ("Error", "Failed to import the kerberos ticket")
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandKerberos),
                request_id,
                kind,
                message,
                None,
            )?);
        }
    }

    Ok(None)
}

/// Maximum number of sessions or tickets we accept from a single agent payload.
/// Protects against malicious payloads that set counts to `u32::MAX` to burn CPU.
pub(super) const MAX_KERBEROS_LIST_ITEMS: u32 = 10_000;

pub(super) fn format_kerberos_klist(
    parser: &mut CallbackParser<'_>,
) -> Result<String, CommandDispatchError> {
    let session_count = parser.read_u32("kerberos session count")?;
    if session_count > MAX_KERBEROS_LIST_ITEMS {
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandKerberos),
            message: format!(
                "kerberos session count {session_count} exceeds maximum {MAX_KERBEROS_LIST_ITEMS}"
            ),
        });
    }
    let mut output = String::new();

    for _ in 0..session_count {
        let username = parser.read_utf16("kerberos username")?;
        let domain = parser.read_utf16("kerberos domain")?;
        let logon_id_low = parser.read_u32("kerberos logon id low")?;
        let logon_id_high = parser.read_u32("kerberos logon id high")?;
        let session = parser.read_u32("kerberos session")?;
        let user_sid = parser.read_utf16("kerberos user sid")?;
        let logon_time_low = parser.read_u32("kerberos logon time low")?;
        let logon_time_high = parser.read_u32("kerberos logon time high")?;
        let logon_type = parser.read_u32("kerberos logon type")?;
        let auth_package = parser.read_utf16("kerberos auth package")?;
        let logon_server = parser.read_utf16("kerberos logon server")?;
        let dns_domain = parser.read_utf16("kerberos dns domain")?;
        let upn = parser.read_utf16("kerberos upn")?;
        let ticket_count = parser.read_u32("kerberos ticket count")?;
        if ticket_count > MAX_KERBEROS_LIST_ITEMS {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandKerberos),
                message: format!(
                    "kerberos ticket count {ticket_count} exceeds maximum {MAX_KERBEROS_LIST_ITEMS}"
                ),
            });
        }

        output.push_str(&format!("UserName                : {username}\n"));
        output.push_str(&format!("Domain                  : {domain}\n"));
        output
            .push_str(&format!("LogonId                 : {logon_id_high:x}:0x{logon_id_low:x}\n"));
        output.push_str(&format!("Session                 : {session}\n"));
        output.push_str(&format!("UserSID                 : {user_sid}\n"));
        output.push_str(&format!(
            "LogonTime               : {}\n",
            format_filetime(logon_time_high, logon_time_low)
        ));
        output.push_str(&format!("Authentication package  : {auth_package}\n"));
        output.push_str(&format!("LogonType               : {}\n", logon_type_name(logon_type)));
        output.push_str(&format!("LogonServer             : {logon_server}\n"));
        output.push_str(&format!("LogonServerDNSDomain    : {dns_domain}\n"));
        output.push_str(&format!("UserPrincipalName       : {upn}\n"));
        output.push_str(&format!("Cached tickets:         : {ticket_count}\n"));

        for _ in 0..ticket_count {
            let client_name = parser.read_utf16("kerberos ticket client name")?;
            let client_realm = parser.read_utf16("kerberos ticket client realm")?;
            let server_name = parser.read_utf16("kerberos ticket server name")?;
            let server_realm = parser.read_utf16("kerberos ticket server realm")?;
            let start_low = parser.read_u32("kerberos ticket start low")?;
            let start_high = parser.read_u32("kerberos ticket start high")?;
            let end_low = parser.read_u32("kerberos ticket end low")?;
            let end_high = parser.read_u32("kerberos ticket end high")?;
            let renew_low = parser.read_u32("kerberos ticket renew low")?;
            let renew_high = parser.read_u32("kerberos ticket renew high")?;
            let encryption_type = parser.read_u32("kerberos ticket encryption type")?;
            let ticket_flags = parser.read_u32("kerberos ticket flags")?;
            let ticket = parser.read_bytes("kerberos ticket bytes")?;

            output.push('\n');
            output.push_str(&format!("\tClient name     : {client_name} @ {client_realm}\n"));
            output.push_str(&format!("\tServer name     : {server_name} @ {server_realm}\n"));
            output.push_str(&format!(
                "\tStart time      : {}\n",
                format_filetime(start_high, start_low)
            ));
            output
                .push_str(&format!("\tEnd time        : {}\n", format_filetime(end_high, end_low)));
            output.push_str(&format!(
                "\tRenew time      : {}\n",
                format_filetime(renew_high, renew_low)
            ));
            output.push_str(&format!(
                "\tEncryption type : {}\n",
                kerberos_encryption_type_name(encryption_type)
            ));
            output.push_str(&format!("\tFlags           :{}\n", format_ticket_flags(ticket_flags)));
            if !ticket.is_empty() {
                output
                    .push_str(&format!("\tTicket          : {}\n", BASE64_STANDARD.encode(ticket)));
            }
        }

        output.push('\n');
    }

    Ok(output.trim_end().to_owned())
}

pub(super) fn format_filetime(high: u32, low: u32) -> String {
    let filetime = ((u64::from(high)) << 32) | u64::from(low);
    if filetime <= 0x019D_B1DE_D53E_8000 {
        return "1970-01-01 00:00:00 +00:00:00".to_owned();
    }

    let intervals = (filetime - 0x019D_B1DE_D53E_8000) / 10_000_000;
    let Ok(unix_seconds) = i64::try_from(intervals) else {
        return format!("{intervals} (overflow)");
    };
    OffsetDateTime::from_unix_timestamp(unix_seconds)
        .map(|time| time.to_string())
        .unwrap_or_else(|_| unix_seconds.to_string())
}

pub(super) fn logon_type_name(value: u32) -> &'static str {
    match value {
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        7 => "Unlock",
        8 => "Network_Cleartext",
        9 => "New_Credentials",
        _ => "Unknown",
    }
}

pub(super) fn kerberos_encryption_type_name(value: u32) -> &'static str {
    match value {
        1 => "DES_CBC_CRC",
        2 => "DES_CBC_MD4",
        3 => "DES_CBC_MD5",
        5 => "DES3_CBC_MD5",
        7 => "DES3_CBC_SHA1",
        11 => "RSAENCRYPTION_ENVOID",
        12 => "RSAES_OAEP_ENV_OID",
        16 => "DES3_CBC_SHA1_KD",
        17 => "AES128_CTS_HMAC_SHA1",
        18 => "AES256_CTS_HMAC_SHA1",
        23 => "RC4_HMAC",
        24 => "RC4_HMAC_EXP",
        _ => "Unknown",
    }
}

pub(super) fn format_ticket_flags(flags: u32) -> String {
    const FLAG_NAMES: [&str; 16] = [
        "name_canonicalize",
        "anonymous",
        "ok_as_delegate",
        "?",
        "hw_authent",
        "pre_authent",
        "initial",
        "renewable",
        "invalid",
        "postdated",
        "may_postdate",
        "proxy",
        "proxiable",
        "forwarded",
        "forwardable",
        "reserved",
    ];

    let mut text = String::new();
    for (index, name) in FLAG_NAMES.iter().enumerate() {
        if ((flags >> (index + 16)) & 1) == 1 {
            text.push(' ');
            text.push_str(name);
        }
    }
    text.push_str(&format!(" (0x{flags:x})"));
    text
}
