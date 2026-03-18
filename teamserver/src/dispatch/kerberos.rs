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

pub(super) fn format_kerberos_klist(
    parser: &mut CallbackParser<'_>,
) -> Result<String, CommandDispatchError> {
    let session_count = parser.read_u32("kerberos session count")?;
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
                "\tRewnew time     : {}\n",
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

    let unix_seconds = ((filetime - 0x019D_B1DE_D53E_8000) / 10_000_000) as i64;
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

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::demon::{DemonCommand, DemonKerberosCommand};
    use red_cell_common::operator::OperatorMessage;

    // ── Byte-builder helpers for CallbackParser inputs ──

    /// Append a u32 as little-endian bytes.
    fn push_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Append a length-prefixed UTF-16LE string (the wire format read_utf16 expects).
    fn push_utf16(buf: &mut Vec<u8>, s: &str) {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let byte_len = (utf16.len() * 2) as u32;
        push_u32(buf, byte_len);
        for code_unit in &utf16 {
            buf.extend_from_slice(&code_unit.to_le_bytes());
        }
    }

    /// Append a length-prefixed raw byte blob (the wire format read_bytes expects).
    fn push_bytes(buf: &mut Vec<u8>, data: &[u8]) {
        push_u32(buf, data.len() as u32);
        buf.extend_from_slice(data);
    }

    /// Build one session's fixed fields (before tickets) into `buf`.
    fn push_session_header(
        buf: &mut Vec<u8>,
        username: &str,
        domain: &str,
        logon_id_low: u32,
        logon_id_high: u32,
        session: u32,
        user_sid: &str,
        logon_time_low: u32,
        logon_time_high: u32,
        logon_type: u32,
        auth_package: &str,
        logon_server: &str,
        dns_domain: &str,
        upn: &str,
        ticket_count: u32,
    ) {
        push_utf16(buf, username);
        push_utf16(buf, domain);
        push_u32(buf, logon_id_low);
        push_u32(buf, logon_id_high);
        push_u32(buf, session);
        push_utf16(buf, user_sid);
        push_u32(buf, logon_time_low);
        push_u32(buf, logon_time_high);
        push_u32(buf, logon_type);
        push_utf16(buf, auth_package);
        push_utf16(buf, logon_server);
        push_utf16(buf, dns_domain);
        push_utf16(buf, upn);
        push_u32(buf, ticket_count);
    }

    /// Build one ticket entry into `buf`.
    fn push_ticket(
        buf: &mut Vec<u8>,
        client_name: &str,
        client_realm: &str,
        server_name: &str,
        server_realm: &str,
        start_low: u32,
        start_high: u32,
        end_low: u32,
        end_high: u32,
        renew_low: u32,
        renew_high: u32,
        encryption_type: u32,
        ticket_flags: u32,
        ticket_data: &[u8],
    ) {
        push_utf16(buf, client_name);
        push_utf16(buf, client_realm);
        push_utf16(buf, server_name);
        push_utf16(buf, server_realm);
        push_u32(buf, start_low);
        push_u32(buf, start_high);
        push_u32(buf, end_low);
        push_u32(buf, end_high);
        push_u32(buf, renew_low);
        push_u32(buf, renew_high);
        push_u32(buf, encryption_type);
        push_u32(buf, ticket_flags);
        push_bytes(buf, ticket_data);
    }

    // ── format_kerberos_klist tests ──

    #[test]
    fn format_kerberos_klist_zero_sessions() {
        let mut payload = Vec::new();
        push_u32(&mut payload, 0); // session_count = 0
        let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandKerberos));
        let result = format_kerberos_klist(&mut parser).expect("should succeed with zero sessions");
        assert_eq!(result, "");
    }

    #[test]
    fn format_kerberos_klist_single_session_zero_tickets() {
        let mut payload = Vec::new();
        push_u32(&mut payload, 1); // session_count = 1
        push_session_header(
            &mut payload,
            "admin",            // username
            "CORP",             // domain
            0x0000_1234,        // logon_id_low
            0x0000_0000,        // logon_id_high
            0,                  // session
            "S-1-5-21-1234",    // user_sid
            0,                  // logon_time_low (epoch guard)
            0,                  // logon_time_high
            2,                  // logon_type = Interactive
            "Kerberos",         // auth_package
            "DC01",             // logon_server
            "corp.local",       // dns_domain
            "admin@corp.local", // upn
            0,                  // ticket_count = 0
        );

        let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandKerberos));
        let result = format_kerberos_klist(&mut parser)
            .expect("should succeed with one session, zero tickets");

        assert!(result.contains("UserName                : admin"), "missing username");
        assert!(result.contains("Domain                  : CORP"), "missing domain");
        assert!(result.contains("LogonId                 : 0:0x1234"), "missing logon id");
        assert!(result.contains("Session                 : 0"), "missing session");
        assert!(result.contains("UserSID                 : S-1-5-21-1234"), "missing sid");
        assert!(result.contains("Authentication package  : Kerberos"), "missing auth package");
        assert!(result.contains("LogonType               : Interactive"), "missing logon type");
        assert!(result.contains("LogonServer             : DC01"), "missing logon server");
        assert!(result.contains("LogonServerDNSDomain    : corp.local"), "missing dns domain");
        assert!(result.contains("UserPrincipalName       : admin@corp.local"), "missing upn");
        assert!(result.contains("Cached tickets:         : 0"), "missing ticket count");
        // Should NOT contain any ticket sub-entries
        assert!(!result.contains("Client name"), "should have no ticket entries");
    }

    #[test]
    fn format_kerberos_klist_single_session_with_ticket() {
        let mut payload = Vec::new();
        push_u32(&mut payload, 1); // session_count = 1
        push_session_header(
            &mut payload,
            "user1",
            "REALM",
            0x00AA,
            0x0000,
            1,
            "S-1-5-21-999",
            0,
            0,
            3, // Network
            "Negotiate",
            "SRV01",
            "realm.local",
            "user1@realm.local",
            1, // ticket_count = 1
        );
        push_ticket(
            &mut payload,
            "user1",
            "REALM.LOCAL",
            "krbtgt/REALM.LOCAL",
            "REALM.LOCAL",
            0,
            0, // start time
            0,
            0, // end time
            0,
            0,                     // renew time
            18,                    // AES256_CTS_HMAC_SHA1
            (1 << 30) | (1 << 23), // forwardable + renewable
            b"TICKETDATA",         // ticket bytes
        );

        let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandKerberos));
        let result =
            format_kerberos_klist(&mut parser).expect("should format session with one ticket");

        assert!(result.contains("UserName                : user1"), "missing username");
        assert!(result.contains("Cached tickets:         : 1"), "missing ticket count");
        assert!(
            result.contains("\tClient name     : user1 @ REALM.LOCAL"),
            "missing client name in ticket"
        );
        assert!(
            result.contains("\tServer name     : krbtgt/REALM.LOCAL @ REALM.LOCAL"),
            "missing server name in ticket"
        );
        assert!(
            result.contains("\tEncryption type : AES256_CTS_HMAC_SHA1"),
            "missing encryption type"
        );
        assert!(result.contains("forwardable"), "missing forwardable flag");
        assert!(result.contains("renewable"), "missing renewable flag");
        // Ticket data should be base64-encoded
        assert!(
            result.contains(&base64::engine::general_purpose::STANDARD.encode(b"TICKETDATA")),
            "missing base64 ticket data"
        );
    }

    #[test]
    fn format_kerberos_klist_multi_session_multi_ticket() {
        let mut payload = Vec::new();
        push_u32(&mut payload, 2); // session_count = 2

        // Session 1: 2 tickets
        push_session_header(
            &mut payload,
            "alice",
            "ALPHA",
            1,
            0,
            0,
            "S-1-5-21-100",
            0,
            0,
            2,
            "Kerberos",
            "DC-A",
            "alpha.local",
            "alice@alpha.local",
            2,
        );
        push_ticket(
            &mut payload,
            "alice",
            "ALPHA",
            "krbtgt/ALPHA",
            "ALPHA",
            0,
            0,
            0,
            0,
            0,
            0,
            23,
            0,
            b"T1",
        );
        push_ticket(
            &mut payload,
            "alice",
            "ALPHA",
            "cifs/fileserv",
            "ALPHA",
            0,
            0,
            0,
            0,
            0,
            0,
            17,
            0,
            b"",
        );

        // Session 2: 1 ticket
        push_session_header(
            &mut payload,
            "bob",
            "BETA",
            2,
            0,
            1,
            "S-1-5-21-200",
            0,
            0,
            3,
            "Negotiate",
            "DC-B",
            "beta.local",
            "bob@beta.local",
            1,
        );
        push_ticket(
            &mut payload,
            "bob",
            "BETA",
            "krbtgt/BETA",
            "BETA",
            0,
            0,
            0,
            0,
            0,
            0,
            18,
            0,
            b"T3",
        );

        let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandKerberos));
        let result = format_kerberos_klist(&mut parser)
            .expect("should format multiple sessions with multiple tickets");

        // Both sessions present
        assert!(result.contains("UserName                : alice"), "missing alice");
        assert!(result.contains("UserName                : bob"), "missing bob");
        assert!(result.contains("Cached tickets:         : 2"), "missing alice ticket count");
        assert!(result.contains("Cached tickets:         : 1"), "missing bob ticket count");
        // Tickets from session 1
        assert!(result.contains("krbtgt/ALPHA"), "missing alice krbtgt ticket");
        assert!(result.contains("cifs/fileserv"), "missing alice cifs ticket");
        // Ticket from session 2
        assert!(result.contains("krbtgt/BETA"), "missing bob krbtgt ticket");
        // Encryption types
        assert!(result.contains("RC4_HMAC"), "missing RC4_HMAC");
        assert!(result.contains("AES128_CTS_HMAC_SHA1"), "missing AES128");
        assert!(result.contains("AES256_CTS_HMAC_SHA1"), "missing AES256");
    }

    #[test]
    fn format_kerberos_klist_empty_ticket_bytes_omits_ticket_line() {
        let mut payload = Vec::new();
        push_u32(&mut payload, 1);
        push_session_header(
            &mut payload,
            "user",
            "DOM",
            0,
            0,
            0,
            "S-1-5-21-0",
            0,
            0,
            2,
            "Kerberos",
            "DC",
            "dom.local",
            "user@dom.local",
            1,
        );
        push_ticket(
            &mut payload,
            "user",
            "DOM",
            "krbtgt/DOM",
            "DOM",
            0,
            0,
            0,
            0,
            0,
            0,
            23,
            0,
            b"", // empty ticket bytes
        );

        let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandKerberos));
        let result = format_kerberos_klist(&mut parser).expect("should succeed");

        // Empty ticket bytes → no "Ticket" line emitted
        assert!(!result.contains("\tTicket"), "should not emit Ticket line for empty bytes");
    }

    #[test]
    fn format_kerberos_klist_truncated_session_header() {
        // Claims 1 session but payload has no session data at all
        let mut payload = Vec::new();
        push_u32(&mut payload, 1); // session_count = 1
        // No session data follows

        let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandKerberos));
        let result = format_kerberos_klist(&mut parser);
        assert!(result.is_err(), "should error on truncated session header");
    }

    #[test]
    fn format_kerberos_klist_truncated_mid_session() {
        // Claims 2 sessions but only has data for 1
        let mut payload = Vec::new();
        push_u32(&mut payload, 2); // session_count = 2

        // Full first session with 0 tickets
        push_session_header(
            &mut payload,
            "user1",
            "DOM",
            0,
            0,
            0,
            "S-1-5-21-0",
            0,
            0,
            2,
            "Kerberos",
            "DC",
            "dom.local",
            "user1@dom.local",
            0,
        );
        // No second session data

        let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandKerberos));
        let result = format_kerberos_klist(&mut parser);
        assert!(result.is_err(), "should error when second session is missing");
    }

    #[test]
    fn format_kerberos_klist_truncated_ticket() {
        // 1 session claiming 2 tickets but only 1 ticket's worth of data
        let mut payload = Vec::new();
        push_u32(&mut payload, 1);
        push_session_header(
            &mut payload,
            "user",
            "DOM",
            0,
            0,
            0,
            "S-1-5-21-0",
            0,
            0,
            2,
            "Kerberos",
            "DC",
            "dom.local",
            "user@dom.local",
            2, // claims 2 tickets
        );
        // Only provide 1 ticket
        push_ticket(
            &mut payload,
            "user",
            "DOM",
            "krbtgt/DOM",
            "DOM",
            0,
            0,
            0,
            0,
            0,
            0,
            23,
            0,
            b"T1",
        );
        // Second ticket is missing

        let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandKerberos));
        let result = format_kerberos_klist(&mut parser);
        assert!(result.is_err(), "should error when second ticket is truncated");
    }

    #[test]
    fn format_kerberos_klist_truncated_no_session_count() {
        // Completely empty payload — can't even read session_count
        let payload: Vec<u8> = Vec::new();
        let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandKerberos));
        let result = format_kerberos_klist(&mut parser);
        assert!(result.is_err(), "should error on empty payload");
    }

    // format_filetime tests

    #[test]
    fn format_filetime_known_value() {
        // Windows FILETIME for 2009-07-25 23:59:59 UTC
        // = 128924159990000000 = 0x01CA0CBE_6F4E4080
        let high: u32 = 0x01CA_0CBE;
        let low: u32 = 0x6F4E_4080;
        let result = format_filetime(high, low);
        // Should contain the date portion
        assert!(result.contains("2009-07-25"), "Expected date 2009-07-25, got: {result}");
    }

    #[test]
    fn format_filetime_epoch_guard_zero() {
        // filetime = 0 is before epoch guard
        let result = format_filetime(0, 0);
        assert_eq!(result, "1970-01-01 00:00:00 +00:00:00");
    }

    #[test]
    fn format_filetime_epoch_guard_exact_boundary() {
        // filetime = 0x019DB1DED53E8000 is exactly at the boundary — should return fallback
        let filetime: u64 = 0x019D_B1DE_D53E_8000;
        let high = (filetime >> 32) as u32;
        let low = filetime as u32;
        let result = format_filetime(high, low);
        assert_eq!(result, "1970-01-01 00:00:00 +00:00:00");
    }

    #[test]
    fn format_filetime_just_above_epoch_guard() {
        // filetime = 0x019DB1DED53E8001 — 1 tick above guard, should map to 1970-01-01 00:00:00 UTC
        let filetime: u64 = 0x019D_B1DE_D53E_8000 + 10_000_000; // exactly 1 second past epoch
        let high = (filetime >> 32) as u32;
        let low = filetime as u32;
        let result = format_filetime(high, low);
        assert!(result.contains("1970-01-01"), "Expected 1970-01-01 epoch date, got: {result}");
    }

    #[test]
    fn format_filetime_overflow_falls_back_to_raw_seconds() {
        // A filetime so far in the future that OffsetDateTime::from_unix_timestamp rejects it.
        // This exercises the unwrap_or_else fallback that returns the raw second count as a string.
        let high: u32 = 0x7FFF_FFFF;
        let low: u32 = 0xFFFF_FFFF;
        let result = format_filetime(high, low);

        // The result should NOT be the sentinel string
        assert_ne!(result, "1970-01-01 00:00:00 +00:00:00");
        // It should be a numeric string (the raw unix seconds), not a formatted date
        // Verify it parses as a number (the fallback path returns unix_seconds.to_string())
        assert!(
            result.parse::<i64>().is_ok(),
            "Expected raw numeric seconds fallback, got: {result}"
        );
    }

    // logon_type_name tests

    #[test]
    fn logon_type_name_interactive() {
        assert_eq!(logon_type_name(2), "Interactive");
    }

    #[test]
    fn logon_type_name_network() {
        assert_eq!(logon_type_name(3), "Network");
    }

    #[test]
    fn logon_type_name_new_credentials() {
        assert_eq!(logon_type_name(9), "New_Credentials");
    }

    #[test]
    fn logon_type_name_unknown() {
        assert_eq!(logon_type_name(0), "Unknown");
        assert_eq!(logon_type_name(99), "Unknown");
    }

    #[test]
    fn logon_type_name_all_known() {
        assert_eq!(logon_type_name(4), "Batch");
        assert_eq!(logon_type_name(5), "Service");
        assert_eq!(logon_type_name(7), "Unlock");
        assert_eq!(logon_type_name(8), "Network_Cleartext");
    }

    // kerberos_encryption_type_name tests

    #[test]
    fn kerberos_encryption_type_name_aes256() {
        assert_eq!(kerberos_encryption_type_name(18), "AES256_CTS_HMAC_SHA1");
    }

    #[test]
    fn kerberos_encryption_type_name_rc4_hmac() {
        assert_eq!(kerberos_encryption_type_name(23), "RC4_HMAC");
    }

    #[test]
    fn kerberos_encryption_type_name_unknown() {
        assert_eq!(kerberos_encryption_type_name(99), "Unknown");
        assert_eq!(kerberos_encryption_type_name(0), "Unknown");
    }

    #[test]
    fn kerberos_encryption_type_name_others() {
        assert_eq!(kerberos_encryption_type_name(17), "AES128_CTS_HMAC_SHA1");
        assert_eq!(kerberos_encryption_type_name(24), "RC4_HMAC_EXP");
        assert_eq!(kerberos_encryption_type_name(1), "DES_CBC_CRC");
    }

    // format_ticket_flags tests

    #[test]
    fn format_ticket_flags_zero() {
        // No bits set — no flag names, only the hex suffix
        let result = format_ticket_flags(0);
        assert_eq!(result, " (0x0)");
    }

    #[test]
    fn format_ticket_flags_single_forwardable() {
        // bit 30 (index 14, shift index+16=30) = forwardable
        let flags: u32 = 1 << 30;
        let result = format_ticket_flags(flags);
        assert!(result.contains("forwardable"), "Expected 'forwardable', got: {result}");
        assert!(!result.contains("forwarded"), "Should not contain 'forwarded'");
    }

    #[test]
    fn format_ticket_flags_single_renewable() {
        // renewable is index 7, bit position 7+16=23
        let flags: u32 = 1 << 23;
        let result = format_ticket_flags(flags);
        assert!(result.contains("renewable"), "Expected 'renewable', got: {result}");
    }

    #[test]
    fn format_ticket_flags_multiple_bits() {
        // Set forwardable (bit 30) and renewable (bit 23)
        let flags: u32 = (1 << 30) | (1 << 23);
        let result = format_ticket_flags(flags);
        assert!(result.contains("forwardable"), "Expected 'forwardable' in: {result}");
        assert!(result.contains("renewable"), "Expected 'renewable' in: {result}");
    }

    #[test]
    fn format_ticket_flags_includes_hex_suffix() {
        let flags: u32 = 1 << 30;
        let result = format_ticket_flags(flags);
        assert!(result.contains(&format!("(0x{flags:x})")), "Expected hex suffix in: {result}");
    }

    #[test]
    fn format_ticket_flags_name_canonicalize() {
        // name_canonicalize is index 0, bit position 0+16=16
        let flags: u32 = 1 << 16;
        let result = format_ticket_flags(flags);
        assert!(
            result.contains("name_canonicalize"),
            "Expected 'name_canonicalize', got: {result}"
        );
    }

    #[test]
    fn format_ticket_flags_reserved() {
        // reserved is index 15, bit position 15+16=31
        let flags: u32 = 1 << 31;
        let result = format_ticket_flags(flags);
        assert!(result.contains("reserved"), "Expected 'reserved', got: {result}");
    }

    // ── handle_kerberos_callback tests ──

    const AGENT_ID: u32 = 0xCAFE_BABE;
    const REQUEST_ID: u32 = 42;

    /// Build a payload for handle_kerberos_callback with the given subcommand and body.
    fn build_kerberos_payload(subcommand: DemonKerberosCommand, body: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u32(&mut buf, u32::from(subcommand));
        buf.extend_from_slice(body);
        buf
    }

    #[tokio::test]
    async fn handle_kerberos_luid_success_formats_hex_output() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();

        let mut body = Vec::new();
        push_u32(&mut body, 1); // success = 1
        push_u32(&mut body, 0xAB); // high
        push_u32(&mut body, 0xCD); // low
        let payload = build_kerberos_payload(DemonKerberosCommand::Luid, &body);

        let result = handle_kerberos_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                assert_eq!(
                    resp.info.extra.get("Type"),
                    Some(&serde_json::Value::String("Good".to_owned())),
                    "Luid success should produce Type=Good"
                );
                let message = resp
                    .info
                    .extra
                    .get("Message")
                    .and_then(|v| v.as_str())
                    .expect("should have Message");
                assert!(
                    message.contains("ab:0xcd"),
                    "Expected 'ab:0xcd' in message, got: {message}"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_kerberos_luid_failure_broadcasts_error() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();

        let mut body = Vec::new();
        push_u32(&mut body, 0); // success = 0
        let payload = build_kerberos_payload(DemonKerberosCommand::Luid, &body);

        let result = handle_kerberos_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                assert_eq!(
                    resp.info.extra.get("Type"),
                    Some(&serde_json::Value::String("Error".to_owned())),
                    "Luid failure should produce Type=Error"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_kerberos_purge_success_broadcasts_good() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();

        let mut body = Vec::new();
        push_u32(&mut body, 1); // success = 1
        let payload = build_kerberos_payload(DemonKerberosCommand::Purge, &body);

        let result = handle_kerberos_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                assert_eq!(
                    resp.info.extra.get("Type"),
                    Some(&serde_json::Value::String("Good".to_owned())),
                    "Purge success should produce Type=Good"
                );
                let message = resp
                    .info
                    .extra
                    .get("Message")
                    .and_then(|v| v.as_str())
                    .expect("should have Message");
                assert!(message.contains("purge"), "Expected purge in message, got: {message}");
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_kerberos_purge_failure_broadcasts_error() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();

        let mut body = Vec::new();
        push_u32(&mut body, 0); // success = 0
        let payload = build_kerberos_payload(DemonKerberosCommand::Purge, &body);

        let result = handle_kerberos_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                assert_eq!(
                    resp.info.extra.get("Type"),
                    Some(&serde_json::Value::String("Error".to_owned())),
                    "Purge failure should produce Type=Error"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_kerberos_ptt_success_broadcasts_good() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();

        let mut body = Vec::new();
        push_u32(&mut body, 1); // success = 1
        let payload = build_kerberos_payload(DemonKerberosCommand::Ptt, &body);

        let result = handle_kerberos_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                assert_eq!(
                    resp.info.extra.get("Type"),
                    Some(&serde_json::Value::String("Good".to_owned())),
                    "Ptt success should produce Type=Good"
                );
                let message = resp
                    .info
                    .extra
                    .get("Message")
                    .and_then(|v| v.as_str())
                    .expect("should have Message");
                assert!(message.contains("import"), "Expected import in message, got: {message}");
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_kerberos_ptt_failure_broadcasts_error() {
        let events = EventBus::new(8);
        let mut receiver = events.subscribe();

        let mut body = Vec::new();
        push_u32(&mut body, 0); // success = 0
        let payload = build_kerberos_payload(DemonKerberosCommand::Ptt, &body);

        let result = handle_kerberos_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
        assert!(matches!(result, Ok(None)));

        let msg = receiver.recv().await.expect("should receive broadcast");
        match msg {
            OperatorMessage::AgentResponse(resp) => {
                assert_eq!(
                    resp.info.extra.get("Type"),
                    Some(&serde_json::Value::String("Error".to_owned())),
                    "Ptt failure should produce Type=Error"
                );
            }
            other => panic!("expected AgentResponse, got {other:?}"),
        }
    }
}
