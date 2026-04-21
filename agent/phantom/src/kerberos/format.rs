//! Human-readable formatting for Kerberos ccache and keytab data.

use std::fmt::Write as FmtWrite;

use super::ccache::CCache;
use super::keytab::Keytab;

/// Map an encryption type number to a human-readable name.
pub(super) fn enctype_name(et: i32) -> &'static str {
    match et {
        1 => "DES_CBC_CRC",
        2 => "DES_CBC_MD4",
        3 => "DES_CBC_MD5",
        5 => "DES3_CBC_MD5",
        7 => "DES3_CBC_SHA1",
        16 => "DES3_CBC_SHA1_KD",
        17 => "AES128_CTS_HMAC_SHA1_96",
        18 => "AES256_CTS_HMAC_SHA1_96",
        23 => "RC4_HMAC",
        24 => "RC4_HMAC_EXP",
        _ => "UNKNOWN",
    }
}

/// Decode ticket flags into human-readable labels.
pub(super) fn ticket_flags_str(flags: u32) -> String {
    // Kerberos ticket flags are in network bit order (bit 0 = MSB).
    let labels = [
        (0x4000_0000, "forwardable"),
        (0x2000_0000, "forwarded"),
        (0x1000_0000, "proxiable"),
        (0x0800_0000, "proxy"),
        (0x0400_0000, "may_postdate"),
        (0x0200_0000, "postdated"),
        (0x0100_0000, "invalid"),
        (0x0080_0000, "renewable"),
        (0x0040_0000, "initial"),
        (0x0020_0000, "pre_authent"),
        (0x0010_0000, "hw_authent"),
        (0x0008_0000, "ok_as_delegate"),
        (0x0001_0000, "name_canonicalize"),
        (0x0000_8000, "anonymous"),
    ];
    let mut parts = Vec::new();
    for (mask, label) in &labels {
        if flags & mask != 0 {
            parts.push(*label);
        }
    }
    if parts.is_empty() {
        format!("(0x{flags:08x})")
    } else {
        let joined = parts.join(" ");
        format!("{joined} (0x{flags:08x})")
    }
}

/// Format a Unix timestamp as an ISO-8601-ish string.
pub(super) fn format_timestamp(ts: u32) -> String {
    if ts == 0 {
        return "(never)".to_owned();
    }
    match time::OffsetDateTime::from_unix_timestamp(i64::from(ts)) {
        Ok(dt) => {
            // YYYY-MM-DD HH:MM:SS UTC
            let (y, m, d) = (dt.year(), dt.month() as u8, dt.day());
            let (h, min, s) = (dt.hour(), dt.minute(), dt.second());
            format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02} UTC")
        }
        Err(_) => format!("{ts}"),
    }
}

/// Format all discovered ccache files into a human-readable klist output.
pub(crate) fn format_klist(ccaches: &[CCache]) -> String {
    let mut out = String::new();
    if ccaches.is_empty() {
        out.push_str("No Kerberos credential caches found.\n");
        return out;
    }

    for cc in ccaches {
        let _ = writeln!(out, "Credential cache: {}", cc.source_path);
        let _ = writeln!(out, "Default principal: {}\n", cc.principal);
        if cc.credentials.is_empty() {
            let _ = writeln!(out, "  (no cached tickets)\n");
            continue;
        }
        for (i, cred) in cc.credentials.iter().enumerate() {
            let _ = writeln!(out, "  [{i}] Service: {}", cred.server);
            let _ = writeln!(out, "      Client:  {}", cred.client);
            let _ = writeln!(
                out,
                "      Encryption: {} ({})",
                enctype_name(cred.encryption_type),
                cred.encryption_type
            );
            let _ = writeln!(out, "      Auth time:  {}", format_timestamp(cred.auth_time));
            let _ = writeln!(out, "      Start time: {}", format_timestamp(cred.start_time));
            let _ = writeln!(out, "      End time:   {}", format_timestamp(cred.end_time));
            let _ = writeln!(out, "      Renew till: {}", format_timestamp(cred.renew_till));
            let _ = writeln!(out, "      Flags:      {}", ticket_flags_str(cred.ticket_flags));
            let _ = writeln!(out, "      Ticket len: {} bytes", cred.ticket.len());
            out.push('\n');
        }
    }

    out
}

/// Format all discovered keytab files into a human-readable list.
pub(crate) fn format_keytabs(keytabs: &[Keytab]) -> String {
    let mut out = String::new();
    if keytabs.is_empty() {
        out.push_str("No keytab files found.\n");
        return out;
    }

    for kt in keytabs {
        let _ = writeln!(out, "Keytab: {}", kt.source_path);
        if kt.entries.is_empty() {
            let _ = writeln!(out, "  (no entries)\n");
            continue;
        }
        for (i, entry) in kt.entries.iter().enumerate() {
            let _ = writeln!(out, "  [{i}] Principal: {}", entry.principal);
            let _ = writeln!(
                out,
                "      KVNO: {}  Enctype: {} ({})",
                entry.kvno,
                enctype_name(entry.enctype as i32),
                entry.enctype
            );
            let _ = writeln!(out, "      Timestamp: {}", format_timestamp(entry.timestamp));
            out.push('\n');
        }
    }

    out
}
