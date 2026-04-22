//! MIT Kerberos ccache file format parsing (version 0x0504 / v4).

use crate::error::PhantomError;

/// Magic bytes for ccache file format v4.
pub(crate) const CCACHE_V4_TAG: u16 = 0x0504;

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

/// Big-endian cursor for parsing ccache and keytab binary data.
pub(super) struct BinaryParser<'a> {
    pub(super) buf: &'a [u8],
    pub(super) pos: usize,
}

impl<'a> BinaryParser<'a> {
    pub(super) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(super) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub(super) fn u8(&mut self) -> Result<u8, PhantomError> {
        let b = *self.buf.get(self.pos).ok_or(PhantomError::TaskParse("ccache truncated"))?;
        self.pos += 1;
        Ok(b)
    }

    pub(super) fn u16(&mut self) -> Result<u16, PhantomError> {
        let s = self
            .buf
            .get(self.pos..self.pos + 2)
            .ok_or(PhantomError::TaskParse("ccache truncated"))?;
        self.pos += 2;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    pub(super) fn u32(&mut self) -> Result<u32, PhantomError> {
        let s = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or(PhantomError::TaskParse("ccache truncated"))?;
        self.pos += 4;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub(super) fn i32(&mut self) -> Result<i32, PhantomError> {
        let s = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or(PhantomError::TaskParse("ccache truncated"))?;
        self.pos += 4;
        Ok(i32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub(super) fn bytes(&mut self, len: usize) -> Result<&'a [u8], PhantomError> {
        let end =
            self.pos.checked_add(len).ok_or(PhantomError::TaskParse("ccache offset overflow"))?;
        let s = self.buf.get(self.pos..end).ok_or(PhantomError::TaskParse("ccache truncated"))?;
        self.pos = end;
        Ok(s)
    }

    pub(super) fn skip(&mut self, n: usize) -> Result<(), PhantomError> {
        let end =
            self.pos.checked_add(n).ok_or(PhantomError::TaskParse("ccache offset overflow"))?;
        if end > self.buf.len() {
            return Err(PhantomError::TaskParse("ccache truncated"));
        }
        self.pos = end;
        Ok(())
    }

    /// Read a counted string: `u32 length` followed by `length` bytes of UTF-8.
    pub(super) fn counted_string(&mut self) -> Result<String, PhantomError> {
        let len = self.u32()? as usize;
        let data = self.bytes(len)?;
        String::from_utf8(data.to_vec())
            .map_err(|_| PhantomError::TaskParse("ccache: invalid UTF-8 in string"))
    }

    /// Read a counted string: `u16 length` followed by `length` bytes of UTF-8.
    pub(super) fn counted_string_u16(&mut self) -> Result<String, PhantomError> {
        let len = self.u16()? as usize;
        let data = self.bytes(len)?;
        String::from_utf8(data.to_vec())
            .map_err(|_| PhantomError::TaskParse("ccache: invalid UTF-8 in string"))
    }

    /// Read a counted octet string: `u32 length` followed by `length` bytes.
    pub(super) fn counted_bytes(&mut self) -> Result<Vec<u8>, PhantomError> {
        let len = self.u32()? as usize;
        Ok(self.bytes(len)?.to_vec())
    }

    /// Read a principal.
    pub(super) fn principal(&mut self) -> Result<KerbPrincipal, PhantomError> {
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
    let mut p = BinaryParser::new(data);

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
