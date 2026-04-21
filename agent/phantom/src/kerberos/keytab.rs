//! MIT Kerberos keytab file format parsing (version 0x0502 / v2).

use super::ccache::{BinaryParser, KerbPrincipal};
use crate::error::PhantomError;

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
    let mut p = BinaryParser::new(data);

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
