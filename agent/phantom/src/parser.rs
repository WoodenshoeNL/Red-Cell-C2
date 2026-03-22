//! Little-endian task parser matching Havoc's `ParserGet*` behavior for command arguments.

use crate::error::PhantomError;

/// Cursor over a task payload.
#[derive(Debug, Clone)]
pub struct TaskParser<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> TaskParser<'a> {
    /// Create a new parser for a raw task payload.
    #[must_use]
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    /// Read a 32-bit signed integer from the payload.
    pub fn int32(&mut self) -> Result<i32, PhantomError> {
        let bytes = self.read_exact(4)?;
        let array: [u8; 4] =
            bytes.try_into().map_err(|_| PhantomError::TaskParse("failed to read int32"))?;
        Ok(i32::from_le_bytes(array))
    }

    /// Read a 16-bit signed integer from the payload.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn int16(&mut self) -> Result<i16, PhantomError> {
        let bytes = self.read_exact(2)?;
        let array: [u8; 2] =
            bytes.try_into().map_err(|_| PhantomError::TaskParse("failed to read int16"))?;
        Ok(i16::from_le_bytes(array))
    }

    /// Read a single byte.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn byte(&mut self) -> Result<u8, PhantomError> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    /// Read a 32-bit boolean where any non-zero value is `true`.
    pub fn bool32(&mut self) -> Result<bool, PhantomError> {
        Ok(self.int32()? != 0)
    }

    /// Read a length-prefixed byte slice.
    pub fn bytes(&mut self) -> Result<&'a [u8], PhantomError> {
        let length = usize::try_from(self.int32()?)
            .map_err(|_| PhantomError::TaskParse("negative byte length"))?;
        self.read_exact(length)
    }

    /// Read a length-prefixed UTF-8 string.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn string(&mut self) -> Result<String, PhantomError> {
        let bytes = self.bytes()?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| PhantomError::TaskParse("invalid utf-8 string in task payload"))
    }

    /// Read a length-prefixed UTF-16LE string.
    pub fn wstring(&mut self) -> Result<String, PhantomError> {
        let bytes = self.bytes()?;
        if bytes.len() % 2 != 0 {
            return Err(PhantomError::TaskParse("invalid UTF-16LE byte length"));
        }

        let utf16 = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&utf16)
            .map_err(|_| PhantomError::TaskParse("invalid UTF-16LE string in task payload"))
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], PhantomError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(PhantomError::TaskParse("task payload offset overflow"))?;
        let slice = self
            .buffer
            .get(self.offset..end)
            .ok_or(PhantomError::TaskParse("task payload truncated"))?;
        self.offset = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::TaskParser;

    #[test]
    fn parser_reads_little_endian_scalars() {
        let mut parser =
            TaskParser::new(&[0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xAB, 0x01, 0x00, 0x00, 0x00]);

        assert_eq!(parser.int32().expect("int32"), 0x1234_5678);
        assert_eq!(parser.int16().expect("int16"), 0x1234);
        assert_eq!(parser.byte().expect("byte"), 0xAB);
        assert!(parser.bool32().expect("bool32"));
    }

    #[test]
    fn parser_reads_utf8_and_utf16le_strings() {
        let utf8 = [3_u8, 0, 0, 0, b'f', b'o', b'o'];
        let utf16 = [4_u8, 0, 0, 0, b'b', 0, b'a', 0];
        let payload = [utf8.as_slice(), utf16.as_slice()].concat();
        let mut parser = TaskParser::new(&payload);

        assert_eq!(parser.string().expect("utf8"), "foo");
        assert_eq!(parser.wstring().expect("utf16"), "ba");
    }

    #[test]
    fn parser_rejects_truncated_bytes() {
        let mut parser = TaskParser::new(&[4_u8, 0, 0, 0, 1, 2]);
        assert!(parser.bytes().is_err());
    }
}
