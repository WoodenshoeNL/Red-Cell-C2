//! Tests for dispatch utility functions.

use crate::dispatch::non_empty_option;
use crate::dispatch::util::win32_error_code_name;

#[test]
fn non_empty_option_empty_string_returns_none() {
    assert_eq!(non_empty_option(""), None);
}

#[test]
fn non_empty_option_non_empty_returns_some() {
    assert_eq!(non_empty_option("value"), Some("value".to_owned()));
}

#[test]
fn non_empty_option_whitespace_only_returns_some() {
    assert_eq!(non_empty_option("  "), Some("  ".to_owned()));
}

#[test]
fn non_empty_option_single_char_returns_some() {
    assert_eq!(non_empty_option("x"), Some("x".to_owned()));
}

// ── win32_error_code_name ────────────────────────────────────────────────

#[test]
fn win32_error_code_name_known_codes_return_symbolic_names() {
    assert_eq!(win32_error_code_name(2), Some("ERROR_FILE_NOT_FOUND"));
    assert_eq!(win32_error_code_name(5), Some("ERROR_ACCESS_DENIED"));
    assert_eq!(win32_error_code_name(6), Some("ERROR_INVALID_HANDLE"));
    assert_eq!(win32_error_code_name(87), Some("ERROR_INVALID_PARAMETER"));
    assert_eq!(win32_error_code_name(183), Some("ERROR_ALREADY_EXISTS"));
    assert_eq!(win32_error_code_name(997), Some("ERROR_IO_PENDING"));
}

#[test]
fn win32_error_code_name_gdi_codes_return_symbolic_names() {
    assert_eq!(win32_error_code_name(1400), Some("ERROR_INVALID_WINDOW_HANDLE"));
    assert_eq!(win32_error_code_name(1401), Some("ERROR_INVALID_MENU_HANDLE"));
    assert_eq!(win32_error_code_name(1402), Some("ERROR_INVALID_CURSOR_HANDLE"));
    assert_eq!(win32_error_code_name(1403), Some("ERROR_INVALID_ACCEL_HANDLE"));
    assert_eq!(win32_error_code_name(1404), Some("ERROR_INVALID_HOOK_HANDLE"));
    assert_eq!(win32_error_code_name(1406), Some("ERROR_INVALID_DWP_HANDLE"));
    assert_eq!(win32_error_code_name(1424), Some("ERROR_DC_NOT_FOUND"));
    assert_eq!(win32_error_code_name(1436), Some("ERROR_INVALID_GW_COMMAND"));
}

#[test]
fn win32_error_code_name_unknown_codes_return_none() {
    assert_eq!(win32_error_code_name(0), None);
    assert_eq!(win32_error_code_name(1), None);
    assert_eq!(win32_error_code_name(9999), None);
}
