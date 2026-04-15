//! Tests for dispatch utility functions.

use crate::dispatch::non_empty_option;

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
