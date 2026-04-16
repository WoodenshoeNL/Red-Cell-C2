use std::sync::Arc;

use super::super::pe_patch::replace_all;
use super::*;

// ── replace_all byte replacement tests ──────────────────────────────

#[test]
fn replace_all_replaces_single_occurrence() {
    let haystack = b"hello world".to_vec();
    let result = replace_all(haystack, b"world", b"earth");
    assert_eq!(result, b"hello earth");
}

#[test]
fn replace_all_replaces_multiple_occurrences() {
    let haystack = b"aXaXa".to_vec();
    let result = replace_all(haystack, b"X", b"Y");
    assert_eq!(result, b"aYaYa");
}

#[test]
fn replace_all_no_match_returns_unchanged() {
    let haystack = b"hello world".to_vec();
    let result = replace_all(haystack.clone(), b"xyz", b"abc");
    assert_eq!(result, haystack);
}

#[test]
fn replace_all_empty_needle_returns_unchanged() {
    let haystack = b"hello".to_vec();
    let result = replace_all(haystack.clone(), b"", b"x");
    assert_eq!(result, haystack);
}

#[test]
fn replace_all_same_length_replacement() {
    let haystack = b"AAAA".to_vec();
    let result = replace_all(haystack, b"AA", b"BB");
    assert_eq!(result, b"BBBB");
}

#[test]
fn replace_all_with_null_padded_replacement() {
    // Simulates the PE string replacement where replacement is
    // null-padded to match the original string length.
    let haystack = b"old_string_here".to_vec();
    let mut replacement = b"new".to_vec();
    replacement.resize(b"old_string_here".len(), 0);
    let result = replace_all(haystack, b"old_string_here", &replacement);
    assert_eq!(&result[..3], b"new");
    assert!(result[3..].iter().all(|&b| b == 0));
}

// ── disabled_for_tests structural tests ─────────────────────────────

#[test]
fn disabled_for_tests_creates_valid_service() {
    let svc = PayloadBuilderService::disabled_for_tests();
    // Should not panic and should have sensible defaults.
    assert_eq!(svc.inner.toolchain.compiler_x64, PathBuf::from("/nonexistent/x64-gcc"));
    assert_eq!(svc.inner.toolchain.compiler_x86, PathBuf::from("/nonexistent/x86-gcc"));
    assert_eq!(svc.inner.toolchain.nasm, PathBuf::from("/nonexistent/nasm"));
    assert_eq!(svc.inner.toolchain.compiler_x64_version.major, 0);
    assert_eq!(svc.inner.default_demon.sleep, None);
    assert!(!svc.inner.default_demon.indirect_syscall);
    assert!(svc.inner.binary_patch.is_none());
}

#[test]
fn disabled_for_tests_is_cloneable() {
    let svc1 = PayloadBuilderService::disabled_for_tests();
    let svc2 = svc1.clone();
    // Both should share the same inner Arc.
    assert!(Arc::ptr_eq(&svc1.inner, &svc2.inner));
}

// ── BuildProgress and PayloadArtifact derive tests ──────────────────

#[test]
fn build_progress_clone_and_eq() {
    let a = BuildProgress { level: "Info".to_owned(), message: "test".to_owned() };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn payload_artifact_clone_and_eq() {
    let a = PayloadArtifact {
        bytes: vec![1, 2, 3],
        file_name: "test.exe".to_owned(),
        format: "Windows Exe".to_owned(),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

// ── PayloadBuildError display tests ────────────────────────────────────

#[test]
fn payload_build_error_display_messages() {
    let err = PayloadBuildError::ToolchainUnavailable { message: "nasm missing".to_owned() };
    assert!(err.to_string().contains("nasm missing"));

    let err = PayloadBuildError::InvalidRequest { message: "bad arch".to_owned() };
    assert!(err.to_string().contains("bad arch"));

    let err = PayloadBuildError::CommandFailed { command: "gcc".to_owned(), diagnostics: vec![] };
    assert!(err.to_string().contains("gcc"));
}

// Phantom / Specter callback URL tests live in `rust_agent::tests`.
