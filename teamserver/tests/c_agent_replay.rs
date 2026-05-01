//! Rust wrapper that invokes the compiled C replay harness as a cargo-nextest
//! test.
//!
//! The C harness is compiled during the teamserver build (see `build.rs`).
//! If `gcc` is not available the build emits a warning and the test skips
//! gracefully rather than failing.
//!
//! Set `SKIP_C_REPLAY=1` in the environment to force-skip this test without
//! changing the build (useful in restricted CI containers).

use std::path::PathBuf;
use std::process::Command;

/// Path to the compiled C harness binary, set by `build.rs` via
/// `cargo:rustc-env=DEMON_C_HARNESS_BIN=…`.  `None` when gcc was absent or
/// compilation failed.
const DEMON_C_HARNESS: Option<&str> = option_env!("DEMON_C_HARNESS_BIN");

fn corpus_dir(agent: &str, scenario: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("wire-corpus")
        .join(agent)
        .join(scenario)
}

/// Feed the Demon checkin corpus through the C replay harness and assert all
/// header and crypto-material checks pass.
///
/// Skips when:
///   - `SKIP_C_REPLAY=1` is set in the environment, or
///   - gcc was unavailable at build time (no `DEMON_C_HARNESS_BIN` env var).
#[test]
fn c_demon_replay_harness_checkin() {
    if std::env::var("SKIP_C_REPLAY").as_deref() == Ok("1") {
        println!("SKIP_C_REPLAY=1 — skipping C harness test");
        return;
    }

    let harness = match DEMON_C_HARNESS {
        Some(p) => p,
        None => {
            println!("C harness not compiled (gcc unavailable at build time) — skipping");
            return;
        }
    };

    let dir = corpus_dir("demon", "checkin");
    if !dir.exists() {
        println!("corpus not found at {dir:?} — skipping");
        return;
    }

    let status = Command::new(harness)
        .arg(&dir)
        .status()
        .unwrap_or_else(|e| panic!("failed to exec C harness at {harness}: {e}"));

    assert!(
        status.success(),
        "C Demon replay harness failed (exit {status:?}); run it manually for details:\n  {harness} {}",
        dir.display()
    );
}
