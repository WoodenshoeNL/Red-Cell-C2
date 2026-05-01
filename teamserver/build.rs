/// Emit a cfg flag so that all non-release builds (dev profile, tests) use
/// reduced-cost Argon2 parameters instead of the OWASP-recommended ones.
///
/// This makes `#[cfg(any(test, fast_argon2))]` work for both unit tests
/// (which already have `cfg(test)`) and integration test binaries in
/// `teamserver/tests/` (which compile the library without `cfg(test)`).
///
/// Release builds (`cargo build --release`, `PROFILE=release`) are
/// unaffected and always use the full m=65536,t=3,p=4 OWASP parameters.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(fast_argon2)");
    let profile = std::env::var("PROFILE").unwrap_or_default();
    if profile != "release" {
        println!("cargo::rustc-cfg=fast_argon2");
    }

    compile_c_replay_harness();
}

/// Compile the C agent replay test harness if `gcc` is available.
///
/// On success, sets `DEMON_C_HARNESS_BIN` to the compiled binary path so
/// that the Rust integration test can locate it via `option_env!`.
/// On failure (gcc absent or compilation error), emits a warning and sets no
/// env var so the test can skip gracefully.
fn compile_c_replay_harness() {
    let manifest_dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(d) => d,
        Err(_) => return,
    };
    let out_dir = match std::env::var("OUT_DIR") {
        Ok(d) => d,
        Err(_) => return,
    };

    let harness_src = std::path::Path::new(&manifest_dir)
        .join("..")
        .join("agent")
        .join("demon")
        .join("tests")
        .join("replay_harness.c");

    if !harness_src.exists() {
        println!(
            "cargo:warning=C replay harness source not found, skipping: {}",
            harness_src.display()
        );
        return;
    }

    let harness_bin = std::path::Path::new(&out_dir).join("demon_replay_harness");

    let result = std::process::Command::new("gcc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2"])
        .arg(&harness_src)
        .arg("-o")
        .arg(&harness_bin)
        .status();

    match result {
        Ok(s) if s.success() => {
            println!("cargo:rustc-env=DEMON_C_HARNESS_BIN={}", harness_bin.display());
            println!("cargo:rerun-if-changed={}", harness_src.display());
        }
        Ok(s) => {
            println!("cargo:warning=C replay harness compilation exited {s}, test will be skipped");
        }
        Err(e) => {
            println!("cargo:warning=gcc not found or failed ({e}), C replay test will be skipped");
        }
    }
}
