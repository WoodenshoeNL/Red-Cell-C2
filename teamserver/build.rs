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
}
