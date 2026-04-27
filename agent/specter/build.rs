fn main() {
    // Compile the C variadic shim for BeaconPrintf.
    // On Windows targets this links via mingw; on non-Windows it still
    // compiles (BOF execution is a no-op on Linux but the tests run).
    cc::Build::new().file("csrc/bof_printf.c").warnings(true).compile("bof_printf");

    for suffix in [
        "CALLBACK_URL",
        "DOH_DOMAIN",
        "DOH_PROVIDER",
        "INIT_SECRET",
        "INIT_SECRET_VERSION",
        "KILL_DATE",
        "LISTENER_PUB_KEY",
        "PINNED_CERT_PEM",
        "SLEEP_DELAY_MS",
        "SLEEP_JITTER",
        "USER_AGENT",
        "WORKING_HOURS",
    ] {
        println!("cargo::rerun-if-env-changed=SPECTER_{suffix}");
    }
}
