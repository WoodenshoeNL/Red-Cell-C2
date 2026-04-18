use super::*;

#[test]
fn vault_add_and_get() {
    let mut vault = TokenVault::new();
    let entry = TokenEntry {
        handle: 0x1234,
        domain_user: "DOMAIN\\user".to_string(),
        process_id: 100,
        token_type: TokenType::Stolen,
        credentials: None,
    };
    let id = vault.add(entry);
    assert_eq!(id, 0);
    let got = vault.get(id);
    assert!(got.is_some());
    assert_eq!(got.map(|e| &e.domain_user).unwrap(), "DOMAIN\\user");
}

#[test]
fn vault_remove() {
    let mut vault = TokenVault::new();
    let entry = TokenEntry {
        handle: 0,
        domain_user: "A\\B".to_string(),
        process_id: 1,
        token_type: TokenType::Stolen,
        credentials: None,
    };
    let id = vault.add(entry);
    assert!(vault.remove(id));
    assert!(vault.get(id).is_none());
    // Removing again returns false.
    assert!(!vault.remove(id));
}

#[test]
fn vault_reuses_removed_slots() {
    let mut vault = TokenVault::new();
    let mk = |pid: u32| TokenEntry {
        handle: 0,
        domain_user: format!("D\\U{pid}"),
        process_id: pid,
        token_type: TokenType::Stolen,
        credentials: None,
    };
    let id0 = vault.add(mk(0));
    let _id1 = vault.add(mk(1));
    vault.remove(id0);
    let id2 = vault.add(mk(2));
    // Should reuse slot 0.
    assert_eq!(id2, 0);
    assert_eq!(vault.get(id2).map(|e| e.process_id), Some(2));
}

#[test]
fn vault_clear() {
    let mut vault = TokenVault::new();
    let entry = TokenEntry {
        handle: 0,
        domain_user: "A\\B".to_string(),
        process_id: 1,
        token_type: TokenType::Stolen,
        credentials: None,
    };
    vault.add(entry);
    vault.set_impersonating(Some(0));
    vault.clear();
    assert!(vault.is_empty());
    assert!(vault.impersonating().is_none());
}

#[test]
fn vault_iter() {
    let mut vault = TokenVault::new();
    let mk = |pid: u32| TokenEntry {
        handle: 0,
        domain_user: format!("D\\U{pid}"),
        process_id: pid,
        token_type: TokenType::Stolen,
        credentials: None,
    };
    vault.add(mk(10));
    vault.add(mk(20));
    vault.add(mk(30));
    vault.remove(1); // Remove middle.
    let ids: Vec<u32> = vault.iter().map(|(id, _)| id).collect();
    assert_eq!(ids, vec![0, 2]);
}

#[test]
fn vault_impersonation_tracking() {
    let mut vault = TokenVault::new();
    let entry = TokenEntry {
        handle: 0,
        domain_user: "A\\B".to_string(),
        process_id: 1,
        token_type: TokenType::MakeNetwork,
        credentials: None,
    };
    let id = vault.add(entry);
    assert!(!vault.is_impersonating(id));
    vault.set_impersonating(Some(id));
    assert!(vault.is_impersonating(id));
    assert_eq!(vault.impersonating(), Some(id));
    // Removing the impersonated token clears impersonation.
    vault.remove(id);
    assert!(vault.impersonating().is_none());
}

#[test]
fn token_type_from_u32() {
    assert_eq!(TokenType::from_u32(0x1), Some(TokenType::Stolen));
    assert_eq!(TokenType::from_u32(0x2), Some(TokenType::MakeNetwork));
    assert_eq!(TokenType::from_u32(0x3), None);
}

#[test]
fn vault_len_and_is_empty() {
    let mut vault = TokenVault::new();
    assert!(vault.is_empty());
    assert_eq!(vault.len(), 0);
    let entry = TokenEntry {
        handle: 0,
        domain_user: "D\\U".to_string(),
        process_id: 1,
        token_type: TokenType::Stolen,
        credentials: None,
    };
    vault.add(entry);
    assert!(!vault.is_empty());
    assert_eq!(vault.len(), 1);
}

#[test]
fn vault_get_nonexistent_returns_none() {
    let vault = TokenVault::new();
    assert!(vault.get(0).is_none());
    assert!(vault.get(999).is_none());
}

// ─── FoundToken / list_found_tokens ──────────────────────────────────────

fn make_found(user: &str, token_type: u32, integrity: u32, imp: u32, handle: u32) -> FoundToken {
    FoundToken {
        domain_user: user.to_string(),
        process_id: 42,
        handle,
        integrity_level: integrity,
        impersonation_level: imp,
        token_type,
    }
}

#[test]
fn found_token_fields_accessible() {
    let ft = make_found("DOMAIN\\user", 1, 8192, 0, 0x100);
    assert_eq!(ft.domain_user, "DOMAIN\\user");
    assert_eq!(ft.process_id, 42);
    assert_eq!(ft.handle, 0x100);
    assert_eq!(ft.integrity_level, 8192);
    assert_eq!(ft.impersonation_level, 0);
    assert_eq!(ft.token_type, 1);
}

#[test]
fn list_found_tokens_stub_returns_empty_on_non_windows() {
    let tokens = native::list_found_tokens();
    // On non-Windows the stub always returns an empty vec.
    assert!(tokens.is_empty());
}
