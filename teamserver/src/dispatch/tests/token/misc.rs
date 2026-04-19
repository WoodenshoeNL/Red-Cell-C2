//! Miscellaneous unit tests: invalid subcommand, empty payload, all-subcommands smoke test.

use super::*;

#[tokio::test]
async fn unit_handle_invalid_subcommand() {
    let mut payload = Vec::new();
    push_u32(&mut payload, 9999);

    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err());
    let err = result.expect_err("expected Err");
    let err_str = err.to_string();
    assert!(err_str.contains("0x00000028"), "error should reference token command id: {err_str}");
}

#[tokio::test]
async fn unit_handle_empty_payload() {
    let payload: &[u8] = &[];
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, payload).await;
    assert!(result.is_err(), "empty payload should fail to read subcommand");
}

#[tokio::test]
async fn unit_handle_all_subcommands_return_none() {
    let test_cases: Vec<Vec<u8>> = {
        let mut cases = Vec::new();

        let mut r = Vec::new();
        push_u32(&mut r, 1);
        push_string(&mut r, "user");
        cases.push(unit_token_payload(DemonTokenCommand::Impersonate, &r));

        let mut r = Vec::new();
        push_utf16(&mut r, "user");
        push_u32(&mut r, 1);
        push_u32(&mut r, 2);
        cases.push(unit_token_payload(DemonTokenCommand::Steal, &r));

        cases.push(unit_token_payload(DemonTokenCommand::List, &[]));

        let mut r = Vec::new();
        push_u32(&mut r, 1);
        cases.push(unit_token_payload(DemonTokenCommand::PrivsGetOrList, &r));

        cases.push(unit_token_payload(DemonTokenCommand::Make, &[]));

        let mut r = Vec::new();
        push_u32(&mut r, 0);
        push_utf16(&mut r, "user");
        cases.push(unit_token_payload(DemonTokenCommand::GetUid, &r));

        let mut r = Vec::new();
        push_u32(&mut r, 1);
        cases.push(unit_token_payload(DemonTokenCommand::Revert, &r));

        let mut r = Vec::new();
        push_u32(&mut r, 1);
        push_u32(&mut r, 0);
        cases.push(unit_token_payload(DemonTokenCommand::Remove, &r));

        cases.push(unit_token_payload(DemonTokenCommand::Clear, &[]));

        let mut r = Vec::new();
        push_u32(&mut r, 0);
        cases.push(unit_token_payload(DemonTokenCommand::FindTokens, &r));

        cases
    };

    for (i, payload) in test_cases.iter().enumerate() {
        let events = EventBus::default();
        let _rx = events.subscribe();
        let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, payload).await;
        assert!(result.is_ok(), "case {i} should succeed");
        assert_eq!(result.expect("ok"), None, "case {i} should return None");
    }
}
