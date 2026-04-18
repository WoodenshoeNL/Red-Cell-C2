use super::*;

#[test]
fn listener_protocol_label_round_trips() {
    for proto in ListenerProtocol::ALL {
        let label = proto.label();
        assert!(!label.is_empty());
    }
    assert_eq!(ListenerProtocol::Http.label(), "Http");
    assert_eq!(ListenerProtocol::Https.label(), "Https");
    assert_eq!(ListenerProtocol::Smb.label(), "Smb");
    assert_eq!(ListenerProtocol::External.label(), "External");
}

#[test]
fn listener_dialog_new_create_defaults() {
    let dialog = ListenerDialogState::new_create();
    assert_eq!(dialog.mode, ListenerDialogMode::Create);
    assert_eq!(dialog.protocol, ListenerProtocol::Http);
    assert!(dialog.name.is_empty());
    assert!(dialog.host.is_empty());
    assert!(dialog.port.is_empty());
    assert!(!dialog.proxy_enabled);
}

#[test]
fn listener_dialog_to_info_http() {
    let mut dialog = ListenerDialogState::new_create();
    dialog.name = "test-http".to_owned();
    dialog.protocol = ListenerProtocol::Http;
    dialog.host = "0.0.0.0".to_owned();
    dialog.port = "8080".to_owned();
    dialog.user_agent = "TestAgent/1.0".to_owned();
    dialog.headers = "X-Custom: val".to_owned();
    dialog.uris = "/api/v1".to_owned();
    dialog.host_header = "example.com".to_owned();

    let info = dialog.to_listener_info();
    assert_eq!(info.name.as_deref(), Some("test-http"));
    assert_eq!(info.protocol.as_deref(), Some("Http"));
    assert_eq!(info.host_bind.as_deref(), Some("0.0.0.0"));
    assert_eq!(info.port_bind.as_deref(), Some("8080"));
    assert_eq!(info.user_agent.as_deref(), Some("TestAgent/1.0"));
    assert_eq!(info.headers.as_deref(), Some("X-Custom: val"));
    assert_eq!(info.uris.as_deref(), Some("/api/v1"));
    assert_eq!(info.secure.as_deref(), Some("false"));
    assert_eq!(info.proxy_enabled.as_deref(), Some("false"));
    // Proxy fields should be None when not enabled
    assert!(info.proxy_type.is_none());
    assert!(info.proxy_host.is_none());
    // HostHeader is in extra
    assert_eq!(info.extra.get("HostHeader").and_then(|v| v.as_str()), Some("example.com"));
}

#[test]
fn listener_dialog_to_info_https_with_proxy() {
    let mut dialog = ListenerDialogState::new_create();
    dialog.name = "test-https".to_owned();
    dialog.protocol = ListenerProtocol::Https;
    dialog.host = "0.0.0.0".to_owned();
    dialog.port = "443".to_owned();
    dialog.proxy_enabled = true;
    dialog.proxy_type = "http".to_owned();
    dialog.proxy_host = "proxy.local".to_owned();
    dialog.proxy_port = "3128".to_owned();
    dialog.proxy_username = "user".to_owned();
    dialog.proxy_password = Zeroizing::new("pass".to_owned());

    let info = dialog.to_listener_info();
    assert_eq!(info.protocol.as_deref(), Some("Https"));
    assert_eq!(info.secure.as_deref(), Some("true"));
    assert_eq!(info.proxy_enabled.as_deref(), Some("true"));
    assert_eq!(info.proxy_type.as_deref(), Some("http"));
    assert_eq!(info.proxy_host.as_deref(), Some("proxy.local"));
    assert_eq!(info.proxy_port.as_deref(), Some("3128"));
    assert_eq!(info.proxy_username.as_deref(), Some("user"));
    assert_eq!(info.proxy_password.as_deref(), Some("pass"));
}

/// The proxy_password field must be `Zeroizing<String>` so that heap memory is wiped on drop.
/// This test is a compile-time contract: if the field type is changed to a bare `String`,
/// the `Zeroizing::clone` call below will fail to compile.
#[test]
fn proxy_password_field_is_zeroizing() {
    let mut dialog = ListenerDialogState::new_create();
    *dialog.proxy_password = "secret".to_owned();
    // Confirm we hold a Zeroizing<String> — the explicit type annotation is the assertion.
    let _z: Zeroizing<String> = dialog.proxy_password.clone();
    assert_eq!(*_z, "secret");
}

#[test]
fn listener_dialog_to_info_smb() {
    let mut dialog = ListenerDialogState::new_create();
    dialog.name = "smb-pipe".to_owned();
    dialog.protocol = ListenerProtocol::Smb;
    dialog.pipe_name = r"\\.\pipe\mypipe".to_owned();

    let info = dialog.to_listener_info();
    assert_eq!(info.name.as_deref(), Some("smb-pipe"));
    assert_eq!(info.protocol.as_deref(), Some("Smb"));
    assert_eq!(info.extra.get("PipeName").and_then(|v| v.as_str()), Some(r"\\.\pipe\mypipe"));
    // HTTP-specific fields should be default
    assert!(info.host_bind.is_none());
    assert!(info.port_bind.is_none());
}

#[test]
fn listener_dialog_to_info_external() {
    let mut dialog = ListenerDialogState::new_create();
    dialog.name = "ext-listener".to_owned();
    dialog.protocol = ListenerProtocol::External;
    dialog.endpoint = "/callback".to_owned();

    let info = dialog.to_listener_info();
    assert_eq!(info.name.as_deref(), Some("ext-listener"));
    assert_eq!(info.protocol.as_deref(), Some("External"));
    assert_eq!(info.extra.get("Endpoint").and_then(|v| v.as_str()), Some("/callback"));
}

#[test]
fn listener_dialog_new_edit_preserves_fields() {
    let mut source = ListenerInfo::default();
    source.host_bind = Some("10.0.0.1".to_owned());
    source.port_bind = Some("8443".to_owned());
    source.user_agent = Some("MyAgent".to_owned());
    source.proxy_enabled = Some("true".to_owned());
    source.proxy_type = Some("https".to_owned());
    source.proxy_host = Some("px.local".to_owned());
    source.extra.insert("PipeName".to_owned(), serde_json::Value::String("pipe1".to_owned()));

    let dialog = ListenerDialogState::new_edit("mylistener", "Https", &source);
    assert_eq!(dialog.mode, ListenerDialogMode::Edit);
    assert_eq!(dialog.name, "mylistener");
    assert_eq!(dialog.protocol, ListenerProtocol::Https);
    assert_eq!(dialog.host, "10.0.0.1");
    assert_eq!(dialog.port, "8443");
    assert_eq!(dialog.user_agent, "MyAgent");
    assert!(dialog.proxy_enabled);
    assert_eq!(dialog.proxy_type, "https");
    assert_eq!(dialog.proxy_host, "px.local");
    assert_eq!(dialog.pipe_name, "pipe1");
}

#[test]
fn build_listener_new_creates_correct_message() {
    let info = ListenerInfo {
        name: Some("http-1".to_owned()),
        protocol: Some("Http".to_owned()),
        ..ListenerInfo::default()
    };
    let msg = build_listener_new(info, "operator1");
    match msg {
        OperatorMessage::ListenerNew(m) => {
            assert_eq!(m.head.event, EventCode::Listener);
            assert_eq!(m.head.user, "operator1");
            assert_eq!(m.info.name.as_deref(), Some("http-1"));
        }
        _ => panic!("expected ListenerNew"),
    }
}

#[test]
fn build_listener_edit_creates_correct_message() {
    let info = ListenerInfo { name: Some("http-1".to_owned()), ..ListenerInfo::default() };
    let msg = build_listener_edit(info, "op2");
    match msg {
        OperatorMessage::ListenerEdit(m) => {
            assert_eq!(m.head.event, EventCode::Listener);
            assert_eq!(m.head.user, "op2");
        }
        _ => panic!("expected ListenerEdit"),
    }
}

#[test]
fn build_listener_remove_creates_correct_message() {
    let msg = build_listener_remove("http-1", "op3");
    match msg {
        OperatorMessage::ListenerRemove(m) => {
            assert_eq!(m.head.event, EventCode::Listener);
            assert_eq!(m.head.user, "op3");
            assert_eq!(m.info.name, "http-1");
        }
        _ => panic!("expected ListenerRemove"),
    }
}

#[test]
fn listener_dialog_http_empty_optional_fields_produce_none() {
    let mut dialog = ListenerDialogState::new_create();
    dialog.name = "minimal".to_owned();
    dialog.protocol = ListenerProtocol::Http;
    dialog.host = "0.0.0.0".to_owned();
    dialog.port = "80".to_owned();
    // Leave user_agent, headers, uris, host_header all empty

    let info = dialog.to_listener_info();
    assert!(info.user_agent.is_none());
    assert!(info.headers.is_none());
    assert!(info.uris.is_none());
    assert!(!info.extra.contains_key("HostHeader"));
}
