use super::*;

fn make_agent(overrides: impl FnOnce(&mut transport::AgentSummary)) -> transport::AgentSummary {
    let mut agent = transport::AgentSummary {
        name_id: "DEAD0001".into(),
        status: "alive".into(),
        domain_name: "CORP".into(),
        username: "admin".into(),
        internal_ip: "10.0.0.5".into(),
        external_ip: "203.0.113.1".into(),
        hostname: "WS01".into(),
        process_arch: "x64".into(),
        process_name: "svchost.exe".into(),
        process_pid: "1234".into(),
        elevated: false,
        os_version: "Windows 10".into(),
        os_build: "19045".into(),
        os_arch: "x86_64".into(),
        sleep_delay: "5".into(),
        sleep_jitter: "20".into(),
        last_call_in: "2s".into(),
        note: String::new(),
        pivot_parent: None,
        pivot_links: Vec::new(),
    };
    overrides(&mut agent);
    agent
}

#[test]
fn agent_ip_prefers_internal() {
    let agent = make_agent(|_| {});
    assert_eq!(agent_ip(&agent), "10.0.0.5");
}

#[test]
fn agent_ip_falls_back_to_external_when_internal_empty() {
    let agent = make_agent(|a| a.internal_ip = String::new());
    assert_eq!(agent_ip(&agent), "203.0.113.1");
}

#[test]
fn agent_ip_falls_back_to_external_when_internal_whitespace() {
    let agent = make_agent(|a| a.internal_ip = "   ".into());
    assert_eq!(agent_ip(&agent), "203.0.113.1");
}

#[test]
fn agent_arch_prefers_process_arch() {
    let agent = make_agent(|_| {});
    assert_eq!(agent_arch(&agent), "x64");
}

#[test]
fn agent_arch_falls_back_to_os_arch_when_process_arch_empty() {
    let agent = make_agent(|a| a.process_arch = String::new());
    assert_eq!(agent_arch(&agent), "x86_64");
}

#[test]
fn agent_arch_falls_back_to_os_arch_when_process_arch_whitespace() {
    let agent = make_agent(|a| a.process_arch = "  ".into());
    assert_eq!(agent_arch(&agent), "x86_64");
}

#[test]
fn agent_os_includes_build_when_present() {
    let agent = make_agent(|_| {});
    assert_eq!(agent_os(&agent), "Windows 10 (19045)");
}

#[test]
fn agent_os_returns_version_only_when_build_empty() {
    let agent = make_agent(|a| a.os_build = String::new());
    assert_eq!(agent_os(&agent), "Windows 10");
}

#[test]
fn agent_os_returns_version_only_when_build_whitespace() {
    let agent = make_agent(|a| a.os_build = "   ".into());
    assert_eq!(agent_os(&agent), "Windows 10");
}

#[test]
fn agent_sleep_jitter_both_present() {
    let agent = make_agent(|_| {});
    assert_eq!(agent_sleep_jitter(&agent), "5s / 20%");
}

#[test]
fn agent_sleep_jitter_delay_only() {
    let agent = make_agent(|a| a.sleep_jitter = String::new());
    assert_eq!(agent_sleep_jitter(&agent), "5");
}

#[test]
fn agent_sleep_jitter_jitter_only() {
    let agent = make_agent(|a| a.sleep_delay = String::new());
    assert_eq!(agent_sleep_jitter(&agent), "j20%");
}

#[test]
fn agent_sleep_jitter_both_empty() {
    let agent = make_agent(|a| {
        a.sleep_delay = String::new();
        a.sleep_jitter = String::new();
    });
    assert_eq!(agent_sleep_jitter(&agent), "");
}

#[test]
fn agent_sleep_jitter_whitespace_treated_as_empty() {
    let agent = make_agent(|a| {
        a.sleep_delay = "  ".into();
        a.sleep_jitter = "  ".into();
    });
    assert_eq!(agent_sleep_jitter(&agent), "");
}

#[test]
fn agent_metadata_all_empty() {
    let agent = make_agent(|a| {
        a.internal_ip = String::new();
        a.external_ip = String::new();
        a.process_arch = String::new();
        a.os_arch = String::new();
        a.os_version = String::new();
        a.os_build = String::new();
        a.sleep_delay = String::new();
        a.sleep_jitter = String::new();
    });
    assert_eq!(agent_ip(&agent), "");
    assert_eq!(agent_arch(&agent), "");
    assert_eq!(agent_os(&agent), "");
    assert_eq!(agent_sleep_jitter(&agent), "");
}
